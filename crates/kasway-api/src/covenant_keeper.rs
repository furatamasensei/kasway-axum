//! Covenant settlement keeper.
//!
//! Once the chain observer marks a covenant `funded`, this worker handles the
//! **auto-refund** side: at/after `expiry`, `refund()` returns the gross to the
//! customer's address (permissionless — no customer key needed), marks the
//! invoice `expired`, and emits `invoice.refunded`.
//!
//! The **release** side (paying the merchant) is NOT done here: release now
//! requires the CUSTOMER's signature (their "confirm delivery"), so it is driven
//! by a customer-facing endpoint, not this background worker. The keeper only
//! ever signs its own fee input to pay the miner fee; it never holds a key over
//! the covenant value. All covenant script/tx crypto lives in `kasway_covenant`.
//!
//! Env: `COVENANT_KEEPER_ENABLED` gate (default on when a keeper fee key and
//! `KASPA_NODE_URL` are set), `COVENANT_KEEPER_FEE_SECRET` (32-byte hex),
//! `COVENANT_KEEPER_MIN_FEE_SOMPI`. Single-process by design; a row is flipped to
//! `settling` before submission so a tick never double-spends a covenant.

use crate::error::{AppError, AppResult};
use crate::handlers::{invoices, webhooks};
use crate::kaspa_wrpc::KaspaWrpcClient;
use crate::kpr1::parse_required_outputs;
use crate::state::AppState;
use crate::util::now_iso;
use kasway_covenant::escrow_v2::{
    compile_escrow_v2, complete_refund_by_arbiter, complete_refund_by_merchant, complete_release,
    complete_release_arbitrated, complete_settlement, prepare_refund_by_arbiter, prepare_release, prepare_settlement,
    ArbiterRefundDraft, EscrowV2Params, EP_REFUND_BY_ARBITER, EP_REFUND_BY_MERCHANT, EP_RELEASE_CAPTURED,
    EP_RELEASE_CONFIRMED,
};
use kasway_covenant::{covenant_address, network_prefix, rpc_submit_params, Destination, KeeperKey, Payout, Utxo};
use serde_json::json;
use tokio::task::JoinHandle;

const POLL_INTERVAL_SECS: u64 = 5;
const CLAIM_BATCH: i64 = 10;

/// `COVENANT_KEEPER_ENABLED` gate. Defaults on only when a keeper fee key and a
/// node URL are configured; `0`/`false`/`off` force-disable.
pub fn enabled_from_env() -> bool {
    match std::env::var("COVENANT_KEEPER_ENABLED").ok().as_deref().map(str::trim) {
        Some("0") | Some("false") | Some("off") | Some("FALSE") | Some("Off") => false,
        Some(v) if !v.is_empty() => true,
        _ => {
            std::env::var("COVENANT_KEEPER_FEE_SECRET").ok().filter(|s| !s.trim().is_empty()).is_some()
                && std::env::var("KASPA_NODE_URL").ok().filter(|s| !s.trim().is_empty()).is_some()
        }
    }
}

/// Spawn the keeper loop. Idle when no node/key is configured.
pub fn spawn(state: AppState) -> JoinHandle<()> {
    tokio::spawn(async move {
        let Some(client) = KaspaWrpcClient::from_env() else {
            tracing::warn!("covenant keeper: KASPA_NODE_URL not set; keeper idle");
            return;
        };
        loop {
            match run_tick(&state, &client).await {
                Ok(0) => tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await,
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!("covenant keeper tick error: {err}");
                    tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
                }
            }
        }
    })
}

#[derive(sqlx::FromRow)]
struct Funded {
    intent_pk: i64,
    invoice_id: i64,
    user_id: i64,
    store_id: Option<i64>,
    public_id: String,
    network: String,
    required_outputs: String,
    customer_refund_address: Option<String>,
    covenant_address: Option<String>,
    gross_amount: Option<i64>,
    expiry_ts: Option<i64>,
    /// Snapshot of the EscrowV2 arbiter panel (JSON array of 32-byte pubkey hex)
    /// baked at finalize. NULL for pre-0034 rows → settlement falls back to config.
    arbiter_panel_json: Option<String>,
    arbiter_threshold: Option<i32>,
}

/// One pass: settle up to `CLAIM_BATCH` funded covenants. Returns how many were
/// acted on (0 → the caller idles).
pub async fn run_tick(state: &AppState, client: &KaspaWrpcClient) -> Result<usize, sqlx::Error> {
    let keeper = match keeper_key(state) {
        Some(k) => k,
        None => return Ok(0), // no fee key configured — nothing to do
    };
    let min_fee = state.config.covenant.keeper_min_fee_sompi;

    // Only past-expiry funded covenants are auto-refunded here. Before expiry the
    // covenant waits for the customer to confirm release (a separate endpoint).
    let now_ts = chrono::Utc::now().timestamp();
    let candidates = sqlx::query_as::<_, Funded>(
        "SELECT i.id AS intent_pk, i.invoice_id, i.user_id, inv.store_id, inv.public_id, i.network, \
                i.required_outputs, i.customer_refund_address, i.covenant_address, i.gross_amount, i.expiry_ts, \
                i.arbiter_panel_json, i.arbiter_threshold \
         FROM kpr1_payment_intents i JOIN invoices inv ON inv.id = i.invoice_id \
         WHERE i.covenant_state = 'funded' AND inv.status = 'open' AND i.expiry_ts <= $2 \
         ORDER BY i.id LIMIT $1",
    )
    .bind(CLAIM_BATCH)
    .bind(now_ts)
    .fetch_all(&state.db.pool)
    .await?;

    let mut acted = 0usize;
    for c in &candidates {
        // Claim the row: 'funded' -> 'settling'. If another tick took it, skip.
        let claimed = sqlx::query("UPDATE kpr1_payment_intents SET covenant_state = 'settling', updated_at = $1 WHERE id = $2 AND covenant_state = 'funded'")
            .bind(now_iso())
            .bind(c.intent_pk)
            .execute(&state.db.pool)
            .await?;
        if claimed.rows_affected() == 0 {
            continue;
        }
        match settle_one(state, client, &keeper, min_fee, c).await {
            Ok(()) => acted += 1,
            Err(err) => {
                tracing::warn!("covenant keeper: intent {} settlement failed: {err}; will retry", c.intent_pk);
                // Release the claim so a later tick retries.
                let _ = sqlx::query("UPDATE kpr1_payment_intents SET covenant_state = 'funded', updated_at = $1 WHERE id = $2 AND covenant_state = 'settling'")
                    .bind(now_iso())
                    .bind(c.intent_pk)
                    .execute(&state.db.pool)
                    .await;
            }
        }
    }
    Ok(acted)
}

fn keeper_key(state: &AppState) -> Option<KeeperKey> {
    let hex = state.config.covenant.keeper_fee_secret_hex.as_deref()?;
    let bytes = decode_hex32(hex.trim())?;
    KeeperKey::from_secret_bytes(&bytes).ok()
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The keeper's own error type for a single settlement (string-wrapped).
#[derive(Debug)]
struct KeeperError(String);
impl std::fmt::Display for KeeperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for KeeperError {}
fn kerr(msg: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(KeeperError(msg.into()))
}

async fn settle_one(
    state: &AppState,
    client: &KaspaWrpcClient,
    keeper: &KeeperKey,
    min_fee: u64,
    c: &Funded,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (params, prefix, covenant_addr) = rebuild_params(state, c).map_err(|e| kerr(format!("{e:?}")))?;
    let compiled = compile_escrow_v2(&params).map_err(|e| kerr(e.to_string()))?;

    // Re-derive and confirm the covenant address matches what we stored (no substitution).
    let derived = covenant_address(&compiled, prefix).map_err(|e| kerr(e.to_string()))?.to_string();
    if derived != covenant_addr {
        return Err(kerr(format!("covenant address mismatch: derived {derived} != stored {covenant_addr}")));
    }
    let gross = params.gross_amount;

    // Locate the covenant funding UTXO (value == gross) and a keeper fee UTXO.
    let cov_utxos = client.fetch_utxos(&covenant_addr).await.map_err(|e| kerr(e.to_string()))?;
    let Some((cov_txid, cov_index, cov_value)) = cov_utxos.into_iter().find(|(_, _, v)| *v == gross) else {
        return Err(kerr("covenant funding UTXO not found yet"));
    };
    let keeper_address = keeper.address(prefix).to_string();
    let fee_utxos = client.fetch_utxos(&keeper_address).await.map_err(|e| kerr(e.to_string()))?;
    let Some((fee_txid, fee_index, fee_value)) = fee_utxos.into_iter().find(|(_, _, v)| *v > min_fee + 1) else {
        return Err(kerr(format!("no keeper fee UTXO > {min_fee} sompi at {keeper_address}")));
    };

    let covenant_utxo = Utxo { transaction_id: cov_txid, index: cov_index, value: cov_value };
    let fee_utxo = Utxo { transaction_id: fee_txid, index: fee_index, value: fee_value };

    // Auto-capture to the merchant after the dispute window (permissionless
    // `release_captured`, lock_time = capture_time). Keeper subsidizes the gas.
    let draft = prepare_release(&compiled, &params, &covenant_utxo, &fee_utxo, min_fee, keeper, prefix, params.capture_time)
        .map_err(|e| kerr(e.to_string()))?;
    let spend = complete_release(&compiled, draft, EP_RELEASE_CAPTURED, None).map_err(|e| kerr(e.to_string()))?;
    let tx_id = client.submit_transaction(rpc_submit_params(&spend)).await.map_err(|e| kerr(e.to_string()))?;
    let now = now_iso();

    sqlx::query(
        "UPDATE kpr1_payment_intents SET covenant_state = 'captured', status = 'settled', settled_at = COALESCE(settled_at, $1), release_tx_id = $2, updated_at = $1 WHERE id = $3",
    )
    .bind(&now).bind(&tx_id).bind(c.intent_pk).execute(&state.db.pool).await?;
    sqlx::query("UPDATE invoices SET status = 'paid', paid_at = COALESCE(paid_at, $1), updated_at = $1 WHERE id = $2 AND status = 'open'")
        .bind(&now).bind(c.invoice_id).execute(&state.db.pool).await?;
    emit_invoice_event(state, c, "invoice.paid", &tx_id).await?;

    tracing::info!("covenant keeper: intent {} auto-captured to merchant via tx {tx_id}", c.intent_pk);
    Ok(())
}

async fn emit_invoice_event(
    state: &AppState,
    c: &Funded,
    event: &str,
    tx_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut payload = invoice_payload(state, c.invoice_id).await.unwrap_or_else(|| json!({ "publicId": c.public_id }));
    if let serde_json::Value::Object(map) = &mut payload {
        map.insert("settlementTxId".into(), json!(tx_id));
    }
    webhooks::emit_event(state, c.user_id, c.store_id, event, "invoice", &c.public_id, &payload)
        .await
        .map_err(|e| kerr(e.to_string()))?;
    Ok(())
}

/// Serialized invoice (post-update) for the settlement webhook payload.
async fn invoice_payload(state: &AppState, invoice_id: i64) -> Option<serde_json::Value> {
    let inv = invoices::load_by_id(state, invoice_id).await.ok()?;
    let (items, intent) = invoices::load_relations(state, invoice_id).await.ok()?;
    Some(invoices::serialize_invoice(&inv, &items, intent.as_ref()))
}

// ---------------------------------------------------------------------------
// Customer-driven release (merchant capture). release() needs the CUSTOMER's
// signature, so it is a two-step checkout flow:
//   1. prepare → server builds the release tx, returns the sighash to sign.
//   2. submit  → server rebuilds the identical tx, attaches the customer's
//                signature, broadcasts, and marks the invoice paid.
// The draft is deterministic (recompiled + deterministic UTXO selection), so no
// server-side draft state is stored between the two calls.
// ---------------------------------------------------------------------------

fn rerr(msg: impl AsRef<str>) -> AppError {
    AppError::commerce(422, msg.as_ref())
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()).collect()
}

/// Everything needed to (re)build a release spend for a funded covenant.
struct ReleaseCtx {
    params: EscrowV2Params,
    prefix: kasway_covenant::Prefix,
    covenant_utxo: Utxo,
    fee_utxo: Utxo,
    keeper: KeeperKey,
    intent_pk: i64,
    invoice_id: i64,
    user_id: i64,
    store_id: Option<i64>,
    public_id: String,
    min_fee: u64,
}

/// The Kasway arbiter signing key (from `COVENANT_ARBITER_SECRET`). It signs
/// dispute rulings — `release_arbitrated` / `refund_by_arbiter` — server-side.
fn arbiter_signing_key(state: &AppState) -> AppResult<KeeperKey> {
    let hex = state
        .config
        .covenant
        .arbiter_secret_hex
        .as_deref()
        .ok_or_else(|| rerr("covenant arbiter key is not configured (COVENANT_ARBITER_SECRET)"))?;
    let bytes = decode_hex32(hex.trim()).ok_or_else(|| rerr("arbiter secret must be 32-byte hex"))?;
    KeeperKey::from_secret_bytes(&bytes).map_err(|e| rerr(e.to_string()))
}

fn rebuild_params(state: &AppState, c: &Funded) -> AppResult<(EscrowV2Params, kasway_covenant::Prefix, String)> {
    let covenant_addr = c.covenant_address.clone().ok_or_else(|| rerr("covenant not finalized"))?;
    let refund_addr = c.customer_refund_address.clone().ok_or_else(|| rerr("missing customer refund address"))?;
    let gross = u64::try_from(c.gross_amount.ok_or_else(|| rerr("missing gross"))?).map_err(|_| rerr("bad gross"))?;
    // Scale seconds -> milliseconds so the on-chain lock_time is a wall-clock
    // timestamp (>= 500e9), matching finalize (see kpr1.rs). Must stay consistent
    // with finalize or the covenant address will not match.
    let capture_time = u64::try_from(c.expiry_ts.ok_or_else(|| rerr("missing capture time"))?)
        .map_err(|_| rerr("bad capture time"))?
        .saturating_mul(1000);
    let prefix = network_prefix(&c.network).map_err(|e| rerr(e.to_string()))?;
    let customer_refund = Destination::parse(&refund_addr).map_err(|e| rerr(e.to_string()))?;
    // Prefer the panel snapshot baked at finalize (robust to config changes);
    // fall back to the configured panel for pre-0034 intents.
    let (arbiter_panel, arbiter_threshold) = match (&c.arbiter_panel_json, c.arbiter_threshold) {
        (Some(json), Some(th)) => {
            let hexes: Vec<String> = serde_json::from_str(json).map_err(|e| rerr(format!("bad arbiter panel snapshot: {e}")))?;
            let mut panel = Vec::with_capacity(hexes.len());
            for h in &hexes {
                panel.push(decode_hex32(h.trim()).ok_or_else(|| rerr("arbiter panel snapshot entry must be 32-byte hex"))?);
            }
            (panel, th as u32)
        }
        _ => crate::kpr1::escrow_arbiter_panel(state)?,
    };

    let outs = parse_required_outputs(&c.required_outputs);
    let merchant_addr = outs
        .iter()
        .find(|o| o.role == "merchant_net")
        .map(|o| o.address.clone())
        .ok_or_else(|| rerr("intent has no merchant_net payout"))?;
    let merchant = Destination::parse(&merchant_addr).map_err(|e| rerr(e.to_string()))?;
    let mut payouts = Vec::new();
    for out in &outs {
        let destination = Destination::parse(&out.address).map_err(|e| rerr(e.to_string()))?;
        let value = u64::try_from(out.amount_sompi).map_err(|_| rerr("bad payout"))?;
        payouts.push(Payout { destination, value });
    }
    Ok((
        EscrowV2Params {
            payouts,
            customer_refund,
            merchant,
            arbiter_panel,
            arbiter_threshold,
            gross_amount: gross,
            capture_time,
        },
        prefix,
        covenant_addr,
    ))
}

async fn gather_release_inputs(state: &AppState, client: &KaspaWrpcClient, public_id: &str) -> AppResult<ReleaseCtx> {
    let keeper = keeper_key(state).ok_or_else(|| rerr("covenant keeper fee key is not configured"))?;
    let min_fee = state.config.covenant.keeper_min_fee_sompi;

    let c = load_funded_open(state, public_id).await?;

    let (params, prefix, covenant_addr) = rebuild_params(state, &c)?;
    let compiled = compile_escrow_v2(&params).map_err(|e| rerr(e.to_string()))?;
    let derived = covenant_address(&compiled, prefix).map_err(|e| rerr(e.to_string()))?.to_string();
    if derived != covenant_addr {
        return Err(rerr("covenant address mismatch"));
    }
    let gross = params.gross_amount;

    let cov_utxos = client.fetch_utxos(&covenant_addr).await.map_err(|e| rerr(e.to_string()))?;
    let covenant_utxo = cov_utxos
        .into_iter()
        .find(|(_, _, v)| *v == gross)
        .map(|(t, i, v)| Utxo { transaction_id: t, index: i, value: v })
        .ok_or_else(|| rerr("covenant funding UTXO not visible yet"))?;

    // Deterministic fee-UTXO pick so prepare and submit build the identical tx.
    let mut fee_utxos = client.fetch_utxos(&keeper.address(prefix).to_string()).await.map_err(|e| rerr(e.to_string()))?;
    fee_utxos.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    let fee_utxo = fee_utxos
        .into_iter()
        .find(|(_, _, v)| *v > min_fee + 1)
        .map(|(t, i, v)| Utxo { transaction_id: t, index: i, value: v })
        .ok_or_else(|| rerr("no keeper fee UTXO available for release"))?;

    Ok(ReleaseCtx {
        params,
        prefix,
        covenant_utxo,
        fee_utxo,
        keeper,
        intent_pk: c.intent_pk,
        invoice_id: c.invoice_id,
        user_id: c.user_id,
        store_id: c.store_id,
        public_id: c.public_id,
        min_fee,
    })
}

/// Step 1: build the release tx and return the sighash the customer must sign.
pub(crate) async fn customer_release_prepare(state: &AppState, public_id: &str) -> AppResult<serde_json::Value> {
    let client = KaspaWrpcClient::from_env().ok_or_else(|| rerr("Kaspa node is not configured"))?;
    let ctx = gather_release_inputs(state, &client, public_id).await?;
    let compiled = compile_escrow_v2(&ctx.params).map_err(|e| rerr(e.to_string()))?;
    let draft = prepare_release(&compiled, &ctx.params, &ctx.covenant_utxo, &ctx.fee_utxo, ctx.min_fee, &ctx.keeper, ctx.prefix, 0)
        .map_err(|e| rerr(e.to_string()))?;
    Ok(json!({
        "covenantSighash": encode_hex(&draft.covenant_sighash),
        "sigHashType": "SIG_HASH_ALL",
        "algorithm": "schnorr",
        "note": "sign this 32-byte sighash with the customer refund key; submit the 65-byte signature (schnorr || sighash-type byte) as hex",
    }))
}

/// Step 2: attach the customer's signature, broadcast, and settle to the merchant.
pub(crate) async fn customer_release_submit(state: &AppState, public_id: &str, signature_hex: &str) -> AppResult<serde_json::Value> {
    let sig = decode_hex(signature_hex.trim())
        .filter(|s| s.len() == 65)
        .ok_or_else(|| rerr("signature must be 65-byte hex (schnorr signature || sighash-type byte)"))?;
    let client = KaspaWrpcClient::from_env().ok_or_else(|| rerr("Kaspa node is not configured"))?;
    let ctx = gather_release_inputs(state, &client, public_id).await?;

    // Claim the row so a concurrent keeper refund can't race this release.
    let claimed = sqlx::query(
        "UPDATE kpr1_payment_intents SET covenant_state = 'releasing', updated_at = $1 WHERE id = $2 AND covenant_state = 'funded'",
    )
    .bind(now_iso())
    .bind(ctx.intent_pk)
    .execute(&state.db.pool)
    .await
    .map_err(AppError::Database)?;
    if claimed.rows_affected() == 0 {
        return Err(rerr("covenant is no longer awaiting release"));
    }

    let outcome = build_and_broadcast_release(&client, &ctx, &sig).await;
    match outcome {
        Ok(tx_id) => {
            let now = now_iso();
            sqlx::query(
                "UPDATE kpr1_payment_intents SET covenant_state = 'released', status = 'settled', \
                 settled_at = COALESCE(settled_at, $1), release_tx_id = $2, updated_at = $1 WHERE id = $3",
            )
            .bind(&now).bind(&tx_id).bind(ctx.intent_pk).execute(&state.db.pool).await.map_err(AppError::Database)?;
            sqlx::query("UPDATE invoices SET status = 'paid', paid_at = COALESCE(paid_at, $1), updated_at = $1 WHERE id = $2 AND status = 'open'")
                .bind(&now).bind(ctx.invoice_id).execute(&state.db.pool).await.map_err(AppError::Database)?;
            let funded = Funded {
                intent_pk: ctx.intent_pk, invoice_id: ctx.invoice_id, user_id: ctx.user_id, store_id: ctx.store_id,
                public_id: ctx.public_id.clone(), network: String::new(), required_outputs: String::new(),
                customer_refund_address: None, covenant_address: None, gross_amount: None, expiry_ts: None,
                arbiter_panel_json: None, arbiter_threshold: None,
            };
            let _ = emit_invoice_event(state, &funded, "invoice.paid", &tx_id).await;
            Ok(json!({ "released": true, "releaseTxId": tx_id, "invoiceStatus": "paid" }))
        }
        Err(e) => {
            // Release failed: return the claim so a later attempt (or expiry refund) can proceed.
            let _ = sqlx::query("UPDATE kpr1_payment_intents SET covenant_state = 'funded', updated_at = $1 WHERE id = $2 AND covenant_state = 'releasing'")
                .bind(now_iso()).bind(ctx.intent_pk).execute(&state.db.pool).await;
            Err(e)
        }
    }
}

async fn build_and_broadcast_release(client: &KaspaWrpcClient, ctx: &ReleaseCtx, customer_sig: &[u8]) -> AppResult<String> {
    let compiled = compile_escrow_v2(&ctx.params).map_err(|e| rerr(e.to_string()))?;
    let draft = prepare_release(&compiled, &ctx.params, &ctx.covenant_utxo, &ctx.fee_utxo, ctx.min_fee, &ctx.keeper, ctx.prefix, 0)
        .map_err(|e| rerr(e.to_string()))?;
    let spend = complete_release(&compiled, draft, EP_RELEASE_CONFIRMED, Some(customer_sig)).map_err(|e| rerr(e.to_string()))?;
    client.submit_transaction(rpc_submit_params(&spend)).await.map_err(|e| rerr(e.to_string()))
}

/// Load the funded, still-open covenant intent for `public_id`. Shared by the
/// customer-release and dispute paths.
async fn load_funded_open(state: &AppState, public_id: &str) -> AppResult<Funded> {
    sqlx::query_as::<_, Funded>(
        "SELECT i.id AS intent_pk, i.invoice_id, i.user_id, inv.store_id, inv.public_id, i.network, \
                i.required_outputs, i.customer_refund_address, i.covenant_address, i.gross_amount, i.expiry_ts, \
                i.arbiter_panel_json, i.arbiter_threshold \
         FROM kpr1_payment_intents i JOIN invoices inv ON inv.id = i.invoice_id \
         WHERE inv.public_id = $1 AND i.covenant_state = 'funded' AND inv.status = 'open'",
    )
    .bind(public_id)
    .fetch_optional(&state.db.pool)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| rerr("covenant is not awaiting settlement (must be funded and open)"))
}

/// Flip a funded intent to `to_state` (claiming it against a racing keeper tick
/// or a concurrent settlement). Returns whether this caller won the claim.
async fn claim_funded(state: &AppState, intent_pk: i64, to_state: &str) -> AppResult<bool> {
    let r = sqlx::query(
        "UPDATE kpr1_payment_intents SET covenant_state = $1, updated_at = $2 WHERE id = $3 AND covenant_state = 'funded'",
    )
    .bind(to_state)
    .bind(now_iso())
    .bind(intent_pk)
    .execute(&state.db.pool)
    .await
    .map_err(AppError::Database)?;
    Ok(r.rows_affected() > 0)
}

/// Return a claimed intent to `funded` after a failed settlement attempt.
async fn restore_funded(state: &AppState, intent_pk: i64, from_state: &str) {
    let _ = sqlx::query(
        "UPDATE kpr1_payment_intents SET covenant_state = 'funded', updated_at = $1 WHERE id = $2 AND covenant_state = $3",
    )
    .bind(now_iso())
    .bind(intent_pk)
    .bind(from_state)
    .execute(&state.db.pool)
    .await;
}

/// Minimal `Funded` carrying just the identity fields needed to emit a webhook.
fn webhook_target(intent_pk: i64, invoice_id: i64, user_id: i64, store_id: Option<i64>, public_id: String) -> Funded {
    Funded {
        intent_pk,
        invoice_id,
        user_id,
        store_id,
        public_id,
        network: String::new(),
        required_outputs: String::new(),
        customer_refund_address: None,
        covenant_address: None,
        gross_amount: None,
        expiry_ts: None,
        arbiter_panel_json: None,
        arbiter_threshold: None,
    }
}

// ---------------------------------------------------------------------------
// Dispute resolution.
//
//   release_arbitrated — Kasway (arbiter) rules FOR the merchant. The server
//       holds both the arbiter key (covenant authorization) and the keeper fee
//       key (release gas is subsidized, covered by merchant fees), so it is a
//       single operator call.
//   refund_by_merchant — the merchant voluntarily refunds the customer. The
//       merchant BOTH authorizes the covenant spend AND pays the gas, so both
//       signatures are external (two-step prepare → submit).
//   refund_by_arbiter  — Kasway rules FOR the customer. The server signs the
//       covenant with the arbiter key; the CUSTOMER pays the gas, never Kasway,
//       so only the fee signature is external (two-step prepare → submit).
//
// Every refund is built with `prepare_refund_by_arbiter`, whose fee input is signed
// by a non-keeper party — honoring "refund gas is never subsidized by Kasway".
// ---------------------------------------------------------------------------

/// Which party funds the miner fee on a refund/settlement (they sign the fee input).
pub(crate) enum FeePayer {
    /// The merchant pays their own refund gas.
    Merchant,
    /// The customer pays their own refund gas.
    Customer,
}

/// Everything needed to (re)build an external-fee refund spend.
struct RefundCtx {
    params: EscrowV2Params,
    covenant_utxo: Utxo,
    fee_utxo: Utxo,
    /// The party paying (and signing) the fee input — always a covenant P2PK party.
    fee_payer: Destination,
    intent_pk: i64,
    invoice_id: i64,
    user_id: i64,
    store_id: Option<i64>,
    public_id: String,
    min_fee: u64,
}

async fn gather_refund_inputs(
    state: &AppState,
    client: &KaspaWrpcClient,
    public_id: &str,
    who: FeePayer,
) -> AppResult<RefundCtx> {
    let min_fee = state.config.covenant.keeper_min_fee_sompi;
    let c = load_funded_open(state, public_id).await?;

    let (params, prefix, covenant_addr) = rebuild_params(state, &c)?;
    let compiled = compile_escrow_v2(&params).map_err(|e| rerr(e.to_string()))?;
    let derived = covenant_address(&compiled, prefix).map_err(|e| rerr(e.to_string()))?.to_string();
    if derived != covenant_addr {
        return Err(rerr("covenant address mismatch"));
    }
    let gross = params.gross_amount;

    let cov_utxos = client.fetch_utxos(&covenant_addr).await.map_err(|e| rerr(e.to_string()))?;
    let covenant_utxo = cov_utxos
        .into_iter()
        .find(|(_, _, v)| *v == gross)
        .map(|(t, i, v)| Utxo { transaction_id: t, index: i, value: v })
        .ok_or_else(|| rerr("covenant funding UTXO not visible yet"))?;

    // The fee payer is a covenant party (merchant or customer); they supply and
    // sign their own fee input, so Kasway never subsidizes refund gas.
    let fee_payer = match who {
        FeePayer::Merchant => params.merchant.clone(),
        FeePayer::Customer => params.customer_refund.clone(),
    };
    let fee_payer_addr = fee_payer.address().to_string();
    // Deterministic fee-UTXO pick so prepare and submit build the identical tx.
    let mut fee_utxos = client.fetch_utxos(&fee_payer_addr).await.map_err(|e| rerr(e.to_string()))?;
    fee_utxos.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    let fee_utxo = fee_utxos
        .into_iter()
        .find(|(_, _, v)| *v > min_fee + 1)
        .map(|(t, i, v)| Utxo { transaction_id: t, index: i, value: v })
        .ok_or_else(|| rerr(format!("no fee UTXO > {min_fee} sompi at fee payer {fee_payer_addr}")))?;

    Ok(RefundCtx {
        params,
        covenant_utxo,
        fee_utxo,
        fee_payer,
        intent_pk: c.intent_pk,
        invoice_id: c.invoice_id,
        user_id: c.user_id,
        store_id: c.store_id,
        public_id: c.public_id,
        min_fee,
    })
}

fn build_refund_draft(ctx: &RefundCtx) -> AppResult<(kasway_covenant::CompiledContract<'static>, ArbiterRefundDraft)> {
    let compiled = compile_escrow_v2(&ctx.params).map_err(|e| rerr(e.to_string()))?;
    let draft = prepare_refund_by_arbiter(
        &compiled,
        &ctx.params,
        &ctx.covenant_utxo,
        &ctx.fee_utxo,
        ctx.min_fee,
        ctx.fee_payer.address(),
    )
    .map_err(|e| rerr(e.to_string()))?;
    Ok((compiled, draft))
}

/// Persist a completed refund: covenant `refunded`, invoice `refunded`, emit
/// `invoice.refunded`.
async fn finalize_refund(state: &AppState, ctx: &RefundCtx, tx_id: &str) -> AppResult<serde_json::Value> {
    let now = now_iso();
    sqlx::query(
        "UPDATE kpr1_payment_intents SET covenant_state = 'refunded', refund_tx_id = $2, updated_at = $1 WHERE id = $3",
    )
    .bind(&now)
    .bind(tx_id)
    .bind(ctx.intent_pk)
    .execute(&state.db.pool)
    .await
    .map_err(AppError::Database)?;
    sqlx::query("UPDATE invoices SET status = 'refunded', updated_at = $1 WHERE id = $2 AND status = 'open'")
        .bind(&now)
        .bind(ctx.invoice_id)
        .execute(&state.db.pool)
        .await
        .map_err(AppError::Database)?;
    let target = webhook_target(ctx.intent_pk, ctx.invoice_id, ctx.user_id, ctx.store_id, ctx.public_id.clone());
    let _ = emit_invoice_event(state, &target, "invoice.refunded", tx_id).await;
    Ok(json!({ "refunded": true, "refundTxId": tx_id, "invoiceStatus": "refunded" }))
}

/// Run a refund submit: claim the row, build+broadcast, persist (or roll back).
async fn submit_refund(
    state: &AppState,
    ctx: &RefundCtx,
    entrypoint: &str,
    covenant_sig: &[u8],
    fee_sig: &[u8],
) -> AppResult<serde_json::Value> {
    if !claim_funded(state, ctx.intent_pk, "refunding").await? {
        return Err(rerr("covenant is no longer awaiting settlement"));
    }
    let client = KaspaWrpcClient::from_env().ok_or_else(|| rerr("Kaspa node is not configured"))?;
    let outcome = async {
        let (compiled, draft) = build_refund_draft(ctx)?;
        // Merchant refund = merchant's single covenant sig. Arbiter refund = the
        // M-of-N panel; in the transitional 1-of-1 panel the arbiter is index 0.
        let spend = if entrypoint == EP_REFUND_BY_MERCHANT {
            complete_refund_by_merchant(&compiled, draft, covenant_sig, fee_sig).map_err(|e| rerr(e.to_string()))?
        } else {
            complete_refund_by_arbiter(&compiled, draft, &[covenant_sig.to_vec()], &[0], fee_sig)
                .map_err(|e| rerr(e.to_string()))?
        };
        client.submit_transaction(rpc_submit_params(&spend)).await.map_err(|e| rerr(e.to_string()))
    }
    .await;
    match outcome {
        Ok(tx_id) => finalize_refund(state, ctx, &tx_id).await,
        Err(e) => {
            restore_funded(state, ctx.intent_pk, "refunding").await;
            Err(e)
        }
    }
}

// ---- release_arbitrated (operator; server holds arbiter + keeper keys) ----

/// Kasway (arbiter) releases the covenant to the merchant, resolving a dispute in
/// the merchant's favor. Single operator call.
pub(crate) async fn arbiter_release(state: &AppState, public_id: &str) -> AppResult<serde_json::Value> {
    let client = KaspaWrpcClient::from_env().ok_or_else(|| rerr("Kaspa node is not configured"))?;
    let arbiter = arbiter_signing_key(state)?;
    let ctx = gather_release_inputs(state, &client, public_id).await?;

    if !claim_funded(state, ctx.intent_pk, "releasing").await? {
        return Err(rerr("covenant is no longer awaiting release"));
    }

    let outcome = async {
        let compiled = compile_escrow_v2(&ctx.params).map_err(|e| rerr(e.to_string()))?;
        let draft = prepare_release(&compiled, &ctx.params, &ctx.covenant_utxo, &ctx.fee_utxo, ctx.min_fee, &ctx.keeper, ctx.prefix, 0)
            .map_err(|e| rerr(e.to_string()))?;
        let arbiter_sig = arbiter.sign_sighash(&draft.covenant_sighash).map_err(|e| rerr(e.to_string()))?;
        // Transitional 1-of-1 arbiter panel: the Kasway arbiter is panel index 0.
        let spend = complete_release_arbitrated(&compiled, draft, &[arbiter_sig], &[0]).map_err(|e| rerr(e.to_string()))?;
        client.submit_transaction(rpc_submit_params(&spend)).await.map_err(|e| rerr(e.to_string()))
    }
    .await;

    match outcome {
        Ok(tx_id) => {
            let now = now_iso();
            sqlx::query(
                "UPDATE kpr1_payment_intents SET covenant_state = 'arbitrated', status = 'settled', \
                 settled_at = COALESCE(settled_at, $1), release_tx_id = $2, updated_at = $1 WHERE id = $3",
            )
            .bind(&now).bind(&tx_id).bind(ctx.intent_pk).execute(&state.db.pool).await.map_err(AppError::Database)?;
            sqlx::query("UPDATE invoices SET status = 'paid', paid_at = COALESCE(paid_at, $1), updated_at = $1 WHERE id = $2 AND status = 'open'")
                .bind(&now).bind(ctx.invoice_id).execute(&state.db.pool).await.map_err(AppError::Database)?;
            let target = webhook_target(ctx.intent_pk, ctx.invoice_id, ctx.user_id, ctx.store_id, ctx.public_id.clone());
            let _ = emit_invoice_event(state, &target, "invoice.paid", &tx_id).await;
            Ok(json!({ "released": true, "resolution": "arbitrated", "releaseTxId": tx_id, "invoiceStatus": "paid" }))
        }
        Err(e) => {
            restore_funded(state, ctx.intent_pk, "releasing").await;
            Err(e)
        }
    }
}

// ---- refund_by_merchant (merchant signs covenant + fee) ----

/// Step 1: the merchant refunds the customer. Returns BOTH sighashes the merchant
/// signs — the covenant authorization and their own fee (gas) input.
pub(crate) async fn merchant_refund_prepare(state: &AppState, public_id: &str) -> AppResult<serde_json::Value> {
    let client = KaspaWrpcClient::from_env().ok_or_else(|| rerr("Kaspa node is not configured"))?;
    let ctx = gather_refund_inputs(state, &client, public_id, FeePayer::Merchant).await?;
    let (_compiled, draft) = build_refund_draft(&ctx)?;
    Ok(json!({
        "covenantSighash": encode_hex(&draft.covenant_sighash),
        "feeSighash": encode_hex(&draft.fee_sighash),
        "feePayerAddress": ctx.fee_payer.address().to_string(),
        "sigHashType": "SIG_HASH_ALL",
        "algorithm": "schnorr",
        "note": "merchant signs BOTH sighashes with the merchant key (covenant authorization + own gas input); submit each as 65-byte hex (schnorr signature || sighash-type byte)",
    }))
}

/// Step 2: attach the merchant's covenant + fee signatures, broadcast, refund.
pub(crate) async fn merchant_refund_submit(
    state: &AppState,
    public_id: &str,
    covenant_sig_hex: &str,
    fee_sig_hex: &str,
) -> AppResult<serde_json::Value> {
    let covenant_sig = decode_sig65(covenant_sig_hex)?;
    let fee_sig = decode_sig65(fee_sig_hex)?;
    let client = KaspaWrpcClient::from_env().ok_or_else(|| rerr("Kaspa node is not configured"))?;
    let ctx = gather_refund_inputs(state, &client, public_id, FeePayer::Merchant).await?;
    submit_refund(state, &ctx, EP_REFUND_BY_MERCHANT, &covenant_sig, &fee_sig).await
}

// ---- refund_by_arbiter (Kasway signs covenant; customer signs fee) ----

/// Step 1: Kasway rules a refund for the customer. Returns only the fee sighash
/// the CUSTOMER signs (they pay the gas); the covenant is authorized server-side.
pub(crate) async fn arbiter_refund_prepare(state: &AppState, public_id: &str) -> AppResult<serde_json::Value> {
    let client = KaspaWrpcClient::from_env().ok_or_else(|| rerr("Kaspa node is not configured"))?;
    // Confirm the arbiter key exists before asking the customer to sign anything.
    let _ = arbiter_signing_key(state)?;
    let ctx = gather_refund_inputs(state, &client, public_id, FeePayer::Customer).await?;
    let (_compiled, draft) = build_refund_draft(&ctx)?;
    Ok(json!({
        "feeSighash": encode_hex(&draft.fee_sighash),
        "feePayerAddress": ctx.fee_payer.address().to_string(),
        "sigHashType": "SIG_HASH_ALL",
        "algorithm": "schnorr",
        "note": "customer signs this fee sighash with their refund key (they pay the refund gas); the covenant is authorized by the Kasway arbiter server-side. Submit the 65-byte signature (schnorr || sighash-type byte) as hex",
    }))
}

/// Step 2: the server signs the covenant with the arbiter key, attaches the
/// customer's fee signature, broadcasts, and refunds the full gross.
pub(crate) async fn arbiter_refund_submit(
    state: &AppState,
    public_id: &str,
    fee_sig_hex: &str,
) -> AppResult<serde_json::Value> {
    let fee_sig = decode_sig65(fee_sig_hex)?;
    let arbiter = arbiter_signing_key(state)?;
    let client = KaspaWrpcClient::from_env().ok_or_else(|| rerr("Kaspa node is not configured"))?;
    let ctx = gather_refund_inputs(state, &client, public_id, FeePayer::Customer).await?;
    // The arbiter signs the deterministic covenant sighash server-side.
    let (_compiled, draft) = build_refund_draft(&ctx)?;
    let arbiter_sig = arbiter.sign_sighash(&draft.covenant_sighash).map_err(|e| rerr(e.to_string()))?;
    submit_refund(state, &ctx, EP_REFUND_BY_ARBITER, &arbiter_sig, &fee_sig).await
}

/// Decode a 65-byte covenant signature (schnorr signature || sighash-type byte).
fn decode_sig65(hex: &str) -> AppResult<Vec<u8>> {
    decode_hex(hex.trim())
        .filter(|s| s.len() == 65)
        .ok_or_else(|| rerr("signature must be 65-byte hex (schnorr signature || sighash-type byte)"))
}

// ---------------------------------------------------------------------------
// Tier 1: bilateral mutual settlement (customer + merchant co-sign an agreed
// split). No arbiter, no jury. Because both sign SIG_HASH_ALL, the two
// signatures ARE joint consent to the exact split, so any agreed division of
// the gross is valid. The fee payer (either party) signs their own gas input.
// ---------------------------------------------------------------------------

/// Parse an agreed split (`[(address, sompi)]`) into covenant destinations and
/// validate it sums to exactly the covenant's gross.
fn parse_split(split: &[(String, u64)], gross: u64) -> AppResult<Vec<(Destination, u64)>> {
    if split.is_empty() {
        return Err(rerr("settlement split must have at least one output"));
    }
    let mut dests = Vec::with_capacity(split.len());
    let mut total: u64 = 0;
    for (addr, amount) in split {
        let dest = Destination::parse(addr).map_err(|e| rerr(format!("settlement split address invalid: {e}")))?;
        total = total.checked_add(*amount).ok_or_else(|| rerr("settlement split overflow"))?;
        dests.push((dest, *amount));
    }
    if total != gross {
        return Err(rerr(format!("settlement split must sum to the covenant gross {gross} (got {total})")));
    }
    Ok(dests)
}

/// Step 1: build a mutual-settlement tx for an agreed split. Returns the covenant
/// sighash BOTH parties sign and the fee sighash the fee payer signs.
pub(crate) async fn mutual_settle_prepare(
    state: &AppState,
    public_id: &str,
    split: &[(String, u64)],
    who: FeePayer,
) -> AppResult<serde_json::Value> {
    let client = KaspaWrpcClient::from_env().ok_or_else(|| rerr("Kaspa node is not configured"))?;
    let ctx = gather_refund_inputs(state, &client, public_id, who).await?;
    let compiled = compile_escrow_v2(&ctx.params).map_err(|e| rerr(e.to_string()))?;
    let dests = parse_split(split, ctx.params.gross_amount)?;
    let draft = prepare_settlement(&compiled, &dests, &ctx.covenant_utxo, &ctx.fee_utxo, ctx.min_fee, ctx.fee_payer.address())
        .map_err(|e| rerr(e.to_string()))?;
    Ok(json!({
        "covenantSighash": encode_hex(&draft.covenant_sighash),
        "feeSighash": encode_hex(&draft.fee_sighash),
        "feePayerAddress": ctx.fee_payer.address().to_string(),
        "sigHashType": "SIG_HASH_ALL",
        "algorithm": "schnorr",
        "note": "customer AND merchant each sign the covenant sighash; the fee payer signs the fee sighash. Submit all three as 65-byte hex (schnorr signature || sighash-type byte)",
    }))
}

/// Step 2: attach both parties' covenant signatures + the fee payer's fee
/// signature, broadcast, and settle the dispute with the agreed split.
pub(crate) async fn mutual_settle_submit(
    state: &AppState,
    public_id: &str,
    split: &[(String, u64)],
    who: FeePayer,
    customer_sig_hex: &str,
    merchant_sig_hex: &str,
    fee_sig_hex: &str,
) -> AppResult<serde_json::Value> {
    let customer_sig = decode_sig65(customer_sig_hex)?;
    let merchant_sig = decode_sig65(merchant_sig_hex)?;
    let fee_sig = decode_sig65(fee_sig_hex)?;
    let client = KaspaWrpcClient::from_env().ok_or_else(|| rerr("Kaspa node is not configured"))?;
    let ctx = gather_refund_inputs(state, &client, public_id, who).await?;

    if !claim_funded(state, ctx.intent_pk, "settling_mutual").await? {
        return Err(rerr("covenant is no longer awaiting settlement"));
    }
    let outcome = async {
        let compiled = compile_escrow_v2(&ctx.params).map_err(|e| rerr(e.to_string()))?;
        let dests = parse_split(split, ctx.params.gross_amount)?;
        let draft = prepare_settlement(&compiled, &dests, &ctx.covenant_utxo, &ctx.fee_utxo, ctx.min_fee, ctx.fee_payer.address())
            .map_err(|e| rerr(e.to_string()))?;
        let spend = complete_settlement(&compiled, draft, &customer_sig, &merchant_sig, &fee_sig)
            .map_err(|e| rerr(e.to_string()))?;
        client.submit_transaction(rpc_submit_params(&spend)).await.map_err(|e| rerr(e.to_string()))
    }
    .await;
    match outcome {
        Ok(tx_id) => {
            let now = now_iso();
            sqlx::query(
                "UPDATE kpr1_payment_intents SET covenant_state = 'settled_mutual', status = 'settled', \
                 settled_at = COALESCE(settled_at, $1), release_tx_id = $2, updated_at = $1 WHERE id = $3",
            )
            .bind(&now).bind(&tx_id).bind(ctx.intent_pk).execute(&state.db.pool).await.map_err(AppError::Database)?;
            sqlx::query("UPDATE invoices SET status = 'paid', paid_at = COALESCE(paid_at, $1), updated_at = $1 WHERE id = $2 AND status = 'open'")
                .bind(&now).bind(ctx.invoice_id).execute(&state.db.pool).await.map_err(AppError::Database)?;
            let target = webhook_target(ctx.intent_pk, ctx.invoice_id, ctx.user_id, ctx.store_id, ctx.public_id.clone());
            let _ = emit_invoice_event(state, &target, "invoice.paid", &tx_id).await;
            Ok(json!({ "settled": true, "resolution": "mutual", "settleTxId": tx_id, "invoiceStatus": "paid" }))
        }
        Err(e) => {
            restore_funded(state, ctx.intent_pk, "settling_mutual").await;
            Err(e)
        }
    }
}
