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
use crate::util::{decode_hex, decode_hex32, encode_hex, now_iso};
use kasway_covenant::escrow_v2::{
    compile_escrow_v2, complete_refund_by_arbiter, complete_refund_by_merchant, complete_release,
    complete_release_arbitrated, complete_settlement, prepare_refund_by_arbiter, prepare_release, prepare_settlement,
    ArbiterRefundDraft, EscrowV2Params, EP_RELEASE_CAPTURED, EP_RELEASE_CONFIRMED,
};
use kasway_covenant::{covenant_address, network_prefix, rpc_submit_params, Destination, KeeperKey, Payout, Utxo};
use serde_json::json;
use tokio::task::JoinHandle;

const POLL_INTERVAL_SECS: u64 = 5;
const CLAIM_BATCH: i64 = 10;
/// Minimum change a fee UTXO must leave behind (1 KAS). KIP-9 charges roughly
/// `1e12 / value` storage mass per output, so 1 KAS of change costs ~10k mass —
/// negligible against the 500k consensus cap. Anything much smaller starts to
/// dominate the transaction's mass on its own.
const KEEPER_CHANGE_FLOOR_SOMPI: u64 = 100_000_000;

/// Pick the fee UTXO for a covenant spend: **the largest one**, not the first.
///
/// KIP-9 storage mass charges ~`1e12 / value` per output, and every settlement
/// leaves the keeper's change behind as a new UTXO. Picking by (txid, index) —
/// as this did — eventually picks one of those leftovers, whose change is
/// smaller again, whose mass is larger again. The keeper self-poisons: a 0.06
/// KAS leftover yields 0.04 KAS of change worth ~250k mass on its own, which
/// alone pushes a normal release past the 500k consensus cap and the node
/// rejects it ("storage mass ... larger than max allowed").
///
/// Taking the largest keeps the change big and its mass ~1k, and leaves the dust
/// untouched instead of feeding on it. Still deterministic — prepare and submit
/// must build the identical transaction — with (txid, index) breaking ties.
pub(crate) fn pick_fee_utxo<T: Ord>(mut utxos: Vec<(T, u32, u64)>, min_fee: u64) -> Option<(T, u32, u64)> {
    // Covering the fee is not enough: the change left over must ALSO be big
    // enough that its own storage mass stays negligible (1 KAS => ~10k mass).
    // Below this floor the transaction is born rejectable, so refuse to build it
    // and surface "no fee UTXO" — an actionable error beats a broadcast loop the
    // node will never accept.
    utxos.retain(|(_, _, v)| *v > min_fee + KEEPER_CHANGE_FLOOR_SOMPI);
    utxos.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| (&a.0, a.1).cmp(&(&b.0, b.1))));
    utxos.into_iter().next()
}

#[cfg(test)]
mod fee_utxo_tests {
    use super::pick_fee_utxo;

    fn utxo(id: &str, index: u32, value: u64) -> (String, u32, u64) {
        (id.to_string(), index, value)
    }

    #[test]
    fn prefers_the_largest_utxo_over_keeper_dust() {
        // The dust is what earlier settlements left behind. Taking it would make
        // the change tiny and the storage mass blow the consensus cap.
        let utxos = vec![
            utxo("aaa", 0, 6_000_000),   // 0.06 KAS — sorts first by txid
            utxo("zzz", 1, 998_000_000), // 9.98 KAS
            utxo("bbb", 0, 8_000_000),
        ];
        assert_eq!(pick_fee_utxo(utxos, 2_000_000).unwrap().2, 998_000_000);
    }

    #[test]
    fn refuses_utxos_whose_change_would_blow_the_storage_mass_cap() {
        // Covers the fee, but leaves only ~0.06 KAS of change: ~16M storage mass
        // on that output alone. Building this tx guarantees a node rejection, so
        // there must be NO pick rather than a doomed one.
        let dust = vec![utxo("aaa", 0, 8_000_000)];
        assert!(pick_fee_utxo(dust, 2_000_000).is_none());
        // Comfortably above the fee + change floor.
        let healthy = vec![utxo("aaa", 0, 998_000_000)];
        assert!(pick_fee_utxo(healthy, 2_000_000).is_some());
    }

    #[test]
    fn is_deterministic_when_values_tie() {
        // prepare and submit must build the identical transaction.
        let a = vec![utxo("bbb", 0, 500_000_000), utxo("aaa", 0, 500_000_000)];
        let b = vec![utxo("aaa", 0, 500_000_000), utxo("bbb", 0, 500_000_000)];
        assert_eq!(pick_fee_utxo(a, 2_000_000), pick_fee_utxo(b, 2_000_000));
    }
}

/// Keeper enable gate (`COVENANT_KEEPER_ENABLED` / `SUBSCRIPTION_KEEPER_ENABLED`).
/// Defaults on only when a keeper fee key and a node URL are configured;
/// `0`/`false`/`off` force-disable.
pub fn keeper_enabled(toggle_var: &str) -> bool {
    match std::env::var(toggle_var).ok().as_deref().map(str::trim) {
        Some("0") | Some("false") | Some("off") | Some("FALSE") | Some("Off") => false,
        Some(v) if !v.is_empty() => true,
        _ => {
            std::env::var("COVENANT_KEEPER_FEE_SECRET").ok().filter(|s| !s.trim().is_empty()).is_some()
                && std::env::var("KASPA_NODE_URL").ok().filter(|s| !s.trim().is_empty()).is_some()
        }
    }
}

/// One keeper pass, boxed: returns how many rows were acted on (0 → idle).
type KeeperTick = for<'a> fn(
    &'a AppState,
    &'a KaspaWrpcClient,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, sqlx::Error>> + Send + 'a>>;

/// Spawn a keeper poll loop around `tick`. Idle when no node is configured.
pub(crate) fn spawn_keeper(name: &'static str, state: AppState, tick: KeeperTick) -> JoinHandle<()> {
    tokio::spawn(async move {
        let Some(client) = KaspaWrpcClient::from_env() else {
            tracing::warn!("{name}: KASPA_NODE_URL not set; keeper idle");
            return;
        };
        // Say so on the way up, like the observer does — a keeper that only ever
        // logs on failure is indistinguishable from a keeper that never started.
        tracing::info!("{name} started");
        loop {
            match tick(&state, &client).await {
                Ok(0) => tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await,
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!("{name} tick error: {err}");
                    tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
                }
            }
        }
    })
}

/// Spawn the keeper loop. Idle when no node/key is configured.
pub fn spawn(state: AppState) -> JoinHandle<()> {
    spawn_keeper("covenant keeper", state, |s, c| Box::pin(run_tick(s, c)))
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
    /// baked at finalize. NULL for legacy rows → settlement falls back to config.
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
    //
    // "Past expiry" must be judged by CONSENSUS time, not the wall clock. The
    // release tx carries lock_time = expiry, and the node only accepts it once
    // its past median time has passed that — a clock that trails real time by a
    // minute or so. Gating on Utc::now() meant every settlement opened with a
    // burst of txs rejected as "input #0 is not finalized" until consensus caught
    // up: harmless thanks to the retry, but it hammered the node and buried the
    // log in warnings that looked like a real failure.
    let consensus_ms = match client.past_median_time().await {
        Ok(ms) => ms,
        Err(err) => {
            tracing::warn!("covenant keeper: past median time unavailable: {err}");
            return Ok(0);
        }
    };
    let candidates = sqlx::query_as::<_, Funded>(
        "SELECT i.id AS intent_pk, i.invoice_id, i.user_id, inv.store_id, inv.public_id, i.network, \
                i.required_outputs, i.customer_refund_address, i.covenant_address, i.gross_amount, i.expiry_ts, \
                i.arbiter_panel_json, i.arbiter_threshold \
         FROM kpr1_payment_intents i JOIN invoices inv ON inv.id = i.invoice_id \
         WHERE i.covenant_state = 'funded' AND inv.status = 'open' AND i.expiry_ts * 1000 < $2 \
         ORDER BY i.id LIMIT $1",
    )
    .bind(CLAIM_BATCH)
    .bind(consensus_ms as i64)
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

pub(crate) fn keeper_key(state: &AppState) -> Option<KeeperKey> {
    let hex = state.config.covenant.keeper_fee_secret_hex.as_deref()?;
    let bytes = decode_hex32(hex.trim())?;
    KeeperKey::from_secret_bytes(&bytes).ok()
}

/// Box a message as the keeper's error for a single settlement (Display = the message).
pub(crate) fn kerr(msg: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    msg.into().into()
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
    // The two lookups are independent, so run them concurrently.
    let keeper_address = keeper.address(prefix).to_string();
    let (cov_utxos, fee_utxos) = tokio::join!(client.fetch_utxos(&covenant_addr), client.fetch_utxos(&keeper_address));
    let cov_utxos = cov_utxos.map_err(|e| kerr(e.to_string()))?;
    let Some((cov_txid, cov_index, cov_value)) = cov_utxos.into_iter().find(|(_, _, v)| *v == gross) else {
        return Err(kerr("covenant funding UTXO not found yet"));
    };
    let fee_utxos = fee_utxos.map_err(|e| kerr(e.to_string()))?;
    let Some((fee_txid, fee_index, fee_value)) = pick_fee_utxo(fee_utxos, min_fee) else {
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

    mark_settled_paid(state, c.intent_pk, c.invoice_id, "captured", &tx_id).await?;
    emit_invoice_event(state, c.invoice_id, &c.public_id, c.user_id, c.store_id, "invoice.paid", &tx_id).await?;

    tracing::info!("covenant keeper: intent {} auto-captured to merchant via tx {tx_id}", c.intent_pk);
    Ok(())
}

pub(crate) async fn emit_invoice_event(
    state: &AppState,
    invoice_id: i64,
    public_id: &str,
    user_id: i64,
    store_id: Option<i64>,
    event: &str,
    tx_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut payload = invoice_payload(state, invoice_id).await.unwrap_or_else(|| json!({ "publicId": public_id }));
    if let serde_json::Value::Object(map) = &mut payload {
        map.insert("settlementTxId".into(), json!(tx_id));
    }
    webhooks::emit_event(state, user_id, store_id, event, "invoice", public_id, &payload)
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

/// Mark the intent settled (with its terminal `covenant_state`) and the invoice
/// paid. Shared by every merchant-payout settlement path. When the invoice
/// belongs to a subscription cycle, the cycle is marked paid too (and the
/// subscription restored from past_due), so autopay AND manually-paid
/// subscription invoices both close their cycle.
pub async fn mark_settled_paid(
    state: &AppState,
    intent_pk: i64,
    invoice_id: i64,
    covenant_state: &str,
    tx_id: &str,
) -> Result<(), sqlx::Error> {
    let now = now_iso();
    sqlx::query(
        "UPDATE kpr1_payment_intents SET covenant_state = $4, status = 'settled', \
         settled_at = COALESCE(settled_at, $1), release_tx_id = $2, updated_at = $1 WHERE id = $3",
    )
    .bind(&now)
    .bind(tx_id)
    .bind(intent_pk)
    .bind(covenant_state)
    .execute(&state.db.pool)
    .await?;
    mark_invoice_paid(state, invoice_id, &now).await
}

/// Flip an open invoice to `paid` and close its subscription cycle (if any).
/// The tail of `mark_settled_paid`, also used directly when an invoice settles
/// without a KPR-1 intent.
pub(crate) async fn mark_invoice_paid(state: &AppState, invoice_id: i64, now: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE invoices SET status = 'paid', paid_at = COALESCE(paid_at, $1), updated_at = $1 WHERE id = $2 AND status = 'open'")
        .bind(now)
        .bind(invoice_id)
        .execute(&state.db.pool)
        .await?;
    mark_cycle_paid(state, invoice_id, now).await
}

/// If `invoice_id` belongs to a subscription cycle, mark the cycle paid and
/// restore the subscription (defensively) from past_due to active.
pub(crate) async fn mark_cycle_paid(state: &AppState, invoice_id: i64, now: &str) -> Result<(), sqlx::Error> {
    let ids: Option<(Option<i64>, Option<i64>)> =
        sqlx::query_as("SELECT subscription_id, subscription_cycle_id FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_optional(&state.db.pool)
            .await?;
    let Some((sub_id, Some(cycle_id))) = ids else { return Ok(()) };
    sqlx::query("UPDATE subscription_cycles SET status = 'paid', paid_at = COALESCE(paid_at, $1), past_due_at = NULL, updated_at = $1 WHERE id = $2 AND status != 'paid'")
        .bind(now)
        .bind(cycle_id)
        .execute(&state.db.pool)
        .await?;
    if let Some(sub_id) = sub_id {
        sqlx::query("UPDATE subscriptions SET status = 'active', updated_at = $1 WHERE id = $2 AND status = 'past_due'")
            .bind(now)
            .bind(sub_id)
            .execute(&state.db.pool)
            .await?;
    }
    Ok(())
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

/// Shorthand for `AppError::unprocessable` (shared by the keeper/checkout modules).
pub(crate) fn rerr(msg: impl AsRef<str>) -> AppError {
    AppError::unprocessable(msg.as_ref())
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

/// Validate externally-collected M-of-N arbiter signatures against the covenant's
/// consented panel and return them ordered `(sigs, signer_idx)`. Enforces: each
/// index is inside the panel, indices are unique (strictly increasing after the
/// sort → the covenant's no-double-count rule), each signature is 65 bytes, and
/// at least `threshold` were supplied. The covenant itself checks the signatures
/// cryptographically on-chain, so we only shape/bound the input here.
fn prepare_arbiter_signatures(
    params: &EscrowV2Params,
    mut provided: Vec<(u32, Vec<u8>)>,
) -> AppResult<(Vec<Vec<u8>>, Vec<u32>)> {
    provided.sort_by_key(|(idx, _)| *idx);
    let n = params.arbiter_panel.len() as u32;
    let mut last: Option<u32> = None;
    for (idx, sig) in &provided {
        if *idx >= n {
            return Err(rerr(format!("arbiter signer index {idx} is outside the {n}-member panel")));
        }
        if Some(*idx) == last {
            return Err(rerr(format!("arbiter signer index {idx} is repeated")));
        }
        if sig.len() != 65 {
            return Err(rerr("each arbiter signature must be 65-byte hex (schnorr signature || sighash-type byte)"));
        }
        last = Some(*idx);
    }
    if (provided.len() as u32) < params.arbiter_threshold {
        return Err(rerr(format!(
            "arbiter panel requires at least {} of {} signatures ({} supplied)",
            params.arbiter_threshold,
            n,
            provided.len()
        )));
    }
    let sigs: Vec<Vec<u8>> = provided.iter().map(|(_, s)| s.clone()).collect();
    let idx: Vec<u32> = provided.iter().map(|(i, _)| *i).collect();
    Ok((sigs, idx))
}

/// The Kasway arbiter signing key (from `COVENANT_ARBITER_SECRET`). Used ONLY for
/// the transitional 1-of-1 dev fallback when no external panel signatures are
/// supplied; production requires a real independent panel (see `state.rs`).
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
    // fall back to the configured panel for legacy intents without a snapshot.
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

    // The covenant and keeper fee lookups are independent; fetch them concurrently.
    let keeper_address = keeper.address(prefix).to_string();
    let (cov_utxos, fee_utxos) = tokio::join!(client.fetch_utxos(&covenant_addr), client.fetch_utxos(&keeper_address));
    let covenant_utxo = cov_utxos
        .map_err(|e| rerr(e.to_string()))?
        .into_iter()
        .find(|(_, _, v)| *v == gross)
        .map(|(t, i, v)| Utxo { transaction_id: t, index: i, value: v })
        .ok_or_else(|| rerr("covenant funding UTXO not visible yet"))?;

    let fee_utxos = fee_utxos.map_err(|e| rerr(e.to_string()))?;
    let fee_utxo = pick_fee_utxo(fee_utxos, min_fee)
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
    if !claim_funded(state, ctx.intent_pk, "releasing").await? {
        return Err(rerr("covenant is no longer awaiting release"));
    }

    let outcome = build_and_broadcast_release(&client, &ctx, &sig).await;
    match outcome {
        Ok(tx_id) => {
            mark_settled_paid(state, ctx.intent_pk, ctx.invoice_id, "released", &tx_id)
                .await
                .map_err(AppError::Database)?;
            let _ = emit_invoice_event(state, ctx.invoice_id, &ctx.public_id, ctx.user_id, ctx.store_id, "invoice.paid", &tx_id).await;
            tracing::info!(
                "covenant release: invoice {} released to merchant by the customer via tx {tx_id}",
                ctx.public_id
            );
            Ok(json!({ "released": true, "releaseTxId": tx_id, "invoiceStatus": "paid" }))
        }
        Err(e) => {
            // Release failed: return the claim so a later attempt (or expiry refund) can proceed.
            restore_funded(state, ctx.intent_pk, "releasing").await;
            tracing::warn!("covenant release: invoice {} failed: {e}", ctx.public_id);
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

    // The fee payer is a covenant party (merchant or customer); they supply and
    // sign their own fee input, so Kasway never subsidizes refund gas.
    let fee_payer = match who {
        FeePayer::Merchant => params.merchant.clone(),
        FeePayer::Customer => params.customer_refund.clone(),
    };
    let fee_payer_addr = fee_payer.address().to_string();

    // The covenant and fee-payer lookups are independent; fetch them concurrently.
    let (cov_utxos, fee_utxos) = tokio::join!(client.fetch_utxos(&covenant_addr), client.fetch_utxos(&fee_payer_addr));
    let covenant_utxo = cov_utxos
        .map_err(|e| rerr(e.to_string()))?
        .into_iter()
        .find(|(_, _, v)| *v == gross)
        .map(|(t, i, v)| Utxo { transaction_id: t, index: i, value: v })
        .ok_or_else(|| rerr("covenant funding UTXO not visible yet"))?;

    let fee_utxos = fee_utxos.map_err(|e| rerr(e.to_string()))?;
    let fee_utxo = pick_fee_utxo(fee_utxos, min_fee)
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
    let _ = emit_invoice_event(state, ctx.invoice_id, &ctx.public_id, ctx.user_id, ctx.store_id, "invoice.refunded", tx_id).await;
    Ok(json!({ "refunded": true, "refundTxId": tx_id, "invoiceStatus": "refunded" }))
}

/// Run a merchant refund submit: claim the row, build+broadcast, persist (or roll
/// back). The merchant's single signature authorizes the covenant refund; the
/// arbiter (M-of-N) path uses `submit_refund_arbitrated` instead.
async fn submit_refund(
    state: &AppState,
    ctx: &RefundCtx,
    covenant_sig: &[u8],
    fee_sig: &[u8],
) -> AppResult<serde_json::Value> {
    if !claim_funded(state, ctx.intent_pk, "refunding").await? {
        return Err(rerr("covenant is no longer awaiting settlement"));
    }
    let client = KaspaWrpcClient::from_env().ok_or_else(|| rerr("Kaspa node is not configured"))?;
    let outcome = async {
        let (compiled, draft) = build_refund_draft(ctx)?;
        let spend = complete_refund_by_merchant(&compiled, draft, covenant_sig, fee_sig)
            .map_err(|e| rerr(e.to_string()))?;
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

/// `submit_refund` for the M-of-N arbiter refund: `signer_idx`-labelled panel
/// signatures on the covenant input, plus the customer's fee signature.
async fn submit_refund_arbitrated(
    state: &AppState,
    ctx: &RefundCtx,
    sigs: &[Vec<u8>],
    signer_idx: &[u32],
    fee_sig: &[u8],
) -> AppResult<serde_json::Value> {
    if !claim_funded(state, ctx.intent_pk, "refunding").await? {
        return Err(rerr("covenant is no longer awaiting settlement"));
    }
    let client = KaspaWrpcClient::from_env().ok_or_else(|| rerr("Kaspa node is not configured"))?;
    let outcome = async {
        let (compiled, draft) = build_refund_draft(ctx)?;
        let spend = complete_refund_by_arbiter(&compiled, draft, sigs, signer_idx, fee_sig)
            .map_err(|e| rerr(e.to_string()))?;
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

/// Step 1: build the arbiter-release tx (merchant split, keeper subsidizes gas)
/// and return the covenant sighash the INDEPENDENT arbiter panel signs, plus how
/// many of the N members must sign. Each arbiter signs this sighash off-band; the
/// operator collects `threshold` signatures and submits them to `arbiter_release`.
pub(crate) async fn arbiter_release_prepare(state: &AppState, public_id: &str) -> AppResult<serde_json::Value> {
    let client = KaspaWrpcClient::from_env().ok_or_else(|| rerr("Kaspa node is not configured"))?;
    let ctx = gather_release_inputs(state, &client, public_id).await?;
    let compiled = compile_escrow_v2(&ctx.params).map_err(|e| rerr(e.to_string()))?;
    let draft = prepare_release(&compiled, &ctx.params, &ctx.covenant_utxo, &ctx.fee_utxo, ctx.min_fee, &ctx.keeper, ctx.prefix, 0)
        .map_err(|e| rerr(e.to_string()))?;
    Ok(json!({
        "covenantSighash": encode_hex(&draft.covenant_sighash),
        "arbiterThreshold": ctx.params.arbiter_threshold,
        "arbiterPanelSize": ctx.params.arbiter_panel.len(),
        "sigHashType": "SIG_HASH_ALL",
        "algorithm": "schnorr",
        "note": "each independent arbiter signs this covenant sighash with their panel key; submit at least `arbiterThreshold` signatures as { index, signature } (signature = 65-byte hex: schnorr || sighash-type byte)",
    }))
}

/// Kasway records the panel's ruling FOR the merchant: release the covenant to
/// the merchant split. `arbiter_sigs` are the independent panel members'
/// `(panel_index, 65-byte signature)` collected off-band. When empty, the
/// transitional dev fallback signs with the single Kasway arbiter key at index 0
/// (only valid for the 1-of-1 dev panel; production forbids that config).
pub(crate) async fn arbiter_release(
    state: &AppState,
    public_id: &str,
    arbiter_sigs: Vec<(u32, Vec<u8>)>,
) -> AppResult<serde_json::Value> {
    let client = KaspaWrpcClient::from_env().ok_or_else(|| rerr("Kaspa node is not configured"))?;
    let ctx = gather_release_inputs(state, &client, public_id).await?;

    if !claim_funded(state, ctx.intent_pk, "releasing").await? {
        return Err(rerr("covenant is no longer awaiting release"));
    }

    let outcome = async {
        let compiled = compile_escrow_v2(&ctx.params).map_err(|e| rerr(e.to_string()))?;
        let draft = prepare_release(&compiled, &ctx.params, &ctx.covenant_utxo, &ctx.fee_utxo, ctx.min_fee, &ctx.keeper, ctx.prefix, 0)
            .map_err(|e| rerr(e.to_string()))?;
        let (sigs, idx) = if arbiter_sigs.is_empty() {
            // Dev fallback only: server signs with the single Kasway arbiter key.
            let arbiter = arbiter_signing_key(state)?;
            let arbiter_sig = arbiter.sign_sighash(&draft.covenant_sighash).map_err(|e| rerr(e.to_string()))?;
            (vec![arbiter_sig], vec![0u32])
        } else {
            prepare_arbiter_signatures(&ctx.params, arbiter_sigs)?
        };
        let spend = complete_release_arbitrated(&compiled, draft, &sigs, &idx).map_err(|e| rerr(e.to_string()))?;
        client.submit_transaction(rpc_submit_params(&spend)).await.map_err(|e| rerr(e.to_string()))
    }
    .await;

    match outcome {
        Ok(tx_id) => {
            mark_settled_paid(state, ctx.intent_pk, ctx.invoice_id, "arbitrated", &tx_id)
                .await
                .map_err(AppError::Database)?;
            let _ = emit_invoice_event(state, ctx.invoice_id, &ctx.public_id, ctx.user_id, ctx.store_id, "invoice.paid", &tx_id).await;
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
    submit_refund(state, &ctx, &covenant_sig, &fee_sig).await
}

// ---- refund_by_arbiter (Kasway signs covenant; customer signs fee) ----

/// Step 1: Kasway rules a refund for the customer. Returns only the fee sighash
/// the CUSTOMER signs (they pay the gas); the covenant is authorized server-side.
pub(crate) async fn arbiter_refund_prepare(state: &AppState, public_id: &str) -> AppResult<serde_json::Value> {
    let client = KaspaWrpcClient::from_env().ok_or_else(|| rerr("Kaspa node is not configured"))?;
    let ctx = gather_refund_inputs(state, &client, public_id, FeePayer::Customer).await?;
    let (_compiled, draft) = build_refund_draft(&ctx)?;
    Ok(json!({
        "covenantSighash": encode_hex(&draft.covenant_sighash),
        "feeSighash": encode_hex(&draft.fee_sighash),
        "feePayerAddress": ctx.fee_payer.address().to_string(),
        "arbiterThreshold": ctx.params.arbiter_threshold,
        "arbiterPanelSize": ctx.params.arbiter_panel.len(),
        "sigHashType": "SIG_HASH_ALL",
        "algorithm": "schnorr",
        "note": "the customer signs feeSighash with their refund key (they pay the refund gas); the independent arbiter panel signs covenantSighash. Submit the customer feeSignature plus at least `arbiterThreshold` arbiterSignatures as { index, signature } (each 65-byte hex: schnorr || sighash-type byte)",
    }))
}

/// Step 2: the independent arbiter panel authorizes the covenant refund. Attaches
/// the panel's `arbiter_sigs` (`(panel_index, 65-byte signature)`) and the
/// customer's fee signature, broadcasts, and refunds the full gross. When
/// `arbiter_sigs` is empty, the transitional dev fallback signs the covenant with
/// the single Kasway arbiter key (only valid for the 1-of-1 dev panel).
pub(crate) async fn arbiter_refund_submit(
    state: &AppState,
    public_id: &str,
    fee_sig_hex: &str,
    arbiter_sigs: Vec<(u32, Vec<u8>)>,
) -> AppResult<serde_json::Value> {
    let fee_sig = decode_sig65(fee_sig_hex)?;
    let client = KaspaWrpcClient::from_env().ok_or_else(|| rerr("Kaspa node is not configured"))?;
    let ctx = gather_refund_inputs(state, &client, public_id, FeePayer::Customer).await?;
    let (_compiled, draft) = build_refund_draft(&ctx)?;
    let (sigs, idx) = if arbiter_sigs.is_empty() {
        // Dev fallback only: server signs with the single Kasway arbiter key.
        let arbiter = arbiter_signing_key(state)?;
        let arbiter_sig = arbiter.sign_sighash(&draft.covenant_sighash).map_err(|e| rerr(e.to_string()))?;
        (vec![arbiter_sig], vec![0u32])
    } else {
        prepare_arbiter_signatures(&ctx.params, arbiter_sigs)?
    };
    submit_refund_arbitrated(state, &ctx, &sigs, &idx, &fee_sig).await
}

/// Decode a 65-byte covenant signature (schnorr signature || sighash-type byte).
pub(crate) fn decode_sig65(hex: &str) -> AppResult<Vec<u8>> {
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
            mark_settled_paid(state, ctx.intent_pk, ctx.invoice_id, "settled_mutual", &tx_id)
                .await
                .map_err(AppError::Database)?;
            let _ = emit_invoice_event(state, ctx.invoice_id, &ctx.public_id, ctx.user_id, ctx.store_id, "invoice.paid", &tx_id).await;
            Ok(json!({ "settled": true, "resolution": "mutual", "settleTxId": tx_id, "invoiceStatus": "paid" }))
        }
        Err(e) => {
            restore_funded(state, ctx.intent_pk, "settling_mutual").await;
            Err(e)
        }
    }
}
