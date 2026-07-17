//! Subscription autopay keeper — claims funded SubscriptionV1 covenant cells.
//!
//! Per tick:
//! 1. **Funding recognition** — for cells `awaiting_funding`/`active`/`past_due`,
//!    scan the covenant address UTXOs and recognize ONLY those whose txid the
//!    customer declared via the public autopay endpoint (`recorded_funding_txids`)
//!    or that are the remainder of our own last claim. Third-party sends are
//!    deliberately ignored (product spec): they stay at the address, and the
//!    customer can always `withdraw` them.
//! 2. **Claims** — for `active` cells with a due `invoiced`/`past_due` cycle and
//!    enough value, build+sign+broadcast the `claim` spend (the covenant pins the
//!    payouts; the keeper only authorizes timing), mark the invoice paid and the
//!    cycle `paid`, and roll the active outpoint to the claim's remainder output.
//!    A remainder below the sweep threshold is swept (cell empties → `past_due`,
//!    waiting for a top-up).
//! 3. **Past-due marking** (DB-only, no RPC) — a due cycle whose cell cannot cover
//!    the claim flips to `past_due` (once, guarded by the status transition) and
//!    emits `subscription.past_due`.
//!
//! Env: `SUBSCRIPTION_KEEPER_ENABLED` — like the covenant keeper, defaults on
//! only when `COVENANT_KEEPER_FEE_SECRET` and `KASPA_NODE_URL` are configured.

use crate::covenant_keeper::{keeper_key, kerr, mark_invoice_paid, mark_settled_paid, pick_fee_utxo, rerr, spawn_keeper};
use crate::error::{AppError, AppResult};
use crate::kaspa_wrpc::KaspaWrpcClient;
use crate::kpr1::parse_required_outputs;
use crate::state::AppState;
use crate::util::{decode_hex32, encode_hex, now_iso};
use kasway_covenant::subscription_v1::{compile_subscription_v1, complete_claim, prepare_claim, SubscriptionV1Params};
use kasway_covenant::{covenant_address, network_prefix, rpc_submit_params, Destination, KeeperKey, Payout, Prefix, Utxo};
use serde_json::json;

const SCAN_BATCH: i64 = 20;

/// Spawn the keeper loop. Idle when no node/key is configured.
pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    spawn_keeper("subscription keeper", state, |s, c| Box::pin(run_tick(s, c)))
}

// ---------------------------------------------------------------------------
// Cell model.
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
pub(crate) struct CellRow {
    pub(crate) id: i64,
    pub(crate) subscription_id: i64,
    pub(crate) covenant_address: String,
    pub(crate) params_json: String,
    pub(crate) claim_total: i64,
    pub(crate) refund_address: String,
    pub(crate) state: String,
    pub(crate) recorded_funding_txids: String,
    pub(crate) active_outpoint_txid: Option<String>,
    pub(crate) active_outpoint_index: Option<i64>,
    pub(crate) active_amount: Option<i64>,
    pub(crate) last_claim_tx_id: Option<String>,
    pub(crate) last_claim_at: Option<String>,
    pub(crate) withdraw_destination: Option<String>,
    pub(crate) withdraw_sighash: Option<String>,
}

pub(crate) const CELL_COLS: &str = "id, subscription_id, covenant_address, params_json, claim_total, \
    refund_address, state, recorded_funding_txids, active_outpoint_txid, active_outpoint_index, \
    active_amount, last_claim_tx_id, last_claim_at, withdraw_destination, withdraw_sighash";

pub(crate) async fn load_cell(state: &AppState, subscription_id: i64) -> AppResult<Option<CellRow>> {
    sqlx::query_as::<_, CellRow>(&format!("SELECT {CELL_COLS} FROM subscription_cells WHERE subscription_id = $1"))
        .bind(subscription_id)
        .fetch_optional(&state.db.pool)
        .await
        .map_err(AppError::Database)
}

/// Rebuild the covenant parameters (and network prefix) from a cell's
/// `params_json` snapshot. The caller must cross-check the derived covenant
/// address against the stored one before spending.
pub(crate) fn cell_params(params_json: &str) -> AppResult<(SubscriptionV1Params, Prefix)> {
    let v: serde_json::Value = serde_json::from_str(params_json).map_err(|e| rerr(format!("bad cell params: {e}")))?;
    let network = v["network"].as_str().unwrap_or_default();
    let prefix = network_prefix(network).map_err(|e| rerr(e.to_string()))?;
    let outs = parse_required_outputs(&v["payouts"].to_string());
    if outs.is_empty() {
        return Err(rerr("cell params have no payouts"));
    }
    let mut payouts = Vec::with_capacity(outs.len());
    for out in &outs {
        let destination = Destination::parse(&out.address).map_err(|e| rerr(e.to_string()))?;
        let value = u64::try_from(out.amount_sompi).map_err(|_| rerr("bad payout amount"))?;
        payouts.push(Payout { destination, value });
    }
    let keeper_pubkey = v["keeperPubkey"].as_str().and_then(decode_hex32).ok_or_else(|| rerr("bad keeper pubkey"))?;
    let customer = Destination::parse(v["customer"].as_str().unwrap_or_default()).map_err(|e| rerr(e.to_string()))?;
    let period_daa = v["periodDaa"].as_u64().filter(|p| *p > 0).ok_or_else(|| rerr("bad periodDaa"))?;
    let sweep_threshold = v["sweepThreshold"].as_u64().unwrap_or(0);
    Ok((SubscriptionV1Params { payouts, keeper_pubkey, customer, period_daa, sweep_threshold }, prefix))
}

// ---------------------------------------------------------------------------
// Funding recognition (pure — unit-tested without RPC).
// ---------------------------------------------------------------------------

/// Pick the cell's backing UTXO out of what sits at the covenant address: only
/// UTXOs from a customer-declared funding txid or from our own last claim
/// (the remainder) count. Largest value wins, (txid, index) breaks ties.
// ponytail: only the single largest recognized UTXO backs the cell — multiple
// concurrent top-ups are not consolidated (a claim spends one input); the
// customer's escape hatch is withdraw + re-fund if value ever strands.
fn recognize_funding(
    utxos: &[([u8; 32], u32, u64)],
    recorded_txids: &[String],
    last_claim_tx_id: Option<&str>,
) -> Option<([u8; 32], u32, u64)> {
    utxos
        .iter()
        .filter(|(txid, _, _)| {
            let hex = encode_hex(txid);
            recorded_txids.iter().any(|t| t.eq_ignore_ascii_case(&hex))
                || last_claim_tx_id.is_some_and(|l| l.eq_ignore_ascii_case(&hex))
        })
        .max_by(|a, b| a.2.cmp(&b.2).then_with(|| (b.0, b.1).cmp(&(a.0, a.1))))
        .copied()
}

// ---------------------------------------------------------------------------
// Tick.
// ---------------------------------------------------------------------------

/// One keeper pass: recognize funding, claim due cycles, mark underfunded ones
/// past due. Returns how many cells were acted on (0 → the caller idles).
pub async fn run_tick(state: &AppState, client: &KaspaWrpcClient) -> Result<usize, sqlx::Error> {
    let Some(keeper) = keeper_key(state) else { return Ok(0) };
    let mut acted = recognize_cells(state, client).await?;
    acted += claim_due(state, client, &keeper).await?;
    acted += mark_underfunded_past_due(state).await?;
    Ok(acted)
}

/// Scan cell addresses and (re)recognize the backing UTXO. Foreign UTXOs are
/// left alone. Activates `awaiting_funding`/`past_due` cells on new funds.
async fn recognize_cells(state: &AppState, client: &KaspaWrpcClient) -> Result<usize, sqlx::Error> {
    let cells = sqlx::query_as::<_, CellRow>(&format!(
        "SELECT {CELL_COLS} FROM subscription_cells \
         WHERE state IN ('awaiting_funding', 'active', 'past_due') ORDER BY id LIMIT $1"
    ))
    .bind(SCAN_BATCH)
    .fetch_all(&state.db.pool)
    .await?;

    let mut changed = 0usize;
    for cell in &cells {
        let utxos = match client.fetch_utxos(&cell.covenant_address).await {
            Ok(u) => u,
            Err(err) => {
                tracing::warn!("subscription keeper: utxo scan for cell {} failed: {err}", cell.id);
                continue;
            }
        };
        let recorded: Vec<String> = serde_json::from_str(&cell.recorded_funding_txids).unwrap_or_default();
        let Some((txid, index, value)) = recognize_funding(&utxos, &recorded, cell.last_claim_tx_id.as_deref())
        else {
            continue;
        };
        let hex = encode_hex(&txid);
        let unchanged = cell.active_outpoint_txid.as_deref() == Some(hex.as_str())
            && cell.active_outpoint_index == Some(index as i64)
            && cell.active_amount == Some(value as i64);
        if unchanged {
            continue;
        }
        sqlx::query(
            "UPDATE subscription_cells SET state = 'active', active_outpoint_txid = $1, \
             active_outpoint_index = $2, active_amount = $3, updated_at = $4 \
             WHERE id = $5 AND state IN ('awaiting_funding', 'active', 'past_due')",
        )
        .bind(&hex)
        .bind(index as i64)
        .bind(value as i64)
        .bind(now_iso())
        .bind(cell.id)
        .execute(&state.db.pool)
        .await?;
        tracing::info!("subscription keeper: cell {} recognized funding {hex}:{index} ({value} sompi)", cell.id);
        // First funding of a pending (QR-flow) subscription activates it —
        // billing anchors here, and `claim_due` later in this same tick can
        // already claim the first period.
        if let Err(err) = activate_pending_subscription(state, cell.subscription_id).await {
            tracing::warn!("subscription keeper: activating subscription {} failed: {err:?}", cell.subscription_id);
        }
        changed += 1;
    }
    Ok(changed)
}

/// Flip a `pending` (wallet_autopay, never funded) subscription to `active`,
/// anchor billing at this moment, and bill the first period immediately.
/// No-op (`Ok(false)`) unless the subscription is `pending`. DB-only —
/// unit-testable without RPC.
pub async fn activate_pending_subscription(state: &AppState, subscription_id: i64) -> AppResult<bool> {
    let now = chrono::Utc::now();
    let flipped: Option<(i64, String)> = sqlx::query_as(
        "UPDATE subscriptions SET status = 'active', next_billing_at = $1, updated_at = $1 \
         WHERE id = $2 AND status = 'pending' RETURNING user_id, public_id",
    )
    .bind(crate::util::to_iso(now))
    .bind(subscription_id)
    .fetch_optional(&state.db.pool)
    .await?;
    let Some((user_id, public_id)) = flipped else { return Ok(false) };
    crate::handlers::subscriptions::generate_due_invoice(state, subscription_id, now).await?;
    let payload = json!({ "publicId": public_id, "status": "active" });
    if let Err(e) = crate::handlers::webhooks::emit_event(
        state, user_id, None, "subscription.activated", "subscription", &public_id, &payload,
    )
    .await
    {
        tracing::warn!("subscription.activated emit failed for {public_id}: {e}");
    }
    tracing::info!("subscription keeper: subscription {public_id} activated on first funding");
    Ok(true)
}

/// A cell with a due, still-open cycle to claim (or to mark past due).
#[derive(sqlx::FromRow)]
struct DueCycle {
    cell_id: i64,
    covenant_address: String,
    params_json: String,
    claim_total: i64,
    active_outpoint_txid: Option<String>,
    active_outpoint_index: Option<i64>,
    active_amount: Option<i64>,
    cycle_id: i64,
    invoice_id: i64,
    invoice_public_id: String,
    user_id: i64,
    store_id: Option<i64>,
}

/// Claim every active, sufficiently-funded cell whose earliest cycle is due.
async fn claim_due(state: &AppState, client: &KaspaWrpcClient, keeper: &KeeperKey) -> Result<usize, sqlx::Error> {
    let now_s = now_iso();
    let due = sqlx::query_as::<_, DueCycle>(
        "SELECT DISTINCT ON (c.id) c.id AS cell_id, c.covenant_address, c.params_json, c.claim_total, \
                c.active_outpoint_txid, c.active_outpoint_index, c.active_amount, \
                cy.id AS cycle_id, inv.id AS invoice_id, inv.public_id AS invoice_public_id, \
                s.user_id, inv.store_id \
         FROM subscription_cells c \
         JOIN subscriptions s ON s.id = c.subscription_id AND s.status = 'active' AND s.payment_mode = 'wallet_autopay' \
         JOIN subscription_cycles cy ON cy.subscription_id = s.id AND cy.status IN ('invoiced', 'past_due') \
         JOIN invoices inv ON inv.id = cy.invoice_id AND inv.status = 'open' \
         WHERE c.state = 'active' AND cy.period_start <= $1 AND c.active_amount >= c.claim_total \
         ORDER BY c.id, cy.period_start, cy.id \
         LIMIT $2",
    )
    .bind(&now_s)
    .bind(SCAN_BATCH)
    .fetch_all(&state.db.pool)
    .await?;

    let mut acted = 0usize;
    for d in &due {
        // Claim the cell (active -> claiming) so nothing else spends it meanwhile.
        let claimed = sqlx::query("UPDATE subscription_cells SET state = 'claiming', updated_at = $1 WHERE id = $2 AND state = 'active'")
            .bind(now_iso())
            .bind(d.cell_id)
            .execute(&state.db.pool)
            .await?;
        if claimed.rows_affected() == 0 {
            continue;
        }
        match claim_one(state, client, keeper, d).await {
            Ok(()) => acted += 1,
            Err(err) => {
                tracing::warn!("subscription keeper: cell {} claim failed: {err}; will retry", d.cell_id);
                let _ = sqlx::query("UPDATE subscription_cells SET state = 'active', updated_at = $1 WHERE id = $2 AND state = 'claiming'")
                    .bind(now_iso())
                    .bind(d.cell_id)
                    .execute(&state.db.pool)
                    .await;
            }
        }
    }
    Ok(acted)
}

async fn claim_one(
    state: &AppState,
    client: &KaspaWrpcClient,
    keeper: &KeeperKey,
    d: &DueCycle,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (params, prefix) = cell_params(&d.params_json).map_err(|e| kerr(format!("{e:?}")))?;
    let compiled = compile_subscription_v1(&params).map_err(|e| kerr(e.to_string()))?;
    let derived = covenant_address(&compiled, prefix).map_err(|e| kerr(e.to_string()))?.to_string();
    if derived != d.covenant_address {
        return Err(kerr(format!("covenant address mismatch: derived {derived} != stored {}", d.covenant_address)));
    }
    let claim_total = params.claim_total().map_err(|e| kerr(e.to_string()))?;
    if claim_total != d.claim_total as u64 {
        return Err(kerr("cell claim_total does not match its params snapshot"));
    }

    let cov_txid = d
        .active_outpoint_txid
        .as_deref()
        .and_then(decode_hex32)
        .ok_or_else(|| kerr("cell has no active outpoint"))?;
    let active_amount = d.active_amount.unwrap_or(0) as u64;
    let covenant_utxo = Utxo {
        transaction_id: cov_txid,
        index: d.active_outpoint_index.unwrap_or(0) as u32,
        value: active_amount,
    };

    let min_fee = state.config.covenant.keeper_min_fee_sompi;
    let keeper_address = keeper.address(prefix).to_string();
    let fee_utxos = client.fetch_utxos(&keeper_address).await.map_err(|e| kerr(e.to_string()))?;
    let Some((fee_txid, fee_index, fee_value)) = pick_fee_utxo(fee_utxos, min_fee) else {
        return Err(kerr(format!("no keeper fee UTXO > {min_fee} sompi at {keeper_address}")));
    };
    let fee_utxo = Utxo { transaction_id: fee_txid, index: fee_index, value: fee_value };

    let draft = prepare_claim(&compiled, &params, &covenant_utxo, &fee_utxo, min_fee, keeper, prefix)
        .map_err(|e| kerr(e.to_string()))?;
    let sig = keeper.sign_sighash(&draft.covenant_sighash).map_err(|e| kerr(e.to_string()))?;
    let spend = complete_claim(&compiled, draft, &sig).map_err(|e| kerr(e.to_string()))?;
    let tx_id = client.submit_transaction(rpc_submit_params(&spend)).await.map_err(|e| kerr(e.to_string()))?;

    // Roll the cell onto the claim's remainder output (index = right after the
    // pinned payouts), or empty it when the remainder was swept as dust.
    let now = now_iso();
    let remainder = active_amount - claim_total;
    if remainder >= params.sweep_threshold {
        sqlx::query(
            "UPDATE subscription_cells SET state = 'active', active_outpoint_txid = $1, active_outpoint_index = $2, \
             active_amount = $3, last_claim_tx_id = $1, last_claim_at = $4, updated_at = $4 WHERE id = $5",
        )
        .bind(&tx_id)
        .bind(params.payouts.len() as i64)
        .bind(remainder as i64)
        .bind(&now)
        .bind(d.cell_id)
        .execute(&state.db.pool)
        .await?;
    } else {
        // Swept empty: waits past_due until the customer tops up (or cancels).
        sqlx::query(
            "UPDATE subscription_cells SET state = 'past_due', active_outpoint_txid = NULL, active_outpoint_index = NULL, \
             active_amount = NULL, last_claim_tx_id = $1, last_claim_at = $2, updated_at = $2 WHERE id = $3",
        )
        .bind(&tx_id)
        .bind(&now)
        .bind(d.cell_id)
        .execute(&state.db.pool)
        .await?;
    }

    // Settle the invoice (and its cycle) through the shared paid funnel.
    let intent_pk: Option<i64> = sqlx::query_scalar("SELECT id FROM kpr1_payment_intents WHERE invoice_id = $1")
        .bind(d.invoice_id)
        .fetch_optional(&state.db.pool)
        .await?;
    match intent_pk {
        Some(pk) => mark_settled_paid(state, pk, d.invoice_id, "captured", &tx_id).await?,
        None => mark_invoice_paid(state, d.invoice_id, &now).await?,
    }
    let _ = crate::covenant_keeper::emit_invoice_event(
        state, d.invoice_id, &d.invoice_public_id, d.user_id, d.store_id, "subscription.invoice.paid", &tx_id,
    )
    .await;
    tracing::info!("subscription keeper: cell {} claimed cycle {} via tx {tx_id}", d.cell_id, d.cycle_id);
    Ok(())
}

/// DB-only scan (unit/integration-testable without a node): due cycles whose
/// cell cannot cover the claim flip to `past_due` — once, guarded by the
/// `invoiced -> past_due` status transition — and emit `subscription.past_due`.
pub async fn mark_underfunded_past_due(state: &AppState) -> Result<usize, sqlx::Error> {
    #[derive(sqlx::FromRow)]
    struct Underfunded {
        cell_id: i64,
        cycle_id: i64,
        cycle_public_id: String,
        sub_public_id: String,
        user_id: i64,
        claim_total: i64,
        active_amount: Option<i64>,
        invoice_public_id: Option<String>,
    }
    let now_s = now_iso();
    let rows = sqlx::query_as::<_, Underfunded>(
        "SELECT c.id AS cell_id, cy.id AS cycle_id, cy.public_id AS cycle_public_id, \
                s.public_id AS sub_public_id, s.user_id, c.claim_total, c.active_amount, \
                inv.public_id AS invoice_public_id \
         FROM subscription_cells c \
         JOIN subscriptions s ON s.id = c.subscription_id AND s.status = 'active' AND s.payment_mode = 'wallet_autopay' \
         JOIN subscription_cycles cy ON cy.subscription_id = s.id AND cy.status = 'invoiced' \
         LEFT JOIN invoices inv ON inv.id = cy.invoice_id \
         WHERE c.state IN ('awaiting_funding', 'active', 'past_due') \
           AND cy.period_start <= $1 AND COALESCE(c.active_amount, 0) < c.claim_total \
         ORDER BY cy.id LIMIT $2",
    )
    .bind(&now_s)
    .bind(SCAN_BATCH)
    .fetch_all(&state.db.pool)
    .await?;

    let mut acted = 0usize;
    let now = now_iso();
    for r in &rows {
        // The status transition is the once-only guard: a cycle only goes
        // invoiced -> past_due a single time (a merchant retry re-invoices it,
        // which legitimately re-arms the notification).
        let flipped = sqlx::query(
            "UPDATE subscription_cycles SET status = 'past_due', past_due_at = $1, updated_at = $1 WHERE id = $2 AND status = 'invoiced'",
        )
        .bind(&now)
        .bind(r.cycle_id)
        .execute(&state.db.pool)
        .await?;
        if flipped.rows_affected() == 0 {
            continue;
        }
        sqlx::query("UPDATE subscription_cells SET state = 'past_due', updated_at = $1 WHERE id = $2 AND state IN ('awaiting_funding', 'active')")
            .bind(&now)
            .bind(r.cell_id)
            .execute(&state.db.pool)
            .await?;
        let payload = json!({
            "subscriptionPublicId": r.sub_public_id,
            "cyclePublicId": r.cycle_public_id,
            "invoicePublicId": r.invoice_public_id,
            "claimTotal": r.claim_total.to_string(),
            "activeAmount": r.active_amount.unwrap_or(0).to_string(),
        });
        if let Err(e) = crate::handlers::webhooks::emit_event(
            state, r.user_id, None, "subscription.past_due", "subscription", &r.sub_public_id, &payload,
        )
        .await
        {
            tracing::warn!("subscription.past_due emit failed for {}: {e}", r.sub_public_id);
        }
        tracing::info!("subscription keeper: cycle {} past due (cell {} underfunded)", r.cycle_id, r.cell_id);
        acted += 1;
    }
    Ok(acted)
}

#[cfg(test)]
mod tests {
    use super::recognize_funding;

    fn utxo(byte: u8, index: u32, value: u64) -> ([u8; 32], u32, u64) {
        ([byte; 32], index, value)
    }
    fn hex(byte: u8) -> String {
        crate::util::encode_hex(&[byte; 32])
    }

    #[test]
    fn recognizes_recorded_funding_and_ignores_foreign_utxos() {
        let utxos = vec![utxo(1, 0, 5_000), utxo(2, 0, 9_000_000)]; // 2 = unsolicited third-party send
        let picked = recognize_funding(&utxos, &[hex(1)], None);
        assert_eq!(picked, Some(utxo(1, 0, 5_000)));
        // Nothing recorded, nothing claimed → nothing recognized.
        assert_eq!(recognize_funding(&utxos, &[], None), None);
    }

    #[test]
    fn recognizes_own_claim_remainder() {
        let utxos = vec![utxo(3, 2, 4_000)];
        assert_eq!(recognize_funding(&utxos, &[], Some(&hex(3))), Some(utxo(3, 2, 4_000)));
    }

    #[test]
    fn prefers_the_largest_recognized_utxo_deterministically() {
        let utxos = vec![utxo(1, 0, 5_000), utxo(2, 1, 7_000), utxo(3, 0, 7_000)];
        let recorded = vec![hex(1), hex(2), hex(3)];
        // Largest wins; on a tie the smaller (txid, index) wins, both orders.
        assert_eq!(recognize_funding(&utxos, &recorded, None), Some(utxo(2, 1, 7_000)));
        let mut reversed = utxos.clone();
        reversed.reverse();
        assert_eq!(recognize_funding(&reversed, &recorded, None), Some(utxo(2, 1, 7_000)));
    }

    #[test]
    fn recorded_txid_match_is_case_insensitive() {
        let utxos = vec![utxo(0xAB, 0, 1_000)];
        let recorded = vec![hex(0xAB).to_uppercase()];
        assert_eq!(recognize_funding(&utxos, &recorded, None), Some(utxo(0xAB, 0, 1_000)));
    }
}
