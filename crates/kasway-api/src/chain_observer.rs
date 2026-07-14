//! Background Kaspa chain observer — first slice of on-chain verification for
//! wallet-submitted KPR-1 payments, closing the loop: payment submitted →
//! observed on chain → confirmations tracked → invoice paid.
//!
//! Txid-driven only: each tick picks up KPR-1 intents in a submitted-but-not-
//! final state (`submitted`/`verified` with a wallet-provided `tx_id`, invoice
//! still `open`), asks the [`ChainSource`] for that transaction's outputs to
//! the intent's required addresses, and:
//!
//! - creates/updates the `payment_observations` row (observed amount/outputs,
//!   accepted DAA score, confirmations),
//! - verifies the covenant funding (one output paying the covenant P2SH
//!   address EXACTLY the gross amount — under- or overfunding is rejected).
//!   On mismatch it FAILS CLOSED: the intent is marked
//!   `failed` with a stable `failure_reason` and a `payment_anomaly_signals`
//!   row records the discrepancy — the invoice is never marked paid,
//! - once confirmations (`virtual DAA score - accepting DAA score`) meet the
//!   tenant's confirmation policy (`payment_tenant_settings`, platform
//!   default 10), settles: `payments` row `confirmed` (the same signal
//!   `derivePaymentStatus` treats as applied), observation + intent →
//!   `settled`, invoice → `paid`, and an `invoice.paid` webhook event is
//!   emitted through the standard fan-out (deliveries are then sent by the
//!   existing webhook worker).
//!
//! Observer progress is checkpointed per (network, asset) in
//! `payment_indexer_checkpoints` (source `chain_observer`, checkpoint = last
//! seen virtual DAA score).
//!
//! Env: `KASPA_NODE_URL` selects the node (see `crate::kaspa_wrpc`);
//! `CHAIN_OBSERVER_ENABLED` overrides the gate (default: on only when
//! `KASPA_NODE_URL` is set). Single-process by design — observation is
//! idempotent (settlement runs in one DB transaction), so no row claiming is
//! needed. The tick is a standalone function so tests can drive it with a
//! mock [`ChainSource`] and no polling loop.

use crate::chain_source::{ChainSource, ObservedTransaction};
use crate::handlers::payment_ops_settings::required_confirmations_for;
use crate::state::AppState;
use crate::util::now_iso;
use serde_json::json;

/// Idle sleep between polls.
const POLL_INTERVAL_SECS: u64 = 5;
/// Sompi per KAS.
const SOMPI_PER_KAS: i64 = 100_000_000;

/// Sompi rendered as KAS for logs — humans reason in KAS, not 9-digit sompi.
/// Trailing zeros are trimmed so 300000000 reads as `3 KAS`, not `3.00000000 KAS`.
fn kas(sompi: i64) -> String {
    let whole = sompi / SOMPI_PER_KAS;
    let frac = (sompi % SOMPI_PER_KAS).abs();
    if frac == 0 {
        return format!("{whole} KAS");
    }
    // Trim the FRACTION, not the finished string — trimming after the unit is
    // appended would do nothing (it ends in 'S').
    let frac = format!("{frac:08}");
    format!("{whole}.{} KAS", frac.trim_end_matches('0'))
}

#[cfg(test)]
mod kas_tests {
    use super::kas;

    #[test]
    fn renders_sompi_as_kas() {
        assert_eq!(kas(300_000_000), "3 KAS");
        assert_eq!(kas(0), "0 KAS");
        assert_eq!(kas(150_000_000), "1.5 KAS");
        assert_eq!(kas(1), "0.00000001 KAS");
        assert_eq!(kas(100_000_001), "1.00000001 KAS");
    }
}
/// Max intents examined per tick.
const CLAIM_BATCH: i64 = 25;

/// `CHAIN_OBSERVER_ENABLED` gate. When unset, the observer defaults to on
/// only when `KASPA_NODE_URL` is configured; `0`/`false`/`off` force-disable,
/// anything else force-enables.
pub fn enabled_from_env() -> bool {
    match std::env::var("CHAIN_OBSERVER_ENABLED") {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off"),
        Err(_) => std::env::var("KASPA_NODE_URL")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false),
    }
}

/// Spawn the polling loop as a tokio background task (called at startup).
/// Returns `None` when `KASPA_NODE_URL` is not configured.
pub fn spawn(state: AppState) -> Option<tokio::task::JoinHandle<()>> {
    let Some(client) = crate::kaspa_wrpc::KaspaWrpcClient::from_env() else {
        tracing::warn!("chain observer enabled but KASPA_NODE_URL is not set; observer not started");
        return None;
    };
    Some(tokio::spawn(async move {
        tracing::info!("chain observer started");
        loop {
            if let Err(err) = run_tick(&state, &client).await {
                tracing::error!("chain observer tick failed: {err}");
            }
            tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
        }
    }))
}

/// A KPR-1 intent awaiting chain observation, joined with its invoice.
#[derive(sqlx::FromRow)]
struct Candidate {
    intent_pk: i64,
    invoice_id: i64,
    user_id: i64,
    intent_id: String,
    tx_id: String,
    network: String,
    asset_id: String,
    script_hash: String,
    covenant_address: Option<String>,
    gross_amount: Option<i64>,
    public_id: String,
    currency: String,
    total_amount: i64,
}

/// One observer tick: examine every submitted-but-not-final intent against the
/// chain source. Returns how many intents made progress (observed, settled,
/// or failed verification). Chain-source errors are logged and skipped so a
/// flaky node never wedges the loop.
pub async fn run_tick<S: ChainSource>(state: &AppState, source: &S) -> Result<usize, sqlx::Error> {
    let candidates = sqlx::query_as::<_, Candidate>(
        "SELECT i.id AS intent_pk, i.invoice_id, i.user_id, i.intent_id, \
                i.tx_id, i.network, i.asset_id, i.script_hash, \
                i.covenant_address, i.gross_amount, \
                inv.public_id, inv.currency, inv.total_amount \
         FROM kpr1_payment_intents i \
         JOIN invoices inv ON inv.id = i.invoice_id \
         WHERE i.tx_id IS NOT NULL AND i.covenant_address IS NOT NULL \
           AND i.covenant_state = 'awaiting_funding' \
           AND inv.status = 'open' \
         ORDER BY i.id \
         LIMIT $1",
    )
    .bind(CLAIM_BATCH)
    .fetch_all(&state.db.pool)
    .await?;

    if candidates.is_empty() {
        return Ok(0);
    }

    let virtual_daa = match source.virtual_daa_score().await {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!("chain observer: virtual DAA score unavailable: {err}");
            return Ok(0);
        }
    };

    let mut progressed = 0usize;
    let mut touched: Vec<(String, String)> = Vec::new();
    for candidate in &candidates {
        match observe_candidate(state, source, candidate, virtual_daa).await? {
            Progress::None => {}
            Progress::Advanced => {
                progressed += 1;
                let key = (candidate.network.clone(), candidate.asset_id.clone());
                if !touched.contains(&key) {
                    touched.push(key);
                }
            }
        }
    }

    for (network, asset_id) in &touched {
        update_checkpoint(state, network, asset_id, virtual_daa).await?;
    }
    Ok(progressed)
}

enum Progress {
    /// Not yet visible on chain (or chain source error) — try again next tick.
    None,
    /// Observation row written (matched, settled, or failed verification).
    Advanced,
}

async fn observe_candidate<S: ChainSource>(
    state: &AppState,
    source: &S,
    c: &Candidate,
    virtual_daa: u64,
) -> Result<Progress, sqlx::Error> {
    // Covenant funding detection: the payer funds ONE output to the covenant
    // P2SH address with EXACTLY the gross amount. Under- or overfunding fails
    // closed (the covenant script would reject any spend of a wrong-valued UTXO).
    let (Some(covenant_address), Some(gross)) = (c.covenant_address.clone(), c.gross_amount) else {
        tracing::warn!("chain observer: covenant intent {} not finalized; skipping", c.intent_id);
        return Ok(Progress::None);
    };

    let tx = match source.transaction_outputs(&c.tx_id, &[covenant_address.clone()]).await {
        Ok(Some(tx)) => tx,
        Ok(None) => return Ok(Progress::None), // funding not visible yet
        Err(err) => {
            tracing::warn!("chain observer: lookup of tx {} failed: {err}", c.tx_id);
            return Ok(Progress::None);
        }
    };

    let confirmations: i64 = tx
        .accepting_daa_score
        .map(|acc| virtual_daa.saturating_sub(acc) as i64)
        .unwrap_or(0);
    let funded: i64 = tx
        .outputs
        .iter()
        .filter(|o| o.address == covenant_address)
        .map(|o| o.amount_sompi as i64)
        .sum();
    let metadata = covenant_observation_metadata(c, &covenant_address, funded, &tx);
    let now = now_iso();

    if funded != gross {
        // Wrong-valued funding: fail closed with a stable reason + anomaly signal.
        let reason = if funded < gross { "covenant_underfunded" } else { "covenant_overfunded" };
        upsert_observation(state, c, "mismatched", funded, confirmations, &tx, &metadata, &now).await?;
        fail_intent(state, c, reason, &now).await?;
        tracing::warn!(
            "chain observer: covenant intent {} tx {} funded {} != gross {} ({reason})",
            c.intent_id,
            c.tx_id,
            kas(funded),
            kas(gross)
        );
        return Ok(Progress::Advanced);
    }

    let required_confirmations =
        required_confirmations_for(state, c.user_id, &c.network, &c.asset_id, &c.currency, c.total_amount as i128).await?;

    if confirmations >= required_confirmations {
        // Covenant is funded and confirmed. The invoice stays OPEN — the keeper
        // releases the split (or auto-refunds after expiry) and only then marks
        // the invoice paid/refunded.
        upsert_observation(state, c, "settled", funded, confirmations, &tx, &metadata, &now).await?;
        mark_funded(state, c, &now).await?;
        // The only line that says the happy path happened. Without it the
        // observer is silent on success and looks dead while it is working.
        tracing::info!(
            "chain observer: covenant intent {} funded ({}, {confirmations} confirmations) -> verified",
            c.intent_id,
            kas(funded)
        );
    } else {
        upsert_observation(state, c, "matched", funded, confirmations, &tx, &metadata, &now).await?;
        mark_verified(state, c, &now).await?;
        tracing::info!(
            "chain observer: covenant intent {} seen on-chain ({confirmations}/{required_confirmations} confirmations)",
            c.intent_id
        );
    }
    Ok(Progress::Advanced)
}

/// Observation metadata in the shape the KPR-1 explorer reads. For covenant
/// settlement the single relevant output is the funding of the covenant address.
fn covenant_observation_metadata(c: &Candidate, covenant_address: &str, funded: i64, tx: &ObservedTransaction) -> String {
    json!({
        "kpr1": {
            "intentId": c.intent_id,
            "scriptHash": c.script_hash,
            "txId": tx.tx_id,
            "covenantAddress": covenant_address,
            "outputs": [{
                "role": "covenant",
                "address": covenant_address,
                "amountSompi": funded.to_string(),
            }],
        }
    })
    .to_string()
}

/// Create or update the observation row for (invoice, tx). Returns its id.
#[allow(clippy::too_many_arguments)]
async fn upsert_observation(
    state: &AppState,
    c: &Candidate,
    status: &str,
    amount: i64,
    confirmations: i64,
    tx: &ObservedTransaction,
    metadata: &str,
    now: &str,
) -> Result<i64, sqlx::Error> {
    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM payment_observations WHERE invoice_id = $1 AND tx_id = $2 ORDER BY id LIMIT 1",
    )
    .bind(c.invoice_id)
    .bind(&c.tx_id)
    .fetch_optional(&state.db.pool)
    .await?;

    let accepted_at = tx.accepting_daa_score.map(|_| now.to_string());
    let block_daa_score = tx.accepting_daa_score.map(|v| v as i64);
    let matched_at = (status == "matched" || status == "settled").then(|| now.to_string());

    if let Some(id) = existing {
        sqlx::query(
            "UPDATE payment_observations SET status = $1, amount = $2, confirmations = $3, \
             accepted_at = COALESCE(accepted_at, $4), block_daa_score = $5, \
             matched_at = COALESCE(matched_at, $6), metadata = $7, updated_at = $8 WHERE id = $9",
        )
        .bind(status)
        .bind(amount)
        .bind(confirmations)
        .bind(&accepted_at)
        .bind(block_daa_score)
        .bind(&matched_at)
        .bind(metadata)
        .bind(now)
        .bind(id)
        .execute(&state.db.pool)
        .await?;
        Ok(id)
    } else {
        sqlx::query_scalar::<_, i64>(
            "INSERT INTO payment_observations \
             (invoice_id, status, amount, confirmations, accepted_at, network, asset_id, tx_id, \
              block_daa_score, matched_at, metadata, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id",
        )
        .bind(c.invoice_id)
        .bind(status)
        .bind(amount)
        .bind(confirmations)
        .bind(&accepted_at)
        .bind(&c.network)
        .bind(&c.asset_id)
        .bind(&c.tx_id)
        .bind(block_daa_score)
        .bind(&matched_at)
        .bind(metadata)
        .bind(now)
        .bind(now)
        .fetch_one(&state.db.pool)
        .await
    }
}

/// Outputs matched but confirmations are still short of the policy: record
/// the intent as observed + verified and keep waiting.
async fn mark_verified(state: &AppState, c: &Candidate, now: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE kpr1_payment_intents SET status = 'verified', verification_status = 'verified', \
         observed_at = COALESCE(observed_at, $1), verified_at = COALESCE(verified_at, $1), \
         updated_at = $1 WHERE id = $2",
    )
    .bind(now)
    .bind(c.intent_pk)
    .execute(&state.db.pool)
    .await?;
    Ok(())
}

/// Covenant funded and confirmed: mark it `funded` + verified. The invoice stays
/// OPEN — the covenant keeper releases the split (or auto-refunds after expiry)
/// and only then closes the invoice.
async fn mark_funded(state: &AppState, c: &Candidate, now: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE kpr1_payment_intents SET covenant_state = 'funded', status = 'verified', \
         verification_status = 'verified', observed_at = COALESCE(observed_at, $1), \
         verified_at = COALESCE(verified_at, $1), updated_at = $1 WHERE id = $2",
    )
    .bind(now)
    .bind(c.intent_pk)
    .execute(&state.db.pool)
    .await?;
    // Publish from the funnel, not from each caller — every path that writes this
    // state notifies the watchers, and a new path cannot forget to.
    state.events.publish(&c.public_id, "funded");
    Ok(())
}

/// Observed outputs do not satisfy the intent: mark the intent failed with a
/// stable reason and record a critical anomaly signal. The invoice stays open.
async fn fail_intent(state: &AppState, c: &Candidate, reason: &str, now: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        // `covenant_state = 'failed'` makes this terminal for the observer: the
        // candidate query only picks `awaiting_funding` rows, so a failed intent
        // is never re-observed (no duplicate anomaly signals).
        "UPDATE kpr1_payment_intents SET status = 'failed', verification_status = 'failed', \
         covenant_state = 'failed', failure_reason = $1, observed_at = COALESCE(observed_at, $2), \
         updated_at = $2 WHERE id = $3",
    )
    .bind(reason)
    .bind(now)
    .bind(c.intent_pk)
    .execute(&state.db.pool)
    .await?;
    state.events.publish(&c.public_id, "failed");

    let metadata = json!({
        "txId": c.tx_id,
        "invoiceId": c.invoice_id,
        "invoicePublicId": c.public_id,
        "reasonCode": reason,
        "source": "chain_observer",
    });
    sqlx::query(
        "INSERT INTO payment_anomaly_signals \
         (user_id, signal_type, severity, status, resource_type, resource_id, detected_at, \
          window_start, window_end, reason, metadata, created_at, updated_at) \
         VALUES ($1, 'kpr1_output_mismatch', 'critical', 'open', 'kpr1_payment_intent', $2, $3, $3, $3, $4, $5, $3, $3)",
    )
    .bind(c.user_id)
    .bind(&c.intent_id)
    .bind(now)
    .bind(reason)
    .bind(metadata.to_string())
    .execute(&state.db.pool)
    .await?;
    Ok(())
}

/// Track observer progress per (network, asset): last seen virtual DAA score.
async fn update_checkpoint(
    state: &AppState,
    network: &str,
    asset_id: &str,
    virtual_daa: u64,
) -> Result<(), sqlx::Error> {
    let now = now_iso();
    let metadata = json!({ "virtualDaaScore": virtual_daa.to_string(), "lastTickAt": now });
    sqlx::query(
        "INSERT INTO payment_indexer_checkpoints (network, asset_id, source, checkpoint, metadata, created_at, updated_at) \
         VALUES ($1, $2, 'chain_observer', $3, $4, $5, $5) \
         ON CONFLICT (network, asset_id, source) DO UPDATE SET \
         checkpoint = excluded.checkpoint, metadata = excluded.metadata, updated_at = excluded.updated_at",
    )
    .bind(network)
    .bind(asset_id)
    .bind(virtual_daa.to_string())
    .bind(metadata.to_string())
    .bind(&now)
    .execute(&state.db.pool)
    .await?;
    Ok(())
}
