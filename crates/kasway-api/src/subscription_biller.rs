//! Subscription billing scheduler.
//!
//! Two scans per tick:
//! 1. Due subscriptions (`status='active' AND next_billing_at <= now`) — each is
//!    billed period by period (`generate_due_invoice` advances one interval per
//!    call) until it is caught up, so a subscription that slept through several
//!    periods mints every missed cycle+invoice.
//! 2. Orphaned cycles (`status='pending' AND invoice_id IS NULL`) — closes the
//!    non-transactional gap in `generate_due_invoice`, which advances
//!    `next_billing_at` before minting the invoice: a crash in between leaves a
//!    cycle without an invoice that scan 1 will never revisit.
//!
//! `subscription.invoice.created` is emitted inside `generate_invoice_for_cycle`
//! (the shared mint path), so both scans — and the create/retry handlers — emit.
//!
//! Env: `SUBSCRIPTION_BILLER_ENABLED` (default on). Errors are per-subscription:
//! one broken merchant setup must not stall everyone else's billing.

use crate::handlers::subscriptions::{generate_due_invoice, generate_invoice_for_cycle};
use crate::state::AppState;
use crate::util::to_iso;

const POLL_INTERVAL_SECS: u64 = 5;
/// Cap on periods billed per subscription per tick (bounds a pathological
/// catch-up, e.g. a daily plan resumed after years).
const MAX_PERIODS_PER_TICK: usize = 100;
const SCAN_BATCH: i64 = 50;

/// `SUBSCRIPTION_BILLER_ENABLED` gate (default on; `0`/`false`/`off` disable).
pub fn enabled_from_env() -> bool {
    match std::env::var("SUBSCRIPTION_BILLER_ENABLED") {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off"),
        Err(_) => true,
    }
}

/// Spawn the polling loop as a tokio background task (called at startup).
pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("subscription biller started");
        loop {
            match run_tick(&state).await {
                Ok(0) => tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await,
                Ok(_) => {}
                Err(err) => {
                    tracing::error!("subscription biller tick failed: {err}");
                    tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
                }
            }
        }
    })
}

/// One tick: bill every due subscription up to `now`, then re-mint invoices for
/// orphaned pending cycles. Returns how many invoices were generated.
pub async fn run_tick(state: &AppState) -> Result<usize, sqlx::Error> {
    let now = chrono::Utc::now();
    let now_s = to_iso(now);
    let mut acted = 0usize;

    let due: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM subscriptions \
         WHERE status = 'active' AND next_billing_at IS NOT NULL AND next_billing_at <= $1 \
         ORDER BY next_billing_at, id LIMIT $2",
    )
    .bind(&now_s)
    .bind(SCAN_BATCH)
    .fetch_all(&state.db.pool)
    .await?;

    for sub_id in due {
        // Multi-period catch-up: each successful call bills one period and
        // advances next_billing_at, so loop until nothing is due.
        for _ in 0..MAX_PERIODS_PER_TICK {
            match generate_due_invoice(state, sub_id, now).await {
                Ok(true) => acted += 1,
                Ok(false) => break,
                Err(err) => {
                    tracing::warn!("subscription biller: subscription {sub_id} billing failed: {err}; will retry");
                    break;
                }
            }
        }
    }

    // Orphaned cycles: created (and next_billing_at advanced) but never invoiced.
    let orphans: Vec<i64> = sqlx::query_scalar(
        "SELECT cy.id FROM subscription_cycles cy \
         JOIN subscriptions s ON s.id = cy.subscription_id \
         WHERE cy.status = 'pending' AND cy.invoice_id IS NULL AND s.status = 'active' \
         ORDER BY cy.id LIMIT $1",
    )
    .bind(SCAN_BATCH)
    .fetch_all(&state.db.pool)
    .await?;
    for cycle_id in orphans {
        match generate_invoice_for_cycle(state, cycle_id, false).await {
            Ok(_) => acted += 1,
            Err(err) => {
                tracing::warn!("subscription biller: cycle {cycle_id} invoicing failed: {err}; will retry");
            }
        }
    }

    Ok(acted)
}
