//! Hard 15-minute payment-window worker.
//!
//! An invoice with no wallet submission recorded by its signed deadline is
//! retired together with its unfunded covenant. A timely submission remains
//! open while the chain observer waits for confirmations.

use crate::handlers::{invoices, webhooks};
use crate::state::AppState;
use crate::util::now_iso;

const POLL_INTERVAL_SECS: u64 = 5;
const SCAN_BATCH: i64 = 100;

pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!("invoice expirer started");
        loop {
            match run_tick(&state).await {
                Ok(0) => {
                    tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::error!("invoice expirer tick failed: {error}");
                    tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
                }
            }
        }
    })
}

/// Expire due invoices that have no tx submitted before their own deadline.
pub async fn run_tick(state: &AppState) -> Result<usize, sqlx::Error> {
    let now = now_iso();
    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT inv.id FROM invoices inv \
         WHERE inv.status = 'open' AND inv.expires_at IS NOT NULL AND inv.expires_at <= $1 \
         AND NOT EXISTS (SELECT 1 FROM kpr1_payment_intents pi \
           WHERE pi.invoice_id = inv.id AND pi.tx_id IS NOT NULL \
           AND pi.submitted_at IS NOT NULL AND pi.submitted_at <= pi.expires_at) \
         ORDER BY inv.expires_at, inv.id LIMIT $2",
    )
    .bind(&now)
    .bind(SCAN_BATCH)
    .fetch_all(&state.db.pool)
    .await?;

    let mut expired = 0;
    for invoice_id in &ids {
        match invoices::expire_invoice(state, *invoice_id).await {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                tracing::warn!("invoice expirer: invoice {invoice_id} failed: {error}");
                continue;
            }
        }
        expired += 1;
        if let Ok(invoice) = invoices::load_by_id(state, *invoice_id).await {
            if let Ok((items, intent)) = invoices::load_relations(state, *invoice_id).await {
                let payload = invoices::serialize_invoice(&invoice, &items, intent.as_ref());
                let public_id = payload["publicId"].as_str().unwrap_or_default();
                let user_id: Option<i64> =
                    sqlx::query_scalar("SELECT user_id FROM invoices WHERE id = $1")
                        .bind(invoice_id)
                        .fetch_optional(&state.db.pool)
                        .await?;
                if let Some(user_id) = user_id {
                    let store_id = payload["storeId"].as_i64();
                    if let Err(error) = webhooks::emit_event(
                        state,
                        user_id,
                        store_id,
                        "invoice.expired",
                        "invoice",
                        public_id,
                        &payload,
                    )
                    .await
                    {
                        tracing::warn!(
                            "invoice.expired emit failed for invoice {invoice_id}: {error}"
                        );
                    }
                }
            }
        }
    }
    Ok(expired)
}
