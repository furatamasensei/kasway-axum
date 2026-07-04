//! Background webhook delivery worker (the Rust port of `DeliverWebhookJob`).
//!
//! Deliveries are created `pending` by the webhook handlers; this worker polls
//! for due rows and POSTs the event to the endpoint URL with the documented
//! signature headers (see `content/en/5.sdk/webhooks.md` and
//! `content/en/2.payments/10.idempotency-rate-limits-retries.md` in kasway-v2):
//!
//! - `X-Kasway-Event` — event type
//! - `X-Kasway-Delivery` — delivery id
//! - `X-Kasway-Timestamp` — unix epoch seconds when the payload was signed
//! - `X-Kasway-Webhook-Version` — payload schema version
//! - `X-Kasway-Signature` — `sha256=<hex HMAC-SHA256>` of `{timestamp}.{rawBody}`
//!   keyed with the endpoint's `signing_secret`
//!
//! Only a `2xx` response counts as delivered; redirects are never followed and
//! `3xx` is a failure (per the docs). Failures retry with exponential backoff
//! following the merchant's `webhook_retry_profile` (conservative 3×30s,
//! balanced 5×60s (default), aggressive 7×15s: delay = base × 2^(n-1)); once
//! max attempts are exhausted the delivery is marked `failed`.
//!
//! Single-process by design: rows are claimed `pending` → `delivering` with
//! `FOR UPDATE SKIP LOCKED`, so concurrent workers won't double-send. The tick
//! is a standalone function so tests can drive it without the polling loop.

use crate::handlers::webhooks::{allow_loopback, validate_webhook_url};
use crate::state::AppState;
use crate::util::now_iso;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

/// Payload schema version reported in `X-Kasway-Webhook-Version`.
const WEBHOOK_VERSION: &str = "1";
/// Per-request timeout, seconds ("respond fast" per the troubleshooting docs).
const REQUEST_TIMEOUT_SECS: u64 = 10;
/// Idle sleep between polls when the queue is empty.
const POLL_INTERVAL_SECS: u64 = 5;
/// Max deliveries claimed per tick.
const CLAIM_BATCH: i64 = 10;
/// Stored `response_body` is truncated to this many bytes.
const RESPONSE_BODY_LIMIT: usize = 4096;

struct RetryProfile {
    max_attempts: i64,
    base_delay_secs: i64,
}

/// The documented retry profiles (balanced is the default).
fn retry_profile(name: &str) -> RetryProfile {
    match name {
        "conservative" => RetryProfile { max_attempts: 3, base_delay_secs: 30 },
        "aggressive" => RetryProfile { max_attempts: 7, base_delay_secs: 15 },
        _ => RetryProfile { max_attempts: 5, base_delay_secs: 60 },
    }
}

/// `WEBHOOK_WORKER_ENABLED` gate (default on; `0`/`false`/`off` disable).
pub fn enabled_from_env() -> bool {
    match std::env::var("WEBHOOK_WORKER_ENABLED") {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off"),
        Err(_) => true,
    }
}

/// Build the outbound HTTP client: 10s timeout, redirects never followed.
pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("webhook http client")
}

/// Spawn the polling loop as a tokio background task (called at startup).
pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let client = http_client();
        tracing::info!("webhook delivery worker started");
        loop {
            match run_tick(&state, &client).await {
                // Backlog drained (or nothing due): idle before polling again.
                Ok(0) => tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await,
                // Claimed a full-or-partial batch: keep draining immediately.
                Ok(_) => {}
                Err(err) => {
                    tracing::error!("webhook worker tick failed: {err}");
                    tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
                }
            }
        }
    })
}

#[derive(sqlx::FromRow)]
struct DueDelivery {
    id: i64,
    attempt_count: i64,
    event_id: i64,
    event_type: String,
    resource_type: String,
    resource_id: String,
    payload: String,
    event_created_at: Option<String>,
    endpoint_user_id: i64,
    url: String,
    signing_secret: String,
}

/// One worker tick: claim due deliveries (pending, next attempt due, endpoint
/// active and not paused) and attempt each one. Returns how many were claimed.
pub async fn run_tick(state: &AppState, client: &reqwest::Client) -> Result<usize, sqlx::Error> {
    let now = now_iso();
    // Claim pending → delivering; SKIP LOCKED keeps concurrent workers from
    // double-sending the same row.
    let ids: Vec<i64> = sqlx::query_scalar(
        "UPDATE webhook_deliveries SET status = 'delivering', updated_at = $1 \
         WHERE id IN ( \
             SELECT d.id FROM webhook_deliveries d \
             JOIN webhook_endpoints e ON e.id = d.webhook_endpoint_id \
             WHERE d.status = 'pending' \
               AND (d.next_attempt_at IS NULL OR d.next_attempt_at <= $1) \
               AND e.is_active = 1 AND e.paused_at IS NULL \
             ORDER BY d.id \
             LIMIT $2 \
             FOR UPDATE OF d SKIP LOCKED \
         ) \
         RETURNING id",
    )
    .bind(&now)
    .bind(CLAIM_BATCH)
    .fetch_all(&state.db.pool)
    .await?;

    for id in &ids {
        let delivery = sqlx::query_as::<_, DueDelivery>(
            "SELECT d.id, d.attempt_count, ev.id AS event_id, ev.event_type, ev.resource_type, \
                    ev.resource_id, ev.payload, ev.created_at AS event_created_at, \
                    e.user_id AS endpoint_user_id, e.url, e.signing_secret \
             FROM webhook_deliveries d \
             JOIN webhook_events ev ON ev.id = d.webhook_event_id \
             JOIN webhook_endpoints e ON e.id = d.webhook_endpoint_id \
             WHERE d.id = $1",
        )
        .bind(id)
        .fetch_one(&state.db.pool)
        .await?;
        attempt_delivery(state, client, &delivery).await?;
    }
    Ok(ids.len())
}

/// `sha256=<hex>` HMAC-SHA256 of `{timestamp}.{raw_body}` (the documented
/// scheme verified by `@kasway/sdk/webhooks`).
pub fn sign_payload(signing_secret: &str, timestamp: &str, raw_body: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(signing_secret.as_bytes())
        .expect("hmac accepts any key length");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(raw_body.as_bytes());
    let hex: String = mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    format!("sha256={hex}")
}

/// Attempt one claimed delivery and record the outcome.
async fn attempt_delivery(
    state: &AppState,
    client: &reqwest::Client,
    d: &DueDelivery,
) -> Result<(), sqlx::Error> {
    // SSRF policy re-check at delivery time (URLs are validated on
    // registration, but DNS/config may have changed since).
    if let Err((code, reason)) = validate_webhook_url(&d.url, allow_loopback(state)) {
        return record_failure(state, d, None, None, &format!("{code}: {reason}")).await;
    }

    let data: Value = serde_json::from_str(&d.payload).unwrap_or_else(|_| json!({}));
    let body = json!({
        "id": d.event_id,
        "type": d.event_type,
        "resourceType": d.resource_type,
        "resourceId": d.resource_id,
        "createdAt": d.event_created_at,
        "data": data,
    })
    .to_string();

    let timestamp = chrono::Utc::now().timestamp().to_string();
    let signature = sign_payload(&d.signing_secret, &timestamp, &body);

    let response = client
        .post(&d.url)
        .header("content-type", "application/json")
        .header("user-agent", "Kasway-Webhooks/1.0")
        .header("x-kasway-event", &d.event_type)
        .header("x-kasway-delivery", d.id.to_string())
        .header("x-kasway-timestamp", &timestamp)
        .header("x-kasway-webhook-version", WEBHOOK_VERSION)
        .header("x-kasway-signature", &signature)
        .body(body)
        .send()
        .await;

    match response {
        Ok(resp) => {
            let status = resp.status().as_u16() as i64;
            let mut body = resp.text().await.unwrap_or_default();
            body.truncate(RESPONSE_BODY_LIMIT);
            if (200..300).contains(&status) {
                record_success(state, d, status, &body).await
            } else {
                record_failure(state, d, Some(status), Some(&body), &format!("HTTP {status}")).await
            }
        }
        Err(err) => record_failure(state, d, None, None, &err.to_string()).await,
    }
}

async fn record_success(
    state: &AppState,
    d: &DueDelivery,
    status: i64,
    body: &str,
) -> Result<(), sqlx::Error> {
    let now = now_iso();
    sqlx::query(
        "UPDATE webhook_deliveries SET status = 'succeeded', attempt_count = $1, \
         response_status = $2, response_body = $3, error = NULL, last_attempted_at = $4, \
         next_attempt_at = NULL, delivered_at = $4, updated_at = $4 WHERE id = $5",
    )
    .bind(d.attempt_count + 1)
    .bind(status)
    .bind(body)
    .bind(&now)
    .bind(d.id)
    .execute(&state.db.pool)
    .await?;
    Ok(())
}

async fn record_failure(
    state: &AppState,
    d: &DueDelivery,
    response_status: Option<i64>,
    response_body: Option<&str>,
    error: &str,
) -> Result<(), sqlx::Error> {
    let profile_name: Option<String> =
        sqlx::query_scalar("SELECT webhook_retry_profile FROM payment_tenant_settings WHERE user_id = $1")
            .bind(d.endpoint_user_id)
            .fetch_optional(&state.db.pool)
            .await?;
    let profile = retry_profile(profile_name.as_deref().unwrap_or("balanced"));

    let attempt = d.attempt_count + 1;
    let now = now_iso();
    let (status, next_attempt_at) = if attempt >= profile.max_attempts {
        ("failed", None)
    } else {
        // Exponential backoff: base × 2^(n-1) after the n-th failed attempt.
        let delay_secs = profile.base_delay_secs * (1i64 << (attempt - 1).min(30));
        let next = (chrono::Utc::now() + chrono::Duration::seconds(delay_secs))
            .format("%Y-%m-%dT%H:%M:%S%.3f+00:00")
            .to_string();
        ("pending", Some(next))
    };

    sqlx::query(
        "UPDATE webhook_deliveries SET status = $1, attempt_count = $2, response_status = $3, \
         response_body = $4, error = $5, last_attempted_at = $6, next_attempt_at = $7, \
         updated_at = $6 WHERE id = $8",
    )
    .bind(status)
    .bind(attempt)
    .bind(response_status)
    .bind(response_body)
    .bind(error)
    .bind(&now)
    .bind(next_attempt_at)
    .bind(d.id)
    .execute(&state.db.pool)
    .await?;
    Ok(())
}
