//! Background webhook delivery worker (`kasway_api::webhook_worker`): one tick
//! claims due pending deliveries, POSTs the signed event to the endpoint URL,
//! and records the outcome (succeeded / retry with backoff / failed).

mod common;

use std::sync::{Arc, Mutex};

use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

/// One request captured by the local receiver.
struct Hit {
    headers: HeaderMap,
    body: String,
}

/// Serve a local HTTP listener on an ephemeral port that records every request
/// and replies with `status`. Returns the URL to register and the hit log.
async fn spawn_receiver(status: u16) -> (String, Arc<Mutex<Vec<Hit>>>) {
    let hits: Arc<Mutex<Vec<Hit>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = hits.clone();
    let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
        let sink = sink.clone();
        async move {
            let (parts, body) = req.into_parts();
            let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
            sink.lock().unwrap().push(Hit {
                headers: parts.headers,
                body: String::from_utf8_lossy(&bytes).into_owned(),
            });
            (axum::http::StatusCode::from_u16(status).unwrap(), "receiver says hi")
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/hook"), hits)
}

/// Create an endpoint subscribed to `invoice.paid` pointing at `url`, then
/// test-send an event; returns (signing secret, delivery id).
async fn endpoint_with_pending_delivery(app: &common::TestApp, token: &str, url: &str) -> (String, i64) {
    let created: Value = app
        .client
        .post(app.url("/api/webhook-endpoints"))
        .bearer_auth(token)
        .json(&json!({ "url": url, "events": ["invoice.paid"] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let endpoint_id = created["id"].as_i64().unwrap();
    let secret = created["signingSecret"].as_str().unwrap().to_string();

    let sent = app
        .client
        .post(app.url(&format!("/api/webhook-endpoints/{endpoint_id}/test-send")))
        .bearer_auth(token)
        .json(&json!({ "eventType": "invoice.paid" }))
        .send()
        .await
        .unwrap();
    assert_eq!(sent.status(), 202);
    let sent: Value = sent.json().await.unwrap();
    (secret, sent["deliveryId"].as_i64().unwrap())
}

type DeliveryRow = (String, i64, Option<i64>, Option<String>, Option<String>, Option<String>);

async fn delivery_row(app: &common::TestApp, id: i64) -> DeliveryRow {
    sqlx::query_as(
        "SELECT status, attempt_count, response_status, next_attempt_at, delivered_at, error \
         FROM webhook_deliveries WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&app.db.pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn worker_delivers_signed_event_and_marks_succeeded() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "whd1@example.com", "secret123").await;
    let (url, hits) = spawn_receiver(200).await;
    let (secret, delivery_id) = endpoint_with_pending_delivery(&app, &token, &url).await;

    let claimed = kasway_api::webhook_worker::run_tick(&app.state, &kasway_api::webhook_worker::http_client())
        .await
        .unwrap();
    assert_eq!(claimed, 1);

    // the receiver got exactly one POST with the documented headers
    let hits = hits.lock().unwrap();
    assert_eq!(hits.len(), 1);
    let hit = &hits[0];
    assert_eq!(hit.headers["x-kasway-event"], "invoice.paid");
    assert_eq!(hit.headers["x-kasway-delivery"], delivery_id.to_string().as_str());
    assert_eq!(hit.headers["x-kasway-webhook-version"], "1");
    assert_eq!(hit.headers["content-type"], "application/json");

    // signature: sha256=<hex HMAC-SHA256(secret, "{timestamp}.{rawBody}")>
    let timestamp = hit.headers["x-kasway-timestamp"].to_str().unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{timestamp}.{}", hit.body).as_bytes());
    let expected: String = mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(hit.headers["x-kasway-signature"].to_str().unwrap(), format!("sha256={expected}"));

    // body is the serialized event
    let body: Value = serde_json::from_str(&hit.body).unwrap();
    assert_eq!(body["type"], "invoice.paid");
    assert_eq!(body["resourceType"], "webhook_endpoint");
    assert_eq!(body["data"]["test"], true);
    assert!(body["id"].is_i64());

    // delivery row updated
    let (status, attempts, response_status, next_attempt_at, delivered_at, error) =
        delivery_row(&app, delivery_id).await;
    assert_eq!(status, "succeeded");
    assert_eq!(attempts, 1);
    assert_eq!(response_status, Some(200));
    assert!(next_attempt_at.is_none());
    assert!(delivered_at.is_some());
    assert!(error.is_none());
}

#[tokio::test]
async fn failed_delivery_schedules_backoff_then_permanently_fails() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "whd2@example.com", "secret123").await;
    let (url, hits) = spawn_receiver(500).await;
    let (_secret, delivery_id) = endpoint_with_pending_delivery(&app, &token, &url).await;

    let claimed = kasway_api::webhook_worker::run_tick(&app.state, &kasway_api::webhook_worker::http_client())
        .await
        .unwrap();
    assert_eq!(claimed, 1);
    assert_eq!(hits.lock().unwrap().len(), 1);

    // first failure: retry scheduled with backoff (balanced profile: +60s)
    let (status, attempts, response_status, next_attempt_at, delivered_at, error) =
        delivery_row(&app, delivery_id).await;
    assert_eq!(status, "pending");
    assert_eq!(attempts, 1);
    assert_eq!(response_status, Some(500));
    assert_eq!(error.as_deref(), Some("HTTP 500"));
    assert!(delivered_at.is_none());
    let next = next_attempt_at.expect("retry must be scheduled");
    assert!(next.as_str() > kasway_api::util::now_iso().as_str(), "next_attempt_at {next} should be in the future");

    // not due yet -> the next tick claims nothing
    let claimed = kasway_api::webhook_worker::run_tick(&app.state, &kasway_api::webhook_worker::http_client())
        .await
        .unwrap();
    assert_eq!(claimed, 0);

    // simulate the final allowed attempt (balanced profile caps at 5)
    sqlx::query("UPDATE webhook_deliveries SET attempt_count = 4, next_attempt_at = NULL WHERE id = $1")
        .bind(delivery_id)
        .execute(&app.db.pool)
        .await
        .unwrap();
    let claimed = kasway_api::webhook_worker::run_tick(&app.state, &kasway_api::webhook_worker::http_client())
        .await
        .unwrap();
    assert_eq!(claimed, 1);

    let (status, attempts, _response_status, next_attempt_at, delivered_at, _error) =
        delivery_row(&app, delivery_id).await;
    assert_eq!(status, "failed");
    assert_eq!(attempts, 5);
    assert!(next_attempt_at.is_none());
    assert!(delivered_at.is_none());
}

#[tokio::test]
async fn paused_endpoint_is_not_delivered() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "whd3@example.com", "secret123").await;
    let (url, hits) = spawn_receiver(200).await;
    let (_secret, delivery_id) = endpoint_with_pending_delivery(&app, &token, &url).await;

    // pause after the delivery was queued
    let endpoint_id: i64 = sqlx::query_scalar("SELECT webhook_endpoint_id FROM webhook_deliveries WHERE id = $1")
        .bind(delivery_id)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    let res = app
        .client
        .post(app.url(&format!("/api/webhook-endpoints/{endpoint_id}/pause")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);

    let claimed = kasway_api::webhook_worker::run_tick(&app.state, &kasway_api::webhook_worker::http_client())
        .await
        .unwrap();
    assert_eq!(claimed, 0);
    assert!(hits.lock().unwrap().is_empty());

    let (status, attempts, ..) = delivery_row(&app, delivery_id).await;
    assert_eq!(status, "pending");
    assert_eq!(attempts, 0);
}
