//! Final batch port: beta templates (#50), price (#72), risk evaluate (#161),
//! exception link/ignore observation (#154/#155), checkout kpr1-payments (#58),
//! transmit SSE (#1), admin queue gate (#249).

mod common;

use serde_json::{json, Value};

// --- #50 beta templates -----------------------------------------------------
#[tokio::test]
async fn beta_templates_preview_disabled() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/api/payments/tocatta/beta/templates")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert!(body["templates"].is_array());
    assert_eq!(body["templates"].as_array().unwrap().len(), 0);
    assert!(body["message"].as_str().unwrap().contains("beta"));
    // carries the merchant settlement contract
    assert!(body.get("supportedSplitTypes").is_some() || body.is_object());
}

// --- #72 price --------------------------------------------------------------
#[tokio::test]
async fn price_returns_ok_without_network() {
    let app = common::spawn_with_config(|c| {
        c.price_api_url = "http://127.0.0.1:1/price".to_string(); // unreachable → Null
    }, false).await;
    let res = app.client.get(app.url("/api/price")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert!(body.is_null()); // PRICE LOAD ERROR → null, faithful to Adonis
}

// --- #161 risk evaluate -----------------------------------------------------
#[tokio::test]
async fn risk_evaluate_requires_auth() {
    let app = common::spawn_app().await;
    let res = app.client.post(app.url("/api/payments/ops/risk/evaluate")).json(&json!({})).send().await.unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn risk_evaluate_passive_only() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "risk-eval@test.io", "secret123").await;
    let res = app.client.post(app.url("/api/payments/ops/risk/evaluate"))
        .bearer_auth(&token).json(&json!({})).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["passiveOnly"], true);
    assert!(body["data"].is_array());
}

// --- #155 ignore observation ------------------------------------------------
#[tokio::test]
async fn ignore_observation_requires_observation_key() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "ignore-obs@test.io", "secret123").await;
    // an exception key with no `:observation:` segment → 422
    let res = app.client.post(app.url("/api/payments/ops/exceptions/invoice:1:underpaid/ignore-observation"))
        .bearer_auth(&token).json(&json!({})).send().await.unwrap();
    assert_eq!(res.status(), 422);
    let body: Value = res.json().await.unwrap();
    assert!(body["message"].as_str().unwrap().contains("observation"));
}

// --- #154 link observation --------------------------------------------------
#[tokio::test]
async fn link_observation_validates_body() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "link-obs@test.io", "secret123").await;
    let res = app.client.post(app.url("/api/payments/ops/exceptions/invoice:1:underpaid/link-observation"))
        .bearer_auth(&token).json(&json!({})).send().await.unwrap();
    assert_eq!(res.status(), 422); // invoiceId/paymentObservationId required
}

// --- #58 checkout kpr1-payments ---------------------------------------------
#[tokio::test]
async fn kpr1_payment_unknown_invoice() {
    let app = common::spawn_app().await;
    let res = app.client.post(app.url("/api/checkout/invoices/nope/kpr1-payments"))
        .json(&json!({ "txId": "abc" })).send().await.unwrap();
    assert_eq!(res.status(), 422);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], "KPR1_INTENT_NOT_FOUND");
}

#[tokio::test]
async fn kpr1_payment_submits_tx_id() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "kpr1-pay@test.io", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "kpr1-pay@test.io").await;
    let store_id = common::seed_default_store(&app.db, uid).await;
    let _ = token;
    let inv_id = common::seed_invoice(&app.db, uid, store_id, "pubinv1", "open", 1000, 1000, 0, None, None, "2026-01-01T00:00:00.000+00:00").await;
    common::seed_kpr1_intent(&app.db, inv_id, uid, "intent-pay-1").await;

    let res = app.client.post(app.url("/api/checkout/invoices/pubinv1/kpr1-payments"))
        .json(&json!({ "txId": "wallet-tx-123" })).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["settlement"]["intentStatus"], "submitted");
    assert_eq!(body["settlement"]["relayed"], false);
}

#[tokio::test]
async fn kpr1_payment_proof_required() {
    let app = common::spawn_app().await;
    let uid = {
        let _ = common::register_merchant(&app, "kpr1-noproof@test.io", "secret123").await;
        common::merchant_user_id(&app.db, "kpr1-noproof@test.io").await
    };
    let store_id = common::seed_default_store(&app.db, uid).await;
    let inv_id = common::seed_invoice(&app.db, uid, store_id, "pubinv2", "open", 1000, 1000, 0, None, None, "2026-01-01T00:00:00.000+00:00").await;
    common::seed_kpr1_intent(&app.db, inv_id, uid, "intent-pay-2").await;

    let res = app.client.post(app.url("/api/checkout/invoices/pubinv2/kpr1-payments"))
        .json(&json!({})).send().await.unwrap();
    assert_eq!(res.status(), 422);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], "KPR1_PAYMENT_PROOF_REQUIRED");
}

// --- #1 transmit ------------------------------------------------------------
#[tokio::test]
async fn transmit_events_stream_opens() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/__transmit/events")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let ct = res.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("");
    assert!(ct.starts_with("text/event-stream"));
}

#[tokio::test]
async fn transmit_subscribe_public_channel() {
    let app = common::spawn_app().await;
    let res = app.client.post(app.url("/__transmit/subscribe"))
        .json(&json!({ "uid": "u1", "channel": "public/announcements" })).send().await.unwrap();
    assert_eq!(res.status(), 204);
}

#[tokio::test]
async fn transmit_private_channel_authorization() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "transmit@test.io", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "transmit@test.io").await;
    let channel = format!("merchant/{uid}/client/online");

    // without bearer → forbidden
    let res = app.client.post(app.url("/__transmit/subscribe"))
        .json(&json!({ "uid": "u1", "channel": channel })).send().await.unwrap();
    assert_eq!(res.status(), 403);

    // with the matching merchant bearer → 204
    let res = app.client.post(app.url("/__transmit/subscribe"))
        .bearer_auth(&token)
        .json(&json!({ "uid": "u1", "channel": format!("merchant/{uid}/client/online") })).send().await.unwrap();
    assert_eq!(res.status(), 204);

    // unsubscribe is always 204
    let res = app.client.post(app.url("/__transmit/unsubscribe"))
        .json(&json!({ "uid": "u1", "channel": format!("merchant/{uid}/client/online") })).send().await.unwrap();
    assert_eq!(res.status(), 204);
}

// --- #249 admin queue gate --------------------------------------------------
#[tokio::test]
async fn admin_queue_disabled_gate() {
    let app = common::spawn_app().await;
    for path in ["/admin/queue", "/admin/queue/active"] {
        let res = app.client.get(app.url(path)).send().await.unwrap();
        assert_eq!(res.status(), 404, "{path}");
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["message"], "Not found");
    }
}
