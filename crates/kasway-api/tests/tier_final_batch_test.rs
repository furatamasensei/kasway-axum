//! Final batch port (slim rail): price (#72), checkout kpr1-payments (#58).

mod common;

use serde_json::{json, Value};

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
