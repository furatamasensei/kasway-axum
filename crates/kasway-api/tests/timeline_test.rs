mod common;

use serde_json::{json, Value};

async fn merchant_with_invoice(app: &common::TestApp, email: &str) -> (String, i64, i64) {
    let token = common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    let store = common::seed_default_store(&app.db, uid).await;
    let inv = common::seed_invoice(
        &app.db, uid, store, &format!("inv_{email}"), "open", 1000, 1000, 0, None, None,
        "2026-01-01T00:00:00.000+00:00",
    )
    .await;
    (token, uid, inv)
}

// ---------- timeline ----------

#[tokio::test]
async fn timeline_fresh_invoice_has_created_event() {
    let app = common::spawn_app().await;
    let (token, _uid, inv) = merchant_with_invoice(&app, "tl1@example.com").await;

    let body: Value = app.client
        .get(app.url(&format!("/api/payments/ops/invoices/{inv}/timeline")))
        .bearer_auth(&token).send().await.unwrap().json().await.unwrap();

    let data = body["data"].as_array().unwrap();
    assert!(!data.is_empty());
    assert_eq!(data[0]["type"], "invoice.created");
    assert_eq!(data[0]["source"], "invoice");
    assert_eq!(data[0]["invoice"]["id"], inv);
}

#[tokio::test]
async fn timeline_includes_adjustment_event() {
    let app = common::spawn_app().await;
    let (token, _uid, inv) = merchant_with_invoice(&app, "tl2@example.com").await;

    // create an adjustment via the ops endpoint so it lands in the timeline
    let created = app.client.post(app.url(&format!("/api/payments/ops/invoices/{inv}/adjustments"))).bearer_auth(&token)
        .json(&json!({ "kind": "manual_credit", "direction": "credit", "amount": "500", "currency": "KAS", "reason": "goodwill" }))
        .send().await.unwrap();
    assert_eq!(created.status(), 201);

    let body: Value = app.client
        .get(app.url(&format!("/api/payments/ops/invoices/{inv}/timeline")))
        .bearer_auth(&token).send().await.unwrap().json().await.unwrap();

    let data = body["data"].as_array().unwrap();
    let has_adj = data.iter().any(|e| e["source"] == "payment_adjustment" && e["type"] == "payment_adjustment.manual_credit");
    assert!(has_adj, "timeline should contain the adjustment event: {data:#?}");
}

#[tokio::test]
async fn timeline_missing_invoice_404() {
    let app = common::spawn_app().await;
    let (token, _uid, _inv) = merchant_with_invoice(&app, "tl3@example.com").await;
    let res = app.client.get(app.url("/api/payments/ops/invoices/99999/timeline")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "Invoice not found");
}

#[tokio::test]
async fn timeline_requires_auth() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/api/payments/ops/invoices/1/timeline")).send().await.unwrap();
    assert_eq!(res.status(), 401);
}
