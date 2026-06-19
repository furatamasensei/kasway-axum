mod common;

use serde_json::Value;

async fn merchant_with_invoice(app: &common::TestApp, email: &str) -> (String, i64, String) {
    let token = common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    let store = common::seed_default_store(&app.db, uid).await;
    let pid = format!("inv_ops_{}", uid);
    let id = common::seed_invoice(&app.db, uid, store, &pid, "open", 1000, 1000, 0, None, None, "2026-01-01T00:00:00.000+00:00").await;
    (token, id, pid)
}

#[tokio::test]
async fn ops_invoices_list_with_payment_status() {
    let app = common::spawn_app().await;
    let (token, _id, _pid) = merchant_with_invoice(&app, "ops1@example.com").await;

    let body: Value = app.client.get(app.url("/api/payments/ops/invoices")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(body["meta"]["total"], 1);
    let inv = &body["data"][0];
    assert_eq!(inv["paymentStatus"]["status"]["paymentState"], "awaiting_payment");
    assert_eq!(inv["paymentStatus"]["totals"]["invoice"], "1000");
}

#[tokio::test]
async fn ops_invoice_detail_with_adjustment_summary() {
    let app = common::spawn_app().await;
    let (token, id, pid) = merchant_with_invoice(&app, "ops2@example.com").await;

    // add an adjustment so the summary is non-zero
    app.client.post(app.url(&format!("/api/payments/ops/invoices/{id}/adjustments"))).bearer_auth(&token)
        .json(&serde_json::json!({ "kind": "manual_credit", "direction": "credit", "amount": "200", "currency": "KAS", "reason": "x" }))
        .send().await.unwrap();

    // detail by numeric id
    let body: Value = app.client.get(app.url(&format!("/api/payments/ops/invoices/{id}"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(body["adjustmentSummary"]["count"], 1);
    assert_eq!(body["adjustmentSummary"]["credit"], "200");
    assert_eq!(body["adjustmentSummary"]["net"], "200");
    assert_eq!(body["paymentStatus"]["status"]["paymentState"], "awaiting_payment");

    // detail by public_id also works
    let by_pid: Value = app.client.get(app.url(&format!("/api/payments/ops/invoices/{pid}"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(by_pid["id"], id);

    // missing
    let missing = app.client.get(app.url("/api/payments/ops/invoices/inv_nope")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(missing.status(), 404);
}

#[tokio::test]
async fn ops_observations_and_credits_empty() {
    let app = common::spawn_app().await;
    let (token, _id, _pid) = merchant_with_invoice(&app, "ops3@example.com").await;

    let obs: Value = app.client.get(app.url("/api/payments/ops/observations")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(obs["meta"]["total"], 0);
    assert_eq!(obs["data"], serde_json::json!([]));

    let cr: Value = app.client.get(app.url("/api/payments/ops/credits")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(cr["meta"]["total"], 0);
}

#[tokio::test]
async fn ops_requires_auth() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/api/payments/ops/invoices")).send().await.unwrap().status(), 401);
}
