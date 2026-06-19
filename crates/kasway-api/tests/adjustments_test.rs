mod common;

use serde_json::{json, Value};

async fn merchant_with_invoice(app: &common::TestApp, email: &str) -> (String, i64) {
    let token = common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    let store = common::seed_default_store(&app.db, uid).await;
    let inv = common::seed_invoice(&app.db, uid, store, &format!("inv_{email}"), "open", 1000, 1000, 0, None, None, "2026-01-01T00:00:00.000+00:00").await;
    (token, inv)
}

#[tokio::test]
async fn adjustment_create_list_show() {
    let app = common::spawn_app().await;
    let (token, inv) = merchant_with_invoice(&app, "adj1@example.com").await;

    let created = app.client.post(app.url(&format!("/api/payments/ops/invoices/{inv}/adjustments"))).bearer_auth(&token)
        .json(&json!({ "kind": "manual_credit", "direction": "credit", "amount": "500", "currency": "KAS", "reason": "goodwill" }))
        .send().await.unwrap();
    assert_eq!(created.status(), 201);
    let adj: Value = created.json().await.unwrap();
    assert_eq!(adj["kind"], "manual_credit");
    assert_eq!(adj["direction"], "credit");
    assert_eq!(adj["amount"], "500");
    assert_eq!(adj["invoiceId"], inv);
    let aid = adj["id"].as_i64().unwrap();

    let list: Value = app.client.get(app.url(&format!("/api/payments/ops/invoices/{inv}/adjustments"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(list["meta"]["total"], 1);

    let shown: Value = app.client.get(app.url(&format!("/api/payments/ops/adjustments/{aid}"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(shown["id"], aid);
    assert_eq!(shown["invoice"]["id"], inv);
}

#[tokio::test]
async fn adjustment_validation() {
    let app = common::spawn_app().await;
    let (token, inv) = merchant_with_invoice(&app, "adj2@example.com").await;

    // refund_record without externalReference -> 422
    let refund = app.client.post(app.url(&format!("/api/payments/ops/invoices/{inv}/adjustments"))).bearer_auth(&token)
        .json(&json!({ "kind": "refund_record", "direction": "debit", "amount": "100", "currency": "KAS", "reason": "r" }))
        .send().await.unwrap();
    assert_eq!(refund.status(), 422);
    assert_eq!(refund.json::<Value>().await.unwrap()["message"], "Refund record adjustments require an external reference");

    // correction without metadata -> 422
    let corr = app.client.post(app.url(&format!("/api/payments/ops/invoices/{inv}/adjustments"))).bearer_auth(&token)
        .json(&json!({ "kind": "correction", "direction": "credit", "amount": "100", "currency": "KAS", "reason": "r" }))
        .send().await.unwrap();
    assert_eq!(corr.status(), 422);
    assert_eq!(corr.json::<Value>().await.unwrap()["message"], "Correction adjustments require metadata");

    // bad amount (leading zero) -> 422 validation
    let amt = app.client.post(app.url(&format!("/api/payments/ops/invoices/{inv}/adjustments"))).bearer_auth(&token)
        .json(&json!({ "kind": "manual_credit", "direction": "credit", "amount": "0100", "currency": "KAS", "reason": "r" }))
        .send().await.unwrap();
    assert_eq!(amt.status(), 422);
    assert_eq!(amt.json::<Value>().await.unwrap()["errors"][0]["field"], "amount");

    // invoice not found -> 404
    let nf = app.client.post(app.url("/api/payments/ops/invoices/99999/adjustments")).bearer_auth(&token)
        .json(&json!({ "kind": "manual_credit", "direction": "credit", "amount": "100", "currency": "KAS", "reason": "r" }))
        .send().await.unwrap();
    assert_eq!(nf.status(), 404);
    assert_eq!(nf.json::<Value>().await.unwrap()["message"], "Invoice not found");
}

#[tokio::test]
async fn adjustment_show_missing_404() {
    let app = common::spawn_app().await;
    let (token, _) = merchant_with_invoice(&app, "adj3@example.com").await;
    let res = app.client.get(app.url("/api/payments/ops/adjustments/9999")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "Payment adjustment not found");
}
