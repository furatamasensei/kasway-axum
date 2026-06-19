mod common;

use serde_json::{json, Value};

async fn merchant(app: &common::TestApp, email: &str) -> (String, i64, i64) {
    let token = common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    let store = common::seed_default_store(&app.db, uid).await;
    (token, uid, store)
}

#[tokio::test]
async fn generate_show_index_download() {
    let app = common::spawn_app().await;
    let (token, uid, store) = merchant(&app, "st1@example.com").await;
    let inv = common::seed_invoice(
        &app.db, uid, store, "inv_st1", "paid", 1000, 1000, 0, None, None,
        "2026-06-10T00:00:00.000+00:00",
    )
    .await;
    // adjustment created "now" (June) -> counted in the June period
    let created = app.client.post(app.url(&format!("/api/payments/ops/invoices/{inv}/adjustments"))).bearer_auth(&token)
        .json(&json!({ "kind": "manual_credit", "direction": "credit", "amount": "250", "currency": "KAS", "reason": "goodwill" }))
        .send().await.unwrap();
    assert_eq!(created.status(), 201);

    let gen = app.client.post(app.url("/api/payments/ops/statements")).bearer_auth(&token)
        .json(&json!({ "periodStart": "2026-06-01", "periodEnd": "2026-06-30" }))
        .send().await.unwrap();
    assert_eq!(gen.status(), 201);
    let st: Value = gen.json().await.unwrap();
    assert_eq!(st["status"], "generated");
    assert_eq!(st["periodStart"], "2026-06-01");
    assert_eq!(st["periodEnd"], "2026-06-30");
    assert_eq!(st["totals"]["grossInvoiceAmount"], "1000");
    assert_eq!(st["totals"]["paidAmount"], "1000");
    assert_eq!(st["totals"]["counts"]["invoices"], 1);
    assert_eq!(st["totals"]["counts"]["adjustments"], 1);
    assert_eq!(st["totals"]["adjustmentsByKind"]["manual_credit"]["credit"], "250");
    assert_eq!(st["totals"]["netAmount"], "1250");
    assert!(st["checksum"].as_str().unwrap().starts_with("sha256:"));
    assert_eq!(st["storagePath"], format!("payment-statements/{uid}/{}.json", st["id"].as_i64().unwrap()));
    let sid = st["id"].as_i64().unwrap();
    let checksum = st["checksum"].as_str().unwrap().to_string();

    let list: Value = app.client.get(app.url("/api/payments/ops/statements")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(list["meta"]["total"], 1);

    let shown: Value = app.client.get(app.url(&format!("/api/payments/ops/statements/{sid}"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(shown["id"], sid);

    let dl = app.client.get(app.url(&format!("/api/payments/ops/statements/{sid}/download"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(dl.status(), 200);
    assert_eq!(dl.headers().get("content-type").unwrap(), "application/json");
    assert_eq!(dl.headers().get("x-kasway-statement-checksum").unwrap().to_str().unwrap(), checksum);
    let artifact: Value = dl.json().await.unwrap();
    assert_eq!(artifact["userId"], uid);
    assert_eq!(artifact["totals"]["grossInvoiceAmount"], "1000");
}

#[tokio::test]
async fn overlap_and_period_validation() {
    let app = common::spawn_app().await;
    let (token, _uid, _store) = merchant(&app, "st2@example.com").await;

    let first = app.client.post(app.url("/api/payments/ops/statements")).bearer_auth(&token)
        .json(&json!({ "periodStart": "2026-01-01", "periodEnd": "2026-01-31" }))
        .send().await.unwrap();
    assert_eq!(first.status(), 201);

    let overlap = app.client.post(app.url("/api/payments/ops/statements")).bearer_auth(&token)
        .json(&json!({ "periodStart": "2026-01-15", "periodEnd": "2026-02-15" }))
        .send().await.unwrap();
    assert_eq!(overlap.status(), 422);
    assert_eq!(overlap.json::<Value>().await.unwrap()["message"], "Payment statement period overlaps an existing statement");

    let bad = app.client.post(app.url("/api/payments/ops/statements")).bearer_auth(&token)
        .json(&json!({ "periodStart": "2026-03-31", "periodEnd": "2026-03-01" }))
        .send().await.unwrap();
    assert_eq!(bad.status(), 422);
    assert_eq!(bad.json::<Value>().await.unwrap()["message"], "Payment reporting period is invalid");

    let missing = app.client.post(app.url("/api/payments/ops/statements")).bearer_auth(&token)
        .json(&json!({ "periodEnd": "2026-03-01" }))
        .send().await.unwrap();
    assert_eq!(missing.status(), 422);
    assert_eq!(missing.json::<Value>().await.unwrap()["errors"][0]["field"], "periodStart");
}

#[tokio::test]
async fn show_missing_404() {
    let app = common::spawn_app().await;
    let (token, _uid, _store) = merchant(&app, "st3@example.com").await;
    let res = app.client.get(app.url("/api/payments/ops/statements/9999")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "Payment statement not found");
}

#[tokio::test]
async fn statements_require_auth() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/api/payments/ops/statements")).send().await.unwrap().status(), 401);
}
