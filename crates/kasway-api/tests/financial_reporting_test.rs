mod common;

use serde_json::{json, Value};

async fn merchant(app: &common::TestApp, email: &str) -> String {
    common::register_merchant(app, email, "secret123").await
}

#[tokio::test]
async fn reporting_categories_crud() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "fr1@example.com").await;

    let created = app.client.post(app.url("/api/payments/ops/reporting-categories")).bearer_auth(&token)
        .json(&json!({ "label": "VAT", "code": "vat", "type": "tax", "calculationMode": "percentage", "rate": "10" }))
        .send().await.unwrap();
    assert_eq!(created.status(), 201);
    let cat: Value = created.json().await.unwrap();
    assert_eq!(cat["label"], "VAT");
    assert_eq!(cat["code"], "vat");
    assert_eq!(cat["type"], "tax");
    assert_eq!(cat["isActive"], true);
    let id = cat["id"].as_i64().unwrap();

    let list: Value = app.client.get(app.url("/api/payments/ops/reporting-categories")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(list["meta"]["total"], 1);

    let upd: Value = app.client.put(app.url(&format!("/api/payments/ops/reporting-categories/{id}"))).bearer_auth(&token)
        .json(&json!({ "label": "VAT 2", "code": "vat", "type": "tax", "calculationMode": "percentage" }))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(upd["label"], "VAT 2");

    let del: Value = app.client.delete(app.url(&format!("/api/payments/ops/reporting-categories/{id}"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(del["isActive"], false);
}

#[tokio::test]
async fn reporting_category_validation_and_dup() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "fr2@example.com").await;

    let bad = app.client.post(app.url("/api/payments/ops/reporting-categories")).bearer_auth(&token).json(&json!({ "label": "X", "code": "x", "type": "nope", "calculationMode": "manual" })).send().await.unwrap();
    assert_eq!(bad.status(), 422);
    assert_eq!(bad.json::<Value>().await.unwrap()["errors"][0]["field"], "type");

    app.client.post(app.url("/api/payments/ops/reporting-categories")).bearer_auth(&token).json(&json!({ "label": "A", "code": "dup", "type": "tax", "calculationMode": "manual" })).send().await.unwrap();
    let dup = app.client.post(app.url("/api/payments/ops/reporting-categories")).bearer_auth(&token).json(&json!({ "label": "B", "code": "dup", "type": "tax", "calculationMode": "manual" })).send().await.unwrap();
    assert_eq!(dup.status(), 422);
    assert_eq!(dup.json::<Value>().await.unwrap()["message"], "Reporting category code 'dup' already exists");
}

#[tokio::test]
async fn accounting_profiles_crud() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "fr3@example.com").await;

    let created = app.client.post(app.url("/api/payments/ops/accounting-profiles")).bearer_auth(&token)
        .json(&json!({ "name": "Default", "accountCodes": { "revenue": "4000" }, "currencyHandling": "home_currency" }))
        .send().await.unwrap();
    assert_eq!(created.status(), 201);
    let prof: Value = created.json().await.unwrap();
    assert_eq!(prof["name"], "Default");
    assert_eq!(prof["accountCodes"]["revenue"], "4000");
    assert_eq!(prof["currencyHandling"], "home_currency");
    assert_eq!(prof["dateFormat"], "yyyy-MM-dd");
    let id = prof["id"].as_i64().unwrap();

    let list: Value = app.client.get(app.url("/api/payments/ops/accounting-profiles")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(list["meta"]["total"], 1);

    let upd: Value = app.client.put(app.url(&format!("/api/payments/ops/accounting-profiles/{id}"))).bearer_auth(&token).json(&json!({ "name": "Renamed" })).send().await.unwrap().json().await.unwrap();
    assert_eq!(upd["name"], "Renamed");

    // dup name
    app.client.post(app.url("/api/payments/ops/accounting-profiles")).bearer_auth(&token).json(&json!({ "name": "Other" })).send().await.unwrap();
    let dup = app.client.put(app.url(&format!("/api/payments/ops/accounting-profiles/{id}"))).bearer_auth(&token).json(&json!({ "name": "Other" })).send().await.unwrap();
    assert_eq!(dup.status(), 422);
    assert_eq!(dup.json::<Value>().await.unwrap()["message"], "Accounting profile 'Other' already exists");
}

#[tokio::test]
async fn reporting_requires_auth() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/api/payments/ops/reporting-categories")).send().await.unwrap().status(), 401);
    assert_eq!(app.client.get(app.url("/api/payments/ops/accounting-profiles")).send().await.unwrap().status(), 401);
}
