mod common;

use serde_json::{json, Value};

async fn merchant_with_underpaid(app: &common::TestApp, email: &str) -> (String, i64) {
    let token = common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    let store = common::seed_default_store(&app.db, uid).await;
    let inv = common::seed_invoice(&app.db, uid, store, &format!("inv_exc_{uid}"), "open", 1000, 1000, 0, None, None, "2026-01-01T00:00:00.000+00:00").await;
    // a partial credit (< total) -> derived paymentState underpaid
    common::seed_credit(&app.db, inv, 500).await;
    (token, inv)
}

#[tokio::test]
async fn exceptions_index_derives_underpaid() {
    let app = common::spawn_app().await;
    let (token, inv) = merchant_with_underpaid(&app, "ex1@example.com").await;

    let body: Value = app.client.get(app.url("/api/payments/ops/exceptions")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(body["meta"]["total"], 1);
    let row = &body["data"][0];
    assert_eq!(row["type"], "underpaid");
    assert_eq!(row["id"], format!("underpaid:invoice:{inv}"));
    assert_eq!(row["invoice"]["id"], inv);
    assert_eq!(row["amounts"]["credited"], "500");
    assert_eq!(row["amounts"]["remaining"], "500");
}

#[tokio::test]
async fn exceptions_resolve_then_filtered_out() {
    let app = common::spawn_app().await;
    let (token, inv) = merchant_with_underpaid(&app, "ex2@example.com").await;
    let key = format!("underpaid:invoice:{inv}");

    // no resolution yet
    let none = app.client.get(app.url(&format!("/api/payments/ops/exceptions/{key}/resolution"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(none.status(), 404);
    assert_eq!(none.json::<Value>().await.unwrap()["message"], "Payment exception resolution not found");

    // resolve
    let resolved = app.client.post(app.url(&format!("/api/payments/ops/exceptions/{key}/resolve"))).bearer_auth(&token).json(&json!({ "note": "reconciled" })).send().await.unwrap();
    assert_eq!(resolved.status(), 201);
    let r: Value = resolved.json().await.unwrap();
    assert_eq!(r["status"], "resolved");
    assert_eq!(r["exceptionKey"], key);
    assert_eq!(r["exceptionType"], "underpaid");
    assert_eq!(r["invoiceId"], inv);

    // index now excludes it
    let body: Value = app.client.get(app.url("/api/payments/ops/exceptions")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(body["meta"]["total"], 0);

    // resolution now returns the record
    let got: Value = app.client.get(app.url(&format!("/api/payments/ops/exceptions/{key}/resolution"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(got["status"], "resolved");
}

#[tokio::test]
async fn exceptions_dismiss_requires_note() {
    let app = common::spawn_app().await;
    let (token, inv) = merchant_with_underpaid(&app, "ex3@example.com").await;
    let key = format!("underpaid:invoice:{inv}");

    let bad = app.client.post(app.url(&format!("/api/payments/ops/exceptions/{key}/dismiss"))).bearer_auth(&token).json(&json!({})).send().await.unwrap();
    assert_eq!(bad.status(), 422);
    assert_eq!(bad.json::<Value>().await.unwrap()["errors"][0]["field"], "note");

    let ok = app.client.post(app.url(&format!("/api/payments/ops/exceptions/{key}/dismiss"))).bearer_auth(&token).json(&json!({ "note": "not real" })).send().await.unwrap();
    assert_eq!(ok.status(), 201);
    assert_eq!(ok.json::<Value>().await.unwrap()["status"], "dismissed");
}

#[tokio::test]
async fn exceptions_empty_and_auth() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "ex4@example.com", "secret123").await;
    let body: Value = app.client.get(app.url("/api/payments/ops/exceptions")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(body["meta"]["total"], 0);
    assert_eq!(app.client.get(app.url("/api/payments/ops/exceptions")).send().await.unwrap().status(), 401);
}
