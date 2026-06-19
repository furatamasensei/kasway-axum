mod common;

use serde_json::{json, Value};

async fn merchant(app: &common::TestApp, email: &str) -> (String, i64) {
    let token = common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    (token, uid)
}

#[tokio::test]
async fn anomalies_index_filter_show() {
    let app = common::spawn_app().await;
    let (token, uid) = merchant(&app, "an1@example.com").await;
    common::seed_anomaly(&app.db, uid, "payment_spike", "high", "open").await;
    let id2 = common::seed_anomaly(&app.db, uid, "webhook_failure_spike", "low", "open").await;

    let all: Value = app.client.get(app.url("/api/payments/ops/anomalies")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(all["meta"]["total"], 2);

    let filtered: Value = app.client.get(app.url("/api/payments/ops/anomalies?severity=low")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(filtered["meta"]["total"], 1);
    assert_eq!(filtered["data"][0]["signalType"], "webhook_failure_spike");

    let shown: Value = app.client.get(app.url(&format!("/api/payments/ops/anomalies/{id2}"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(shown["id"], id2);

    let missing = app.client.get(app.url("/api/payments/ops/anomalies/9999")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(missing.status(), 404);
    assert_eq!(missing.json::<Value>().await.unwrap()["message"], "Payment anomaly signal not found");
}

#[tokio::test]
async fn anomalies_acknowledge_dismiss() {
    let app = common::spawn_app().await;
    let (token, uid) = merchant(&app, "an2@example.com").await;
    let id = common::seed_anomaly(&app.db, uid, "payment_spike", "high", "open").await;

    let ack: Value = app.client.post(app.url(&format!("/api/payments/ops/anomalies/{id}/acknowledge"))).bearer_auth(&token).json(&json!({ "note": "looking into it" })).send().await.unwrap().json().await.unwrap();
    assert_eq!(ack["status"], "acknowledged");

    let dis: Value = app.client.post(app.url(&format!("/api/payments/ops/anomalies/{id}/dismiss"))).bearer_auth(&token).json(&json!({ "note": "false positive" })).send().await.unwrap().json().await.unwrap();
    assert_eq!(dis["status"], "dismissed");

    // note required
    let bad = app.client.post(app.url(&format!("/api/payments/ops/anomalies/{id}/acknowledge"))).bearer_auth(&token).json(&json!({})).send().await.unwrap();
    assert_eq!(bad.status(), 422);
    assert_eq!(bad.json::<Value>().await.unwrap()["errors"][0]["field"], "note");
}

#[tokio::test]
async fn anomalies_requires_auth() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/api/payments/ops/anomalies")).send().await.unwrap().status(), 401);
}
