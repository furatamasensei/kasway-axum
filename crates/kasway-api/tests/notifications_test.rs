mod common;

use serde_json::{json, Value};

async fn merchant(app: &common::TestApp, email: &str) -> String {
    common::register_merchant(app, email, "secret123").await
}

#[tokio::test]
async fn notification_preferences_defaults_and_update() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "nt1@example.com").await;

    let prefs: Value = app.client.get(app.url("/api/payments/ops/notification-preferences")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    let arr = prefs.as_array().unwrap();
    assert_eq!(arr.len(), 7); // 7 default categories
    assert_eq!(arr[0]["enabled"], true);
    assert_eq!(arr[0]["channels"], json!(["email", "in_app"]));

    let upd: Value = app.client.put(app.url("/api/payments/ops/notification-preferences")).bearer_auth(&token)
        .json(&json!({ "preferences": [{ "category": "export_failed", "channels": ["email", "email"], "enabled": false }] }))
        .send().await.unwrap().json().await.unwrap();
    let exp = upd.as_array().unwrap().iter().find(|p| p["category"] == "export_failed").unwrap();
    assert_eq!(exp["enabled"], false);
    assert_eq!(exp["channels"], json!(["email"])); // deduped
}

#[tokio::test]
async fn notification_preferences_validation() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "nt2@example.com").await;

    let empty = app.client.put(app.url("/api/payments/ops/notification-preferences")).bearer_auth(&token).json(&json!({ "preferences": [] })).send().await.unwrap();
    assert_eq!(empty.status(), 422);

    let bad = app.client.put(app.url("/api/payments/ops/notification-preferences")).bearer_auth(&token)
        .json(&json!({ "preferences": [{ "category": "nope", "channels": ["email"], "enabled": true }] }))
        .send().await.unwrap();
    assert_eq!(bad.status(), 422);
}

#[tokio::test]
async fn notifications_index_and_read() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "nt3@example.com").await;
    let uid = common::merchant_user_id(&app.db, "nt3@example.com").await;

    // empty
    let empty: Value = app.client.get(app.url("/api/payments/ops/notifications")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(empty["meta"]["total"], 0);

    // seed a notification
    sqlx::query("INSERT INTO payment_notifications (user_id, category, severity, title_key, body_key, resource_type, resource_id, metadata, created_at, updated_at) VALUES ($1, 'export_failed', 'warning', 't', 'b', 'export', '1', '{}', '2026-01-01T00:00:00.000+00:00', '2026-01-01T00:00:00.000+00:00')")
        .bind(uid).execute(&app.db.pool).await.unwrap();

    let list: Value = app.client.get(app.url("/api/payments/ops/notifications")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(list["meta"]["total"], 1);
    let nid = list["data"][0]["id"].as_i64().unwrap();
    assert!(list["data"][0]["readAt"].is_null());

    let read: Value = app.client.post(app.url(&format!("/api/payments/ops/notifications/{nid}/read"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert!(!read["readAt"].is_null());

    let missing = app.client.post(app.url("/api/payments/ops/notifications/9999/read")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(missing.status(), 404);
    assert_eq!(missing.json::<Value>().await.unwrap()["message"], "Payment notification not found");
}

#[tokio::test]
async fn notifications_requires_auth() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/api/payments/ops/notification-preferences")).send().await.unwrap().status(), 401);
}
