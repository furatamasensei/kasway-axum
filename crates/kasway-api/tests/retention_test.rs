mod common;

use serde_json::{json, Value};

async fn merchant(app: &common::TestApp, email: &str) -> String {
    common::register_merchant(app, email, "secret123").await
}

#[tokio::test]
async fn retention_policy_default_update_runs() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "rt1@example.com").await;

    let def: Value = app.client.get(app.url("/api/payments/ops/retention-policy")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(def["exportsRetentionDays"], 7);
    assert_eq!(def["notificationsRetentionDays"], 30);
    assert!(def["supportNotesRetentionDays"].is_null());

    let upd: Value = app.client.put(app.url("/api/payments/ops/retention-policy")).bearer_auth(&token)
        .json(&json!({ "exportsRetentionDays": 14, "supportNotesRetentionDays": 90 }))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(upd["exportsRetentionDays"], 14);
    assert_eq!(upd["supportNotesRetentionDays"], 90);
    assert_eq!(upd["notificationsRetentionDays"], 30); // unchanged

    // persisted
    let again: Value = app.client.get(app.url("/api/payments/ops/retention-policy")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(again["exportsRetentionDays"], 14);

    // runs empty
    let runs: Value = app.client.get(app.url("/api/payments/ops/retention-runs")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(runs["meta"]["total"], 0);
}

#[tokio::test]
async fn retention_policy_validation() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "rt2@example.com").await;
    let bad = app.client.put(app.url("/api/payments/ops/retention-policy")).bearer_auth(&token).json(&json!({ "exportsRetentionDays": 0 })).send().await.unwrap();
    assert_eq!(bad.status(), 422);
    assert_eq!(bad.json::<Value>().await.unwrap()["errors"][0]["field"], "exportsRetentionDays");
}

#[tokio::test]
async fn retention_requires_auth() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/api/payments/ops/retention-policy")).send().await.unwrap().status(), 401);
}
