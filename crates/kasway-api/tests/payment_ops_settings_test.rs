mod common;

use serde_json::{json, Value};

async fn merchant(app: &common::TestApp, email: &str) -> String {
    common::register_merchant(app, email, "secret123").await
}

#[tokio::test]
async fn confirmation_policy_default_and_update() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "po5@example.com").await;

    let def: Value = app.client.get(app.url("/api/payments/ops/confirmation-policy")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(def["requiredConfirmations"], 10);
    assert_eq!(def["reasonKey"], "platform_default");
    assert_eq!(def["policyId"], "kasway-confirmation-policy:v1");
    assert_eq!(def["platformMinimumConfirmations"], 10);
    assert_eq!(def["network"], "tn10");
    assert_eq!(def["configuredPolicy"]["overrides"], json!([]));

    // update with defaultConfirmations 12
    let upd = app.client.put(app.url("/api/payments/ops/confirmation-policy")).bearer_auth(&token).json(&json!({ "defaultConfirmations": 12 })).send().await.unwrap();
    assert_eq!(upd.status(), 201);
    assert_eq!(upd.json::<Value>().await.unwrap()["defaultConfirmations"], 12);

    // resolve now reflects 12
    let resolved: Value = app.client.get(app.url("/api/payments/ops/confirmation-policy")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(resolved["requiredConfirmations"], 12);
    assert_eq!(resolved["reasonKey"], "merchant_override");
}

#[tokio::test]
async fn confirmation_policy_update_validation() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "po6@example.com").await;

    let below_min = app.client.put(app.url("/api/payments/ops/confirmation-policy")).bearer_auth(&token).json(&json!({ "defaultConfirmations": 3 })).send().await.unwrap();
    assert_eq!(below_min.status(), 422);
    assert_eq!(below_min.json::<Value>().await.unwrap()["message"], "Confirmation policy minimum confirmations must be at least 10");

    let unknown = app.client.put(app.url("/api/payments/ops/confirmation-policy")).bearer_auth(&token).json(&json!({ "bogus": 1 })).send().await.unwrap();
    assert_eq!(unknown.status(), 422);
    assert!(unknown.json::<Value>().await.unwrap()["message"].as_str().unwrap().contains("Unknown confirmation policy keys"));
}
