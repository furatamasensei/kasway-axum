mod common;

use serde_json::{json, Value};

async fn merchant(app: &common::TestApp, email: &str) -> String {
    common::register_merchant(app, email, "secret123").await
}

#[tokio::test]
async fn settings_requires_auth() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/api/payments/ops/settings")).send().await.unwrap().status(), 401);
}

#[tokio::test]
async fn settings_default_then_update() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "po1@example.com").await;

    let def: Value = app.client.get(app.url("/api/payments/ops/settings")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(def["allowedNetworks"], json!(["tn10"]));
    assert_eq!(def["allowedAssets"], json!(["KAS"]));
    assert_eq!(def["defaultExportRetentionDays"], 7);
    assert_eq!(def["webhookRetryProfile"], "balanced");
    assert_eq!(def["enabledPaymentModules"].as_array().unwrap().len(), 8);
    assert_eq!(def["exceptionNotificationCategories"]["export_failed"], true);

    let upd = app.client.put(app.url("/api/payments/ops/settings")).bearer_auth(&token)
        .json(&json!({ "defaultExportRetentionDays": 30, "webhookRetryProfile": "aggressive", "allowedAssets": ["KAS", "KAS"] }))
        .send().await.unwrap();
    assert_eq!(upd.status(), 201);
    let body: Value = upd.json().await.unwrap();
    assert_eq!(body["defaultExportRetentionDays"], 30);
    assert_eq!(body["webhookRetryProfile"], "aggressive");
    assert_eq!(body["allowedAssets"], json!(["KAS"])); // deduped

    // persisted
    let again: Value = app.client.get(app.url("/api/payments/ops/settings")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(again["defaultExportRetentionDays"], 30);
}

#[tokio::test]
async fn settings_update_validation() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "po2@example.com").await;

    let unknown = app.client.put(app.url("/api/payments/ops/settings")).bearer_auth(&token).json(&json!({ "bogusKey": 1 })).send().await.unwrap();
    assert_eq!(unknown.status(), 422);
    assert!(unknown.json::<Value>().await.unwrap()["message"].as_str().unwrap().contains("Unknown setting keys"));

    let bad_enum = app.client.put(app.url("/api/payments/ops/settings")).bearer_auth(&token).json(&json!({ "webhookRetryProfile": "nope" })).send().await.unwrap();
    assert_eq!(bad_enum.status(), 422);
    assert_eq!(bad_enum.json::<Value>().await.unwrap()["errors"][0]["field"], "webhookRetryProfile");

    let bad_cat = app.client.put(app.url("/api/payments/ops/settings")).bearer_auth(&token).json(&json!({ "exceptionNotificationCategories": { "nope": true } })).send().await.unwrap();
    assert_eq!(bad_cat.status(), 422);
    assert!(bad_cat.json::<Value>().await.unwrap()["message"].as_str().unwrap().contains("Unknown exception notification categories"));
}

#[tokio::test]
async fn capabilities_shape() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "po3@example.com").await;
    let body: Value = app.client.get(app.url("/api/payments/ops/capabilities")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(body["setup"]["exists"], false);
    assert_eq!(body["modules"]["exports"]["setupRequired"], true);
    assert_eq!(body["modules"]["webhooks"]["activeEndpointCount"], 0);
    assert_eq!(body["constraints"]["allowedNetworks"], json!(["tn10"]));
    assert!(body["configured"].is_object());
}

#[tokio::test]
async fn network_capabilities_merchant_filtered() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "po4@example.com").await;
    let body: Value = app.client.get(app.url("/api/payments/ops/network-capabilities")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(body["allowedNetworks"], json!(["tn10"]));
    assert_eq!(body["capabilities"][0]["network"], "tn10");
    assert_eq!(body["capabilities"][0]["assets"][0]["assetId"], "KAS");
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
