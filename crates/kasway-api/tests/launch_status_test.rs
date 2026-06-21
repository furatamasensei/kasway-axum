mod common;

use serde_json::Value;

#[tokio::test]
async fn merchant_status_report() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "ls1@example.com", "secret123").await;

    let res = app.client.get(app.url("/api/payments/ops/status")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let r: Value = res.json().await.unwrap();
    assert_eq!(r["scope"], "merchant");
    assert!(r["merchantId"].as_i64().unwrap() > 0);
    let checks = r["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 9);
    let by = |k: &str| checks.iter().find(|c| c["key"] == k).unwrap().clone();
    assert_eq!(by("merchant.networkAssets")["status"], "pass");
    // no setup row -> walletSetup fails -> not ready
    assert_eq!(by("merchant.walletSetup")["status"], "fail");
    assert_eq!(by("merchant.walletSetup")["messageKey"], "payments.status.walletSetup.missingSetup");
    assert_eq!(by("merchant.retentionPolicy")["status"], "pass"); // defaults valid
    assert_eq!(by("system.storage")["status"], "pass");
    assert_eq!(by("merchant.apiScopes")["messageKey"], "payments.status.apiScope.sessionAuth");
    assert!(by("merchant.queue")["metadata"]["checked"] == true);
    assert_eq!(r["summary"]["ready"], false);
}

#[tokio::test]
async fn merchant_status_with_setup_and_endpoint() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "ls2@example.com", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "ls2@example.com").await;
    sqlx::query("INSERT INTO setups (user_id, kaspa_main_address, webhook_url, created_at, updated_at) VALUES (?, 'kaspatest:merchantaddr', 'https://hook.test', '2026-01-01T00:00:00.000+00:00', '2026-01-01T00:00:00.000+00:00')")
        .bind(uid).execute(&app.db.pool).await.unwrap();
    sqlx::query("INSERT INTO webhook_endpoints (user_id, url, events, signing_secret, is_active, created_at, updated_at) VALUES (?, 'https://hook.test', '[]', 's', 1, '2026-01-01T00:00:00.000+00:00', '2026-01-01T00:00:00.000+00:00')")
        .bind(uid).execute(&app.db.pool).await.unwrap();

    let r: Value = app.client.get(app.url("/api/payments/ops/status")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    let checks = r["checks"].as_array().unwrap();
    let by = |k: &str| checks.iter().find(|c| c["key"] == k).unwrap().clone();
    assert_eq!(by("merchant.walletSetup")["status"], "pass");
    assert_eq!(by("merchant.walletSetup")["metadata"]["hasWalletAddress"], true);
    assert_eq!(by("merchant.webhookHealth")["status"], "pass");
    assert_eq!(by("merchant.webhookHealth")["metadata"]["activeEndpointCount"], 1);
}

#[tokio::test]
async fn internal_platform_status() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/internal/payment-ops/status")).bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let r: Value = res.json().await.unwrap();
    assert_eq!(r["scope"], "platform");
    let checks = r["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 8);
    let by = |k: &str| checks.iter().find(|c| c["key"] == k).unwrap().clone();
    assert_eq!(by("platform.networkAssets")["status"], "pass");
    assert_eq!(by("platform.networkAssets")["metadata"]["supportedAssetCount"], 1);
    assert_eq!(by("platform.tn10NodeStatus")["status"], "warn");
    assert_eq!(by("platform.tn10NodeStatus")["metadata"]["statusStatus"], "disabled");
    assert_eq!(by("platform.webhookHealth")["status"], "pass"); // no endpoints -> total 0 -> pass
    assert!(r["summary"]["pass"].as_i64().unwrap() >= 1);
}

#[tokio::test]
async fn status_requires_auth() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/api/payments/ops/status")).send().await.unwrap().status(), 401);
    assert_eq!(app.client.get(app.url("/internal/payment-ops/status")).send().await.unwrap().status(), 401);
}
