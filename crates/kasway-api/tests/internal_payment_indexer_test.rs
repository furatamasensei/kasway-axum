mod common;

use serde_json::Value;

// --- internalApiToken contract (internal_api_token_middleware.ts) ---

// No token configured -> 503 { message: "Internal API token is not configured" }
#[tokio::test]
async fn indexer_healthz_503_when_token_unconfigured() {
    let app = common::spawn_with(None).await;

    let res = app
        .client
        .get(app.url("/internal/payment-indexer/healthz"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 503);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["message"], "Internal API token is not configured");
}

// Missing/invalid token -> 401 { message: "Unauthorized access" }
#[tokio::test]
async fn indexer_healthz_401_without_token() {
    let app = common::spawn_app().await;

    let res = app
        .client
        .get(app.url("/internal/payment-indexer/healthz"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["message"], "Unauthorized access");
}

// Bearer token accepted; empty DB -> checkpoint null
#[tokio::test]
async fn indexer_healthz_ok_empty() {
    let app = common::spawn_app().await;

    let res = app
        .client
        .get(app.url("/internal/payment-indexer/healthz"))
        .bearer_auth(common::INTERNAL_TOKEN)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["network"], "tn10");
    assert_eq!(body["assetId"], "KAS");
    assert_eq!(body["source"], "rusty-kaspa-node");
    assert!(body["checkpoint"].is_null());
}

// x-internal-api-token header also accepted; returns latest matching checkpoint
#[tokio::test]
async fn indexer_healthz_returns_latest_checkpoint() {
    let app = common::spawn_app().await;
    common::seed_checkpoint(
        &app.db,
        "tn10",
        "KAS",
        "rusty-kaspa-node",
        Some("12345"),
        Some(r#"{"height":12345}"#),
        "2026-01-01T00:00:00.000Z",
    )
    .await;

    let res = app
        .client
        .get(app.url("/internal/payment-indexer/healthz"))
        .header("x-internal-api-token", common::INTERNAL_TOKEN)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let cp = &body["checkpoint"];
    assert_eq!(cp["network"], "tn10");
    assert_eq!(cp["assetId"], "KAS");
    assert_eq!(cp["checkpoint"], "12345");
    assert_eq!(cp["metadata"], serde_json::json!({ "height": 12345 }));
}

// checkpoints lists only tn10, newest first, wrapped in { data: [...] }
#[tokio::test]
async fn indexer_checkpoints_lists_tn10() {
    let app = common::spawn_app().await;
    common::seed_checkpoint(&app.db, "tn10", "KAS", "rusty-kaspa-node", Some("100"), None, "2026-01-01T00:00:00.000Z").await;
    common::seed_checkpoint(&app.db, "tn10", "KAS", "other-source", Some("200"), None, "2026-02-01T00:00:00.000Z").await;
    common::seed_checkpoint(&app.db, "mainnet", "KAS", "rusty-kaspa-node", Some("300"), None, "2026-03-01T00:00:00.000Z").await;

    let res = app
        .client
        .get(app.url("/internal/payment-indexer/checkpoints"))
        .bearer_auth(common::INTERNAL_TOKEN)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let data = body["data"].as_array().unwrap();
    assert_eq!(data.len(), 2); // tn10 only
    // newest updated_at first
    assert_eq!(data[0]["checkpoint"], "200");
    assert_eq!(data[1]["checkpoint"], "100");
}
