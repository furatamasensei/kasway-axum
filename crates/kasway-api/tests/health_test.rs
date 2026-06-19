mod common;

use serde_json::Value;

// GET /internal/healthz -> 200 { "status": "ok" }
#[tokio::test]
async fn healthz_returns_ok() {
    let app = common::spawn_app().await;

    let res = app
        .client
        .get(app.url("/internal/healthz"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body, serde_json::json!({ "status": "ok" }));
}
