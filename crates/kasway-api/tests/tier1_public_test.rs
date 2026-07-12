mod common;

use serde_json::Value;

#[tokio::test]
async fn openapi_json_served() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/openapi.json")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers().get("content-type").unwrap(), "application/json");
    assert_eq!(res.headers().get("cache-control").unwrap(), "public, max-age=300");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["openapi"], "3.1.0");
    assert_eq!(body["info"]["title"], "Kasway v2 API");
}
