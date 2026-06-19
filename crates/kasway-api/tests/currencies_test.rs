mod common;

use serde_json::Value;

// GET /api/currencies requires merchant auth
#[tokio::test]
async fn currencies_requires_auth() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/api/currencies")).send().await.unwrap();
    assert_eq!(res.status(), 401);
}

// GET /api/currencies -> rows ordered id ASC (Currency.all() desc, then toReversed)
#[tokio::test]
async fn currencies_lists_ascending() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "cur@example.com", "secret123").await;
    common::seed_currency(&app.db, "USD", "US Dollar").await; // id 1
    common::seed_currency(&app.db, "EUR", "Euro").await; // id 2

    let res = app
        .client
        .get(app.url("/api/currencies"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["code"], "USD"); // id 1 first (ascending)
    assert_eq!(arr[1]["code"], "EUR");
    // camelCase serialization sanity
    assert!(arr[0].get("createdAt").is_some());
    assert_eq!(arr[0]["type"], "fiat");
}
