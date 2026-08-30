mod common;

use serde_json::{json, Value};

// --- regional pricing ---

#[tokio::test]
async fn regional_countries_lists_supported() {
    let app = common::spawn_app().await;
    let token = common::merchant(&app, "rp1@example.com").await;
    let body: Value = app.client.get(app.url("/api/regional-pricing/countries")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    let arr = body.as_array().unwrap();
    assert!(arr.len() >= 10);
    assert!(arr.iter().any(|c| c["code"] == "US"));
}

#[tokio::test]
async fn regional_settings_default_then_update() {
    let app = common::spawn_app().await;
    let token = common::merchant(&app, "rp2@example.com").await;

    // default settings (lazily created) -> fail_closed, no countries
    let def: Value = app.client.get(app.url("/api/regional-pricing/settings")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(def["fallbackPolicy"], "fail_closed");
    assert_eq!(def["countryCodes"], json!([]));

    // update
    let upd: Value = app
        .client
        .put(app.url("/api/regional-pricing/settings"))
        .bearer_auth(&token)
        .json(&json!({ "fallbackPolicy": "allow_default_price", "countryCodes": ["us", "GB"] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(upd["fallbackPolicy"], "allow_default_price");
    assert_eq!(upd["countryCodes"], json!(["GB", "US"])); // normalized + sorted
    assert!(upd["countries"].as_array().unwrap().iter().any(|c| c["code"] == "US" && c["name"] == "United States"));
}

#[tokio::test]
async fn regional_update_rejects_unsupported_and_duplicates() {
    let app = common::spawn_app().await;
    let token = common::merchant(&app, "rp3@example.com").await;

    let unsupported = app
        .client
        .put(app.url("/api/regional-pricing/settings"))
        .bearer_auth(&token)
        .json(&json!({ "fallbackPolicy": "fail_closed", "countryCodes": ["ZZ"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(unsupported.status(), 422);
    assert_eq!(unsupported.json::<Value>().await.unwrap()["message"], "Unsupported country code: ZZ");

    let dup = app
        .client
        .put(app.url("/api/regional-pricing/settings"))
        .bearer_auth(&token)
        .json(&json!({ "fallbackPolicy": "fail_closed", "countryCodes": ["US", "us"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(dup.status(), 422);
    assert_eq!(dup.json::<Value>().await.unwrap()["message"], "countryCodes must not contain duplicate countries");

    let bad_policy = app
        .client
        .put(app.url("/api/regional-pricing/settings"))
        .bearer_auth(&token)
        .json(&json!({ "fallbackPolicy": "nope" }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_policy.status(), 422);
    assert_eq!(bad_policy.json::<Value>().await.unwrap()["errors"][0]["field"], "fallbackPolicy");
}
