mod common;

use serde_json::{json, Value};

// --- stores ---

#[tokio::test]
async fn stores_index_requires_auth() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/api/stores")).send().await.unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn stores_index_lazily_creates_default() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "st1@example.com", "secret123").await;

    let res = app.client.get(app.url("/api/stores")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["isDefault"], true);
    assert_eq!(arr[0]["isIncluded"], true);
    assert_eq!(arr[0]["slug"], "default");
}

#[tokio::test]
async fn stores_create_disabled_non_default() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "st2@example.com", "secret123").await;

    let res = app
        .client
        .post(app.url("/api/stores"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Second", "slug": "second" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["name"], "Second");
    assert_eq!(body["slug"], "second");
    assert_eq!(body["status"], "disabled");
    assert_eq!(body["isDefault"], false);
    assert_eq!(body["isIncluded"], false);
    assert_eq!(body["metadata"]["entitlementRequired"], true);
    assert!(body["publicId"].as_str().unwrap().starts_with("store_"));
}

#[tokio::test]
async fn stores_create_duplicate_slug_422() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "st3@example.com", "secret123").await;
    app.client.post(app.url("/api/stores")).bearer_auth(&token).json(&json!({ "name": "A", "slug": "shop" })).send().await.unwrap();

    let res = app
        .client
        .post(app.url("/api/stores"))
        .bearer_auth(&token)
        .json(&json!({ "name": "B", "slug": "shop" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "Store slug has already been used");
}

#[tokio::test]
async fn stores_create_bad_slug_validation() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "st4@example.com", "secret123").await;
    let res = app
        .client
        .post(app.url("/api/stores"))
        .bearer_auth(&token)
        .json(&json!({ "name": "X", "slug": "Bad Slug!" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    assert_eq!(res.json::<Value>().await.unwrap()["errors"][0]["field"], "slug");
}

#[tokio::test]
async fn stores_show_update_and_missing() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "st5@example.com", "secret123").await;
    let created: Value = app.client.post(app.url("/api/stores")).bearer_auth(&token).json(&json!({ "name": "Orig" })).send().await.unwrap().json().await.unwrap();
    let id = created["id"].as_i64().unwrap();

    let updated: Value = app
        .client
        .put(app.url(&format!("/api/stores/{id}")))
        .bearer_auth(&token)
        .json(&json!({ "name": "Renamed" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated["name"], "Renamed");

    let missing = app.client.get(app.url("/api/stores/99999")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(missing.status(), 404);
    assert_eq!(missing.json::<Value>().await.unwrap()["message"], "Store not found");
}

#[tokio::test]
async fn stores_set_default_on_paid_store_402() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "st6@example.com", "secret123").await;
    let created: Value = app.client.post(app.url("/api/stores")).bearer_auth(&token).json(&json!({ "name": "Paid" })).send().await.unwrap().json().await.unwrap();
    let id = created["id"].as_i64().unwrap();

    // not entitled -> 402
    let res = app.client.post(app.url(&format!("/api/stores/{id}/default"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(res.status(), 402);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "Active store entitlement is required");
}

// --- default-store setup (/api/setup) ---

#[tokio::test]
async fn setup_index_null_then_store_then_get() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "se1@example.com", "secret123").await;

    // no setup yet -> null
    let res = app.client.get(app.url("/api/setup")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert!(res.json::<Value>().await.unwrap().is_null());

    // store it
    let stored: Value = app
        .client
        .post(app.url("/api/setup"))
        .bearer_auth(&token)
        .json(&json!({
            "kaspa": { "mainAddress": "kaspatest:merchantpayout00001" },
            "redirectUrl": "https://shop.test/done",
            "webhookUrl": "https://shop.test/hook"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(stored["kaspaMainAddress"], "kaspatest:merchantpayout00001");
    assert_eq!(stored["kaspaTaxEnabled"], false);
    assert_eq!(stored["redirectUrl"], "https://shop.test/done");

    // get again -> present
    let got: Value = app.client.get(app.url("/api/setup")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(got["kaspaMainAddress"], "kaspatest:merchantpayout00001");

    // user is now onboarded
    let onboarded: i64 = sqlx::query_scalar("SELECT onboarded FROM users WHERE email = $1")
        .bind("se1@example.com")
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    assert_eq!(onboarded, 1);
}

#[tokio::test]
async fn setup_store_missing_main_address_422() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "se2@example.com", "secret123").await;
    let res = app
        .client
        .post(app.url("/api/setup"))
        .bearer_auth(&token)
        .json(&json!({ "kaspa": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    assert_eq!(res.json::<Value>().await.unwrap()["errors"][0]["field"], "kaspa.mainAddress");
}

#[tokio::test]
async fn setup_tax_enabled_requires_valid_address() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "se3@example.com", "secret123").await;
    let res = app
        .client
        .post(app.url("/api/setup"))
        .bearer_auth(&token)
        .json(&json!({
            "kaspa": { "mainAddress": "kaspatest:merchantpayout00001", "taxEnabled": true }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "Kaspa tax address is required when tax is enabled");
}

#[tokio::test]
async fn setup_with_tax_and_split() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "se4@example.com", "secret123").await;
    let res = app
        .client
        .post(app.url("/api/setup"))
        .bearer_auth(&token)
        .json(&json!({
            "kaspa": {
                "mainAddress": "kaspatest:merchantpayout00001",
                "taxEnabled": true,
                "taxAddress": "kaspatest:taxaddress000001",
                "taxPercentage": 5,
                "splitEnabled": true,
                "splitAddresses": [
                    { "address": "kaspatest:partnerone00001", "identifier": "partner-1", "percentage": 10 }
                ]
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["kaspaTaxEnabled"], true);
    assert_eq!(body["kaspaTaxAddress"], "kaspatest:taxaddress000001");
    assert_eq!(body["kaspaTaxPercentage"], "5");
    assert_eq!(body["kaspaSplitEnabled"], true);
    assert_eq!(body["kaspaSplitAddresses"][0]["identifier"], "partner-1");
    assert_eq!(body["kaspaSplitAddresses"][0]["percentage"], 10.0);
}

#[tokio::test]
async fn setup_update_requires_existing() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "se5@example.com", "secret123").await;
    let res = app
        .client
        .put(app.url("/api/setup"))
        .bearer_auth(&token)
        .json(&json!({ "redirectUrl": "https://x.test" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "Setup not found");
}

// --- per-store setup + clone/copy ---

#[tokio::test]
async fn store_setup_clone_copies_from_source() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "se6@example.com", "secret123").await;

    // default store id 1 (lazy). Configure its setup.
    app.client
        .post(app.url("/api/setup"))
        .bearer_auth(&token)
        .json(&json!({ "kaspa": { "mainAddress": "kaspatest:sourcepayout0001" }, "redirectUrl": "https://src.test/r" }))
        .send()
        .await
        .unwrap();
    let default_id: i64 = sqlx::query_scalar("SELECT id FROM stores WHERE user_id = (SELECT id FROM users WHERE email = $1) AND is_default = 1")
        .bind("se6@example.com")
        .fetch_one(&app.db.pool)
        .await
        .unwrap();

    // a second store
    let target: Value = app.client.post(app.url("/api/stores")).bearer_auth(&token).json(&json!({ "name": "Target" })).send().await.unwrap().json().await.unwrap();
    let target_id = target["id"].as_i64().unwrap();

    // clone all sections from default into target
    let cloned: Value = app
        .client
        .post(app.url(&format!("/api/stores/{target_id}/setup/clone")))
        .bearer_auth(&token)
        .json(&json!({ "sourceStoreId": default_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cloned["storeId"], target_id);
    assert_eq!(cloned["kaspaMainAddress"], "kaspatest:sourcepayout0001");
    assert_eq!(cloned["redirectUrl"], "https://src.test/r");
}

#[tokio::test]
async fn store_setup_copy_only_selected_section() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "se7@example.com", "secret123").await;

    app.client
        .post(app.url("/api/setup"))
        .bearer_auth(&token)
        .json(&json!({ "kaspa": { "mainAddress": "kaspatest:sourcepayout0001" }, "redirectUrl": "https://src.test/r" }))
        .send()
        .await
        .unwrap();
    let default_id: i64 = sqlx::query_scalar("SELECT id FROM stores WHERE user_id = (SELECT id FROM users WHERE email = $1) AND is_default = 1")
        .bind("se7@example.com")
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    let target: Value = app.client.post(app.url("/api/stores")).bearer_auth(&token).json(&json!({ "name": "T" })).send().await.unwrap().json().await.unwrap();
    let target_id = target["id"].as_i64().unwrap();

    // copy only 'redirects' -> payout NOT copied
    let copied: Value = app
        .client
        .post(app.url(&format!("/api/stores/{target_id}/setup/copy")))
        .bearer_auth(&token)
        .json(&json!({ "sourceStoreId": default_id, "sections": ["redirects"] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(copied["redirectUrl"], "https://src.test/r");
    assert!(copied["kaspaMainAddress"].is_null(), "payout section not copied");
}

#[tokio::test]
async fn store_setup_copy_missing_source_setup_404() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "se8@example.com", "secret123").await;
    let default_id: i64 = {
        // trigger default store creation
        app.client.get(app.url("/api/stores")).bearer_auth(&token).send().await.unwrap();
        sqlx::query_scalar("SELECT id FROM stores WHERE user_id = (SELECT id FROM users WHERE email = $1) AND is_default = 1")
            .bind("se8@example.com").fetch_one(&app.db.pool).await.unwrap()
    };
    let target: Value = app.client.post(app.url("/api/stores")).bearer_auth(&token).json(&json!({ "name": "T" })).send().await.unwrap().json().await.unwrap();
    let target_id = target["id"].as_i64().unwrap();

    // default store has no setup configured -> source setup not found
    let res = app
        .client
        .post(app.url(&format!("/api/stores/{target_id}/setup/clone")))
        .bearer_auth(&token)
        .json(&json!({ "sourceStoreId": default_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "Source setup not found");
}
