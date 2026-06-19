mod common;

use serde_json::{json, Value};

// --- auth ---

#[tokio::test]
async fn api_keys_index_requires_auth() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/api/api-keys")).send().await.unwrap();
    assert_eq!(res.status(), 401);
}

// --- index pagination contract (Lucid paginator) ---

#[tokio::test]
async fn api_keys_index_empty_pagination_shape() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "ak1@example.com", "secret123").await;

    let res = app
        .client
        .get(app.url("/api/api-keys"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["data"], json!([]));
    let meta = &body["meta"];
    assert_eq!(meta["total"], 0);
    assert_eq!(meta["perPage"], 10);
    assert_eq!(meta["currentPage"], 1);
    assert_eq!(meta["lastPage"], 1);
    assert_eq!(meta["firstPage"], 1);
    assert_eq!(meta["nextPageUrl"], Value::Null);
    assert_eq!(meta["previousPageUrl"], Value::Null);
}

#[tokio::test]
async fn api_keys_index_orders_created_desc_and_paginates() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "ak2@example.com", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "ak2@example.com").await;
    common::seed_api_key(&app.db, uid, "older", "aaaaaa", r#"["payments:read"]"#, "2026-01-01T00:00:00.000+00:00").await;
    common::seed_api_key(&app.db, uid, "newer", "bbbbbb", r#"["payments:read"]"#, "2026-02-01T00:00:00.000+00:00").await;

    // page 1, perPage 1 -> newest first
    let res = app
        .client
        .get(app.url("/api/api-keys?page=1&perPage=1"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let data = body["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["name"], "newer");
    assert!(data[0].get("keyHash").is_none(), "keyHash must be hidden");
    let meta = &body["meta"];
    assert_eq!(meta["total"], 2);
    assert_eq!(meta["perPage"], 1);
    assert_eq!(meta["lastPage"], 2);
    assert_eq!(meta["nextPageUrl"], "/?page=2");
    assert_eq!(meta["previousPageUrl"], Value::Null);
}

// --- store ---

#[tokio::test]
async fn api_keys_store_creates_and_returns_plaintext_key() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "ak3@example.com", "secret123").await;

    let res = app
        .client
        .post(app.url("/api/api-keys"))
        .bearer_auth(&token)
        .json(&json!({ "name": "My key", "scopes": ["payments:read", "webhooks:manage"] }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 201);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["name"], "My key");
    assert_eq!(body["scopes"], json!(["payments:read", "webhooks:manage"]));
    assert_eq!(body["revokedAt"], Value::Null);
    assert_eq!(body["lastUsedAt"], Value::Null);
    let key = body["key"].as_str().unwrap();
    assert!(key.starts_with("ksw_"), "plaintext key returned");
    assert!(body.get("keyHash").is_none(), "keyHash must not be serialized");
    // prefix is the middle segment of the key
    let prefix = body["prefix"].as_str().unwrap();
    assert!(key.contains(&format!("_{prefix}_")));
}

#[tokio::test]
async fn api_keys_store_validation_required_fields() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "ak4@example.com", "secret123").await;

    let res = app
        .client
        .post(app.url("/api/api-keys"))
        .bearer_auth(&token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
    let body: Value = res.json().await.unwrap();
    let fields: Vec<&str> = body["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["field"].as_str().unwrap())
        .collect();
    assert_eq!(fields, vec!["name", "scopes"]);
    assert_eq!(body["errors"][0]["rule"], "required");
}

#[tokio::test]
async fn api_keys_store_validation_invalid_scope() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "ak5@example.com", "secret123").await;

    let res = app
        .client
        .post(app.url("/api/api-keys"))
        .bearer_auth(&token)
        .json(&json!({ "name": "k", "scopes": ["not-a-scope"] }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["errors"][0]["rule"], "enum");
    assert_eq!(body["errors"][0]["field"], "scopes.0");
}

// --- show ---

#[tokio::test]
async fn api_keys_show_own_missing_and_foreign() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "owner@example.com", "secret123").await;

    // create one
    let created: Value = app
        .client
        .post(app.url("/api/api-keys"))
        .bearer_auth(&token)
        .json(&json!({ "name": "k", "scopes": ["payments:read"] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_i64().unwrap();

    // own -> 200
    let res = app
        .client
        .get(app.url(&format!("/api/api-keys/{id}")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.json::<Value>().await.unwrap()["id"], id);

    // missing -> 404 Row not found
    let res = app
        .client
        .get(app.url("/api/api-keys/99999"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "Row not found");

    // foreign owner -> 403
    let other = common::register_merchant(&app, "other@example.com", "secret123").await;
    let res = app
        .client
        .get(app.url(&format!("/api/api-keys/{id}")))
        .bearer_auth(&other)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
}

// --- revoke ---

#[tokio::test]
async fn api_keys_revoke_sets_revoked_at() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "rev@example.com", "secret123").await;
    let created: Value = app
        .client
        .post(app.url("/api/api-keys"))
        .bearer_auth(&token)
        .json(&json!({ "name": "k", "scopes": ["payments:read"] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_i64().unwrap();

    let res = app
        .client
        .post(app.url(&format!("/api/api-keys/{id}/revoke")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["id"], id);
    assert!(!body["revokedAt"].is_null(), "revokedAt should be set");
}

// --- rotate ---

#[tokio::test]
async fn api_keys_rotate_issues_new_key() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "rot@example.com", "secret123").await;
    let created: Value = app
        .client
        .post(app.url("/api/api-keys"))
        .bearer_auth(&token)
        .json(&json!({ "name": "k", "scopes": ["payments:read"] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_i64().unwrap();
    let old_prefix = created["prefix"].as_str().unwrap().to_string();

    let res = app
        .client
        .post(app.url(&format!("/api/api-keys/{id}/rotate")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["id"], id);
    assert!(body["key"].as_str().unwrap().starts_with("ksw_"));
    assert_ne!(body["prefix"].as_str().unwrap(), old_prefix, "prefix rotated");
    assert_eq!(body["revokedAt"], Value::Null);
}
