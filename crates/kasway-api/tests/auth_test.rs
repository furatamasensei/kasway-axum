mod common;

use serde_json::{json, Value};

// POST /api/auth/register -> { success: true, token }
#[tokio::test]
async fn register_creates_user_and_returns_token() {
    let app = common::spawn_app().await;

    let res = app
        .client
        .post(app.url("/api/auth/register"))
        .json(&json!({ "fullName": "Ada", "email": "ada@example.com", "password": "secret123" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert!(body["token"].as_str().unwrap().starts_with("oat_"));
}

// register validation: missing fields -> 422 { errors: [...] } in field order
#[tokio::test]
async fn register_validation_errors() {
    let app = common::spawn_app().await;

    let res = app
        .client
        .post(app.url("/api/auth/register"))
        .json(&json!({ "email": "not-an-email" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
    let body: Value = res.json().await.unwrap();
    let errors = body["errors"].as_array().unwrap();
    // fullName required, email invalid, password required
    let fields: Vec<&str> = errors.iter().map(|e| e["field"].as_str().unwrap()).collect();
    assert_eq!(fields, vec!["fullName", "email", "password"]);
    assert_eq!(errors[1]["rule"], "email");
}

// register duplicate email -> 422 database.unique
#[tokio::test]
async fn register_duplicate_email() {
    let app = common::spawn_app().await;
    common::register_merchant(&app, "dup@example.com", "secret123").await;

    let res = app
        .client
        .post(app.url("/api/auth/register"))
        .json(&json!({ "fullName": "Two", "email": "DUP@example.com", "password": "secret123" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["errors"][0]["rule"], "database.unique");
    assert_eq!(body["errors"][0]["field"], "email");
    assert_eq!(body["errors"][0]["message"], "The email has already been taken");
}

// login success -> { token, role: "merchant", onboarded: false }
#[tokio::test]
async fn login_success() {
    let app = common::spawn_app().await;
    common::register_merchant(&app, "login@example.com", "secret123").await;

    let res = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&json!({ "email": "login@example.com", "password": "secret123" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert!(body["token"].as_str().unwrap().starts_with("oat_"));
    assert_eq!(body["role"], "merchant");
    assert_eq!(body["onboarded"], false);
}

// login wrong password -> 401 { message: "Invalid credentials" }
#[tokio::test]
async fn login_wrong_password() {
    let app = common::spawn_app().await;
    common::register_merchant(&app, "wp@example.com", "secret123").await;

    let res = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&json!({ "email": "wp@example.com", "password": "wrong" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 401);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["message"], "Invalid credentials");
}

// login unknown email -> 401 Invalid credentials
#[tokio::test]
async fn login_unknown_email() {
    let app = common::spawn_app().await;

    let res = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&json!({ "email": "nobody@example.com", "password": "secret123" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 401);
    assert_eq!(
        res.json::<Value>().await.unwrap()["message"],
        "Invalid credentials"
    );
}

// profile with valid token -> user (camelCase, no password)
#[tokio::test]
async fn profile_returns_user() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "me@example.com", "secret123").await;

    let res = app
        .client
        .get(app.url("/api/auth/profile"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["email"], "me@example.com");
    assert_eq!(body["fullName"], "Test User");
    assert_eq!(body["onboarded"], false);
    assert!(body.get("password").is_none(), "password must not be serialized");
}

// profile without token -> 401 Unauthorized access
#[tokio::test]
async fn profile_requires_auth() {
    let app = common::spawn_app().await;

    let res = app
        .client
        .get(app.url("/api/auth/profile"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 401);
    assert_eq!(
        res.json::<Value>().await.unwrap()["message"],
        "Unauthorized access"
    );
}

// logout deletes token -> { success: true }, then token no longer works
#[tokio::test]
async fn logout_invalidates_token() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "out@example.com", "secret123").await;

    let res = app
        .client
        .post(app.url("/api/auth/logout"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.json::<Value>().await.unwrap()["success"], true);

    // token is now invalid
    let res2 = app
        .client
        .get(app.url("/api/auth/profile"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res2.status(), 401);
}
