mod common;

use axum::{routing::{get, post}, Json, Router};
use serde_json::{json, Value};

/// Spin a tiny mock Google OAuth server (token + userinfo). Returns its base URL.
async fn spawn_mock_google(email: &'static str) -> String {
    let app = Router::new()
        .route("/token", post(|| async { Json(json!({ "access_token": "mock-access-token", "token_type": "Bearer" })) }))
        .route("/userinfo", get(move || async move {
            Json(json!({ "email": email, "name": "Mock User", "picture": "https://img.test/a.png" }))
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    format!("http://{addr}")
}

#[tokio::test]
async fn google_redirect_url() {
    let app = common::spawn_with_config(|c| {
        c.google.client_id = "client-123".into();
        c.google.app_url = "https://api.kasway.test".into();
    }, false).await;

    let res = app.client.get(app.url("/api/auth/google/redirect")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let url = res.text().await.unwrap();
    assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
    assert!(url.contains("client_id=client-123"));
    assert!(url.contains("response_type=code"));
    assert!(url.contains("redirect_uri=https%3A%2F%2Fapi.kasway.test%2Fauth%2Fgoogle%2Fcallback"));
    assert!(url.contains("scope=openid+email+profile"));
}

#[tokio::test]
async fn google_callback_access_denied() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/auth/google/callback?error=access_denied")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "You have cancelled the login process");
}

#[tokio::test]
async fn google_callback_missing_code() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/auth/google/callback")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "We are unable to verify the request. Please try again");
}

#[tokio::test]
async fn google_callback_happy_path_creates_user_and_redirects() {
    let mock = spawn_mock_google("oauthuser@example.com").await;
    let mock_token = format!("{mock}/token");
    let mock_userinfo = format!("{mock}/userinfo");
    let app = common::spawn_with_config(move |c| {
        c.google.client_id = "cid".into();
        c.google.client_secret = "secret".into();
        c.google.frontend_url = "https://app.kasway.test".into();
        c.google.token_url = mock_token;
        c.google.userinfo_url = mock_userinfo;
    }, false).await;

    // don't follow the redirect — inspect Location
    let no_redirect = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    let res = no_redirect.get(app.url("/auth/google/callback?code=abc123")).send().await.unwrap();
    assert_eq!(res.status(), 302);
    let loc = res.headers().get("location").unwrap().to_str().unwrap().to_string();
    assert!(loc.starts_with("https://app.kasway.test/auth/callback?token="), "loc={loc}");
    assert!(loc.contains("onboarded=false"));

    // user created
    let uid = common::merchant_user_id(&app.db, "oauthuser@example.com").await;
    assert!(uid > 0);
    let (name, avatar): (Option<String>, Option<String>) = sqlx::query_as("SELECT full_name, avatar_url FROM users WHERE id = ?")
        .bind(uid).fetch_one(&app.db.pool).await.unwrap();
    assert_eq!(name.as_deref(), Some("Mock User"));
    assert_eq!(avatar.as_deref(), Some("https://img.test/a.png"));

    // second login with same email reuses the user (firstOrCreate)
    let res2 = no_redirect.get(app.url("/auth/google/callback?code=def456")).send().await.unwrap();
    assert_eq!(res2.status(), 302);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = ?")
        .bind("oauthuser@example.com").fetch_one(&app.db.pool).await.unwrap();
    assert_eq!(count, 1);

    let _ = json!({}); // keep serde_json import used
}
