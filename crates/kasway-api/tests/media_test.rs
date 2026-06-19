mod common;

use reqwest::multipart::{Form, Part};
use serde_json::Value;

async fn merchant(app: &common::TestApp, email: &str) -> (String, i64) {
    let token = common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    (token, uid)
}

#[tokio::test]
async fn upload_image_creates_media() {
    let app = common::spawn_app().await;
    let (token, uid) = merchant(&app, "med1@example.com").await;

    let form = Form::new()
        .part("file", Part::bytes(b"fake-png-bytes".to_vec()).file_name("logo.PNG"))
        .text("width", "640")
        .text("height", "480");
    let res = app.client.post(app.url("/api/media")).bearer_auth(&token).multipart(form).send().await.unwrap();
    assert_eq!(res.status(), 201);
    let m: Value = res.json().await.unwrap();
    assert_eq!(m["userId"], uid);
    assert_eq!(m["mediaType"], "image");
    assert_eq!(m["status"], "uploaded");
    assert_eq!(m["size"], 14); // "fake-png-bytes"
    assert_eq!(m["width"], 640);
    assert_eq!(m["height"], 480);
    assert!(m["key"].as_str().unwrap().starts_with("media/images/"));
    assert!(m["key"].as_str().unwrap().ends_with(".png"));
}

#[tokio::test]
async fn upload_video_and_delete() {
    let app = common::spawn_app().await;
    let (token, _uid) = merchant(&app, "med2@example.com").await;

    let form = Form::new().part("file", Part::bytes(b"vid".to_vec()).file_name("clip.mp4")).text("duration", "12");
    let res = app.client.post(app.url("/api/media")).bearer_auth(&token).multipart(form).send().await.unwrap();
    assert_eq!(res.status(), 201);
    let m: Value = res.json().await.unwrap();
    assert_eq!(m["mediaType"], "video");
    assert_eq!(m["duration"], 12);
    assert!(m["key"].as_str().unwrap().starts_with("media/videos/"));
    let id = m["id"].as_i64().unwrap();

    let del = app.client.delete(app.url(&format!("/api/media/{id}"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(del.status(), 204);

    // deleting again -> 404
    let again = app.client.delete(app.url(&format!("/api/media/{id}"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(again.status(), 404);
    assert_eq!(again.json::<Value>().await.unwrap()["message"], "Media not found");
}

#[tokio::test]
async fn unsupported_extension_rejected() {
    let app = common::spawn_app().await;
    let (token, _uid) = merchant(&app, "med3@example.com").await;
    let form = Form::new().part("file", Part::bytes(b"data".to_vec()).file_name("doc.txt"));
    let res = app.client.post(app.url("/api/media")).bearer_auth(&token).multipart(form).send().await.unwrap();
    assert_eq!(res.status(), 422);
    assert_eq!(res.json::<Value>().await.unwrap()["errors"][0]["field"], "file");
}

#[tokio::test]
async fn cannot_delete_other_merchants_media() {
    let app = common::spawn_app().await;
    let (token_a, _a) = merchant(&app, "meda@example.com").await;
    let (token_b, _b) = merchant(&app, "medb@example.com").await;
    let form = Form::new().part("file", Part::bytes(b"x".to_vec()).file_name("a.jpg"));
    let m: Value = app.client.post(app.url("/api/media")).bearer_auth(&token_a).multipart(form).send().await.unwrap().json().await.unwrap();
    let id = m["id"].as_i64().unwrap();
    // merchant B cannot delete A's media
    let del = app.client.delete(app.url(&format!("/api/media/{id}"))).bearer_auth(&token_b).send().await.unwrap();
    assert_eq!(del.status(), 404);
}

#[tokio::test]
async fn media_requires_auth() {
    let app = common::spawn_app().await;
    let form = Form::new().part("file", Part::bytes(b"x".to_vec()).file_name("a.jpg"));
    assert_eq!(app.client.post(app.url("/api/media")).multipart(form).send().await.unwrap().status(), 401);
}
