mod common;

use serde_json::{json, Value};

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

#[tokio::test]
async fn docs_html_served() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/docs")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert!(res.headers().get("content-type").unwrap().to_str().unwrap().starts_with("text/html"));
    let body = res.text().await.unwrap();
    assert!(body.contains("Kasway Documentation"));
    assert!(body.starts_with("<!doctype html>"));
}

fn valid_report() -> Value {
    json!({
        "token": "test-token",
        "summary": "Checkout button broken",
        "description": "The pay button does nothing when clicked on mobile Safari.",
        "category": "checkout"
    })
}

#[tokio::test]
async fn bug_report_created() {
    let app = common::spawn_app().await;
    let res = app.client.post(app.url("/api/bug-reports")).json(&valid_report()).send().await.unwrap();
    assert_eq!(res.status(), 201);
    let b: Value = res.json().await.unwrap();
    assert!(b["publicId"].as_str().unwrap().starts_with("bug_"));
    assert_eq!(b["status"], "new");
    assert!(b["message"].as_str().unwrap().contains("Bug report received"));
}

#[tokio::test]
async fn bug_report_honeypot_marks_spam_and_attachment_note() {
    let app = common::spawn_app().await;
    let mut body = valid_report();
    body["website"] = json!("http://spammer.test");
    body["attachments"] = json!(["file1.png"]);
    let res = app.client.post(app.url("/api/bug-reports")).json(&body).send().await.unwrap();
    assert_eq!(res.status(), 201);
    let b: Value = res.json().await.unwrap();
    assert_eq!(b["status"], "spam");
    assert!(b["message"].as_str().unwrap().contains("file attachments aren't supported"));
}

#[tokio::test]
async fn bug_report_validation() {
    let app = common::spawn_app().await;
    // short summary
    let mut s = valid_report();
    s["summary"] = json!("short");
    let r1 = app.client.post(app.url("/api/bug-reports")).json(&s).send().await.unwrap();
    assert_eq!(r1.status(), 422);
    assert_eq!(r1.json::<Value>().await.unwrap()["errors"][0]["field"], "summary");

    // bad category
    let mut c = valid_report();
    c["category"] = json!("bogus");
    let r2 = app.client.post(app.url("/api/bug-reports")).json(&c).send().await.unwrap();
    assert_eq!(r2.status(), 422);
    assert_eq!(r2.json::<Value>().await.unwrap()["errors"][0]["field"], "category");
}
