mod common;

use serde_json::{json, Value};

async fn merchant(app: &common::TestApp, email: &str) -> String {
    common::register_merchant(app, email, "secret123").await
}

async fn create_endpoint(app: &common::TestApp, token: &str, events: Value) -> Value {
    app.client
        .post(app.url("/api/webhook-endpoints"))
        .bearer_auth(token)
        .json(&json!({ "url": "https://hooks.test/wh", "events": events }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn endpoints_index_requires_auth() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/api/webhook-endpoints")).send().await.unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn endpoint_store_returns_signing_secret() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "wh1@example.com").await;

    let res = app
        .client
        .post(app.url("/api/webhook-endpoints"))
        .bearer_auth(&token)
        .json(&json!({ "url": "https://hooks.test/wh", "events": ["invoice.created", "invoice.paid"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["url"], "https://hooks.test/wh");
    assert_eq!(body["events"], json!(["invoice.created", "invoice.paid"]));
    assert_eq!(body["isActive"], true);
    assert!(body["signingSecret"].as_str().unwrap().starts_with("whsec_"));
}

#[tokio::test]
async fn endpoint_store_rejects_http_and_invalid_event() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "wh2@example.com").await;

    // plain http to a non-loopback host -> forbidden_protocol
    let http = app
        .client
        .post(app.url("/api/webhook-endpoints"))
        .bearer_auth(&token)
        .json(&json!({ "url": "http://example.com/wh", "events": ["invoice.created"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(http.status(), 422);
    let body: Value = http.json().await.unwrap();
    assert_eq!(body["errors"][0]["field"], "url");
    assert_eq!(body["errors"][0]["rule"], "forbidden_protocol");

    // invalid event type
    let bad = app
        .client
        .post(app.url("/api/webhook-endpoints"))
        .bearer_auth(&token)
        .json(&json!({ "url": "https://hooks.test/wh", "events": ["nope.event"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 422);
    assert_eq!(bad.json::<Value>().await.unwrap()["errors"][0]["field"], "events.0");
}

#[tokio::test]
async fn endpoint_show_update_destroy() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "wh3@example.com").await;
    let ep = create_endpoint(&app, &token, json!(["invoice.created"])).await;
    let id = ep["id"].as_i64().unwrap();

    let shown: Value = app.client.get(app.url(&format!("/api/webhook-endpoints/{id}"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(shown["id"], id);
    assert!(shown["deliveries"].is_array());
    assert!(shown.get("signingSecret").is_none(), "secret hidden on read");

    let updated: Value = app
        .client
        .put(app.url(&format!("/api/webhook-endpoints/{id}")))
        .bearer_auth(&token)
        .json(&json!({ "isActive": false, "events": ["invoice.paid"] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated["isActive"], false);
    assert_eq!(updated["events"], json!(["invoice.paid"]));

    let del = app.client.delete(app.url(&format!("/api/webhook-endpoints/{id}"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(del.status(), 204);
    let missing = app.client.get(app.url(&format!("/api/webhook-endpoints/{id}"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(missing.status(), 404);
}

#[tokio::test]
async fn endpoint_pause_resume_rotate() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "wh4@example.com").await;
    let ep = create_endpoint(&app, &token, json!(["invoice.created"])).await;
    let id = ep["id"].as_i64().unwrap();

    let paused: Value = app.client.post(app.url(&format!("/api/webhook-endpoints/{id}/pause"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert!(!paused["pausedAt"].is_null());

    let resumed: Value = app.client.post(app.url(&format!("/api/webhook-endpoints/{id}/resume"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert!(resumed["pausedAt"].is_null());

    let rotated: Value = app.client.post(app.url(&format!("/api/webhook-endpoints/{id}/rotate-secret"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert!(rotated["signingSecret"].as_str().unwrap().starts_with("whsec_"));
    assert!(!rotated["secretRotatedAt"].is_null());
}

#[tokio::test]
async fn endpoint_pause_foreign_403() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "wh5@example.com").await;
    let other = merchant(&app, "wh5b@example.com").await;
    let ep = create_endpoint(&app, &token, json!(["invoice.created"])).await;
    let id = ep["id"].as_i64().unwrap();

    let res = app.client.post(app.url(&format!("/api/webhook-endpoints/{id}/pause"))).bearer_auth(&other).send().await.unwrap();
    assert_eq!(res.status(), 403);
}

#[tokio::test]
async fn test_send_creates_event_and_delivery() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "wh6@example.com").await;
    let ep = create_endpoint(&app, &token, json!(["invoice.created"])).await;
    let id = ep["id"].as_i64().unwrap();

    // subscribed -> 202
    let res = app
        .client
        .post(app.url(&format!("/api/webhook-endpoints/{id}/test-send")))
        .bearer_auth(&token)
        .json(&json!({ "eventType": "invoice.created" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 202);
    let body: Value = res.json().await.unwrap();
    assert!(body["eventId"].is_number());
    assert!(body["deliveryId"].is_number());
    assert_eq!(body["eventType"], "invoice.created");

    // not subscribed -> 422
    let no = app
        .client
        .post(app.url(&format!("/api/webhook-endpoints/{id}/test-send")))
        .bearer_auth(&token)
        .json(&json!({ "eventType": "invoice.paid" }))
        .send()
        .await
        .unwrap();
    assert_eq!(no.status(), 422);
    assert_eq!(no.json::<Value>().await.unwrap()["errors"][0]["message"], "Endpoint is not subscribed to invoice.paid");
}

#[tokio::test]
async fn deliveries_and_events_listing_and_replay() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "wh7@example.com").await;
    let ep = create_endpoint(&app, &token, json!(["invoice.created"])).await;
    let id = ep["id"].as_i64().unwrap();

    // generate an event + delivery via test-send
    let ts: Value = app
        .client
        .post(app.url(&format!("/api/webhook-endpoints/{id}/test-send")))
        .bearer_auth(&token)
        .json(&json!({ "eventType": "invoice.created" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let delivery_id = ts["deliveryId"].as_i64().unwrap();
    let event_id = ts["eventId"].as_i64().unwrap();

    // deliveries index
    let dlist: Value = app.client.get(app.url("/api/webhook-deliveries")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(dlist["meta"]["total"], 1);
    assert_eq!(dlist["data"][0]["status"], "pending");
    assert_eq!(dlist["data"][0]["endpoint"]["id"], id);
    assert_eq!(dlist["data"][0]["event"]["id"], event_id);

    // delivery show
    let dshow: Value = app.client.get(app.url(&format!("/api/webhook-deliveries/{delivery_id}"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(dshow["id"], delivery_id);

    // delivery replay -> 202 new replay delivery
    let replay = app.client.post(app.url(&format!("/api/webhook-deliveries/{delivery_id}/replay"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(replay.status(), 202);
    assert_eq!(replay.json::<Value>().await.unwrap()["isReplay"], true);

    // events index includes the event with deliveries
    let elist: Value = app.client.get(app.url("/api/webhook-events")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(elist["meta"]["total"], 1);
    assert_eq!(elist["data"][0]["eventType"], "invoice.created");
    assert!(elist["data"][0]["deliveries"].as_array().unwrap().len() >= 1);

    // event show + replay (creates another delivery for the subscribed endpoint)
    let eshow: Value = app.client.get(app.url(&format!("/api/webhook-events/{event_id}"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(eshow["id"], event_id);

    let ereplay = app.client.post(app.url(&format!("/api/webhook-events/{event_id}/replay"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(ereplay.status(), 202);
}

#[tokio::test]
async fn delivery_show_foreign_404() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "wh8@example.com").await;
    let other = merchant(&app, "wh8b@example.com").await;
    let ep = create_endpoint(&app, &token, json!(["invoice.created"])).await;
    let id = ep["id"].as_i64().unwrap();
    let ts: Value = app.client.post(app.url(&format!("/api/webhook-endpoints/{id}/test-send"))).bearer_auth(&token).json(&json!({ "eventType": "invoice.created" })).send().await.unwrap().json().await.unwrap();
    let did = ts["deliveryId"].as_i64().unwrap();

    let res = app.client.get(app.url(&format!("/api/webhook-deliveries/{did}"))).bearer_auth(&other).send().await.unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test]
async fn event_show_foreign_403() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "wh9@example.com").await;
    let other = merchant(&app, "wh9b@example.com").await;
    let ep = create_endpoint(&app, &token, json!(["invoice.created"])).await;
    let id = ep["id"].as_i64().unwrap();
    let ts: Value = app.client.post(app.url(&format!("/api/webhook-endpoints/{id}/test-send"))).bearer_auth(&token).json(&json!({ "eventType": "invoice.created" })).send().await.unwrap().json().await.unwrap();
    let eid = ts["eventId"].as_i64().unwrap();

    // event_show uses id-only query then ownership -> 403 for foreign
    let res = app.client.get(app.url(&format!("/api/webhook-events/{eid}"))).bearer_auth(&other).send().await.unwrap();
    assert_eq!(res.status(), 403);
}
