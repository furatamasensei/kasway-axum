mod common;

use serde_json::{json, Value};

async fn merchant_with_setup(app: &common::TestApp, email: &str) -> String {
    let token = common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    let store = common::seed_default_store(&app.db, uid).await;
    common::seed_setup(&app.db, uid, store, "kaspatest:merchantpayout00001").await;
    token
}

async fn create_plan(app: &common::TestApp, token: &str) -> String {
    let p: Value = app.client.post(app.url("/api/commerce/subscription-plans")).bearer_auth(token)
        .json(&json!({ "name": "Monthly", "amount": "500000000", "intervalUnit": "month", "intervalCount": 1 }))
        .send().await.unwrap().json().await.unwrap();
    p["publicId"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn subscription_create_spawns_first_invoice() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "su1@example.com").await;
    let plan = create_plan(&app, &token).await;

    let res = app
        .client
        .post(app.url("/api/commerce/subscriptions"))
        .bearer_auth(&token)
        .json(&json!({ "planPublicId": plan, "customer": { "email": "buyer@x.com", "name": "Buyer" } }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let sub: Value = res.json().await.unwrap();
    assert_eq!(sub["status"], "active");
    assert_eq!(sub["paymentMode"], "recurring_invoice");
    assert!(sub["publicId"].as_str().unwrap().starts_with("sub_"));
    assert_eq!(sub["planSnapshot"]["amount"], "500000000");
    assert_eq!(sub["customer"]["email"], "buyer@x.com");
    assert_eq!(sub["plan"]["publicId"], plan);
    let cycles = sub["cycles"].as_array().unwrap();
    assert_eq!(cycles.len(), 1);
    assert_eq!(cycles[0]["status"], "invoiced");
    assert_eq!(cycles[0]["invoice"]["paymentRail"], "kpr1_covenant");
    assert_eq!(cycles[0]["invoice"]["subtotalAmount"], "500000000");
}

#[tokio::test]
async fn subscription_validation_and_archived_plan() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "su2@example.com").await;

    let bad = app.client.post(app.url("/api/commerce/subscriptions")).bearer_auth(&token).json(&json!({ "customer": { "email": "a@x.com" } })).send().await.unwrap();
    assert_eq!(bad.status(), 422);
    assert_eq!(bad.json::<Value>().await.unwrap()["errors"][0]["field"], "planPublicId");

    let plan = create_plan(&app, &token).await;
    let wa = app.client.post(app.url("/api/commerce/subscriptions")).bearer_auth(&token).json(&json!({ "planPublicId": plan, "paymentMode": "wallet_autopay", "customer": { "email": "a@x.com" } })).send().await.unwrap();
    assert_eq!(wa.status(), 422);
    assert_eq!(wa.json::<Value>().await.unwrap()["message"], "wallet_autopay is not supported yet");

    let nc = app.client.post(app.url("/api/commerce/subscriptions")).bearer_auth(&token).json(&json!({ "planPublicId": plan })).send().await.unwrap();
    assert_eq!(nc.status(), 422);
    assert_eq!(nc.json::<Value>().await.unwrap()["message"], "A subscription customer is required");

    app.client.post(app.url(&format!("/api/commerce/subscription-plans/{plan}/archive"))).bearer_auth(&token).send().await.unwrap();
    let arch = app.client.post(app.url("/api/commerce/subscriptions")).bearer_auth(&token).json(&json!({ "planPublicId": plan, "customer": { "email": "a@x.com" } })).send().await.unwrap();
    assert_eq!(arch.status(), 422);
    assert_eq!(arch.json::<Value>().await.unwrap()["message"], "Subscription plan is archived");
}

#[tokio::test]
async fn subscription_lifecycle_pause_resume_cancel() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "su3@example.com").await;
    let plan = create_plan(&app, &token).await;
    let sub: Value = app.client.post(app.url("/api/commerce/subscriptions")).bearer_auth(&token).json(&json!({ "planPublicId": plan, "customer": { "email": "a@x.com" } })).send().await.unwrap().json().await.unwrap();
    let sid = sub["publicId"].as_str().unwrap().to_string();

    let paused: Value = app.client.post(app.url(&format!("/api/commerce/subscriptions/{sid}/pause"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(paused["status"], "paused");
    assert!(!paused["pausedAt"].is_null());

    let resumed: Value = app.client.post(app.url(&format!("/api/commerce/subscriptions/{sid}/resume"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(resumed["status"], "active");

    let cancel: Value = app.client.post(app.url(&format!("/api/commerce/subscriptions/{sid}/cancel"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(cancel["status"], "cancelled");

    let pc = app.client.post(app.url(&format!("/api/commerce/subscriptions/{sid}/pause"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(pc.status(), 422);
    assert_eq!(pc.json::<Value>().await.unwrap()["message"], "Cancelled subscriptions cannot be paused");
}

#[tokio::test]
async fn subscription_invoices_list_and_retry_guard() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "su4@example.com").await;
    let plan = create_plan(&app, &token).await;
    let sub: Value = app.client.post(app.url("/api/commerce/subscriptions")).bearer_auth(&token).json(&json!({ "planPublicId": plan, "customer": { "email": "a@x.com" } })).send().await.unwrap().json().await.unwrap();
    let sid = sub["publicId"].as_str().unwrap().to_string();

    let invs: Value = app.client.get(app.url(&format!("/api/commerce/subscriptions/{sid}/invoices"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(invs["meta"]["total"], 1);
    assert_eq!(invs["data"][0]["subscriptionId"], sub["id"]);

    let retry = app.client.post(app.url(&format!("/api/commerce/subscriptions/{sid}/invoices/retry"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(retry.status(), 422);
    assert_eq!(retry.json::<Value>().await.unwrap()["message"], "Subscription does not have a past due cycle to retry");

    let missing = app.client.get(app.url("/api/commerce/subscriptions/sub_missing")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(missing.status(), 404);
    assert_eq!(missing.json::<Value>().await.unwrap()["message"], "Subscription not found");
}

#[tokio::test]
async fn subscription_future_start_no_invoice() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "su5@example.com").await;
    let plan = create_plan(&app, &token).await;
    let sub: Value = app.client.post(app.url("/api/commerce/subscriptions")).bearer_auth(&token).json(&json!({ "planPublicId": plan, "startsAt": "2099-01-01T00:00:00.000+00:00", "customer": { "email": "a@x.com" } })).send().await.unwrap().json().await.unwrap();
    assert_eq!(sub["cycles"].as_array().unwrap().len(), 0);
    assert_eq!(sub["nextBillingAt"], "2099-01-01T00:00:00.000+00:00");
}
