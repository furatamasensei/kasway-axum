mod common;

use serde_json::{json, Value};

async fn merchant(app: &common::TestApp, email: &str) -> String {
    common::register_merchant(app, email, "secret123").await
}

// --- payments/networks (public) ---

#[tokio::test]
async fn networks_public_list_and_assets() {
    let app = common::spawn_app().await;
    // public, no auth
    let nets: Value = app.client.get(app.url("/api/payments/networks")).send().await.unwrap().json().await.unwrap();
    let arr = nets.as_array().unwrap();
    assert_eq!(arr[0]["network"], "tn10");
    assert_eq!(arr[0]["assets"][0]["assetId"], "KAS");

    let assets: Value = app.client.get(app.url("/api/payments/networks/tn10/assets")).send().await.unwrap().json().await.unwrap();
    assert_eq!(assets["network"], "tn10");

    let unknown = app.client.get(app.url("/api/payments/networks/eth/assets")).send().await.unwrap();
    assert_eq!(unknown.status(), 404);
    assert_eq!(unknown.json::<Value>().await.unwrap()["message"], "Unknown payment network: eth");
}

// --- subscription plans ---

#[tokio::test]
async fn subscription_plans_crud() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "sp1@example.com").await;

    let created = app
        .client
        .post(app.url("/api/commerce/subscription-plans"))
        .bearer_auth(&token)
        .json(&json!({ "name": "Pro", "amount": "5000", "intervalUnit": "month", "intervalCount": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let plan: Value = created.json().await.unwrap();
    assert_eq!(plan["name"], "Pro");
    assert_eq!(plan["amount"], "5000");
    assert_eq!(plan["status"], "active");
    assert_eq!(plan["intervalUnit"], "month");
    assert_eq!(plan["paymentAsset"], "KAS");
    assert!(plan["publicId"].as_str().unwrap().starts_with("plan_"));
    let pid = plan["publicId"].as_str().unwrap().to_string();

    // index
    let list: Value = app.client.get(app.url("/api/commerce/subscription-plans")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(list["meta"]["total"], 1);

    // show
    let shown: Value = app.client.get(app.url(&format!("/api/commerce/subscription-plans/{pid}"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(shown["publicId"], pid);

    // update
    let updated: Value = app.client.put(app.url(&format!("/api/commerce/subscription-plans/{pid}"))).bearer_auth(&token).json(&json!({ "name": "Pro Plus", "amount": "6000" })).send().await.unwrap().json().await.unwrap();
    assert_eq!(updated["name"], "Pro Plus");
    assert_eq!(updated["amount"], "6000");

    // archive -> archived; then update rejected
    let archived: Value = app.client.post(app.url(&format!("/api/commerce/subscription-plans/{pid}/archive"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(archived["status"], "archived");
    let upd_archived = app.client.put(app.url(&format!("/api/commerce/subscription-plans/{pid}"))).bearer_auth(&token).json(&json!({ "name": "Nope" })).send().await.unwrap();
    assert_eq!(upd_archived.status(), 422);
    assert_eq!(upd_archived.json::<Value>().await.unwrap()["message"], "Archived subscription plans cannot be updated");
}

#[tokio::test]
async fn subscription_plan_validation_and_404() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "sp2@example.com").await;

    let bad = app.client.post(app.url("/api/commerce/subscription-plans")).bearer_auth(&token).json(&json!({ "amount": "abc", "intervalCount": 1 })).send().await.unwrap();
    assert_eq!(bad.status(), 422);
    let bad_body: Value = bad.json().await.unwrap();
    let fields: Vec<&str> = bad_body["errors"].as_array().unwrap().iter().map(|e| e["field"].as_str().unwrap()).collect();
    assert!(fields.contains(&"name"));
    assert!(fields.contains(&"amount"));
    assert!(fields.contains(&"intervalUnit"));

    let missing = app.client.get(app.url("/api/commerce/subscription-plans/plan_missing")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(missing.status(), 404);
    assert_eq!(missing.json::<Value>().await.unwrap()["message"], "Subscription plan not found");
}

#[tokio::test]
async fn subscription_plan_duplicate_external_id() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "sp3@example.com").await;
    app.client.post(app.url("/api/commerce/subscription-plans")).bearer_auth(&token).json(&json!({ "name": "A", "amount": "100", "intervalUnit": "month", "intervalCount": 1, "externalId": "ext-1" })).send().await.unwrap();
    let dup = app.client.post(app.url("/api/commerce/subscription-plans")).bearer_auth(&token).json(&json!({ "name": "B", "amount": "200", "intervalUnit": "month", "intervalCount": 1, "externalId": "ext-1" })).send().await.unwrap();
    assert_eq!(dup.status(), 422);
    assert_eq!(dup.json::<Value>().await.unwrap()["message"], "External id has already been used");
}

// --- subscription customers ---

#[tokio::test]
async fn subscription_customers_crud() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "sc1@example.com").await;

    let created = app.client.post(app.url("/api/commerce/subscription-customers")).bearer_auth(&token).json(&json!({ "email": "c@x.com", "name": "Cust" })).send().await.unwrap();
    assert_eq!(created.status(), 201);
    let cust: Value = created.json().await.unwrap();
    assert_eq!(cust["email"], "c@x.com");
    assert!(cust["publicId"].as_str().unwrap().starts_with("cus_"));
    let cid = cust["publicId"].as_str().unwrap().to_string();

    let list: Value = app.client.get(app.url("/api/commerce/subscription-customers")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(list["meta"]["total"], 1);

    let shown: Value = app.client.get(app.url(&format!("/api/commerce/subscription-customers/{cid}"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(shown["publicId"], cid);

    let updated: Value = app.client.put(app.url(&format!("/api/commerce/subscription-customers/{cid}"))).bearer_auth(&token).json(&json!({ "name": "Renamed" })).send().await.unwrap().json().await.unwrap();
    assert_eq!(updated["name"], "Renamed");

    let missing = app.client.get(app.url("/api/commerce/subscription-customers/cus_missing")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(missing.status(), 404);
    assert_eq!(missing.json::<Value>().await.unwrap()["message"], "Subscription customer not found");
}
