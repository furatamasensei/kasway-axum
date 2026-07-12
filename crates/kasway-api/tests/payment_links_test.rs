mod common;

use serde_json::{json, Value};

async fn merchant_with_setup(app: &common::TestApp, email: &str) -> String {
    let token = common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    let store = common::seed_default_store(&app.db, uid).await;
    common::seed_setup(&app.db, uid, store, "kaspatest:merchantpayout00001").await;
    token
}

async fn create_link(app: &common::TestApp, token: &str, title: &str, amount: &str) -> Value {
    app.client
        .post(app.url("/api/payment-links"))
        .bearer_auth(token)
        .json(&json!({ "title": title, "amount": amount }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

// --- merchant CRUD ---

#[tokio::test]
async fn payment_links_index_requires_auth() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/api/payment-links")).send().await.unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn payment_links_store_creates_active_link() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "pl1@example.com").await;

    let res = app
        .client
        .post(app.url("/api/payment-links"))
        .bearer_auth(&token)
        .json(&json!({ "title": "Coffee", "amount": "5000" }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["status"], "active");
    assert_eq!(body["title"], "Coffee");
    assert_eq!(body["amount"], "5000");
    assert_eq!(body["paymentsCount"], 0);
    assert!(body["publicId"].as_str().unwrap().starts_with("plink_"));
}

#[tokio::test]
async fn payment_links_store_zero_amount_422() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "pl2@example.com").await;

    let res = app
        .client
        .post(app.url("/api/payment-links"))
        .bearer_auth(&token)
        .json(&json!({ "title": "Free", "amount": "0" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    assert_eq!(
        res.json::<Value>().await.unwrap()["message"],
        "Payment link amount must be greater than zero"
    );
}

#[tokio::test]
async fn payment_links_store_validation_missing_title() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "pl3@example.com").await;

    let res = app
        .client
        .post(app.url("/api/payment-links"))
        .bearer_auth(&token)
        .json(&json!({ "amount": "100" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["errors"][0]["field"], "title");
}

#[tokio::test]
async fn payment_links_show_and_missing() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "pl4@example.com").await;
    let link = create_link(&app, &token, "Item", "1000").await;
    let id = link["id"].as_i64().unwrap();

    let res = app
        .client
        .get(app.url(&format!("/api/payment-links/{id}")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.json::<Value>().await.unwrap()["id"], id);

    let missing = app
        .client
        .get(app.url("/api/payment-links/99999"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    assert_eq!(missing.json::<Value>().await.unwrap()["message"], "Payment link not found");
}

#[tokio::test]
async fn payment_links_disable_enable() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "pl5@example.com").await;
    let link = create_link(&app, &token, "Item", "1000").await;
    let id = link["id"].as_i64().unwrap();

    let disabled: Value = app
        .client
        .post(app.url(&format!("/api/payment-links/{id}/disable")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(disabled["status"], "disabled");

    let enabled: Value = app
        .client
        .post(app.url(&format!("/api/payment-links/{id}/enable")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(enabled["status"], "active");
}

#[tokio::test]
async fn payment_links_index_lists() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "pl6@example.com").await;
    create_link(&app, &token, "A", "100").await;
    create_link(&app, &token, "B", "200").await;

    let body: Value = app
        .client
        .get(app.url("/api/payment-links?perPage=1&page=1"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["meta"]["total"], 2);
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    assert_eq!(body["data"][0]["paymentsCount"], 0);
}

// --- public checkout-links ---

#[tokio::test]
async fn checkout_link_show_public_summary() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "pl7@example.com").await;
    let link = create_link(&app, &token, "Donate", "12345").await;
    let public_id = link["publicId"].as_str().unwrap();

    // public: no auth
    let res = app
        .client
        .get(app.url(&format!("/api/checkout/links/{public_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["publicId"], public_id);
    assert_eq!(body["title"], "Donate");
    assert_eq!(body["amount"], "12345");
    assert_eq!(body["status"], "active");
    assert_eq!(body["merchant"]["name"], "Test User");
    assert_eq!(body["merchant"]["verified"], true);
}

#[tokio::test]
async fn checkout_link_show_inactive_410_and_missing_404() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "pl8@example.com").await;
    let link = create_link(&app, &token, "X", "100").await;
    let id = link["id"].as_i64().unwrap();
    let public_id = link["publicId"].as_str().unwrap().to_string();

    app.client
        .post(app.url(&format!("/api/payment-links/{id}/disable")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    let res = app
        .client
        .get(app.url(&format!("/api/checkout/links/{public_id}")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 410);
    assert_eq!(
        res.json::<Value>().await.unwrap()["message"],
        "This payment link is no longer active"
    );

    let missing = app
        .client
        .get(app.url("/api/checkout/links/plink_missing"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
}

#[tokio::test]
async fn checkout_link_create_invoice_spawns_and_increments_count() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "pl9@example.com").await;
    // Settleable amount: a covenant release of this must clear the KIP-9
    // storage-mass cap (a tiny amount would be rejected by the minter guard).
    let link = create_link(&app, &token, "Subscription", "500000000").await;
    let id = link["id"].as_i64().unwrap();
    let public_id = link["publicId"].as_str().unwrap();

    // public: spawn an invoice
    let res = app
        .client
        .post(app.url(&format!("/api/checkout/links/{public_id}/invoices")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let inv: Value = res.json().await.unwrap();
    assert_eq!(inv["status"], "open");
    assert_eq!(inv["paymentRail"], "kpr1_covenant");
    assert_eq!(inv["paymentLinkId"], id);
    assert_eq!(inv["subtotalAmount"], "500000000");
    assert!(inv["kpr1PaymentIntent"]["intentId"].as_str().unwrap().starts_with("kpr1_"));
    // metadata carries the payment-link channel markers
    assert_eq!(inv["metadata"]["source"], "payment_link");
    assert_eq!(inv["metadata"]["paymentLinkPublicId"], public_id);
    // line item copied from the link title
    assert_eq!(inv["items"][0]["name"], "Subscription");

    // spawn a second one
    app.client
        .post(app.url(&format!("/api/checkout/links/{public_id}/invoices")))
        .send()
        .await
        .unwrap();

    // paymentsCount now 2
    let shown: Value = app
        .client
        .get(app.url(&format!("/api/payment-links/{id}")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(shown["paymentsCount"], 2);
}
