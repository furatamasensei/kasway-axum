mod common;

use serde_json::{json, Value};

/// Register a merchant, seed default store + payout setup, return (token, email).
async fn merchant_with_setup(app: &common::TestApp, email: &str) -> String {
    let token = common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    let store = common::seed_default_store(&app.db, uid).await;
    common::seed_setup(&app.db, uid, store, "kaspatest:merchantpayout00001").await;
    token
}

async fn create_invoice(app: &common::TestApp, token: &str) -> Value {
    app.client
        .post(app.url("/api/invoices"))
        .bearer_auth(token)
        .json(&json!({ "items": [{ "name": "Widget", "quantity": 1, "unitAmount": "1000" }] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

// --- commerce ---

#[tokio::test]
async fn commerce_store_returns_kpr1_contract() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "com1@example.com").await;

    let res = app
        .client
        .post(app.url("/api/commerce/invoices"))
        .bearer_auth(&token)
        .json(&json!({ "items": [{ "name": "Widget", "quantity": 1, "unitAmount": "1000" }] }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["status"], "open");
    assert_eq!(body["paymentRail"], "kpr1_covenant");
    assert!(body.get("paymentAddress").is_none(), "contract drops paymentAddress");
    assert!(body["kpr1PaymentIntent"]["intentId"].as_str().unwrap().starts_with("kpr1_"));
}

#[tokio::test]
async fn commerce_show_roundtrip_and_missing() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "com2@example.com").await;
    let created = create_invoice(&app, &token).await;
    let public_id = created["publicId"].as_str().unwrap();

    let res = app
        .client
        .get(app.url(&format!("/api/commerce/invoices/{public_id}")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["publicId"], public_id);
    assert!(body.get("paymentAddress").is_none());

    let missing = app
        .client
        .get(app.url("/api/commerce/invoices/inv_does_not_exist"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    assert_eq!(missing.json::<Value>().await.unwrap()["message"], "Invoice not found");
}

// --- checkout (public, no auth) ---

#[tokio::test]
async fn checkout_show_returns_status_and_state() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "chk1@example.com").await;
    let created = create_invoice(&app, &token).await;
    let public_id = created["publicId"].as_str().unwrap();

    // public: no auth header
    let res = app
        .client
        .get(app.url(&format!("/api/checkout/invoices/{public_id}")))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["status"], "open");
    assert!(body.get("paymentAddress").is_none());
    // payment status baseline
    assert_eq!(body["paymentStatus"]["status"]["paymentState"], "awaiting_payment");
    assert_eq!(body["paymentStatus"]["totals"]["invoice"], "1000");
    assert_eq!(body["paymentStatus"]["totals"]["remaining"], "1000");
    assert_eq!(body["paymentStatus"]["finality"]["confirmationsRequired"], 10);
    // checkout state
    assert_eq!(body["checkoutState"]["state"], "awaiting_payment");
    assert_eq!(body["checkoutState"]["nextAction"], "open_kpr1_wallet");
    assert_eq!(body["checkoutState"]["isTerminal"], false);
}

#[tokio::test]
async fn checkout_show_missing_404() {
    let app = common::spawn_app().await;
    let res = app
        .client
        .get(app.url("/api/checkout/invoices/inv_missing"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "Invoice not found");
}

#[tokio::test]
async fn checkout_kpr1_intent_returns_canonical_and_marks_fetched() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "chk2@example.com").await;
    let created = create_invoice(&app, &token).await;
    let public_id = created["publicId"].as_str().unwrap();

    let res = app
        .client
        .get(app.url(&format!("/api/checkout/invoices/{public_id}/kpr1-intent")))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let intent: Value = res.json().await.unwrap();
    // canonical signed intent shape
    assert_eq!(intent["version"], "kpr-1");
    assert!(intent["intentId"].as_str().unwrap().starts_with("kpr1_"));
    assert_eq!(intent["signature"]["alg"], "ed25519");
    assert!(intent["outputs"].is_array());

    // status transitioned created -> fetched
    let status: String = sqlx::query_scalar(
        "SELECT status FROM kpr1_payment_intents WHERE intent_id = ?",
    )
    .bind(intent["intentId"].as_str().unwrap())
    .fetch_one(&app.db.pool)
    .await
    .unwrap();
    assert_eq!(status, "fetched");
}

#[tokio::test]
async fn checkout_kpr1_intent_missing_422() {
    let app = common::spawn_app().await;
    let res = app
        .client
        .get(app.url("/api/checkout/invoices/inv_missing/kpr1-intent"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], "KPR1_INTENT_NOT_FOUND");
    assert_eq!(body["message"], "KPR-1 payment intent not found");
}

#[tokio::test]
async fn checkout_kpr1_intent_not_open_422() {
    let app = common::spawn_app().await;
    let token = merchant_with_setup(&app, "chk3@example.com").await;
    let created = create_invoice(&app, &token).await;
    let id = created["id"].as_i64().unwrap();
    let public_id = created["publicId"].as_str().unwrap().to_string();

    // cancel it
    app.client
        .post(app.url(&format!("/api/invoices/{id}/cancel")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    let res = app
        .client
        .get(app.url(&format!("/api/checkout/invoices/{public_id}/kpr1-intent")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["code"], "KPR1_INVOICE_NOT_OPEN");
}
