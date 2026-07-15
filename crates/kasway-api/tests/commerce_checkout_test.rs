mod common;

use serde_json::{json, Value};

async fn create_invoice(app: &common::TestApp, token: &str) -> Value {
    app.client
        .post(app.url("/api/invoices"))
        .bearer_auth(token)
        .json(&json!({ "items": [{ "name": "Widget", "quantity": 1, "unitAmount": "500000000" }] }))
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
    let token = common::merchant_with_setup(&app, "com1@example.com").await;

    let res = app
        .client
        .post(app.url("/api/commerce/invoices"))
        .bearer_auth(&token)
        .json(&json!({ "items": [{ "name": "Widget", "quantity": 1, "unitAmount": "500000000" }] }))
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
    let token = common::merchant_with_setup(&app, "com2@example.com").await;
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
    let token = common::merchant_with_setup(&app, "chk1@example.com").await;
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
    assert_eq!(body["paymentStatus"]["totals"]["invoice"], "500000000");
    assert_eq!(body["paymentStatus"]["totals"]["remaining"], "500000000");
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
    let token = common::merchant_with_setup(&app, "chk2@example.com").await;
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
        "SELECT status FROM kpr1_payment_intents WHERE intent_id = $1",
    )
    .bind(intent["intentId"].as_str().unwrap())
    .fetch_one(&app.db.pool)
    .await
    .unwrap();
    assert_eq!(status, "fetched");
}

// The `expires_at` column can drift from the signed intent's own `expiresAt`
// (e.g. a manual edit). The endpoint must judge expiry from the value it signed
// and returns, so it never serves a request the pending list calls "awaiting"
// while the review screen 422s it as expired.
#[tokio::test]
async fn checkout_kpr1_intent_ignores_stale_expires_column() {
    let app = common::spawn_app().await;
    let token = common::merchant_with_setup(&app, "chk_drift@example.com").await;
    let created = create_invoice(&app, &token).await;
    let public_id = created["publicId"].as_str().unwrap();

    // Drift the column into the deep past while the signed intent stays valid.
    sqlx::query(
        "UPDATE kpr1_payment_intents SET expires_at = '2020-01-01T00:00:00+00:00' \
         WHERE invoice_id = (SELECT id FROM invoices WHERE public_id = $1)",
    )
    .bind(public_id)
    .execute(&app.db.pool)
    .await
    .unwrap();

    let res = app
        .client
        .get(app.url(&format!("/api/checkout/invoices/{public_id}/kpr1-intent")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "signed intent is still valid; stale column must not expire it");
    assert_eq!(res.json::<Value>().await.unwrap()["version"], "kpr-1");
}

// An expired (but open) intent is still SERVED with its details, so the wallet
// can show the payer what lapsed instead of a blank wall — the wallet refuses to
// pay it from the signed `expiresAt`. The intent is also marked expired for the
// merchant's records.
#[tokio::test]
async fn checkout_kpr1_intent_expired_still_served_with_details() {
    let app = common::spawn_app().await;
    let token = common::merchant_with_setup(&app, "chk_exp@example.com").await;
    let created = create_invoice(&app, &token).await;
    let public_id = created["publicId"].as_str().unwrap();

    // Expire the SIGNED value itself.
    sqlx::query(
        "UPDATE kpr1_payment_intents \
         SET canonical_intent = jsonb_set(canonical_intent::jsonb, '{expiresAt}', '\"2020-01-01T00:00:00+00:00\"')::text \
         WHERE invoice_id = (SELECT id FROM invoices WHERE public_id = $1)",
    )
    .bind(public_id)
    .execute(&app.db.pool)
    .await
    .unwrap();

    let res = app
        .client
        .get(app.url(&format!("/api/checkout/invoices/{public_id}/kpr1-intent")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "expired intent must still return its details");
    let intent: Value = res.json().await.unwrap();
    assert_eq!(intent["version"], "kpr-1");
    assert!(intent["outputs"].is_array(), "details (outputs/items) are present");
    assert_eq!(intent["expiresAt"], "2020-01-01T00:00:00+00:00");

    // ...and it was recorded as expired for the merchant.
    let status: String =
        sqlx::query_scalar("SELECT status FROM kpr1_payment_intents WHERE invoice_id = (SELECT id FROM invoices WHERE public_id = $1)")
            .bind(public_id)
            .fetch_one(&app.db.pool)
            .await
            .unwrap();
    assert_eq!(status, "expired");
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

// A closed invoice (cancelled/paid) still hands back its signed details, so the
// wallet renders a reference/receipt view instead of a blank 0-KAS wall. It's
// public signed data; payment is refused at submit, not by hiding the details.
#[tokio::test]
async fn checkout_kpr1_intent_not_open_still_served() {
    let app = common::spawn_app().await;
    let token = common::merchant_with_setup(&app, "chk3@example.com").await;
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
    assert_eq!(res.status(), 200, "closed invoice still serves its details for reference");
    let intent: Value = res.json().await.unwrap();
    assert_eq!(intent["version"], "kpr-1");
    assert!(intent["outputs"].is_array());
}
