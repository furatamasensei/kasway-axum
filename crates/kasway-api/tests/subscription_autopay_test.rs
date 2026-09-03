//! Wallet-local subscription auto-renew contract.

mod common;

use serde_json::{json, Value};

async fn create_subscription(app: &common::TestApp, email: &str) -> (String, String, Value) {
    let token = common::merchant_with_setup(app, email).await;
    let plan: Value = app
        .client
        .post(app.url("/api/commerce/subscription-plans"))
        .bearer_auth(&token)
        .json(&json!({
            "name": "Monthly",
            "amount": "500000000",
            "intervalUnit": "month",
            "intervalCount": 1,
            "invoiceExpiresAfterSeconds": 86400
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let subscription: Value = app
        .client
        .post(app.url("/api/commerce/subscriptions"))
        .bearer_auth(&token)
        .json(&json!({
            "planPublicId": plan["publicId"],
            "paymentMode": "wallet_autopay",
            "customer": { "email": "buyer@example.com" }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (
        token,
        plan["publicId"].as_str().unwrap().to_string(),
        subscription,
    )
}

#[tokio::test]
async fn legacy_autopay_input_creates_an_ordinary_subscription_invoice() {
    let app = common::spawn_app().await;
    let (_token, _plan, subscription) = create_subscription(&app, "local-auto@example.com").await;
    let public_id = subscription["publicId"].as_str().unwrap();

    assert_eq!(subscription["status"], "active");
    assert_eq!(subscription["paymentMode"], "recurring_invoice");
    assert_eq!(
        subscription["planSnapshot"]["invoiceExpiresAfterSeconds"],
        900
    );

    let checkout: Value = app
        .client
        .get(app.url(&format!("/api/checkout/subscriptions/{public_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(checkout["paymentType"], "subscription");
    assert_eq!(checkout["autoRenewAuthority"], "wallet_local");
    assert_eq!(checkout["paymentWindowSeconds"], 900);
    assert_eq!(checkout["currentInvoice"]["status"], "open");
    assert!(checkout["paymentRequestUri"]
        .as_str()
        .unwrap()
        .starts_with("kaspa-payment:v1?"));

    let invoice_public_id = checkout["currentInvoice"]["publicId"].as_str().unwrap();
    let intent: Value = app
        .client
        .get(app.url(&format!(
            "/api/checkout/invoices/{invoice_public_id}/kpr1-intent"
        )))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(intent["paymentType"], "subscription");
    assert_eq!(intent["subscriptionId"], public_id);

    let removed = app
        .client
        .post(app.url(&format!(
            "/api/checkout/subscriptions/{public_id}/autopay/prepare"
        )))
        .json(&json!({ "refundAddress": "kaspatest:qanything" }))
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 404);
}

#[tokio::test]
async fn invalid_initial_invoice_does_not_persist_subscription_state() {
    let app = common::spawn_app().await;
    let token = common::merchant_with_setup(&app, "invalid-initial-invoice@example.com").await;
    let plan: Value = app
        .client
        .post(app.url("/api/commerce/subscription-plans"))
        .bearer_auth(&token)
        .json(&json!({
            "name": "Below covenant minimum",
            "amount": "1000000",
            "intervalUnit": "month",
            "intervalCount": 1
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let before: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
            (SELECT COUNT(*) FROM subscription_customers), \
            (SELECT COUNT(*) FROM subscriptions), \
            (SELECT COUNT(*) FROM subscription_cycles), \
            (SELECT COUNT(*) FROM invoices)",
    )
    .fetch_one(&app.db.pool)
    .await
    .unwrap();

    let response = app
        .client
        .post(app.url("/api/commerce/subscriptions"))
        .bearer_auth(&token)
        .json(&json!({
            "planPublicId": plan["publicId"],
            "customer": { "email": "buyer@example.com" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 422);
    assert!(response
        .json::<Value>()
        .await
        .unwrap()["message"]
        .as_str()
        .unwrap()
        .contains("must be at least"));

    let after: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
            (SELECT COUNT(*) FROM subscription_customers), \
            (SELECT COUNT(*) FROM subscriptions), \
            (SELECT COUNT(*) FROM subscription_cycles), \
            (SELECT COUNT(*) FROM invoices)",
    )
    .fetch_one(&app.db.pool)
    .await
    .unwrap();
    assert_eq!(after, before);
}

#[tokio::test]
async fn expirer_retires_unpaid_cycle_but_keeps_a_timely_submission_alive() {
    let app = common::spawn_app().await;
    let (_token, _plan, first) = create_subscription(&app, "expire-cycle@example.com").await;
    let first_invoice_id = first["cycles"][0]["invoice"]["id"].as_i64().unwrap();

    sqlx::query("UPDATE invoices SET expires_at = '2020-01-01T00:00:00+00:00' WHERE id = $1")
        .bind(first_invoice_id)
        .execute(&app.db.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE kpr1_payment_intents SET expires_at = '2020-01-01T00:00:00+00:00' WHERE invoice_id = $1")
        .bind(first_invoice_id)
        .execute(&app.db.pool)
        .await
        .unwrap();

    assert_eq!(
        kasway_api::invoice_expirer::run_tick(&app.state)
            .await
            .unwrap(),
        1
    );
    let expired: (String, String, String) = sqlx::query_as(
        "SELECT inv.status, pi.covenant_state, cy.status FROM invoices inv \
         JOIN kpr1_payment_intents pi ON pi.invoice_id = inv.id \
         JOIN subscription_cycles cy ON cy.invoice_id = inv.id WHERE inv.id = $1",
    )
    .bind(first_invoice_id)
    .fetch_one(&app.db.pool)
    .await
    .unwrap();
    assert_eq!(
        expired,
        ("expired".into(), "expired".into(), "past_due".into())
    );

    let (_token, _plan, second) = create_subscription(&app, "confirm-later@example.com").await;
    let second_invoice_id = second["cycles"][0]["invoice"]["id"].as_i64().unwrap();
    sqlx::query("UPDATE invoices SET expires_at = '2020-01-01T00:00:00+00:00' WHERE id = $1")
        .bind(second_invoice_id)
        .execute(&app.db.pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE kpr1_payment_intents SET tx_id = $1, submitted_at = '2019-12-31T23:59:59+00:00', \
         expires_at = '2020-01-01T00:00:00+00:00', status = 'submitted' WHERE invoice_id = $2",
    )
    .bind("a".repeat(64))
    .bind(second_invoice_id)
    .execute(&app.db.pool)
    .await
    .unwrap();

    assert_eq!(
        kasway_api::invoice_expirer::run_tick(&app.state)
            .await
            .unwrap(),
        0
    );
    let status: String = sqlx::query_scalar("SELECT status FROM invoices WHERE id = $1")
        .bind(second_invoice_id)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    assert_eq!(status, "open");

    // Simulate the expiry worker crossing a request that the server received
    // before its deadline. Submission wins and restores all payable state.
    let (_token, _plan, crossed) = create_subscription(&app, "deadline-race@example.com").await;
    let crossed_invoice = &crossed["cycles"][0]["invoice"];
    let crossed_invoice_id = crossed_invoice["id"].as_i64().unwrap();
    let crossed_public_id = crossed_invoice["publicId"].as_str().unwrap();
    sqlx::query("UPDATE invoices SET status = 'expired', expires_at = '2999-01-01T00:00:00+00:00' WHERE id = $1")
        .bind(crossed_invoice_id).execute(&app.db.pool).await.unwrap();
    sqlx::query("UPDATE kpr1_payment_intents SET status = 'expired', covenant_state = 'expired', failure_reason = 'payment_window_expired', expires_at = '2999-01-01T00:00:00+00:00' WHERE invoice_id = $1")
        .bind(crossed_invoice_id).execute(&app.db.pool).await.unwrap();
    sqlx::query("UPDATE subscription_cycles SET status = 'past_due', past_due_at = '2026-01-01T00:00:00+00:00' WHERE invoice_id = $1")
        .bind(crossed_invoice_id).execute(&app.db.pool).await.unwrap();

    let submission = app.client
        .post(app.url(&format!("/api/checkout/invoices/{crossed_public_id}/kpr1-payments")))
        .json(&json!({ "txId": "b".repeat(64) }))
        .send().await.unwrap();
    assert_eq!(submission.status(), 200);
    let restored: (String, String, String) = sqlx::query_as(
        "SELECT inv.status, pi.status, cy.status FROM invoices inv \
         JOIN kpr1_payment_intents pi ON pi.invoice_id = inv.id \
         JOIN subscription_cycles cy ON cy.invoice_id = inv.id WHERE inv.id = $1",
    )
    .bind(crossed_invoice_id).fetch_one(&app.db.pool).await.unwrap();
    assert_eq!(restored, ("open".into(), "submitted".into(), "invoiced".into()));
}

#[tokio::test]
async fn changed_plan_price_is_signed_and_emits_customer_notice_event() {
    let app = common::spawn_app().await;
    let (token, plan, subscription) = create_subscription(&app, "price-change@example.com").await;
    let public_id = subscription["publicId"].as_str().unwrap();

    let updated = app
        .client
        .put(app.url(&format!("/api/commerce/subscription-plans/{plan}")))
        .bearer_auth(&token)
        .json(&json!({ "amount": "600000000" }))
        .send()
        .await
        .unwrap();
    assert_eq!(updated.status(), 200);

    let sub_id: i64 = sqlx::query_scalar("SELECT id FROM subscriptions WHERE public_id = $1")
        .bind(public_id)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    let due = chrono::Utc::now() - chrono::Duration::seconds(1);
    sqlx::query("UPDATE subscriptions SET next_billing_at = $1 WHERE id = $2")
        .bind(due.to_rfc3339())
        .bind(sub_id)
        .execute(&app.db.pool)
        .await
        .unwrap();
    assert_eq!(
        kasway_api::subscription_biller::run_tick(&app.state)
            .await
            .unwrap(),
        1
    );

    let canonical: String = sqlx::query_scalar(
        "SELECT pi.canonical_intent FROM kpr1_payment_intents pi \
         JOIN invoices inv ON inv.id = pi.invoice_id WHERE inv.subscription_id = $1 \
         ORDER BY inv.id DESC LIMIT 1",
    )
    .bind(sub_id)
    .fetch_one(&app.db.pool)
    .await
    .unwrap();
    let intent: Value = serde_json::from_str(&canonical).unwrap();
    assert_eq!(intent["amountSompi"], "600000000");
    assert_eq!(intent["subscription"]["priceChange"]["changed"], true);
    assert_eq!(
        intent["subscription"]["priceChange"]["previousAmountSompi"],
        "500000000"
    );
    assert_eq!(
        intent["subscription"]["priceChange"]["currentAmountSompi"],
        "600000000"
    );

    let notices: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM webhook_events WHERE event_type = 'subscription.price.changed' AND resource_id = $1",
    )
    .bind(public_id)
    .fetch_one(&app.db.pool)
    .await
    .unwrap();
    assert_eq!(notices, 1);
}

// A plan row whose `invoice_expires_after_seconds` is SHORTER than the 15-minute
// cap is honored on the cycle invoice (and reported honestly in the snapshot);
// longer ones are capped at 900 — see
// `legacy_autopay_input_creates_an_ordinary_subscription_invoice` (86400 -> 900).
// The plan API pins new plans to the cap, so the shorter window is set on the row.
#[tokio::test]
async fn short_plan_window_shortens_the_cycle_invoice() {
    let app = common::spawn_app().await;
    let token = common::merchant_with_setup(&app, "short-window@example.com").await;
    let plan: Value = app
        .client
        .post(app.url("/api/commerce/subscription-plans"))
        .bearer_auth(&token)
        .json(&json!({
            "name": "Monthly",
            "amount": "500000000",
            "intervalUnit": "month",
            "intervalCount": 1
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    sqlx::query("UPDATE subscription_plans SET invoice_expires_after_seconds = 300 WHERE public_id = $1")
        .bind(plan["publicId"].as_str().unwrap())
        .execute(&app.db.pool)
        .await
        .unwrap();
    let before = chrono::Utc::now();
    let subscription: Value = app
        .client
        .post(app.url("/api/commerce/subscriptions"))
        .bearer_auth(&token)
        .json(&json!({
            "planPublicId": plan["publicId"],
            "customer": { "email": "buyer@example.com" }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(subscription["planSnapshot"]["invoiceExpiresAfterSeconds"], 300);

    let public_id = subscription["publicId"].as_str().unwrap();
    let checkout: Value = app
        .client
        .get(app.url(&format!("/api/checkout/subscriptions/{public_id}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let invoice_public_id = checkout["currentInvoice"]["publicId"].as_str().unwrap();
    let intent: Value = app
        .client
        .get(app.url(&format!("/api/checkout/invoices/{invoice_public_id}/kpr1-intent")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let expires_at = chrono::DateTime::parse_from_rfc3339(intent["expiresAt"].as_str().unwrap()).unwrap();
    let secs = (expires_at.with_timezone(&chrono::Utc) - before).num_seconds();
    assert!((295..=310).contains(&secs), "expected ~300 s window, got {secs} s");
}
