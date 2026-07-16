//! Subscription Pocket autopay: biller scheduling, public checkout endpoints,
//! cancel auth, withdraw guards, the invoice-paid → cycle-paid funnel, and the
//! once-only past-due marker. On-chain claim/withdraw submission needs a Kaspa
//! node and is NOT covered here (the pure funding-recognition logic is
//! unit-tested inside `subscription_keeper`).

mod common;

use kasway_covenant::{KeeperKey, Prefix};
use serde_json::{json, Value};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn key(byte: u8) -> KeeperKey {
    KeeperKey::from_secret_bytes(&[byte; 32]).unwrap()
}

fn addr(byte: u8) -> String {
    key(byte).address(Prefix::Testnet).to_string()
}

/// Keeper fee secret (also the claim-authorizing key) used by the autopay tests.
const KEEPER: u8 = 7;
/// Customer refund key.
const CUSTOMER: u8 = 3;

/// App configured for autopay: real (parseable) platform fee address + keeper key.
async fn autopay_app() -> common::TestApp {
    common::spawn_with_config(
        |c| {
            c.covenant.keeper_fee_secret_hex = Some(hex(&[KEEPER; 32]));
            c.kpr1.platform_fee_address = addr(0x22);
        },
        false,
    )
    .await
}

/// Merchant with a REAL (bech32-parseable) payout address, needed once a
/// covenant is compiled from the payout split.
async fn merchant_with_real_setup(app: &common::TestApp, email: &str) -> String {
    let token = common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    let store = common::seed_default_store(&app.db, uid).await;
    common::seed_setup(&app.db, uid, store, &addr(0x44)).await;
    token
}

async fn create_plan(app: &common::TestApp, token: &str, unit: &str) -> String {
    let p: Value = app
        .client
        .post(app.url("/api/commerce/subscription-plans"))
        .bearer_auth(token)
        .json(&json!({ "name": "Pocket", "amount": "500000000", "intervalUnit": unit, "intervalCount": 1 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    p["publicId"].as_str().unwrap().to_string()
}

async fn create_sub(app: &common::TestApp, token: &str, plan: &str, body_extra: Value) -> Value {
    let mut body = json!({ "planPublicId": plan, "customer": { "email": "buyer@x.com" } });
    if let (Value::Object(b), Value::Object(e)) = (&mut body, body_extra) {
        b.extend(e);
    }
    let res = app
        .client
        .post(app.url("/api/commerce/subscriptions"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    res.json().await.unwrap()
}

async fn event_count(app: &common::TestApp, event_type: &str, resource_id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM webhook_events WHERE event_type = $1 AND resource_id = $2")
        .bind(event_type)
        .bind(resource_id)
        .fetch_one(&app.db.pool)
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// Biller.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn biller_catches_up_every_due_period_and_emits_invoice_created() {
    let app = common::spawn_app().await;
    let token = common::merchant_with_setup(&app, "biller1@example.com").await;
    let plan = create_plan(&app, &token, "day").await;
    // 2.5 days ago → three due daily periods (d0, d1, d2); creation bills d0.
    let starts = (chrono::Utc::now() - chrono::Duration::hours(60)).to_rfc3339();
    let sub = create_sub(&app, &token, &plan, json!({ "startsAt": starts })).await;
    let sub_id = sub["id"].as_i64().unwrap();

    let billed = kasway_api::subscription_biller::run_tick(&app.state).await.unwrap();
    assert_eq!(billed, 2, "biller should mint the two remaining due periods");

    let cycles: Vec<(String, Option<i64>)> =
        sqlx::query_as("SELECT status, invoice_id FROM subscription_cycles WHERE subscription_id = $1 ORDER BY period_start")
            .bind(sub_id)
            .fetch_all(&app.db.pool)
            .await
            .unwrap();
    assert_eq!(cycles.len(), 3);
    for (status, invoice_id) in &cycles {
        assert_eq!(status, "invoiced");
        assert!(invoice_id.is_some());
    }
    let next: Option<String> = sqlx::query_scalar("SELECT next_billing_at FROM subscriptions WHERE id = $1")
        .bind(sub_id)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    assert!(next.unwrap() > kasway_api::util::now_iso(), "caught up past now");

    // Every mint path emits subscription.invoice.created (creation + biller).
    let created_events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM webhook_events WHERE event_type = 'subscription.invoice.created'")
            .fetch_one(&app.db.pool)
            .await
            .unwrap();
    assert_eq!(created_events, 3);

    // Caught up: the next tick is a no-op.
    assert_eq!(kasway_api::subscription_biller::run_tick(&app.state).await.unwrap(), 0);
}

// ---------------------------------------------------------------------------
// Public autopay endpoints.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn autopay_prepare_record_and_status_roundtrip() {
    let app = autopay_app().await;
    let token = merchant_with_real_setup(&app, "pocket1@example.com").await;
    let plan = create_plan(&app, &token, "month").await;
    let sub = create_sub(&app, &token, &plan, json!({})).await;
    let pid = sub["publicId"].as_str().unwrap();

    // prepare → covenant cell
    let res = app
        .client
        .post(app.url(&format!("/api/checkout/subscriptions/{pid}/autopay/prepare")))
        .json(&json!({ "refundAddress": addr(CUSTOMER) }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let prep: Value = res.json().await.unwrap();
    let cov_addr = prep["covenantAddress"].as_str().unwrap();
    assert!(cov_addr.starts_with("kaspatest:"), "got {cov_addr}");
    assert_eq!(prep["claimTotal"], "500000000");
    assert!(!prep["redeemScriptHex"].as_str().unwrap().is_empty());
    assert_eq!(prep["suggestedFunding"][0]["periods"], 3);
    assert_eq!(prep["suggestedFunding"][0]["amountSompi"], "1500000000");
    assert_eq!(prep["params"]["periodDaa"].as_u64().unwrap(), 30 * 864_000 * 9 / 10);

    // record funding txid (idempotent; repeatable for top-ups)
    let txid = hex(&[0xAA; 32]);
    for _ in 0..2 {
        let res = app
            .client
            .post(app.url(&format!("/api/checkout/subscriptions/{pid}/autopay")))
            .json(&json!({ "txId": txid }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let rec: Value = res.json().await.unwrap();
        assert_eq!(rec["recorded"], true);
        assert_eq!(rec["txIds"].as_array().unwrap().len(), 1);
    }
    let res = app
        .client
        .post(app.url(&format!("/api/checkout/subscriptions/{pid}/autopay")))
        .json(&json!({ "txId": hex(&[0xBB; 32]) }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.json::<Value>().await.unwrap()["txIds"].as_array().unwrap().len(), 2);

    // bad txid rejected
    let bad = app
        .client
        .post(app.url(&format!("/api/checkout/subscriptions/{pid}/autopay")))
        .json(&json!({ "txId": "nope" }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 422);

    // public status
    let show: Value = app
        .client
        .get(app.url(&format!("/api/checkout/subscriptions/{pid}")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(show["paymentMode"], "wallet_autopay");
    assert_eq!(show["cell"]["state"], "awaiting_funding");
    assert_eq!(show["cell"]["covenantAddress"], cov_addr);
    assert_eq!(show["cell"]["claimTotal"], "500000000");
    assert_eq!(show["cell"]["recordedFundingTxIds"].as_array().unwrap().len(), 2);
    assert_eq!(show["plan"]["amount"], "500000000");
    assert!(!show["cancelChallengeHex"].as_str().unwrap().is_empty());

    // a funded (recorded) cell cannot be silently re-derived
    let again = app
        .client
        .post(app.url(&format!("/api/checkout/subscriptions/{pid}/autopay/prepare")))
        .json(&json!({ "refundAddress": addr(CUSTOMER) }))
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 422);
}

#[tokio::test]
async fn cancel_without_cell_needs_only_public_id() {
    let app = common::spawn_app().await;
    let token = common::merchant_with_setup(&app, "cancel1@example.com").await;
    let plan = create_plan(&app, &token, "month").await;
    let sub = create_sub(&app, &token, &plan, json!({})).await;
    let pid = sub["publicId"].as_str().unwrap();

    let res = app
        .client
        .post(app.url(&format!("/api/checkout/subscriptions/{pid}/cancel")))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.json::<Value>().await.unwrap()["status"], "cancelled");

    let (status, next): (String, Option<String>) =
        sqlx::query_as("SELECT status, next_billing_at FROM subscriptions WHERE public_id = $1")
            .bind(pid)
            .fetch_one(&app.db.pool)
            .await
            .unwrap();
    assert_eq!(status, "cancelled");
    assert!(next.is_none());
    assert_eq!(event_count(&app, "subscription.cancelled", pid).await, 1);

    // idempotent
    let res = app
        .client
        .post(app.url(&format!("/api/checkout/subscriptions/{pid}/cancel")))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(event_count(&app, "subscription.cancelled", pid).await, 1);
}

#[tokio::test]
async fn cancel_with_funded_cell_requires_refund_key_signature() {
    let app = autopay_app().await;
    let token = merchant_with_real_setup(&app, "cancel2@example.com").await;
    let plan = create_plan(&app, &token, "month").await;
    let sub = create_sub(&app, &token, &plan, json!({})).await;
    let pid = sub["publicId"].as_str().unwrap();

    app.client
        .post(app.url(&format!("/api/checkout/subscriptions/{pid}/autopay/prepare")))
        .json(&json!({ "refundAddress": addr(CUSTOMER) }))
        .send()
        .await
        .unwrap();
    app.client
        .post(app.url(&format!("/api/checkout/subscriptions/{pid}/autopay")))
        .json(&json!({ "txId": hex(&[0xCC; 32]) }))
        .send()
        .await
        .unwrap();

    // No signature → 422 with the challenge to sign.
    let res = app
        .client
        .post(app.url(&format!("/api/checkout/subscriptions/{pid}/cancel")))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    let body: Value = res.json().await.unwrap();
    let challenge_hex = body["challengeHex"].as_str().unwrap().to_string();
    let mut challenge = [0u8; 32];
    for (i, byte) in challenge.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&challenge_hex[i * 2..i * 2 + 2], 16).unwrap();
    }

    // Wrong key → rejected.
    let impostor_sig = key(9).sign_datasig(&challenge).unwrap();
    let res = app
        .client
        .post(app.url(&format!("/api/checkout/subscriptions/{pid}/cancel")))
        .json(&json!({ "signatureHex": hex(&impostor_sig) }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);

    // Refund key → cancelled; cell flips too.
    let sig = key(CUSTOMER).sign_datasig(&challenge).unwrap();
    let res = app
        .client
        .post(app.url(&format!("/api/checkout/subscriptions/{pid}/cancel")))
        .json(&json!({ "signatureHex": hex(&sig) }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let (status, cell_state): (String, String) = sqlx::query_as(
        "SELECT s.status, c.state FROM subscriptions s JOIN subscription_cells c ON c.subscription_id = s.id WHERE s.public_id = $1",
    )
    .bind(pid)
    .fetch_one(&app.db.pool)
    .await
    .unwrap();
    assert_eq!(status, "cancelled");
    assert_eq!(cell_state, "cancelled");
    assert_eq!(event_count(&app, "subscription.cancelled", pid).await, 1);
}

#[tokio::test]
async fn withdraw_prepare_rejects_unfunded_cell() {
    let app = autopay_app().await;
    let token = merchant_with_real_setup(&app, "withdraw1@example.com").await;
    let plan = create_plan(&app, &token, "month").await;
    let sub = create_sub(&app, &token, &plan, json!({})).await;
    let pid = sub["publicId"].as_str().unwrap();

    // No cell at all.
    let res = app
        .client
        .post(app.url(&format!("/api/checkout/subscriptions/{pid}/autopay/withdraw/prepare")))
        .json(&json!({ "destinationAddress": addr(CUSTOMER) }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);

    // Cell prepared but never recognized on-chain → still nothing to withdraw.
    app.client
        .post(app.url(&format!("/api/checkout/subscriptions/{pid}/autopay/prepare")))
        .json(&json!({ "refundAddress": addr(CUSTOMER) }))
        .send()
        .await
        .unwrap();
    let res = app
        .client
        .post(app.url(&format!("/api/checkout/subscriptions/{pid}/autopay/withdraw/prepare")))
        .json(&json!({ "destinationAddress": addr(CUSTOMER) }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    let msg = res.json::<Value>().await.unwrap()["message"].as_str().unwrap().to_string();
    assert!(msg.contains("no recognized funds"), "got {msg}");
}

// ---------------------------------------------------------------------------
// Paid funnel + past-due marking (DB-only keeper logic).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn settled_invoice_marks_its_subscription_cycle_paid() {
    let app = common::spawn_app().await;
    let token = common::merchant_with_setup(&app, "funnel1@example.com").await;
    let plan = create_plan(&app, &token, "month").await;
    let sub = create_sub(&app, &token, &plan, json!({})).await;
    let sub_id = sub["id"].as_i64().unwrap();

    let (invoice_id, cycle_id): (i64, i64) = sqlx::query_as(
        "SELECT invoice_id, id FROM subscription_cycles WHERE subscription_id = $1 AND invoice_id IS NOT NULL",
    )
    .bind(sub_id)
    .fetch_one(&app.db.pool)
    .await
    .unwrap();
    let intent_pk: i64 = sqlx::query_scalar("SELECT id FROM kpr1_payment_intents WHERE invoice_id = $1")
        .bind(invoice_id)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();

    // The shared settlement funnel every paid path routes through.
    kasway_api::covenant_keeper::mark_settled_paid(&app.state, intent_pk, invoice_id, "captured", "txdeadbeef")
        .await
        .unwrap();

    let inv_status: String = sqlx::query_scalar("SELECT status FROM invoices WHERE id = $1")
        .bind(invoice_id)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    assert_eq!(inv_status, "paid");
    let (cy_status, paid_at): (String, Option<String>) =
        sqlx::query_as("SELECT status, paid_at FROM subscription_cycles WHERE id = $1")
            .bind(cycle_id)
            .fetch_one(&app.db.pool)
            .await
            .unwrap();
    assert_eq!(cy_status, "paid");
    assert!(paid_at.is_some());
}

#[tokio::test]
async fn underfunded_due_cycle_goes_past_due_exactly_once() {
    let app = autopay_app().await;
    let token = merchant_with_real_setup(&app, "pastdue1@example.com").await;
    let plan = create_plan(&app, &token, "month").await;
    let sub = create_sub(&app, &token, &plan, json!({})).await;
    let pid = sub["publicId"].as_str().unwrap();
    let sub_id = sub["id"].as_i64().unwrap();

    // Autopay cell exists (awaiting funding, so it cannot cover the due cycle).
    app.client
        .post(app.url(&format!("/api/checkout/subscriptions/{pid}/autopay/prepare")))
        .json(&json!({ "refundAddress": addr(CUSTOMER) }))
        .send()
        .await
        .unwrap();
    app.client
        .post(app.url(&format!("/api/checkout/subscriptions/{pid}/autopay")))
        .json(&json!({ "txId": hex(&[0xDD; 32]) }))
        .send()
        .await
        .unwrap();

    assert_eq!(kasway_api::subscription_keeper::mark_underfunded_past_due(&app.state).await.unwrap(), 1);
    // Once only: the second pass is a no-op and no duplicate event is emitted.
    assert_eq!(kasway_api::subscription_keeper::mark_underfunded_past_due(&app.state).await.unwrap(), 0);
    assert_eq!(event_count(&app, "subscription.past_due", pid).await, 1);

    let (cy_status, past_due_at): (String, Option<String>) =
        sqlx::query_as("SELECT status, past_due_at FROM subscription_cycles WHERE subscription_id = $1")
            .bind(sub_id)
            .fetch_one(&app.db.pool)
            .await
            .unwrap();
    assert_eq!(cy_status, "past_due");
    assert!(past_due_at.is_some());
    let cell_state: String = sqlx::query_scalar("SELECT state FROM subscription_cells WHERE subscription_id = $1")
        .bind(sub_id)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    assert_eq!(cell_state, "past_due");
}

#[tokio::test]
async fn merchant_lifecycle_endpoints_emit_subscription_events() {
    let app = common::spawn_app().await;
    let token = common::merchant_with_setup(&app, "events1@example.com").await;
    let plan = create_plan(&app, &token, "month").await;
    let sub = create_sub(&app, &token, &plan, json!({})).await;
    let pid = sub["publicId"].as_str().unwrap();

    assert_eq!(event_count(&app, "subscription.created", pid).await, 1);
    app.client.post(app.url(&format!("/api/commerce/subscriptions/{pid}/pause"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(event_count(&app, "subscription.paused", pid).await, 1);
    app.client.post(app.url(&format!("/api/commerce/subscriptions/{pid}/resume"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(event_count(&app, "subscription.resumed", pid).await, 1);
    app.client.post(app.url(&format!("/api/commerce/subscriptions/{pid}/cancel"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(event_count(&app, "subscription.cancelled", pid).await, 1);
}
