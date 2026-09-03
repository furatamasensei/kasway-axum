//! Chain observer (`kasway_api::chain_observer`): covenant funding verification.
//! Each tick picks up finalized KPR-1 covenant intents (`covenant_address` set,
//! `covenant_state = 'awaiting_funding'`, invoice open, wallet `tx_id` recorded),
//! asks the [`ChainSource`] for that tx's outputs to the covenant address, and:
//!  - funded `== gross` + enough confirmations -> `covenant_state = 'funded'`
//!    + one `payment.confirmed` webhook event (the invoice stays OPEN; the
//!    keeper auto-captures / the parties settle later),
//!  - funded `== gross` but too few confirmations -> observed + verified, keeps
//!    waiting (still `awaiting_funding`),
//!  - funded `!= gross` (under/overfund) or more than ONE covenant output ->
//!    FAIL CLOSED: intent `failed` with a stable reason + a critical anomaly
//!    signal; the invoice is never funded.
//! Ticks are driven directly with an in-memory `ChainSource`; no polling loop,
//! no real node.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use kasway_api::chain_observer;
use kasway_api::chain_source::{ChainSource, ChainSourceError, ObservedOutput, ObservedTransaction};
use kasway_api::state::AppConfig;
use serde_json::{json, Value};

// Valid schnorr P2PK testnet-10 addresses (covenant `Destination::parse` rejects
// placeholders). The arbiter pubkey baked into the covenant comes from
// `ARBITER_SECRET`; the fee/merchant/customer addresses are independent P2PK keys.
const MERCHANT_ADDR: &str = "kaspatest:qprx6l72u437tjcf5rgcwza4sq6ysprp0pu6zj2feu3zshcm4cljwrzqrunpu";
const PLATFORM_FEE_ADDR: &str = "kaspatest:qqkqkl8e2vj2qlg98x9jgqt5msxzhezym943tx4xclmmrengdqyeznn0pna8v";
const CUSTOMER_REFUND: &str = "kaspatest:qp8n2k7uklxq4aegau7vawtptkgxsja4kt99lpv6krctwpq8tpc655cyvcmd3";
const ARBITER_SECRET: &str = "3333333333333333333333333333333333333333333333333333333333333333";

// A 5-TKAS invoice: with the default 1% platform fee the covenant pays
// merchant_net 495_000_000 + kasway_fee 5_000_000, keeping the release's KIP-9
// storage mass (~202k) under the 500_000 consensus cap so it can actually settle.
const INVOICE_UNIT_AMOUNT: &str = "500000000";

// ---------- mock chain source ----------

/// In-memory ChainSource: tx registry + settable virtual DAA score.
#[derive(Default)]
struct MockChain {
    /// tx_id -> (outputs (address, amount sompi), accepting DAA score).
    txs: Mutex<HashMap<String, (Vec<(String, u64)>, Option<u64>)>>,
    virtual_daa: AtomicU64,
}

impl MockChain {
    fn set_tx(&self, tx_id: &str, outputs: Vec<(String, u64)>, accepting_daa_score: Option<u64>) {
        self.txs.lock().unwrap().insert(tx_id.to_string(), (outputs, accepting_daa_score));
    }
    fn set_virtual_daa(&self, v: u64) {
        self.virtual_daa.store(v, Ordering::Relaxed);
    }
}

impl ChainSource for MockChain {
    async fn transaction_outputs(
        &self,
        tx_id: &str,
        addresses: &[String],
    ) -> Result<Option<ObservedTransaction>, ChainSourceError> {
        let txs = self.txs.lock().unwrap();
        let Some((outputs, accepting_daa_score)) = txs.get(tx_id) else { return Ok(None) };
        let outputs: Vec<ObservedOutput> = outputs
            .iter()
            .filter(|(address, _)| addresses.contains(address))
            .map(|(address, amount)| ObservedOutput { address: address.clone(), amount_sompi: *amount })
            .collect();
        if outputs.is_empty() {
            return Ok(None);
        }
        Ok(Some(ObservedTransaction {
            tx_id: tx_id.to_string(),
            outputs,
            accepting_daa_score: *accepting_daa_score,
        }))
    }

    async fn virtual_daa_score(&self) -> Result<u64, ChainSourceError> {
        Ok(self.virtual_daa.load(Ordering::Relaxed))
    }
}

// ---------- fixtures ----------

/// Spawn a test app whose config has the covenant arbiter key + a valid platform
/// fee payout address, so `finalize_covenant_for_invoice` can derive a covenant.
fn covenant_config(cfg: &mut AppConfig) {
    cfg.covenant.arbiter_secret_hex = Some(ARBITER_SECRET.to_string());
    cfg.kpr1.platform_fee_address = PLATFORM_FEE_ADDR.to_string();
}

async fn spawn_covenant_app() -> common::TestApp {
    common::spawn_with_config(covenant_config, false).await
}

/// Register a merchant, create an open invoice via the API (mints a covenant
/// intent), then finalize the covenant (the payer supplies a refund address).
/// Returns (token, user_id, invoice, covenant_address, gross_sompi).
async fn setup_finalized_intent(app: &common::TestApp, email: &str) -> (String, i64, Value, String, i64) {
    let token = common::register_merchant(app, email, "secret123").await;
    let user_id = common::merchant_user_id(&app.db, email).await;
    let store_id = common::seed_default_store(&app.db, user_id).await;
    common::seed_setup(&app.db, user_id, store_id, MERCHANT_ADDR).await;

    let res = app
        .client
        .post(app.url("/api/invoices"))
        .bearer_auth(&token)
        .json(&json!({ "items": [{ "name": "Widget", "quantity": 1, "unitAmount": INVOICE_UNIT_AMOUNT }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "invoice create should succeed");
    let invoice: Value = res.json().await.unwrap();
    let invoice_id = invoice["id"].as_i64().unwrap();
    let public_id = invoice["publicId"].as_str().unwrap();

    // Finalize the covenant: derives the P2SH address the payer funds and moves
    // the intent to `awaiting_funding`.
    kasway_api::kpr1::finalize_covenant_for_invoice(&app.state, public_id, CUSTOMER_REFUND)
        .await
        .expect("covenant finalize should succeed");

    let (cov_addr, gross): (Option<String>, Option<i64>) = sqlx::query_as(
        "SELECT covenant_address, gross_amount FROM kpr1_payment_intents WHERE invoice_id = $1",
    )
    .bind(invoice_id)
    .fetch_one(&app.db.pool)
    .await
    .unwrap();
    (
        token,
        user_id,
        invoice,
        cov_addr.expect("covenant address set after finalize"),
        gross.expect("gross set at mint"),
    )
}

/// Wallet submits the funding tx id for the invoice's intent (public checkout).
async fn submit_tx(app: &common::TestApp, public_id: &str, tx_id: &str) {
    let res = app
        .client
        .post(app.url(&format!("/api/checkout/invoices/{public_id}/kpr1-payments")))
        .json(&json!({ "txId": tx_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "kpr1-payments submission should succeed");
}

/// Register a webhook endpoint subscribed to invoice.paid; returns its id.
async fn subscribe_invoice_paid(app: &common::TestApp, token: &str) -> i64 {
    let created: Value = app
        .client
        .post(app.url("/api/webhook-endpoints"))
        .bearer_auth(token)
        .json(&json!({ "url": "https://hooks.example.com/kasway", "events": ["invoice.paid"] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    created["id"].as_i64().unwrap()
}

async fn invoice_row(app: &common::TestApp, id: i64) -> (String, Option<String>) {
    sqlx::query_as("SELECT status, paid_at FROM invoices WHERE id = $1")
        .bind(id)
        .fetch_one(&app.db.pool)
        .await
        .unwrap()
}

/// (intent status, verification_status, failure_reason, covenant_state).
async fn intent_row(app: &common::TestApp, invoice_id: i64) -> (String, Option<String>, Option<String>, String) {
    sqlx::query_as(
        "SELECT status, verification_status, failure_reason, covenant_state \
         FROM kpr1_payment_intents WHERE invoice_id = $1",
    )
    .bind(invoice_id)
    .fetch_one(&app.db.pool)
    .await
    .unwrap()
}

type ObservationRow = (String, i64, i64, Option<String>, Option<i64>, Option<String>);

async fn observation_rows(app: &common::TestApp, invoice_id: i64) -> Vec<ObservationRow> {
    sqlx::query_as(
        "SELECT status, amount, confirmations, tx_id, block_daa_score, metadata \
         FROM payment_observations WHERE invoice_id = $1 ORDER BY id",
    )
    .bind(invoice_id)
    .fetch_all(&app.db.pool)
    .await
    .unwrap()
}

async fn count(app: &common::TestApp, sql: &str, id: i64) -> i64 {
    sqlx::query_scalar(sql).bind(id).fetch_one(&app.db.pool).await.unwrap()
}

// ---------- tests ----------

// Covenant funded with EXACTLY gross + enough confirmations: the observer marks
// it `funded`, records a settled observation and emits `payment.confirmed`, but
// the invoice stays OPEN and NO payment/`invoice.paid` is produced — that is the
// keeper's job on release. A second tick is a no-op (funded is terminal for the
// observer), so no duplicate event.
#[tokio::test]
async fn covenant_funded_and_confirmed_marks_funded() {
    let app = spawn_covenant_app().await;
    let (token, user_id, invoice, cov_addr, gross) =
        setup_finalized_intent(&app, "chain1@example.com").await;
    let invoice_id = invoice["id"].as_i64().unwrap();
    let public_id = invoice["publicId"].as_str().unwrap();
    let _endpoint_id = subscribe_invoice_paid(&app, &token).await;

    let tx_id = "ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34";
    submit_tx(&app, public_id, tx_id).await;

    let chain = MockChain::default();
    chain.set_tx(tx_id, vec![(cov_addr.clone(), gross as u64)], Some(1_000));
    chain.set_virtual_daa(1_015); // 15 confirmations >= platform default 10

    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 1);

    // Invoice stays OPEN — the keeper releases the split and only then pays it.
    let (status, paid_at) = invoice_row(&app, invoice_id).await;
    assert_eq!(status, "open");
    assert!(paid_at.is_none());

    // Intent funded + verified; no failure.
    let (intent_status, verification_status, failure_reason, covenant_state) =
        intent_row(&app, invoice_id).await;
    assert_eq!(covenant_state, "funded");
    assert_eq!(intent_status, "verified");
    assert_eq!(verification_status.as_deref(), Some("verified"));
    assert!(failure_reason.is_none());

    // Observation settled with the covenant funding output.
    let observations = observation_rows(&app, invoice_id).await;
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].0, "settled");
    assert_eq!(observations[0].1, gross);
    assert_eq!(observations[0].2, 15);
    let meta: Value = serde_json::from_str(observations[0].5.as_deref().unwrap()).unwrap();
    let meta_outputs = meta["kpr1"]["outputs"].as_array().unwrap();
    assert_eq!(meta_outputs.len(), 1);
    assert_eq!(meta_outputs[0]["role"], "covenant");
    assert_eq!(meta_outputs[0]["address"], cov_addr);

    // No payment row, no invoice.paid event yet (keeper produces those on release);
    // exactly one payment.confirmed carrying the invoice + funding tx + confirmations.
    assert_eq!(count(&app, "SELECT COUNT(*) FROM payments WHERE invoice_id = $1", invoice_id).await, 0);
    let events: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT event_type, resource_type, resource_id, payload FROM webhook_events WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(&app.db.pool)
    .await
    .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, "payment.confirmed");
    assert_eq!(events[0].1, "invoice");
    assert_eq!(events[0].2, public_id);
    let payload: Value = serde_json::from_str(&events[0].3).unwrap();
    assert_eq!(payload["publicId"], public_id);
    assert_eq!(payload["status"], "open");
    assert_eq!(payload["txId"], tx_id);
    assert_eq!(payload["confirmations"], 15);

    // Checkpoint tracks the virtual DAA score.
    let checkpoint: Option<String> = sqlx::query_scalar(
        "SELECT checkpoint FROM payment_indexer_checkpoints \
         WHERE network = 'tn10' AND asset_id = 'KAS' AND source = 'chain_observer'",
    )
    .fetch_one(&app.db.pool)
    .await
    .unwrap();
    assert_eq!(checkpoint.as_deref(), Some("1015"));

    // Funded intent is terminal for the observer: next tick does nothing — and
    // emits nothing again.
    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 0);
    assert_eq!(count(&app, "SELECT COUNT(*) FROM webhook_events WHERE user_id = $1", user_id).await, 1);
}

// Funded == gross but too few confirmations: observed + verified, still
// `awaiting_funding`; when confirmations catch up a later tick marks it funded,
// updating (not duplicating) the same observation row.
#[tokio::test]
async fn insufficient_confirmations_stay_awaiting_until_policy_met() {
    let app = spawn_covenant_app().await;
    let (_token, user_id, invoice, cov_addr, gross) =
        setup_finalized_intent(&app, "chain2@example.com").await;
    let invoice_id = invoice["id"].as_i64().unwrap();
    let public_id = invoice["publicId"].as_str().unwrap();

    let tx_id = "bb34ee56bb34ee56bb34ee56bb34ee56bb34ee56bb34ee56bb34ee56bb34ee56";
    submit_tx(&app, public_id, tx_id).await;

    let chain = MockChain::default();
    chain.set_tx(tx_id, vec![(cov_addr.clone(), gross as u64)], Some(2_000));
    chain.set_virtual_daa(2_003); // 3 confirmations < platform default 10

    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 1);

    // Not yet funded; invoice open; no event.
    let (status, _) = invoice_row(&app, invoice_id).await;
    assert_eq!(status, "open");
    let (_, verification_status, _, covenant_state) = intent_row(&app, invoice_id).await;
    assert_eq!(covenant_state, "awaiting_funding");
    assert_eq!(verification_status.as_deref(), Some("verified"));
    assert_eq!(count(&app, "SELECT COUNT(*) FROM webhook_events WHERE user_id = $1", user_id).await, 0);

    let observations = observation_rows(&app, invoice_id).await;
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].0, "matched");
    assert_eq!(observations[0].2, 3);

    // Confirmations catch up -> same observation row settles, covenant funded.
    chain.set_virtual_daa(2_012);
    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 1);

    let (_, _, _, covenant_state) = intent_row(&app, invoice_id).await;
    assert_eq!(covenant_state, "funded");
    let observations = observation_rows(&app, invoice_id).await;
    assert_eq!(observations.len(), 1, "observation row is updated, not duplicated");
    assert_eq!(observations[0].0, "settled");
    assert_eq!(observations[0].2, 12);
    // Still the keeper's job to pay: payment.confirmed now, no invoice.paid.
    let (status, _) = invoice_row(&app, invoice_id).await;
    assert_eq!(status, "open");
    assert_eq!(
        count(&app, "SELECT COUNT(*) FROM webhook_events WHERE user_id = $1 AND event_type = 'payment.confirmed'", user_id).await,
        1
    );
    assert_eq!(
        count(&app, "SELECT COUNT(*) FROM webhook_events WHERE user_id = $1 AND event_type = 'invoice.paid'", user_id).await,
        0
    );
}

// Underfunded covenant (gross - 1): fail closed — intent failed with
// `covenant_underfunded`, a critical anomaly signal, invoice never funded. The
// failed intent is terminal (covenant_state = 'failed'): no re-observation.
#[tokio::test]
async fn underfunded_covenant_fails_closed() {
    let app = spawn_covenant_app().await;
    let (_token, user_id, invoice, cov_addr, gross) =
        setup_finalized_intent(&app, "chain3@example.com").await;
    let invoice_id = invoice["id"].as_i64().unwrap();
    let public_id = invoice["publicId"].as_str().unwrap();
    let intent_id = invoice["kpr1PaymentIntent"]["intentId"].as_str().unwrap();

    let tx_id = "cc56aa78cc56aa78cc56aa78cc56aa78cc56aa78cc56aa78cc56aa78cc56aa78";
    submit_tx(&app, public_id, tx_id).await;

    let chain = MockChain::default();
    chain.set_tx(tx_id, vec![(cov_addr.clone(), gross as u64 - 1)], Some(3_000));
    chain.set_virtual_daa(3_050); // plenty of confirmations — must still fail

    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 1);

    let (status, paid_at) = invoice_row(&app, invoice_id).await;
    assert_eq!(status, "open");
    assert!(paid_at.is_none());
    assert_eq!(count(&app, "SELECT COUNT(*) FROM webhook_events WHERE user_id = $1", user_id).await, 0);

    let (intent_status, verification_status, failure_reason, covenant_state) =
        intent_row(&app, invoice_id).await;
    assert_eq!(intent_status, "failed");
    assert_eq!(verification_status.as_deref(), Some("failed"));
    assert_eq!(failure_reason.as_deref(), Some("covenant_underfunded"));
    assert_eq!(covenant_state, "failed");
    let observations = observation_rows(&app, invoice_id).await;
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].0, "mismatched");

    // Critical anomaly signal recorded against the intent.
    let anomalies: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT signal_type, severity, status, resource_type, resource_id \
         FROM payment_anomaly_signals WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(&app.db.pool)
    .await
    .unwrap();
    assert_eq!(anomalies.len(), 1);
    assert_eq!(anomalies[0].0, "kpr1_output_mismatch");
    assert_eq!(anomalies[0].1, "critical");
    assert_eq!(anomalies[0].3, "kpr1_payment_intent");
    assert_eq!(anomalies[0].4, intent_id);

    // Terminal: next tick does nothing (no duplicate anomaly).
    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 0);
    assert_eq!(
        count(&app, "SELECT COUNT(*) FROM payment_anomaly_signals WHERE user_id = $1", user_id).await,
        1
    );
}

// Overfunded covenant (gross + 1): fail closed with `covenant_overfunded`.
#[tokio::test]
async fn overfunded_covenant_fails_closed() {
    let app = spawn_covenant_app().await;
    let (_token, _user_id, invoice, cov_addr, gross) =
        setup_finalized_intent(&app, "chain4@example.com").await;
    let invoice_id = invoice["id"].as_i64().unwrap();
    let public_id = invoice["publicId"].as_str().unwrap();

    let tx_id = "dd78bb90dd78bb90dd78bb90dd78bb90dd78bb90dd78bb90dd78bb90dd78bb90";
    submit_tx(&app, public_id, tx_id).await;

    let chain = MockChain::default();
    chain.set_tx(tx_id, vec![(cov_addr.clone(), gross as u64 + 1)], Some(4_000));
    chain.set_virtual_daa(4_050);

    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 1);

    let (status, _) = invoice_row(&app, invoice_id).await;
    assert_eq!(status, "open");
    let (intent_status, verification_status, failure_reason, covenant_state) =
        intent_row(&app, invoice_id).await;
    assert_eq!(intent_status, "failed");
    assert_eq!(verification_status.as_deref(), Some("failed"));
    assert_eq!(failure_reason.as_deref(), Some("covenant_overfunded"));
    assert_eq!(covenant_state, "failed");
}

// Two outputs to the covenant address that SUM to gross: fail closed with
// `covenant_output_count`. The covenant is ONE UTXO worth exactly gross; two
// half-value UTXOs are unspendable and must never count as funding.
#[tokio::test]
async fn split_covenant_funding_fails_closed() {
    let app = spawn_covenant_app().await;
    let (_token, user_id, invoice, cov_addr, gross) =
        setup_finalized_intent(&app, "chain6@example.com").await;
    let invoice_id = invoice["id"].as_i64().unwrap();
    let public_id = invoice["publicId"].as_str().unwrap();

    let tx_id = "ff12dd34ff12dd34ff12dd34ff12dd34ff12dd34ff12dd34ff12dd34ff12dd34";
    submit_tx(&app, public_id, tx_id).await;

    let chain = MockChain::default();
    let half = gross as u64 / 2;
    chain.set_tx(tx_id, vec![(cov_addr.clone(), half), (cov_addr.clone(), gross as u64 - half)], Some(6_000));
    chain.set_virtual_daa(6_050); // plenty of confirmations — must still fail

    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 1);

    let (status, paid_at) = invoice_row(&app, invoice_id).await;
    assert_eq!(status, "open");
    assert!(paid_at.is_none());
    let (intent_status, verification_status, failure_reason, covenant_state) =
        intent_row(&app, invoice_id).await;
    assert_eq!(intent_status, "failed");
    assert_eq!(verification_status.as_deref(), Some("failed"));
    assert_eq!(failure_reason.as_deref(), Some("covenant_output_count"));
    assert_eq!(covenant_state, "failed");
    let observations = observation_rows(&app, invoice_id).await;
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].0, "mismatched");

    let anomalies: Vec<(String, String)> =
        sqlx::query_as("SELECT signal_type, severity FROM payment_anomaly_signals WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&app.db.pool)
            .await
            .unwrap();
    assert_eq!(anomalies, vec![("kpr1_output_mismatch".to_string(), "critical".to_string())]);
    // Never funded: no payment.confirmed either.
    assert_eq!(count(&app, "SELECT COUNT(*) FROM webhook_events WHERE user_id = $1", user_id).await, 0);
}

// Unobserved tx: nothing on chain yet -> no progress, intent keeps waiting.
#[tokio::test]
async fn unobserved_tx_keeps_waiting() {
    let app = spawn_covenant_app().await;
    let (_token, _user_id, invoice, _cov_addr, _gross) =
        setup_finalized_intent(&app, "chain5@example.com").await;
    let invoice_id = invoice["id"].as_i64().unwrap();
    let public_id = invoice["publicId"].as_str().unwrap();

    let tx_id = "ee90cc12ee90cc12ee90cc12ee90cc12ee90cc12ee90cc12ee90cc12ee90cc12";
    submit_tx(&app, public_id, tx_id).await;

    let chain = MockChain::default(); // tx not registered — not visible on chain
    chain.set_virtual_daa(5_000);

    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 0);

    let (status, _) = invoice_row(&app, invoice_id).await;
    assert_eq!(status, "open");
    let (_, _, _, covenant_state) = intent_row(&app, invoice_id).await;
    assert_eq!(covenant_state, "awaiting_funding");
    assert!(observation_rows(&app, invoice_id).await.is_empty());
}
