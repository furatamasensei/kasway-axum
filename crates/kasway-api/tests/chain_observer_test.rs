//! Chain observer (`kasway_api::chain_observer`): txid-driven on-chain
//! verification of wallet-submitted KPR-1 payments. Ticks are driven directly
//! with an in-memory `ChainSource`; no polling loop, no real node.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use kasway_api::chain_observer;
use kasway_api::chain_source::{ChainSource, ChainSourceError, ObservedOutput, ObservedTransaction};
use serde_json::{json, Value};

/// Merchant payout address seeded into the Setup (drives merchant_net output).
const MERCHANT_ADDR: &str = "kaspatest:merchantpayout00001";

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

/// Register a merchant with a store + Kaspa setup and create an open invoice
/// via the API (mints a real KPR-1 intent). Returns (token, user_id, invoice).
async fn setup_invoice(app: &common::TestApp, email: &str) -> (String, i64, Value) {
    let token = common::register_merchant(app, email, "secret123").await;
    let user_id = common::merchant_user_id(&app.db, email).await;
    let store_id = common::seed_default_store(&app.db, user_id).await;
    common::seed_setup(&app.db, user_id, store_id, MERCHANT_ADDR).await;

    let res = app
        .client
        .post(app.url("/api/invoices"))
        .bearer_auth(&token)
        .json(&json!({ "items": [{ "name": "Widget", "quantity": 1, "unitAmount": "100000000" }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "invoice create should succeed");
    let invoice: Value = res.json().await.unwrap();
    (token, user_id, invoice)
}

/// The intent's required outputs as (address, amount sompi) pairs.
fn required_outputs(invoice: &Value) -> Vec<(String, u64)> {
    invoice["requiredOutputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| {
            (
                o["address"].as_str().unwrap().to_string(),
                o["amountSompi"].as_str().unwrap().parse().unwrap(),
            )
        })
        .collect()
}

/// Wallet submits the tx id for the invoice's intent (public checkout).
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

type IntentRow = (String, Option<String>, Option<String>, Option<String>);

async fn intent_row(app: &common::TestApp, invoice_id: i64) -> IntentRow {
    sqlx::query_as(
        "SELECT status, verification_status, failure_reason, settled_at \
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

// ---------- tests ----------

// Happy path: submitted -> observed with enough confirmations -> settled in
// one tick: observation row, confirmed payment, invoice paid, invoice.paid
// event + pending delivery, checkpoint updated. Second tick is a no-op.
#[tokio::test]
async fn observed_payment_with_enough_confirmations_pays_invoice() {
    let app = common::spawn_app().await;
    let (token, user_id, invoice) = setup_invoice(&app, "chain1@example.com").await;
    let invoice_id = invoice["id"].as_i64().unwrap();
    let public_id = invoice["publicId"].as_str().unwrap();
    let endpoint_id = subscribe_invoice_paid(&app, &token).await;

    let tx_id = "ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34ab12cd34";
    submit_tx(&app, public_id, tx_id).await;

    let chain = MockChain::default();
    chain.set_tx(tx_id, required_outputs(&invoice), Some(1_000));
    chain.set_virtual_daa(1_015); // 15 confirmations >= platform default 10

    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 1);

    // invoice paid
    let (status, paid_at) = invoice_row(&app, invoice_id).await;
    assert_eq!(status, "paid");
    assert!(paid_at.is_some());

    // confirmed payment row for the full amount
    let payments: Vec<(String, i64, Option<String>)> =
        sqlx::query_as("SELECT status, amount, metadata FROM payments WHERE invoice_id = $1")
            .bind(invoice_id)
            .fetch_all(&app.db.pool)
            .await
            .unwrap();
    assert_eq!(payments.len(), 1);
    assert_eq!(payments[0].0, "confirmed");
    assert_eq!(payments[0].1, 100_000_000);
    let payment_meta: Value = serde_json::from_str(payments[0].2.as_deref().unwrap()).unwrap();
    assert_eq!(payment_meta["source"], "chain_observer");
    assert_eq!(payment_meta["txId"], tx_id);

    // observation row settled with the observed facts + kpr1 metadata
    let observations = observation_rows(&app, invoice_id).await;
    assert_eq!(observations.len(), 1);
    let (obs_status, amount, confirmations, obs_tx, block_daa, metadata) = &observations[0];
    assert_eq!(obs_status, "settled");
    assert_eq!(*amount, 100_000_000);
    assert_eq!(*confirmations, 15);
    assert_eq!(obs_tx.as_deref(), Some(tx_id));
    assert_eq!(*block_daa, Some(1_000));
    let meta: Value = serde_json::from_str(metadata.as_deref().unwrap()).unwrap();
    assert_eq!(meta["kpr1"]["intentId"], invoice["kpr1PaymentIntent"]["intentId"]);
    let meta_outputs = meta["kpr1"]["outputs"].as_array().unwrap();
    assert_eq!(meta_outputs.len(), 2);
    assert!(meta_outputs.iter().any(|o| o["role"] == "merchant_net"));
    assert!(meta_outputs.iter().any(|o| o["role"] == "kasway_fee"));

    // intent settled + verified
    let (intent_status, verification_status, failure_reason, settled_at) =
        intent_row(&app, invoice_id).await;
    assert_eq!(intent_status, "settled");
    assert_eq!(verification_status.as_deref(), Some("verified"));
    assert!(failure_reason.is_none());
    assert!(settled_at.is_some());

    // invoice.paid event + pending delivery for the subscribed endpoint
    let events: Vec<(i64, String, String, String)> = sqlx::query_as(
        "SELECT id, event_type, resource_type, resource_id FROM webhook_events WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(&app.db.pool)
    .await
    .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].1, "invoice.paid");
    assert_eq!(events[0].2, "invoice");
    assert_eq!(events[0].3, public_id);
    let deliveries: Vec<(i64, String)> = sqlx::query_as(
        "SELECT webhook_endpoint_id, status FROM webhook_deliveries WHERE webhook_event_id = $1",
    )
    .bind(events[0].0)
    .fetch_all(&app.db.pool)
    .await
    .unwrap();
    assert_eq!(deliveries, vec![(endpoint_id, "pending".to_string())]);

    // event payload is the serialized paid invoice
    let payload: String =
        sqlx::query_scalar("SELECT payload FROM webhook_events WHERE id = $1")
            .bind(events[0].0)
            .fetch_one(&app.db.pool)
            .await
            .unwrap();
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload["status"], "paid");
    assert_eq!(payload["publicId"], public_id);

    // observer checkpoint tracks the virtual DAA score
    let checkpoint: Option<String> = sqlx::query_scalar(
        "SELECT checkpoint FROM payment_indexer_checkpoints \
         WHERE network = 'tn10' AND asset_id = 'KAS' AND source = 'chain_observer'",
    )
    .fetch_one(&app.db.pool)
    .await
    .unwrap();
    assert_eq!(checkpoint.as_deref(), Some("1015"));

    // settled intent is terminal: the next tick has nothing to do
    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 0);
}

// Insufficient confirmations: observation is recorded and the intent is
// verified, but the invoice stays open until the policy is met — then a later
// tick settles by updating the same observation row.
#[tokio::test]
async fn insufficient_confirmations_stay_pending_until_policy_met() {
    let app = common::spawn_app().await;
    let (_token, user_id, invoice) = setup_invoice(&app, "chain2@example.com").await;
    let invoice_id = invoice["id"].as_i64().unwrap();
    let public_id = invoice["publicId"].as_str().unwrap();

    let tx_id = "bb34ee56bb34ee56bb34ee56bb34ee56bb34ee56bb34ee56bb34ee56bb34ee56";
    submit_tx(&app, public_id, tx_id).await;

    let chain = MockChain::default();
    chain.set_tx(tx_id, required_outputs(&invoice), Some(2_000));
    chain.set_virtual_daa(2_003); // 3 confirmations < platform default 10

    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 1);

    // invoice still open, no payment yet, no invoice.paid event
    let (status, paid_at) = invoice_row(&app, invoice_id).await;
    assert_eq!(status, "open");
    assert!(paid_at.is_none());
    let payment_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM payments WHERE invoice_id = $1")
            .bind(invoice_id)
            .fetch_one(&app.db.pool)
            .await
            .unwrap();
    assert_eq!(payment_count, 0);
    let event_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM webhook_events WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&app.db.pool)
            .await
            .unwrap();
    assert_eq!(event_count, 0);

    // observation matched with 3 confirmations; intent verified, not settled
    let observations = observation_rows(&app, invoice_id).await;
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].0, "matched");
    assert_eq!(observations[0].2, 3);
    let (intent_status, verification_status, _, settled_at) = intent_row(&app, invoice_id).await;
    assert_eq!(intent_status, "verified");
    assert_eq!(verification_status.as_deref(), Some("verified"));
    assert!(settled_at.is_none());

    // confirmations catch up -> the same observation row settles the invoice
    chain.set_virtual_daa(2_012);
    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 1);

    let (status, _) = invoice_row(&app, invoice_id).await;
    assert_eq!(status, "paid");
    let observations = observation_rows(&app, invoice_id).await;
    assert_eq!(observations.len(), 1, "observation row is updated, not duplicated");
    assert_eq!(observations[0].0, "settled");
    assert_eq!(observations[0].2, 12);
    let event_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM webhook_events WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&app.db.pool)
            .await
            .unwrap();
    assert_eq!(event_count, 1);
}

// Wrong amount on a required output: fail closed — intent failed with a
// stable reason + anomaly signal, invoice NOT paid, no event. The failed
// intent is terminal for the observer.
#[tokio::test]
async fn output_amount_mismatch_fails_closed() {
    let app = common::spawn_app().await;
    let (_token, user_id, invoice) = setup_invoice(&app, "chain3@example.com").await;
    let invoice_id = invoice["id"].as_i64().unwrap();
    let public_id = invoice["publicId"].as_str().unwrap();
    let intent_id = invoice["kpr1PaymentIntent"]["intentId"].as_str().unwrap();

    let tx_id = "cc56aa78cc56aa78cc56aa78cc56aa78cc56aa78cc56aa78cc56aa78cc56aa78";
    submit_tx(&app, public_id, tx_id).await;

    // merchant_net output short by 1 sompi; fee output correct
    let mut outputs = required_outputs(&invoice);
    let merchant = outputs.iter_mut().find(|(a, _)| a == MERCHANT_ADDR).unwrap();
    merchant.1 -= 1;

    let chain = MockChain::default();
    chain.set_tx(tx_id, outputs, Some(3_000));
    chain.set_virtual_daa(3_050); // plenty of confirmations — must still fail

    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 1);

    // invoice NOT paid, no payment, no invoice.paid event
    let (status, paid_at) = invoice_row(&app, invoice_id).await;
    assert_eq!(status, "open");
    assert!(paid_at.is_none());
    let payment_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM payments WHERE invoice_id = $1")
            .bind(invoice_id)
            .fetch_one(&app.db.pool)
            .await
            .unwrap();
    assert_eq!(payment_count, 0);
    let event_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM webhook_events WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&app.db.pool)
            .await
            .unwrap();
    assert_eq!(event_count, 0);

    // intent failed with the stable reason; discrepancy recorded
    let (intent_status, verification_status, failure_reason, _) = intent_row(&app, invoice_id).await;
    assert_eq!(intent_status, "failed");
    assert_eq!(verification_status.as_deref(), Some("failed"));
    assert_eq!(failure_reason.as_deref(), Some("amount_mismatch"));
    let observations = observation_rows(&app, invoice_id).await;
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].0, "mismatched");

    // anomaly signal records the discrepancy against the intent
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

    // failed intent is terminal: nothing to do next tick
    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 0);
}

// Missing required fee output: fail closed with the role-specific reason.
#[tokio::test]
async fn missing_fee_output_fails_closed() {
    let app = common::spawn_app().await;
    let (_token, _user_id, invoice) = setup_invoice(&app, "chain4@example.com").await;
    let invoice_id = invoice["id"].as_i64().unwrap();
    let public_id = invoice["publicId"].as_str().unwrap();

    let tx_id = "dd78bb90dd78bb90dd78bb90dd78bb90dd78bb90dd78bb90dd78bb90dd78bb90";
    submit_tx(&app, public_id, tx_id).await;

    // only the merchant output is present — the kasway_fee output is missing
    let outputs: Vec<(String, u64)> = required_outputs(&invoice)
        .into_iter()
        .filter(|(a, _)| a == MERCHANT_ADDR)
        .collect();

    let chain = MockChain::default();
    chain.set_tx(tx_id, outputs, Some(4_000));
    chain.set_virtual_daa(4_050);

    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 1);

    let (status, _) = invoice_row(&app, invoice_id).await;
    assert_eq!(status, "open");
    let (intent_status, verification_status, failure_reason, _) = intent_row(&app, invoice_id).await;
    assert_eq!(intent_status, "failed");
    assert_eq!(verification_status.as_deref(), Some("failed"));
    assert_eq!(failure_reason.as_deref(), Some("missing_required_kasway_fee_output"));
}

// Unobserved tx: nothing changes, the intent keeps waiting.
#[tokio::test]
async fn unobserved_tx_keeps_waiting() {
    let app = common::spawn_app().await;
    let (_token, _user_id, invoice) = setup_invoice(&app, "chain5@example.com").await;
    let invoice_id = invoice["id"].as_i64().unwrap();
    let public_id = invoice["publicId"].as_str().unwrap();

    let tx_id = "ee90cc12ee90cc12ee90cc12ee90cc12ee90cc12ee90cc12ee90cc12ee90cc12";
    submit_tx(&app, public_id, tx_id).await;

    let chain = MockChain::default(); // knows no transactions
    chain.set_virtual_daa(5_000);

    let progressed = chain_observer::run_tick(&app.state, &chain).await.unwrap();
    assert_eq!(progressed, 0);

    let (status, _) = invoice_row(&app, invoice_id).await;
    assert_eq!(status, "open");
    let (intent_status, verification_status, _, _) = intent_row(&app, invoice_id).await;
    assert_eq!(intent_status, "submitted");
    assert!(verification_status.is_none());
    assert!(observation_rows(&app, invoice_id).await.is_empty());
}

// Env gate: default off without KASPA_NODE_URL, on with it, and
// CHAIN_OBSERVER_ENABLED overrides in both directions.
#[tokio::test]
async fn enabled_from_env_gate() {
    // Only this test touches these env vars, so mutation is race-free.
    std::env::remove_var("CHAIN_OBSERVER_ENABLED");
    std::env::remove_var("KASPA_NODE_URL");
    assert!(!chain_observer::enabled_from_env());

    std::env::set_var("KASPA_NODE_URL", "ws://127.0.0.1:17210");
    assert!(chain_observer::enabled_from_env());

    std::env::set_var("CHAIN_OBSERVER_ENABLED", "0");
    assert!(!chain_observer::enabled_from_env());

    std::env::remove_var("KASPA_NODE_URL");
    std::env::set_var("CHAIN_OBSERVER_ENABLED", "1");
    assert!(chain_observer::enabled_from_env());

    std::env::remove_var("CHAIN_OBSERVER_ENABLED");
}
