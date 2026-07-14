//! Integration-test harness: boots the real router on an ephemeral port over a
//! fresh disposable PostgreSQL database, and hands back a reqwest client + base URL.

#![allow(dead_code)]

use std::sync::Arc;

use kasway_api::state::{AppConfig, AppState};
use kasway_db::Db;

pub const INTERNAL_TOKEN: &str = "test-internal-token";

pub struct TestApp {
    pub base_url: String,
    pub client: reqwest::Client,
    pub db: Db,
    pub state: AppState,
}

impl TestApp {
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

/// Spawn the app with an internal token configured.
pub async fn spawn_app() -> TestApp {
    spawn_with(Some(INTERNAL_TOKEN.to_string())).await
}

/// Spawn with explicit internal-token config (None => `internalApiToken` 503s).
pub async fn spawn_with(internal_api_token: Option<String>) -> TestApp {
    spawn_with_config(|c| c.internal_api_token = Some(INTERNAL_TOKEN.to_string()), internal_api_token.is_none()).await
}

/// Spawn the app with a custom config mutator (for OAuth endpoint overrides etc).
/// `clear_internal_token` removes the internal token after the mutator runs.
pub async fn spawn_with_config(mutate: impl FnOnce(&mut AppConfig), clear_internal_token: bool) -> TestApp {
    let db = Db::connect_memory().await.expect("connect test db");

    let mut config = AppConfig::test_default();
    config.internal_api_token = Some(INTERNAL_TOKEN.to_string());
    mutate(&mut config);
    if clear_internal_token {
        config.internal_api_token = None;
    }

    let state = AppState {
        db: db.clone(),
        config: Arc::new(config),
        events: kasway_api::events::InvoiceEvents::new(),
    };

    let app = kasway_api::build_router(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    TestApp {
        base_url: format!("http://{addr}"),
        client: reqwest::Client::new(),
        db,
        state,
    }
}

/// Register a merchant via the public endpoint and return its Bearer token.
pub async fn register_merchant(app: &TestApp, email: &str, password: &str) -> String {
    let res = app
        .client
        .post(app.url("/api/auth/register"))
        .json(&serde_json::json!({
            "fullName": "Test User",
            "email": email,
            "password": password,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200, "register should succeed");
    let body: serde_json::Value = res.json().await.unwrap();
    body["token"].as_str().unwrap().to_string()
}

/// Look up a user id by email (after `register_merchant`).
pub async fn merchant_user_id(db: &Db, email: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_one(&db.pool)
        .await
        .expect("user id by email")
}

/// Insert an api_keys row directly (deterministic created_at for ordering tests).
pub async fn seed_api_key(
    db: &Db,
    user_id: i64,
    name: &str,
    prefix: &str,
    scopes_json: &str,
    created_at: &str,
) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(user_id)
    .bind(name)
    .bind(prefix)
    .bind(format!("hash_{prefix}"))
    .bind(scopes_json)
    .bind(created_at)
    .bind(created_at)
    .fetch_one(&db.pool)
    .await
    .expect("seed api key")
}

/// Insert a currency row directly; returns its id.
pub async fn seed_currency(db: &Db, code: &str, name: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO currencies (type, code, name, symbol, country, locale, created_at, updated_at) \
         VALUES ('fiat', $1, $2, '$', 'US', 'en-US', $3, $4) RETURNING id",
    )
    .bind(code)
    .bind(name)
    .bind("2026-01-01T00:00:00.000+00:00")
    .bind("2026-01-01T00:00:00.000+00:00")
    .fetch_one(&db.pool)
    .await
    .expect("seed currency")
}

/// Seed the per-user default store (+ included entitlement); returns store id.
pub async fn seed_default_store(db: &Db, user_id: i64) -> i64 {
    let now = "2026-01-01T00:00:00.000+00:00";
    let store_id: i64 = sqlx::query_scalar(
        "INSERT INTO stores (user_id, public_id, name, slug, status, is_included, is_default, metadata, created_at, updated_at) \
         VALUES ($1, $2, 'Default store', 'default', 'active', 1, 1, '{\"backfilled\":true}', $3, $4) RETURNING id",
    )
    .bind(user_id)
    .bind(format!("store_{user_id}_default"))
    .bind(now)
    .bind(now)
    .fetch_one(&db.pool)
    .await
    .expect("seed store");

    sqlx::query(
        "INSERT INTO store_entitlements (user_id, store_id, status, source, price_cents, currency, created_at, updated_at) \
         VALUES ($1, $2, 'active', 'included', 0, 'USD', $3, $4)",
    )
    .bind(user_id)
    .bind(store_id)
    .bind(now)
    .bind(now)
    .execute(&db.pool)
    .await
    .expect("seed entitlement");

    store_id
}

/// Seed a Setup with a Kaspa payout address (required by the KPR-1 minter).
pub async fn seed_setup(db: &Db, user_id: i64, store_id: i64, kaspa_main_address: &str) {
    sqlx::query(
        "INSERT INTO setups (user_id, store_id, tos_agreed, kaspa_main_address, created_at, updated_at) \
         VALUES ($1, $2, 1, $3, '2026-01-01T00:00:00.000+00:00', '2026-01-01T00:00:00.000+00:00')",
    )
    .bind(user_id)
    .bind(store_id)
    .bind(kaspa_main_address)
    .execute(&db.pool)
    .await
    .expect("seed setup");
}

/// Seed an invoice; returns its id. Non-listed fields use sensible defaults.
#[allow(clippy::too_many_arguments)]
pub async fn seed_invoice(
    db: &Db,
    user_id: i64,
    store_id: i64,
    public_id: &str,
    status: &str,
    subtotal: i64,
    total: i64,
    service_fee: i64,
    payment_link_id: Option<i64>,
    expires_at: Option<&str>,
    created_at: &str,
) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO invoices \
         (user_id, store_id, public_id, status, payment_address, payment_network, payment_asset, \
          payment_reference, subtotal_amount, total_amount, fee_delegation, service_fee_amount, \
          currency, payment_link_id, metadata, expires_at, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, 'tn10', 'KAS', $6, $7, $8, 'merchant_subsidized', $9, 'KAS', $10, NULL, $11, $12, $13) RETURNING id",
    )
    .bind(user_id)
    .bind(store_id)
    .bind(public_id)
    .bind(status)
    .bind(format!("kpr1:pending:{public_id}"))
    .bind(format!("payref_{public_id}"))
    .bind(subtotal)
    .bind(total)
    .bind(service_fee)
    .bind(payment_link_id)
    .bind(expires_at)
    .bind(created_at)
    .bind(created_at)
    .fetch_one(&db.pool)
    .await
    .expect("seed invoice")
}

/// Seed an invoice item; returns its id.
pub async fn seed_invoice_item(
    db: &Db,
    invoice_id: i64,
    name: &str,
    quantity: i64,
    unit_amount: i64,
    total_amount: i64,
) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO invoice_items (invoice_id, name, quantity, unit_amount, total_amount, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, '2026-01-01T00:00:00.000+00:00', '2026-01-01T00:00:00.000+00:00') RETURNING id",
    )
    .bind(invoice_id)
    .bind(name)
    .bind(quantity)
    .bind(unit_amount)
    .bind(total_amount)
    .fetch_one(&db.pool)
    .await
    .expect("seed invoice item")
}

/// Seed a KPR-1 payment intent for an invoice (stubbed crypto fields).
pub async fn seed_kpr1_intent(db: &Db, invoice_id: i64, user_id: i64, intent_id: &str) -> i64 {
    let outputs = r#"[{"role":"merchant_net","address":"kaspatest:merchant","amountSompi":"900"},{"role":"split","address":"kaspatest:partner","amountSompi":"100","percentage":10}]"#;
    sqlx::query_scalar(
        "INSERT INTO kpr1_payment_intents \
         (invoice_id, user_id, intent_id, status, network, asset_id, amount_sompi, platform_fee_bps, \
          platform_fee_amount, merchant_address, platform_fee_address, template_id, template_version, \
          script_hash, canonical_hash, payment_request_uri, payment_intent_url, signature_algorithm, \
          signature_key_id, signature_value, required_outputs, canonical_intent, expires_at, created_at, updated_at) \
         VALUES ($1, $2, $3, 'created', 'tn10', 'KAS', 1000, 100, 10, 'kaspatest:merchant', 'kaspatest:fee', \
          'covenant-v1', '1', $4, $5, $6, $7, 'ed25519', 'key-1', 'sig', $8, '{}', \
          '2026-12-01T00:00:00.000+00:00', '2026-01-01T00:00:00.000+00:00', '2026-01-01T00:00:00.000+00:00') RETURNING id",
    )
    .bind(invoice_id)
    .bind(user_id)
    .bind(intent_id)
    .bind(format!("scripthash_{intent_id}"))
    .bind(format!("canon_{intent_id}"))
    .bind(format!("kaspa:?address=kaspatest:merchant&intent={intent_id}"))
    .bind(format!("https://pay.kasway.test/i/{intent_id}"))
    .bind(outputs)
    .fetch_one(&db.pool)
    .await
    .expect("seed intent")
}

/// Insert a payment_indexer_checkpoint row; returns its id.
pub async fn seed_checkpoint(
    db: &Db,
    network: &str,
    asset_id: &str,
    source: &str,
    checkpoint: Option<&str>,
    metadata: Option<&str>,
    updated_at: &str,
) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO payment_indexer_checkpoints \
         (network, asset_id, source, checkpoint, metadata, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(network)
    .bind(asset_id)
    .bind(source)
    .bind(checkpoint)
    .bind(metadata)
    .bind(updated_at)
    .bind(updated_at)
    .fetch_one(&db.pool)
    .await
    .expect("seed checkpoint")
}

/// Register a merchant with the standard test password; returns the bearer token.
pub async fn merchant(app: &TestApp, email: &str) -> String {
    register_merchant(app, email, "secret123").await
}

/// Register a merchant plus a default store and payout setup; returns the token.
pub async fn merchant_with_setup(app: &TestApp, email: &str) -> String {
    let token = register_merchant(app, email, "secret123").await;
    let uid = merchant_user_id(&app.db, email).await;
    let store = seed_default_store(&app.db, uid).await;
    seed_setup(&app.db, uid, store, "kaspatest:merchantpayout00001").await;
    token
}
