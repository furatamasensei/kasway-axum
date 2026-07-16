//! TN10 end-to-end smoke test for **subscription autopay** (Subscription Pocket).
//!
//! Boots the REAL router over a fresh disposable PostgreSQL database, drives the
//! full merchant + public-checkout API surface with reqwest, then proves the
//! SubscriptionV1 covenant on a LIVE testnet-10 node:
//!
//! - Phase 1 (API, no chain): register/login → setup → plan → customer →
//!   subscription (`wallet_autopay`) → cycle-1 invoice + webhook event →
//!   public status → `autopay/prepare` (cross-checked against a locally
//!   compiled covenant P2SH) → funding-txid record → webhook endpoint towards
//!   a local sink.
//! - Phase 2 (on-chain): installs a mini-period cell (`period_daa = 60`,
//!   ~6s on TN10) at the same payout split, funds it from the keeper fee
//!   wallet (2×claim_total + 1 TKAS), then drives `subscription_keeper::run_tick`
//!   until cycle 1 is claimed, forces `next_billing_at` into the past, bills
//!   cycle 2 via `subscription_biller::run_tick`, and proves cycle 2 is claimed
//!   from the FIRST claim's remainder (covenant self-replication on-chain).
//! - Phase 3: customer `withdraw` (schnorr-signed sighash) empties the cell to
//!   the payer address, then `cancel` with a signature over the cancel
//!   challenge; webhook deliveries are asserted against the local sink.
//!
//! # Safety
//! - Secrets come from `.env` / the environment and are NEVER printed.
//! - Spends only from the keeper fee wallet (`COVENANT_KEEPER_FEE_SECRET`),
//!   which doubles as the smoke "customer"/payer key. If it is underfunded the
//!   run aborts and prints the ADDRESS to top up (via the TN10 faucet).
//!
//! # Usage
//! ```text
//! cargo run -p kasway-api --example subscription_tn10_smoke
//! ```
//! Reads `.env` at the workspace root (values already present in the
//! environment win). Requires: `KASPA_NODE_URL`, `COVENANT_KEEPER_FEE_SECRET`,
//! `KASWAY_PLATFORM_FEE_ADDRESS`, and local PostgreSQL (default
//! `postgres://postgres:postgres@localhost:5432`, override `SMOKE_DATABASE_URL`).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kaspa_consensus_core::hashing::sighash::{
    calc_schnorr_signature_hash, SigHashReusedValuesUnsync,
};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::units::ComputeBudget;
use kaspa_consensus_core::tx::{
    ComputeCommit, MutableTransaction, Transaction, TransactionId, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::pay_to_address_script;
use kaspa_txscript::script_builder::ScriptBuilder;
use kasway_api::chain_source::ChainSource;
use kasway_api::kaspa_wrpc::KaspaWrpcClient;
use kasway_api::state::{AppConfig, AppState};
use kasway_api::util::to_iso;
use kasway_covenant::subscription_v1::{compile_subscription_v1, SubscriptionV1Params};
use kasway_covenant::{
    covenant_address, network_prefix, rpc_submit_params, Destination, KeeperKey, Payout,
    SignedSpend, Utxo, FEE_COMPUTE_BUDGET,
};
use serde_json::{json, Value};
use sha2::Digest;

/// Plan price per period: 5 TKAS (well above the 2 TKAS covenant floor + fee).
const PLAN_AMOUNT: u64 = 500_000_000;
/// Phase-2 claim period: 60 DAA ≈ 6 seconds at TN10's 10 bps.
const MINI_PERIOD_DAA: u64 = 60;
/// Extra on top of 2×claim_total so a remainder survives claim 2 for withdraw.
const FUND_EXTRA: u64 = 100_000_000;
/// Miner fee for the plain P2PK funding send (generous; simple tx is ~2k mass).
const FUNDING_FEE: u64 = 1_000_000;
/// Poll cadence / deadline for chain-dependent steps.
const POLL_SECS: u64 = 2;
const CHAIN_DEADLINE_SECS: u64 = 180;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::try_init().ok();
    let t0 = Instant::now();
    match run().await {
        Ok(()) => println!(
            "\nDONE in {:.0?} — subscription autopay proven end-to-end on TN10.",
            t0.elapsed()
        ),
        Err(e) => {
            eprintln!("\nFAILED after {:.0?}: {e}", t0.elapsed());
            std::process::exit(1);
        }
    }
}

fn step(n: u32, msg: impl AsRef<str>) {
    println!("[{n:>2}] {}", msg.as_ref());
}

fn check(cond: bool, msg: &str) -> Result<(), String> {
    if cond {
        Ok(())
    } else {
        Err(format!("assertion failed: {msg}"))
    }
}

fn es(e: impl std::fmt::Display) -> String {
    e.to_string()
}

async fn run() -> Result<(), String> {
    // -----------------------------------------------------------------------
    // Boot: env, node, wallet, fresh DB, router, webhook sink.
    // -----------------------------------------------------------------------
    load_dotenv();
    // The smoke must run with captcha bypassed and no production panics.
    std::env::set_var("NODE_ENV", "development");
    std::env::remove_var("TURNSTILE_SECRET");
    step(1, ".env loaded (secrets stay unprinted)");

    let client = KaspaWrpcClient::from_env().ok_or("KASPA_NODE_URL is not set")?;
    let daa = client.virtual_daa_score().await.map_err(es)?;
    step(2, format!("node reachable: virtualDaaScore={daa}"));

    let payer = env_key("COVENANT_KEEPER_FEE_SECRET")?; // keeper fee wallet = smoke payer/customer
    env_key("COVENANT_ARBITER_SECRET")?; // present per the environment contract (unused on this path)
    let prefix = network_prefix("tn10").map_err(es)?;
    let payer_addr = payer.address(prefix).to_string();
    let wallet_utxos = client.fetch_utxos(&payer_addr).await.map_err(es)?;
    let balance: u64 = wallet_utxos.iter().map(|(_, _, v)| v).sum();
    let fund_total = PLAN_AMOUNT * 2 + FUND_EXTRA;
    let need = fund_total + FUNDING_FEE + 200_000_000; // + keeper gas & change floor
    if balance < need {
        return Err(format!(
            "keeper/payer wallet underfunded on TN10: balance {balance} sompi < required {need}. \
             Top it up via the faucet at address {payer_addr}"
        ));
    }
    step(
        3,
        format!(
            "wallet {payer_addr}: {balance} sompi across {} utxo(s)",
            wallet_utxos.len()
        ),
    );

    let db_name = format!(
        "kasway_smoke_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );
    let db = fresh_db(&db_name).await?;
    step(4, format!("database {db_name} created + migrated"));

    let config = AppConfig::from_env();
    check(
        config.captcha_ok(None, None).await,
        "captcha_ok must bypass with TURNSTILE unset outside production",
    )?;
    check(
        config.covenant.keeper_fee_secret_hex.is_some(),
        "COVENANT_KEEPER_FEE_SECRET must reach AppConfig",
    )?;
    let state = AppState {
        db: db.clone(),
        config: Arc::new(config),
    };
    let app = kasway_api::build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(es)?;
    let base = format!("http://{}", listener.local_addr().map_err(es)?);
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    step(
        5,
        format!("api listening at {base} (captcha bypass verified)"),
    );

    // Local webhook sink: records X-Kasway-Event of every delivery it receives.
    let sink: Arc<Mutex<Vec<String>>> = Arc::default();
    let sink_handler = sink.clone();
    let hook_app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |headers: axum::http::HeaderMap| {
            let sink = sink_handler.clone();
            async move {
                let ev = headers
                    .get("x-kasway-event")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                sink.lock().unwrap().push(ev);
                "ok"
            }
        }),
    );
    let hook_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(es)?;
    let hook_url = format!("http://{}/hook", hook_listener.local_addr().map_err(es)?);
    tokio::spawn(async move {
        axum::serve(hook_listener, hook_app)
            .await
            .expect("serve sink");
    });
    step(6, format!("webhook sink at {hook_url}"));

    // -----------------------------------------------------------------------
    // Phase 1 — API surface (no chain).
    // -----------------------------------------------------------------------
    let http = reqwest::Client::new();
    let email = format!("{db_name}@smoke.test");
    let (st, _) = post(
        &http,
        &base,
        "/api/auth/register",
        None,
        &json!({ "fullName": "TN10 Smoke", "email": email, "password": "smoke-secret-1" }),
    )
    .await?;
    check(st == 200, "register must return 200")?;
    let (st, login) = post(
        &http,
        &base,
        "/api/auth/login",
        None,
        &json!({ "email": email, "password": "smoke-secret-1" }),
    )
    .await?;
    check(st == 200, "login must return 200")?;
    let token = login["token"]
        .as_str()
        .ok_or("login token missing")?
        .to_string();
    step(7, "merchant registered + logged in");

    let (st, _) = post(
        &http,
        &base,
        "/api/setup",
        Some(&token),
        &json!({ "kaspa": { "mainAddress": payer_addr } }),
    )
    .await?;
    check(st == 200, "POST /api/setup must return 200")?;
    step(8, format!("setup stored: payout={payer_addr}"));

    let (st, plan) = post(&http, &base, "/api/commerce/subscription-plans", Some(&token),
        &json!({ "name": "Pocket TN10", "amount": PLAN_AMOUNT.to_string(), "intervalUnit": "day", "intervalCount": 1 })).await?;
    check(st == 201, "plan create must return 201")?;
    let plan_pid = plan["publicId"]
        .as_str()
        .ok_or("plan publicId missing")?
        .to_string();
    step(9, format!("plan {plan_pid} created (5 TKAS / 1 day)"));

    let (st, cust) = post(
        &http,
        &base,
        "/api/commerce/subscription-customers",
        Some(&token),
        &json!({ "email": "buyer@smoke.test", "name": "Smoke Buyer" }),
    )
    .await?;
    check(st == 201, "customer create must return 201")?;
    let cust_pid = cust["publicId"]
        .as_str()
        .ok_or("customer publicId missing")?
        .to_string();
    step(10, format!("customer {cust_pid} created"));

    let (st, sub) = post(&http, &base, "/api/commerce/subscriptions", Some(&token),
        &json!({ "planPublicId": plan_pid, "customerPublicId": cust_pid, "paymentMode": "wallet_autopay", "startsAt": to_iso(chrono::Utc::now()) })).await?;
    check(st == 201, "subscription create must return 201")?;
    let sub_pid = sub["publicId"]
        .as_str()
        .ok_or("subscription publicId missing")?
        .to_string();
    let sub_id = sub["id"].as_i64().ok_or("subscription id missing")?;
    check(
        sub["paymentMode"] == "wallet_autopay",
        "subscription must be wallet_autopay",
    )?;
    step(
        11,
        format!("subscription {sub_pid} created (wallet_autopay, startsAt=now)"),
    );

    // Cycle 1 must have been invoiced at creation, with its webhook event row.
    let (cy1_id, inv1_id, inv1_pid): (i64, i64, String) = sqlx::query_as(
        "SELECT cy.id, inv.id, inv.public_id FROM subscription_cycles cy JOIN invoices inv ON inv.id = cy.invoice_id \
         WHERE cy.subscription_id = $1 AND cy.status = 'invoiced'",
    )
    .bind(sub_id)
    .fetch_one(&state.db.pool)
    .await
    .map_err(es)?;
    let inv1_status: String = sqlx::query_scalar("SELECT status FROM invoices WHERE id = $1")
        .bind(inv1_id)
        .fetch_one(&state.db.pool)
        .await
        .map_err(es)?;
    check(inv1_status == "open", "cycle-1 invoice must be open")?;
    check(
        event_count(&state, "subscription.invoice.created", &inv1_pid).await? == 1,
        "subscription.invoice.created must be emitted once for cycle 1",
    )?;
    step(
        12,
        format!("cycle 1 invoiced: {inv1_pid} (open) + subscription.invoice.created event"),
    );

    let (st, show) = get(
        &http,
        &base,
        &format!("/api/checkout/subscriptions/{sub_pid}"),
    )
    .await?;
    check(st == 200, "public GET must return 200")?;
    check(
        show["publicId"] == *sub_pid && show["status"] == "active",
        "public status shape",
    )?;
    check(
        show["plan"]["amount"] == PLAN_AMOUNT.to_string(),
        "plan.amount in public status",
    )?;
    check(
        show["plan"]["intervalUnit"] == "day" && show["plan"]["intervalCount"] == 1,
        "plan interval in public status",
    )?;
    check(show["cell"].is_null(), "cell must be null before prepare")?;
    let mut h = sha2::Sha256::new();
    h.update(b"kasway.subscription.cancel.v1:");
    h.update(sub_pid.as_bytes());
    let challenge: [u8; 32] = h.finalize().into();
    check(
        show["cancelChallengeHex"] == hex(&challenge),
        "cancelChallengeHex must be sha256(kasway.subscription.cancel.v1:<publicId>)",
    )?;
    step(
        13,
        "public status shape ok (cell=null, cancel challenge verified locally)",
    );

    let (st, prep) = post(
        &http,
        &base,
        &format!("/api/checkout/subscriptions/{sub_pid}/autopay/prepare"),
        None,
        &json!({ "refundAddress": payer_addr }),
    )
    .await?;
    check(st == 200, "autopay/prepare must return 200")?;
    let cov_addr1 = prep["covenantAddress"]
        .as_str()
        .ok_or("covenantAddress missing")?
        .to_string();
    check(
        cov_addr1.starts_with("kaspatest:"),
        "covenant address must be kaspatest P2SH",
    )?;
    check(
        prep["claimTotal"] == PLAN_AMOUNT.to_string(),
        "claimTotal must equal the plan amount (payout sum)",
    )?;
    check(
        prep["params"]["periodDaa"].as_u64() == Some(864_000 * 9 / 10),
        "1-day plan must pin period_daa = 864000*9/10",
    )?;
    // Local cross-check: recompile the covenant from the returned params — the
    // P2SH address MUST match what the server derived.
    let (params1, prefix1) = params_from_json(&prep["params"])?;
    check(prefix1 == prefix, "params network must be tn10")?;
    check(
        params1.payouts.len() == 2,
        "split must be merchant_net + kasway_fee",
    )?;
    check(
        params1.claim_total().map_err(es)? == PLAN_AMOUNT,
        "local claim_total must match",
    )?;
    let local_addr = covenant_address(&compile_subscription_v1(&params1).map_err(es)?, prefix)
        .map_err(es)?
        .to_string();
    check(
        local_addr == cov_addr1,
        "locally compiled covenant P2SH must equal the server's covenantAddress",
    )?;
    step(
        14,
        format!("autopay/prepare ok: {cov_addr1} — local P2SH re-derivation MATCHES"),
    );

    let dummy_txid = hex(&[0xAA; 32]);
    let (st, rec) = post(
        &http,
        &base,
        &format!("/api/checkout/subscriptions/{sub_pid}/autopay"),
        None,
        &json!({ "txId": dummy_txid }),
    )
    .await?;
    check(
        st == 200 && rec["recorded"] == true,
        "autopay record must succeed",
    )?;
    check(
        rec["paymentMode"] == "wallet_autopay" && rec["cellState"] == "awaiting_funding",
        "record response shape",
    )?;
    let (_, show2) = get(
        &http,
        &base,
        &format!("/api/checkout/subscriptions/{sub_pid}"),
    )
    .await?;
    check(
        show2["cell"]["state"] == "awaiting_funding",
        "cell must be awaiting_funding after record",
    )?;
    check(
        show2["cell"]["recordedFundingTxIds"]
            .as_array()
            .map(Vec::len)
            == Some(1),
        "one recorded funding txid",
    )?;
    step(
        15,
        "funding txid recorded (dummy); paymentMode=wallet_autopay confirmed",
    );

    let (st, ep) = post(&http, &base, "/api/webhook-endpoints", Some(&token), &json!({
        "url": hook_url,
        "events": ["subscription.invoice.created", "subscription.invoice.paid", "subscription.past_due", "subscription.cancelled"],
    })).await?;
    check(
        st == 201 || st == 200,
        "webhook endpoint registration must succeed",
    )?;
    check(
        ep["signingSecret"]
            .as_str()
            .is_some_and(|s| s.starts_with("whsec_")),
        "signingSecret must be returned once",
    )?;
    step(
        16,
        "webhook endpoint registered → local sink (4 subscription events)",
    );

    // -----------------------------------------------------------------------
    // Phase 2 — on-chain claims with a mini period (bypasses prepare).
    // -----------------------------------------------------------------------
    // Same payout split, but period_daa=60 so the CSV lock matures in seconds.
    // The sweep threshold is salted per run: covenant params are deterministic,
    // and a reused P2SH address would inherit residue from previous smoke runs.
    let mut params2_json = prep["params"].clone();
    params2_json["periodDaa"] = json!(MINI_PERIOD_DAA);
    let salt = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64 % 999_983)
        .unwrap_or(0);
    params2_json["sweepThreshold"] = json!(50_000_000 + salt);
    let (params2, _) = params_from_json(&params2_json)?;
    let compiled2 = compile_subscription_v1(&params2).map_err(es)?;
    let cov_addr2 = covenant_address(&compiled2, prefix)
        .map_err(es)?
        .to_string();
    check(
        cov_addr2 != cov_addr1,
        "mini-period covenant must be a different cell address",
    )?;
    sqlx::query(
        "UPDATE subscription_cells SET covenant_address = $1, params_json = $2, claim_total = $3, \
         state = 'awaiting_funding', recorded_funding_txids = '[]', active_outpoint_txid = NULL, \
         active_outpoint_index = NULL, active_amount = NULL, last_claim_tx_id = NULL, last_claim_at = NULL, \
         withdraw_destination = NULL, withdraw_sighash = NULL, updated_at = $4 WHERE subscription_id = $5",
    )
    .bind(&cov_addr2)
    .bind(params2_json.to_string())
    .bind(PLAN_AMOUNT as i64)
    .bind(to_iso(chrono::Utc::now()))
    .bind(sub_id)
    .execute(&state.db.pool)
    .await
    .map_err(es)?;
    step(
        17,
        format!("mini-period cell installed: period_daa={MINI_PERIOD_DAA}, {cov_addr2}"),
    );

    let funding_txid =
        send_p2pk(&client, &payer, prefix, &cov_addr2, fund_total, FUNDING_FEE).await?;
    step(
        18,
        format!("funding broadcast: {fund_total} sompi → covenant, txid={funding_txid}"),
    );

    let (st, rec2) = post(
        &http,
        &base,
        &format!("/api/checkout/subscriptions/{sub_pid}/autopay"),
        None,
        &json!({ "txId": funding_txid }),
    )
    .await?;
    check(
        st == 200 && rec2["recorded"] == true,
        "real funding txid must record",
    )?;
    check(
        rec2["txIds"].as_array().map(Vec::len) == Some(1),
        "cell reset must leave exactly the real funding txid",
    )?;
    step(19, "funding txid recorded via POST /autopay");

    wait_utxo(&client, &cov_addr2, &funding_txid, fund_total).await?;
    step(20, "funding UTXO visible on-chain at the covenant address");

    // Keeper: recognize funding → cell active with the full funded amount.
    let deadline = Instant::now() + Duration::from_secs(CHAIN_DEADLINE_SECS);
    loop {
        kasway_api::subscription_keeper::run_tick(&state, &client)
            .await
            .map_err(es)?;
        let (cell_state, amount): (String, Option<i64>) = sqlx::query_as(
            "SELECT state, active_amount FROM subscription_cells WHERE subscription_id = $1",
        )
        .bind(sub_id)
        .fetch_one(&state.db.pool)
        .await
        .map_err(es)?;
        if cell_state == "active" && amount == Some(fund_total as i64) {
            break;
        }
        check(
            Instant::now() < deadline,
            "keeper never recognized the funding UTXO",
        )?;
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
    step(
        21,
        format!("keeper recognized funding: cell active, amount={fund_total}"),
    );

    // Claim cycle 1 (CSV needs the funding UTXO to age ~60 DAA; the keeper
    // retries until the node accepts the spend).
    let claim1 = wait_claim(&state, &client, sub_id, inv1_id, PLAN_AMOUNT + FUND_EXTRA).await?;
    let cy1_status: String =
        sqlx::query_scalar("SELECT status FROM subscription_cycles WHERE id = $1")
            .bind(cy1_id)
            .fetch_one(&state.db.pool)
            .await
            .map_err(es)?;
    check(cy1_status == "paid", "cycle 1 must be paid")?;
    let cov_state: Option<String> =
        sqlx::query_scalar("SELECT covenant_state FROM kpr1_payment_intents WHERE invoice_id = $1")
            .bind(inv1_id)
            .fetch_optional(&state.db.pool)
            .await
            .map_err(es)?;
    check(
        cov_state.as_deref() == Some("captured"),
        "cycle-1 intent covenant_state must be 'captured'",
    )?;
    check(
        event_count(&state, "subscription.invoice.paid", &inv1_pid).await? == 1,
        "subscription.invoice.paid emitted once for cycle 1",
    )?;
    let (out_idx, last_claim): (Option<i64>, Option<String>) =
        sqlx::query_as("SELECT active_outpoint_index, last_claim_tx_id FROM subscription_cells WHERE subscription_id = $1")
            .bind(sub_id)
            .fetch_one(&state.db.pool)
            .await
            .map_err(es)?;
    check(
        out_idx == Some(params2.payouts.len() as i64),
        "remainder must sit right after the pinned payouts",
    )?;
    check(
        last_claim.as_deref() == Some(claim1.as_str()),
        "cell must roll onto claim 1's remainder",
    )?;
    step(
        22,
        format!("cycle 1 CLAIMED on-chain: tx={claim1}; invoice paid, cycle paid, intent captured"),
    );
    step(
        23,
        format!(
            "cell rolled to remainder {claim1}:{} amount={}",
            params2.payouts.len(),
            PLAN_AMOUNT + FUND_EXTRA
        ),
    );

    wait_webhook(&state, &sink, "subscription.invoice.paid").await?;
    step(
        24,
        "webhook DELIVERED to local sink: subscription.invoice.paid",
    );

    // Bill cycle 2 now: pull next_billing_at into the past and tick the biller.
    sqlx::query("UPDATE subscriptions SET next_billing_at = $1, updated_at = $1 WHERE id = $2")
        .bind(to_iso(chrono::Utc::now() - chrono::Duration::hours(1)))
        .bind(sub_id)
        .execute(&state.db.pool)
        .await
        .map_err(es)?;
    let billed = kasway_api::subscription_biller::run_tick(&state)
        .await
        .map_err(es)?;
    check(billed >= 1, "biller must mint the forced-due cycle 2")?;
    let (cy2_id, inv2_id, inv2_pid): (i64, i64, String) = sqlx::query_as(
        "SELECT cy.id, inv.id, inv.public_id FROM subscription_cycles cy JOIN invoices inv ON inv.id = cy.invoice_id \
         WHERE cy.subscription_id = $1 AND cy.id != $2",
    )
    .bind(sub_id)
    .bind(cy1_id)
    .fetch_one(&state.db.pool)
    .await
    .map_err(es)?;
    check(
        event_count(&state, "subscription.invoice.created", &inv2_pid).await? == 1,
        "cycle-2 mint must emit subscription.invoice.created",
    )?;
    step(
        25,
        format!("biller minted cycle 2: {inv2_pid} (next_billing_at forced 1h past)"),
    );

    // Claim cycle 2 — its covenant input can only be claim 1's remainder, so a
    // successful claim IS the on-chain self-replication proof.
    let claim2 = wait_claim(&state, &client, sub_id, inv2_id, FUND_EXTRA).await?;
    check(claim2 != claim1, "claim 2 must be a new transaction")?;
    let cy2_status: String =
        sqlx::query_scalar("SELECT status FROM subscription_cycles WHERE id = $1")
            .bind(cy2_id)
            .fetch_one(&state.db.pool)
            .await
            .map_err(es)?;
    check(cy2_status == "paid", "cycle 2 must be paid")?;
    // On-chain: the covenant address now holds exactly claim 2's remainder
    // (poll — the node's UTXO index lags the acceptance by a moment).
    wait_utxo(&client, &cov_addr2, &claim2, FUND_EXTRA).await?;
    let utxos = client.fetch_utxos(&cov_addr2).await.map_err(es)?;
    check(
        !utxos.iter().any(|(t, _, _)| hex(t) == claim1),
        "claim 1's remainder must be spent (consumed by claim 2)",
    )?;
    step(26, format!("cycle 2 CLAIMED from claim-1 remainder: tx={claim2} — self-replication PROVEN on-chain"));

    // -----------------------------------------------------------------------
    // Phase 3 — customer withdraw + signed cancel.
    // -----------------------------------------------------------------------
    let (st, wprep) = post(
        &http,
        &base,
        &format!("/api/checkout/subscriptions/{sub_pid}/autopay/withdraw/prepare"),
        None,
        &json!({ "destinationAddress": payer_addr }),
    )
    .await?;
    check(st == 200, "withdraw/prepare must return 200")?;
    check(
        wprep["amountSompi"] == FUND_EXTRA.to_string(),
        "withdraw amount must be the remaining cell value",
    )?;
    let sighash = unhex32(wprep["sighashHex"].as_str().unwrap_or_default())
        .ok_or("withdraw sighash must be 32-byte hex")?;
    step(
        27,
        format!("withdraw/prepare ok: amount={FUND_EXTRA}, sighash received"),
    );

    // 65-byte covenant signature: schnorr || SIGHASH_ALL byte (sign_sighash).
    let wsig = payer.sign_sighash(&sighash).map_err(es)?;
    let (st, wres) = post(
        &http,
        &base,
        &format!("/api/checkout/subscriptions/{sub_pid}/autopay/withdraw"),
        None,
        &json!({ "signatureHex": hex(&wsig) }),
    )
    .await?;
    check(
        st == 200 && wres["withdrawn"] == true,
        "withdraw must succeed",
    )?;
    let withdraw_txid = wres["txId"]
        .as_str()
        .ok_or("withdraw txId missing")?
        .to_string();
    let (_, show3) = get(
        &http,
        &base,
        &format!("/api/checkout/subscriptions/{sub_pid}"),
    )
    .await?;
    check(
        show3["cell"]["state"] == "withdrawn",
        "cell must be withdrawn",
    )?;
    wait_covenant_empty(&client, &cov_addr2).await?;
    step(
        28,
        format!("withdraw broadcast: tx={withdraw_txid}; cell withdrawn, covenant empty on-chain"),
    );

    // Cancel: first without a signature (must 422 with the challenge), then
    // with a 64-byte schnorr datasig by the refund key.
    let (st, cbody) = post(
        &http,
        &base,
        &format!("/api/checkout/subscriptions/{sub_pid}/cancel"),
        None,
        &json!({}),
    )
    .await?;
    check(st == 422, "funded-cell cancel without signature must 422")?;
    check(
        cbody["challengeHex"] == hex(&challenge),
        "cancel 422 must return the same challenge",
    )?;
    let csig = payer.sign_datasig(&challenge).map_err(es)?;
    let (st, cres) = post(
        &http,
        &base,
        &format!("/api/checkout/subscriptions/{sub_pid}/cancel"),
        None,
        &json!({ "signatureHex": hex(&csig) }),
    )
    .await?;
    check(
        st == 200 && cres["cancelled"] == true,
        "signed cancel must succeed",
    )?;
    let sub_status: String = sqlx::query_scalar("SELECT status FROM subscriptions WHERE id = $1")
        .bind(sub_id)
        .fetch_one(&state.db.pool)
        .await
        .map_err(es)?;
    check(sub_status == "cancelled", "subscription must be cancelled")?;
    check(
        event_count(&state, "subscription.cancelled", &sub_pid).await? == 1,
        "subscription.cancelled emitted once",
    )?;
    step(
        29,
        "cancel: challenge signature accepted → subscription cancelled",
    );

    wait_webhook(&state, &sink, "subscription.cancelled").await?;
    step(
        30,
        "webhook DELIVERED to local sink: subscription.cancelled",
    );

    println!("\nProof txids (https://explorer-tn10.kaspa.org/txs/<txid>):");
    println!("  funding : {funding_txid}");
    println!("  claim 1 : {claim1}");
    println!("  claim 2 : {claim2}  (spends claim 1's remainder — self-replication)");
    println!("  withdraw: {withdraw_txid}");
    println!("  database: {db_name} (kept for inspection)");
    Ok(())
}

// ---------------------------------------------------------------------------
// Poll helpers (chain steps converge, DB steps are exact).
// ---------------------------------------------------------------------------

/// Tick the subscription keeper until `invoice_id` is paid AND the cell settles
/// on the expected post-claim amount; returns the claim txid.
async fn wait_claim(
    state: &AppState,
    client: &KaspaWrpcClient,
    sub_id: i64,
    invoice_id: i64,
    expect_amount: u64,
) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(CHAIN_DEADLINE_SECS);
    loop {
        kasway_api::subscription_keeper::run_tick(state, client)
            .await
            .map_err(es)?;
        let paid: String = sqlx::query_scalar("SELECT status FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(&state.db.pool)
            .await
            .map_err(es)?;
        if paid == "paid" {
            // Poll until the cell has rolled onto the remainder (a lagging UTXO
            // index can transiently re-recognize the spent funding outpoint).
            let (cell_state, amount, last_claim): (String, Option<i64>, Option<String>) = sqlx::query_as(
                "SELECT state, active_amount, last_claim_tx_id FROM subscription_cells WHERE subscription_id = $1",
            )
            .bind(sub_id)
            .fetch_one(&state.db.pool)
            .await
            .map_err(es)?;
            if cell_state == "active" && amount == Some(expect_amount as i64) {
                return last_claim.ok_or_else(|| "claim recorded no txid".to_string());
            }
        }
        check(
            Instant::now() < deadline,
            "keeper never completed the claim (CSV/funds/node)",
        )?;
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

/// Tick the webhook delivery worker until the sink has received `event`.
async fn wait_webhook(
    state: &AppState,
    sink: &Arc<Mutex<Vec<String>>>,
    event: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        kasway_api::webhook_worker::run_tick(state)
            .await
            .map_err(es)?;
        if sink.lock().unwrap().iter().any(|e| e == event) {
            return Ok(());
        }
        check(
            Instant::now() < deadline,
            &format!("webhook {event} was never delivered to the local sink"),
        )?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Wait until `address` holds a UTXO from `txid_hex` worth exactly `value`.
async fn wait_utxo(
    client: &KaspaWrpcClient,
    address: &str,
    txid_hex: &str,
    value: u64,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(CHAIN_DEADLINE_SECS);
    loop {
        let utxos = client.fetch_utxos(address).await.unwrap_or_default();
        if utxos
            .iter()
            .any(|(t, _, v)| hex(t) == txid_hex && *v == value)
        {
            return Ok(());
        }
        check(
            Instant::now() < deadline,
            &format!("UTXO {txid_hex}:{value} never appeared at {address}"),
        )?;
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

async fn wait_covenant_empty(client: &KaspaWrpcClient, address: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(CHAIN_DEADLINE_SECS);
    loop {
        if client
            .fetch_utxos(address)
            .await
            .unwrap_or_default()
            .is_empty()
        {
            return Ok(());
        }
        check(
            Instant::now() < deadline,
            "covenant address never emptied after withdraw",
        )?;
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

async fn event_count(state: &AppState, event_type: &str, resource_id: &str) -> Result<i64, String> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM webhook_events WHERE event_type = $1 AND resource_id = $2",
    )
    .bind(event_type)
    .bind(resource_id)
    .fetch_one(&state.db.pool)
    .await
    .map_err(es)
}

// ---------------------------------------------------------------------------
// Covenant params round-trip (mirrors subscription_keeper::cell_params).
// ---------------------------------------------------------------------------

fn params_from_json(p: &Value) -> Result<(SubscriptionV1Params, kasway_covenant::Prefix), String> {
    let prefix = network_prefix(p["network"].as_str().unwrap_or_default()).map_err(es)?;
    let mut payouts = Vec::new();
    for out in p["payouts"].as_array().ok_or("params.payouts missing")? {
        let destination =
            Destination::parse(out["address"].as_str().unwrap_or_default()).map_err(es)?;
        let value: u64 = out["amountSompi"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or("bad payout amountSompi")?;
        payouts.push(Payout { destination, value });
    }
    Ok((
        SubscriptionV1Params {
            payouts,
            keeper_pubkey: unhex32(p["keeperPubkey"].as_str().unwrap_or_default())
                .ok_or("bad keeperPubkey")?,
            customer: Destination::parse(p["customer"].as_str().unwrap_or_default()).map_err(es)?,
            period_daa: p["periodDaa"].as_u64().ok_or("bad periodDaa")?,
            sweep_threshold: p["sweepThreshold"].as_u64().unwrap_or(0),
        },
        prefix,
    ))
}

// ---------------------------------------------------------------------------
// Plain P2PK send: fund the covenant address from the keeper/payer wallet.
// ---------------------------------------------------------------------------

async fn send_p2pk(
    client: &KaspaWrpcClient,
    key: &KeeperKey,
    prefix: kasway_covenant::Prefix,
    to_address: &str,
    amount: u64,
    fee: u64,
) -> Result<String, String> {
    let from = key.address(prefix);
    let mut utxos = client.fetch_utxos(&from.to_string()).await.map_err(es)?;
    utxos.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| (a.0, a.1).cmp(&(b.0, b.1))));
    let mut picked: Vec<Utxo> = Vec::new();
    let mut total = 0u64;
    for (t, i, v) in utxos {
        picked.push(Utxo {
            transaction_id: t,
            index: i,
            value: v,
        });
        total += v;
        if total >= amount + fee {
            break;
        }
        if picked.len() >= 20 {
            return Err(
                "wallet is too fragmented (>20 inputs needed) — consolidate or top up".into(),
            );
        }
    }
    if total < amount + fee {
        return Err(format!(
            "insufficient wallet funds: {total} < {} at {from}",
            amount + fee
        ));
    }

    let to = Destination::parse(to_address).map_err(es)?;
    let mut outputs = vec![TransactionOutput {
        value: amount,
        script_public_key: to.script_public_key(),
        covenant: None,
    }];
    let change = total - amount - fee;
    // Sub-0.1-KAS change would carry outsized KIP-9 storage mass; fold into fee.
    if change >= 10_000_000 {
        outputs.push(TransactionOutput {
            value: change,
            script_public_key: pay_to_address_script(&from),
            covenant: None,
        });
    }

    let inputs: Vec<TransactionInput> = picked
        .iter()
        .map(|u| TransactionInput {
            previous_outpoint: TransactionOutpoint {
                transaction_id: TransactionId::from_bytes(u.transaction_id),
                index: u.index,
            },
            signature_script: vec![],
            sequence: 0,
            compute_commit: ComputeCommit::ComputeBudget(ComputeBudget(FEE_COMPUTE_BUDGET)),
        })
        .collect();
    let entries: Vec<UtxoEntry> = picked
        .iter()
        .map(|u| UtxoEntry::new(u.value, pay_to_address_script(&from), 0, false, None))
        .collect();

    let tx = Transaction::new(1, inputs, outputs, 0, Default::default(), 0, vec![]);
    let mtx = MutableTransaction::with_entries(tx, entries.clone());
    let reused = SigHashReusedValuesUnsync::new();
    let mut sig_scripts = Vec::with_capacity(picked.len());
    for i in 0..picked.len() {
        let sighash: [u8; 32] =
            calc_schnorr_signature_hash(&mtx.as_verifiable(), i, SIG_HASH_ALL, &reused).as_bytes();
        let sig = key.sign_sighash(&sighash).map_err(es)?;
        sig_scripts.push(ScriptBuilder::new().add_data(&sig).map_err(es)?.drain());
    }
    let mut tx = mtx.tx;
    for (i, script) in sig_scripts.into_iter().enumerate() {
        tx.inputs[i].signature_script = script;
    }
    let spend = SignedSpend {
        transaction: tx,
        entries,
    };
    client
        .submit_transaction(rpc_submit_params(&spend))
        .await
        .map_err(es)
}

// ---------------------------------------------------------------------------
// Small plumbing: dotenv, fresh DB, HTTP, hex, env keys.
// ---------------------------------------------------------------------------

/// Minimal .env loader: workspace-root `.env`, KEY=VALUE lines, `#` comments,
/// optional surrounding quotes. Already-set env vars win. DATABASE_URL is
/// skipped — it targets the docker-compose `db` host; the smoke uses
/// SMOKE_DATABASE_URL / localhost instead.
fn load_dotenv() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../.env");
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim().trim_matches('"').trim_matches('\'');
        if k == "DATABASE_URL" || k.is_empty() || std::env::var(k).is_ok() {
            continue;
        }
        std::env::set_var(k, v);
    }
}

/// Create `db_name` on the local PostgreSQL server and connect+migrate.
async fn fresh_db(db_name: &str) -> Result<kasway_db::Db, String> {
    use std::str::FromStr;
    let base = std::env::var("SMOKE_DATABASE_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "postgres://postgres:postgres@localhost:5432/kasway".to_string());
    let opts = sqlx::postgres::PgConnectOptions::from_str(&base).map_err(es)?;
    let admin = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(opts.clone().database("postgres"))
        .await
        .map_err(es)?;
    sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
        .execute(&admin)
        .await
        .map_err(es)?;
    admin.close().await;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect_with(opts.database(db_name))
        .await
        .map_err(es)?;
    let db = kasway_db::Db { pool };
    db.migrate().await.map_err(es)?;
    Ok(db)
}

async fn post(
    http: &reqwest::Client,
    base: &str,
    path: &str,
    token: Option<&str>,
    body: &Value,
) -> Result<(u16, Value), String> {
    let mut req = http.post(format!("{base}{path}")).json(body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let res = req.send().await.map_err(|e| format!("POST {path}: {e}"))?;
    let status = res.status().as_u16();
    let val = res.json().await.unwrap_or(Value::Null);
    if status >= 500 {
        return Err(format!("POST {path} → {status}: {val}"));
    }
    Ok((status, val))
}

async fn get(http: &reqwest::Client, base: &str, path: &str) -> Result<(u16, Value), String> {
    let res = http
        .get(format!("{base}{path}"))
        .send()
        .await
        .map_err(|e| format!("GET {path}: {e}"))?;
    let status = res.status().as_u16();
    Ok((status, res.json().await.unwrap_or(Value::Null)))
}

fn env_key(name: &str) -> Result<KeeperKey, String> {
    let hex = std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{name} is required (32-byte hex secret)"))?;
    let bytes = unhex32(&hex).ok_or_else(|| format!("{name} must be 64 hex chars"))?;
    KeeperKey::from_secret_bytes(&bytes).map_err(|e| format!("{name}: {e}"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}
