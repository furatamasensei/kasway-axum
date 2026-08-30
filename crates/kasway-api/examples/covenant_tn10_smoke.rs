//! TN10 on-chain proof harness for the Kasway **EscrowV2** escrow covenant.
//!
//! Drives EscrowV2 end-to-end against a live rusty-kaspa v2.0.1 (Toccata)
//! testnet-10 node: compile the covenant, derive its P2SH address, detect the
//! funding UTXO, then build + broadcast one settlement path. This is the ONLY
//! part of the settlement stack that can't be proven with the local
//! `TxScriptEngine` — it calibrates the exact wRPC `submitTransaction` wire
//! format against a real node.
//!
//! # Safety
//! - NEVER moves funds on its own. The user funds the covenant from their own
//!   wallet (the tool only prints the address).
//! - Broadcasting is gated behind `SMOKE_BROADCAST=1`; otherwise it dry-runs.
//! - Secrets are read from env and NEVER printed — only addresses/pubkeys/txids.
//!
//! # Usage
//! ```text
//! KASPA_NODE_URL=ws://217.154.124.162:18210 \
//! cargo run -p kasway-api --example covenant_tn10_smoke -- <mode>
//! ```
//!
//! Modes:
//! - `status`             node reachability + virtual DAA score (no secrets).
//! - `address`            derive + print the covenant address to fund.
//! - `utxos`              list the covenant address UTXOs (funding check).
//! - `release-confirmed`  Tier 0: customer-signed release → merchant split.
//! - `release-captured`   Tier 0: permissionless capture → merchant (needs a PAST capture time).
//! - `release-settled`    Tier 1: customer + merchant co-sign an agreed split.
//! - `release-arbitrated` Tier 2: M-of-N arbiter panel → merchant.
//! - `refund-merchant`    merchant-signed refund → customer (merchant pays gas).
//! - `refund-arbiter`     Tier 2: arbiter panel refund → customer (customer pays gas).
//!
//! Env (amounts in sompi; 1 TKAS = 100_000_000 sompi):
//! - `SMOKE_NETWORK` (default `tn10`), `SMOKE_GROSS_SOMPI`, `SMOKE_FEE_SOMPI`,
//!   `SMOKE_MINER_FEE_SOMPI`, `SMOKE_CAPTURE_TIME` (ms wall-clock; PAST for capture),
//!   `SMOKE_BROADCAST`, secrets: `SMOKE_CUSTOMER_SECRET`, `SMOKE_MERCHANT_SECRET`,
//!   `SMOKE_ARBITER_SECRET`, `COVENANT_KEEPER_FEE_SECRET`.

use kasway_api::chain_source::ChainSource;
use kasway_api::kaspa_wrpc::KaspaWrpcClient;
use kasway_covenant::escrow_v2::{
    compile_escrow_v2, complete_refund_by_arbiter, complete_refund_by_merchant, complete_release,
    complete_release_arbitrated, complete_settlement, prepare_refund_by_arbiter, prepare_refund_by_merchant,
    prepare_release, prepare_release_arbitrated, prepare_settlement, EscrowV2Params, EP_RELEASE_CAPTURED,
    EP_RELEASE_CONFIRMED,
};
use kasway_covenant::{
    covenant_address, network_prefix, rpc_submit_params, Destination, KeeperKey, Payout, Prefix, SignedSpend, Utxo,
};

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("\nERROR: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let client = KaspaWrpcClient::from_env().ok_or("KASPA_NODE_URL is not set (e.g. ws://217.154.124.162:18210)")?;

    match mode.as_str() {
        "status" => status(&client).await,
        "address" => {
            let ctx = SmokeCtx::from_env()?;
            ctx.print_address();
            Ok(())
        }
        "utxos" => {
            let ctx = SmokeCtx::from_env()?;
            ctx.print_address();
            show_utxos(&client, &ctx.covenant_addr).await
        }
        "release-confirmed" => release(&client, ReleaseKind::Confirmed).await,
        "release-captured" => release(&client, ReleaseKind::Captured).await,
        "release-arbitrated" => release(&client, ReleaseKind::Arbitrated).await,
        "release-settled" => settle(&client).await,
        "refund-merchant" => refund(&client, RefundKind::Merchant).await,
        "refund-arbiter" => refund(&client, RefundKind::Arbiter).await,
        other => Err(format!(
            "unknown mode {other:?}. Modes: status | address | utxos | release-confirmed | release-captured | \
             release-arbitrated | release-settled | refund-merchant | refund-arbiter"
        )),
    }
}

// ---------------------------------------------------------------------------
// Node connectivity (no secrets).
// ---------------------------------------------------------------------------

async fn status(client: &KaspaWrpcClient) -> Result<(), String> {
    println!("Connecting to node…");
    let daa = client.virtual_daa_score().await.map_err(|e| e.to_string())?;
    println!("OK — node reachable. virtualDaaScore = {daa}");
    match client.raw_call("getInfo", serde_json::json!({})).await {
        Ok(info) => println!("getInfo: {info}"),
        Err(e) => println!("getInfo failed: {e}"),
    }
    Ok(())
}

async fn show_utxos(client: &KaspaWrpcClient, address: &str) -> Result<(), String> {
    let utxos = client.fetch_utxos(address).await.map_err(|e| e.to_string())?;
    if utxos.is_empty() {
        println!("No UTXOs at covenant address yet — fund it, then re-run.");
    } else {
        println!("{} UTXO(s) at covenant address:", utxos.len());
        for (txid, index, value) in &utxos {
            println!("  {}:{index}  value={value} sompi", hex_encode(txid));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared covenant context.
// ---------------------------------------------------------------------------

struct SmokeCtx {
    params: EscrowV2Params,
    prefix: Prefix,
    covenant_addr: String,
    gross: u64,
    miner_fee: u64,
    capture_time: u64,
    customer: KeeperKey,
    merchant: KeeperKey,
    arbiter: KeeperKey,
    keeper: KeeperKey,
}

impl SmokeCtx {
    fn from_env() -> Result<Self, String> {
        let network = env_str("SMOKE_NETWORK").unwrap_or_else(|| "tn10".to_string());
        let prefix = network_prefix(&network).map_err(|e| e.to_string())?;

        let gross = env_u64("SMOKE_GROSS_SOMPI", 100_000_000);
        let fee = env_u64("SMOKE_FEE_SOMPI", 10_000_000);
        let miner_fee = env_u64("SMOKE_MINER_FEE_SOMPI", 1_200_000);
        let capture_time = env_u64("SMOKE_CAPTURE_TIME", 0);
        if fee >= gross {
            return Err(format!("SMOKE_FEE_SOMPI ({fee}) must be < SMOKE_GROSS_SOMPI ({gross})"));
        }
        let merchant_net = gross - fee;

        let customer = env_key("SMOKE_CUSTOMER_SECRET")?;
        let merchant = env_key("SMOKE_MERCHANT_SECRET")?;
        let arbiter = env_key("SMOKE_ARBITER_SECRET")?;
        let keeper = env_key("COVENANT_KEEPER_FEE_SECRET")?;

        let payouts = vec![
            Payout { destination: dest(&merchant, prefix)?, value: merchant_net },
            Payout { destination: dest(&arbiter, prefix)?, value: fee },
        ];
        // Transitional 1-of-1 arbiter panel (the arbiter is the only member) —
        // matches the backend default. Extend `arbiter_panel` for a real M-of-N.
        let params = EscrowV2Params {
            payouts,
            customer_refund: dest(&customer, prefix)?,
            merchant: dest(&merchant, prefix)?,
            arbiter_panel: vec![arbiter.x_only_pubkey()],
            arbiter_threshold: 1,
            gross_amount: gross,
            capture_time,
        };
        let compiled = compile_escrow_v2(&params).map_err(|e| e.to_string())?;
        let covenant_addr = covenant_address(&compiled, prefix).map_err(|e| e.to_string())?.to_string();

        Ok(Self { params, prefix, covenant_addr, gross, miner_fee, capture_time, customer, merchant, arbiter, keeper })
    }

    fn print_address(&self) {
        println!("Covenant (EscrowV2) parameters:");
        println!("  network        {:?}", self.prefix);
        println!("  gross_amount   {} sompi", self.gross);
        println!("  merchant_net   {} sompi  -> {}", self.params.payouts[0].value, self.merchant.address(self.prefix));
        println!("  kasway_fee     {} sompi  -> {}", self.params.payouts[1].value, self.arbiter.address(self.prefix));
        println!("  customer_refund               -> {}", self.customer.address(self.prefix));
        println!("  arbiter panel  1-of-1         -> {}", self.arbiter.address(self.prefix));
        println!("  keeper (release gas)          -> {}", self.keeper.address(self.prefix));
        println!("  capture_time   {} (ms wall-clock)", self.capture_time);
        println!("  miner_fee      {} sompi (from the fee input, never the covenant)", self.miner_fee);
        println!("\n  >>> FUND #1 — the covenant, EXACTLY {} sompi:", self.gross);
        println!("      {}", self.covenant_addr);
        println!("\n  >>> FUND #2 — the keeper (a little TKAS for release gas), e.g. 0.1 TKAS:");
        println!("      {}", self.keeper.address(self.prefix));
        println!("\n  Then run `utxos` to confirm covenant funding, then a settlement mode.");
    }
}

// ---------------------------------------------------------------------------
// Release → merchant (Tier 0 confirmed/captured, Tier 2 arbitrated).
// ---------------------------------------------------------------------------

enum ReleaseKind {
    Confirmed,
    Captured,
    Arbitrated,
}

async fn release(client: &KaspaWrpcClient, kind: ReleaseKind) -> Result<(), String> {
    let ctx = SmokeCtx::from_env()?;
    ctx.print_address();
    let compiled = compile_escrow_v2(&ctx.params).map_err(|e| e.to_string())?;

    let cov_utxo = find_covenant_utxo(client, &ctx.covenant_addr, ctx.gross).await?;
    let keeper_addr = ctx.keeper.address(ctx.prefix).to_string();
    let fee_utxo = find_fee_utxo(client, &keeper_addr, ctx.miner_fee, "keeper").await?;

    let (label, spend) = match kind {
        ReleaseKind::Arbitrated => {
            let draft = prepare_release_arbitrated(&compiled, &ctx.params, &cov_utxo, &fee_utxo, ctx.miner_fee, &ctx.keeper, ctx.prefix)
                .map_err(|e| e.to_string())?;
            // 1-of-1 panel: the arbiter signs at index 0.
            let sig = ctx.arbiter.sign_sighash(&draft.covenant_sighash).map_err(|e| e.to_string())?;
            let spend = complete_release_arbitrated(&compiled, draft, &[sig], &[0]).map_err(|e| e.to_string())?;
            ("release_arbitrated (M-of-N panel)".to_string(), spend)
        }
        _ => {
            let (entrypoint, lock_time) = match kind {
                ReleaseKind::Confirmed => (EP_RELEASE_CONFIRMED, 0),
                ReleaseKind::Captured => (EP_RELEASE_CAPTURED, ctx.capture_time),
                ReleaseKind::Arbitrated => unreachable!(),
            };
            let draft = prepare_release(&compiled, &ctx.params, &cov_utxo, &fee_utxo, ctx.miner_fee, &ctx.keeper, ctx.prefix, lock_time)
                .map_err(|e| e.to_string())?;
            let sig = match kind {
                ReleaseKind::Confirmed => Some(ctx.customer.sign_sighash(&draft.covenant_sighash).map_err(|e| e.to_string())?),
                _ => None,
            };
            let spend = complete_release(&compiled, draft, entrypoint, sig.as_deref()).map_err(|e| e.to_string())?;
            (format!("{entrypoint} (lock_time={lock_time})"), spend)
        }
    };

    println!("\nSettlement: {label} → merchant split");
    broadcast_or_dry_run(client, &spend).await
}

// ---------------------------------------------------------------------------
// Mutual settlement (Tier 1): customer + merchant co-sign an agreed split.
// ---------------------------------------------------------------------------

async fn settle(client: &KaspaWrpcClient) -> Result<(), String> {
    let ctx = SmokeCtx::from_env()?;
    ctx.print_address();
    let compiled = compile_escrow_v2(&ctx.params).map_err(|e| e.to_string())?;

    let cov_utxo = find_covenant_utxo(client, &ctx.covenant_addr, ctx.gross).await?;
    // Customer pays the settlement gas from their own UTXO.
    let fee_payer_address = ctx.customer.address(ctx.prefix);
    let fee_utxo = find_fee_utxo(client, &fee_payer_address.to_string(), ctx.miner_fee, "customer").await?;

    // Agreed split: half back to the customer, half to the merchant (sum == gross).
    let half = ctx.gross / 2;
    let split = vec![
        (dest(&ctx.customer, ctx.prefix)?, half),
        (dest(&ctx.merchant, ctx.prefix)?, ctx.gross - half),
    ];
    let draft = prepare_settlement(&compiled, &split, &cov_utxo, &fee_utxo, ctx.miner_fee, &fee_payer_address)
        .map_err(|e| e.to_string())?;
    let customer_sig = ctx.customer.sign_sighash(&draft.covenant_sighash).map_err(|e| e.to_string())?;
    let merchant_sig = ctx.merchant.sign_sighash(&draft.covenant_sighash).map_err(|e| e.to_string())?;
    let fee_sig = ctx.customer.sign_sighash(&draft.fee_sighash).map_err(|e| e.to_string())?;
    let spend = complete_settlement(&compiled, draft, &customer_sig, &merchant_sig, &fee_sig).map_err(|e| e.to_string())?;

    println!("\nSettlement: release_settled → agreed split ({half} customer / {} merchant)", ctx.gross - half);
    broadcast_or_dry_run(client, &spend).await
}

// ---------------------------------------------------------------------------
// Refund → customer (external, non-keeper fee input).
// ---------------------------------------------------------------------------

enum RefundKind {
    Merchant,
    Arbiter,
}

async fn refund(client: &KaspaWrpcClient, kind: RefundKind) -> Result<(), String> {
    let ctx = SmokeCtx::from_env()?;
    ctx.print_address();
    let compiled = compile_escrow_v2(&ctx.params).map_err(|e| e.to_string())?;

    let cov_utxo = find_covenant_utxo(client, &ctx.covenant_addr, ctx.gross).await?;

    let (fee_payer, fee_label): (&KeeperKey, &str) = match kind {
        RefundKind::Merchant => (&ctx.merchant, "merchant"),
        RefundKind::Arbiter => (&ctx.customer, "customer"),
    };
    let fee_payer_address = fee_payer.address(ctx.prefix);
    let fee_utxo = find_fee_utxo(client, &fee_payer_address.to_string(), ctx.miner_fee, fee_label).await?;

    let (label, spend) = match kind {
        RefundKind::Merchant => {
            let draft = prepare_refund_by_merchant(&compiled, &ctx.params, &cov_utxo, &fee_utxo, ctx.miner_fee, &fee_payer_address)
                .map_err(|e| e.to_string())?;
            let merchant_sig = ctx.merchant.sign_sighash(&draft.covenant_sighash).map_err(|e| e.to_string())?;
            let fee_sig = fee_payer.sign_sighash(&draft.fee_sighash).map_err(|e| e.to_string())?;
            let spend = complete_refund_by_merchant(&compiled, draft, &merchant_sig, &fee_sig).map_err(|e| e.to_string())?;
            ("refund_by_merchant".to_string(), spend)
        }
        RefundKind::Arbiter => {
            let draft = prepare_refund_by_arbiter(&compiled, &ctx.params, &cov_utxo, &fee_utxo, ctx.miner_fee, &fee_payer_address)
                .map_err(|e| e.to_string())?;
            // 1-of-1 panel: the arbiter signs at index 0.
            let arbiter_sig = ctx.arbiter.sign_sighash(&draft.covenant_sighash).map_err(|e| e.to_string())?;
            let fee_sig = fee_payer.sign_sighash(&draft.fee_sighash).map_err(|e| e.to_string())?;
            let spend = complete_refund_by_arbiter(&compiled, draft, &[arbiter_sig], &[0], &fee_sig).map_err(|e| e.to_string())?;
            ("refund_by_arbiter (M-of-N panel)".to_string(), spend)
        }
    };

    println!("\nSettlement: {label} → full gross to customer ({fee_label} pays gas)");
    broadcast_or_dry_run(client, &spend).await
}

// ---------------------------------------------------------------------------
// UTXO selection + broadcast.
// ---------------------------------------------------------------------------

fn synthetic() -> bool {
    env_str("SMOKE_SYNTHETIC_UTXO").as_deref() == Some("1")
}

async fn fetch_utxos_retry(client: &KaspaWrpcClient, address: &str) -> Result<Vec<([u8; 32], u32, u64)>, String> {
    let mut last = String::new();
    for attempt in 1..=4 {
        match client.fetch_utxos(address).await {
            Ok(u) => return Ok(u),
            Err(e) => {
                last = e.to_string();
                eprintln!("  fetch_utxos({address}) attempt {attempt} failed: {last}; retrying…");
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
    }
    Err(format!("fetch_utxos({address}) failed after retries: {last}"))
}

async fn find_covenant_utxo(client: &KaspaWrpcClient, address: &str, gross: u64) -> Result<Utxo, String> {
    if synthetic() {
        println!("  [synthetic] using placeholder covenant UTXO (value={gross}) — not on-chain");
        return Ok(Utxo { transaction_id: [0xC0; 32], index: 0, value: gross });
    }
    let utxos = fetch_utxos_retry(client, address).await?;
    utxos
        .into_iter()
        .find(|(_, _, v)| *v == gross)
        .map(|(t, i, v)| Utxo { transaction_id: t, index: i, value: v })
        .ok_or_else(|| format!("no covenant funding UTXO of exactly {gross} sompi at {address} — fund it first (mode `utxos` to check)"))
}

async fn find_fee_utxo(client: &KaspaWrpcClient, address: &str, min_fee: u64, label: &str) -> Result<Utxo, String> {
    if synthetic() {
        println!("  [synthetic] using placeholder {label} fee UTXO — not on-chain");
        return Ok(Utxo { transaction_id: [0xFE; 32], index: 0, value: 100_000_000 });
    }
    let mut utxos = fetch_utxos_retry(client, address).await?;
    utxos.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    utxos
        .into_iter()
        .find(|(_, _, v)| *v > min_fee + 1)
        .map(|(t, i, v)| Utxo { transaction_id: t, index: i, value: v })
        .ok_or_else(|| format!("no {label} fee UTXO > {min_fee} sompi at {address} — fund the {label} address to pay gas"))
}

async fn broadcast_or_dry_run(client: &KaspaWrpcClient, spend: &SignedSpend) -> Result<(), String> {
    let params = rpc_submit_params(spend);
    if synthetic() && env_str("SMOKE_BROADCAST").as_deref() == Some("1") {
        return Err("refusing to broadcast a synthetic-UTXO transaction (its outpoints are fake). Unset SMOKE_SYNTHETIC_UTXO and fund a real covenant to broadcast.".to_string());
    }
    if env_str("SMOKE_BROADCAST").as_deref() == Some("1") {
        println!("Broadcasting…");
        let tx_id = client.submit_transaction(params).await.map_err(|e| e.to_string())?;
        println!("\n  ✅ ACCEPTED. txid = {tx_id}");
        println!("     explorer: https://explorer-tn10.kaspa.org/txs/{tx_id}");
        Ok(())
    } else {
        println!("\n  [dry-run] signed submitTransaction params:");
        println!("{}", serde_json::to_string_pretty(&params).unwrap_or_else(|_| params.to_string()));
        println!("\n  Set SMOKE_BROADCAST=1 to actually submit this to the node.");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Env / hex helpers.
// ---------------------------------------------------------------------------

fn dest(k: &KeeperKey, prefix: Prefix) -> Result<Destination, String> {
    Destination::from_address(k.address(prefix)).map_err(|e| e.to_string())
}

fn env_str(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn env_u64(name: &str, default: u64) -> u64 {
    env_str(name).and_then(|s| s.replace('_', "").parse().ok()).unwrap_or(default)
}

fn env_key(name: &str) -> Result<KeeperKey, String> {
    let hex = env_str(name).ok_or_else(|| format!("{name} is required (32-byte hex secret)"))?;
    let bytes = hex_decode32(&hex).ok_or_else(|| format!("{name} must be 64 hex chars (32 bytes)"))?;
    KeeperKey::from_secret_bytes(&bytes).map_err(|e| format!("{name}: {e}"))
}

fn hex_decode32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
