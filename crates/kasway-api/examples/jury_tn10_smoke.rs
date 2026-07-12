//! TN10 on-chain proof harness for the Kasway **Tier-3 jury** dispute-escrow.
//!
//! Proves the marquee Tier-3 primitive on a live rusty-kaspa v2.0.1 (Toccata)
//! testnet-10 node: a K-of-N committee's `datasig` verdicts are honored on-chain
//! via `checkSigFromStack` (opcode 0xd7). Compiles the `JuryEscrow` covenant with
//! a baked committee + the two verdict digests, derives its P2SH address, detects
//! the funding UTXO, then builds + broadcasts `release_jury` (verdict = merchant)
//! or `refund_jury` (verdict = customer) signed by a threshold of the committee.
//!
//! # Safety
//! - NEVER moves funds on its own; the user funds the covenant (tool prints addr).
//! - Broadcasting gated behind `SMOKE_BROADCAST=1`; otherwise dry-runs.
//! - Secrets read from env, NEVER printed.
//!
//! # Usage
//! ```text
//! KASPA_NODE_URL=ws://217.154.124.162:18210 \
//! cargo run -p kasway-api --example jury_tn10_smoke -- <mode>
//! ```
//!
//! Modes: `status` | `address` | `utxos` | `release-jury` | `refund-jury`.
//!
//! Env (amounts in sompi): `SMOKE_NETWORK` (default tn10), `SMOKE_GROSS_SOMPI`,
//! `SMOKE_FEE_SOMPI`, `SMOKE_MINER_FEE_SOMPI`, `SMOKE_JURY_N` (default 5),
//! `SMOKE_JURY_K` (default 3), `SMOKE_BROADCAST`. Secrets (32-byte hex):
//! `SMOKE_CUSTOMER_SECRET`, `SMOKE_MERCHANT_SECRET`, `COVENANT_KEEPER_FEE_SECRET`,
//! and `SMOKE_JUROR_SECRET_0..N-1` (juror committee keys).

use kasway_api::chain_source::ChainSource;
use kasway_api::kaspa_wrpc::KaspaWrpcClient;
use kasway_covenant::jury_escrow::{
    compile_jury_escrow, complete_refund_jury, complete_release_jury, prepare_refund_jury, prepare_release_jury,
    JuryEscrowParams, VERDICT_CUSTOMER, VERDICT_MERCHANT, VERDICT_TAG,
};
use kasway_covenant::{
    covenant_address, network_prefix, rpc_submit_params, Destination, KeeperKey, Payout, Prefix, SignedSpend, Utxo,
};
use sha2::{Digest, Sha256};

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
            JuryCtx::from_env()?.print_address();
            Ok(())
        }
        "utxos" => {
            let ctx = JuryCtx::from_env()?;
            ctx.print_address();
            show_utxos(&client, &ctx.covenant_addr).await
        }
        "release-jury" => settle(&client, Verdict::Merchant).await,
        "refund-jury" => settle(&client, Verdict::Customer).await,
        other => Err(format!("unknown mode {other:?}. Modes: status | address | utxos | release-jury | refund-jury")),
    }
}

async fn status(client: &KaspaWrpcClient) -> Result<(), String> {
    println!("Connecting to node…");
    let daa = client.virtual_daa_score().await.map_err(|e| e.to_string())?;
    println!("OK — node reachable. virtualDaaScore = {daa}");
    Ok(())
}

async fn show_utxos(client: &KaspaWrpcClient, address: &str) -> Result<(), String> {
    let utxos = client.fetch_utxos(address).await.map_err(|e| e.to_string())?;
    if utxos.is_empty() {
        println!("No UTXOs at the jury covenant address yet — fund it, then re-run.");
    } else {
        println!("{} UTXO(s):", utxos.len());
        for (txid, index, value) in &utxos {
            println!("  {}:{index}  value={value} sompi", hex_encode(txid));
        }
    }
    Ok(())
}

/// The two verdict digests, computed the same way the juror clients and the
/// covenant parameters agree on: `sha256(TAG || dispute_id || verdict_byte || evidence_root)`.
fn verdict_digest(dispute_id: &[u8; 32], verdict_byte: u8, evidence_root: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(VERDICT_TAG);
    h.update(dispute_id);
    h.update([verdict_byte]);
    h.update(evidence_root);
    h.finalize().into()
}

struct JuryCtx {
    params: JuryEscrowParams,
    prefix: Prefix,
    covenant_addr: String,
    gross: u64,
    miner_fee: u64,
    customer: KeeperKey,
    keeper: KeeperKey,
    jurors: Vec<KeeperKey>,
    k: u32,
    digest_merchant: [u8; 32],
    digest_customer: [u8; 32],
}

impl JuryCtx {
    fn from_env() -> Result<Self, String> {
        let network = env_str("SMOKE_NETWORK").unwrap_or_else(|| "tn10".to_string());
        let prefix = network_prefix(&network).map_err(|e| e.to_string())?;
        let gross = env_u64("SMOKE_GROSS_SOMPI", 100_000_000);
        let fee = env_u64("SMOKE_FEE_SOMPI", 10_000_000);
        let miner_fee = env_u64("SMOKE_MINER_FEE_SOMPI", 1_200_000);
        if fee >= gross {
            return Err(format!("SMOKE_FEE_SOMPI ({fee}) must be < SMOKE_GROSS_SOMPI ({gross})"));
        }
        let merchant_net = gross - fee;
        let n = env_u64("SMOKE_JURY_N", 5) as usize;
        let k = env_u64("SMOKE_JURY_K", 3) as u32;

        let customer = env_key("SMOKE_CUSTOMER_SECRET")?;
        let merchant = env_key("SMOKE_MERCHANT_SECRET")?;
        let keeper = env_key("COVENANT_KEEPER_FEE_SECRET")?;
        let mut jurors = Vec::with_capacity(n);
        for i in 0..n {
            jurors.push(env_key(&format!("SMOKE_JUROR_SECRET_{i}"))?);
        }

        // Fixed smoke dispute identity + evidence root (any 32-byte values; the
        // covenant honors whatever the committee signs over the baked digests).
        let dispute_id = sha256_bytes(b"kasway-jury-smoke/dispute-1");
        let evidence_root = sha256_bytes(b"kasway-jury-smoke/evidence-root-1");
        let digest_merchant = verdict_digest(&dispute_id, VERDICT_MERCHANT, &evidence_root);
        let digest_customer = verdict_digest(&dispute_id, VERDICT_CUSTOMER, &evidence_root);

        let payouts = vec![
            Payout { destination: dest(&merchant, prefix)?, value: merchant_net },
            Payout { destination: dest(&keeper, prefix)?, value: fee },
        ];
        let params = JuryEscrowParams {
            payouts,
            customer_refund: dest(&customer, prefix)?,
            committee: jurors.iter().map(|j| j.x_only_pubkey()).collect(),
            jury_threshold: k,
            verdict_digest_merchant: digest_merchant,
            verdict_digest_customer: digest_customer,
            gross_amount: gross,
        };
        let compiled = compile_jury_escrow(&params).map_err(|e| e.to_string())?;
        let covenant_addr = covenant_address(&compiled, prefix).map_err(|e| e.to_string())?.to_string();

        Ok(Self { params, prefix, covenant_addr, gross, miner_fee, customer, keeper, jurors, k, digest_merchant, digest_customer })
    }

    fn print_address(&self) {
        println!("Jury dispute-escrow (JuryEscrow) parameters:");
        println!("  network        {:?}", self.prefix);
        println!("  gross_amount   {} sompi", self.gross);
        println!("  committee      {}-of-{}", self.k, self.jurors.len());
        for (i, j) in self.jurors.iter().enumerate() {
            println!("    juror[{i}]     -> {}", j.address(self.prefix));
        }
        println!("  customer_refund -> {}", self.customer.address(self.prefix));
        println!("  keeper (gas)    -> {}", self.keeper.address(self.prefix));
        println!("\n  >>> FUND the jury covenant, EXACTLY {} sompi:", self.gross);
        println!("      {}", self.covenant_addr);
        println!("\n  Then run `utxos` to confirm, then `release-jury` / `refund-jury`.");
    }
}

enum Verdict {
    Merchant,
    Customer,
}

async fn settle(client: &KaspaWrpcClient, verdict: Verdict) -> Result<(), String> {
    let ctx = JuryCtx::from_env()?;
    ctx.print_address();
    let compiled = compile_jury_escrow(&ctx.params).map_err(|e| e.to_string())?;

    let cov_utxo = find_covenant_utxo(client, &ctx.covenant_addr, ctx.gross).await?;

    // The winning verdict digest, and the K committee members who vote for it.
    let (digest, signer_idx): ([u8; 32], Vec<u32>) = match verdict {
        Verdict::Merchant => (ctx.digest_merchant, (0..ctx.k).collect()),
        Verdict::Customer => (ctx.digest_customer, (0..ctx.k).collect()),
    };
    // Each selected juror signs the winning verdict digest (checkSigFromStack input).
    let datasigs: Vec<Vec<u8>> = signer_idx
        .iter()
        .map(|&i| ctx.jurors[i as usize].sign_datasig(&digest).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;

    let spend = match verdict {
        Verdict::Merchant => {
            // Keeper subsidizes the gas for a merchant-favouring jury release.
            let keeper_addr = ctx.keeper.address(ctx.prefix).to_string();
            let fee_utxo = find_fee_utxo(client, &keeper_addr, ctx.miner_fee, "keeper").await?;
            let draft = prepare_release_jury(&compiled, &ctx.params, &cov_utxo, &fee_utxo, ctx.miner_fee, &ctx.keeper, ctx.prefix)
                .map_err(|e| e.to_string())?;
            complete_release_jury(&compiled, draft, &datasigs, &signer_idx).map_err(|e| e.to_string())?
        }
        Verdict::Customer => {
            // Customer pays their own gas on a customer-favouring jury refund.
            let fee_payer_address = ctx.customer.address(ctx.prefix);
            let fee_utxo = find_fee_utxo(client, &fee_payer_address.to_string(), ctx.miner_fee, "customer").await?;
            let draft = prepare_refund_jury(&compiled, &ctx.params, &cov_utxo, &fee_utxo, ctx.miner_fee, &fee_payer_address)
                .map_err(|e| e.to_string())?;
            let fee_sig = ctx.customer.sign_sighash(&draft.fee_sighash).map_err(|e| e.to_string())?;
            complete_refund_jury(&compiled, draft, &datasigs, &signer_idx, &fee_sig).map_err(|e| e.to_string())?
        }
    };

    let label = match verdict {
        Verdict::Merchant => "release_jury (verdict=merchant) → merchant split",
        Verdict::Customer => "refund_jury (verdict=customer) → full gross to customer",
    };
    println!("\nSettlement: {label}  [{}-of-{} committee datasigs]", ctx.k, ctx.jurors.len());
    broadcast_or_dry_run(client, &spend).await
}

// ---------------------------------------------------------------------------
// UTXO selection + broadcast (shared shape with the base-escrow harness).
// ---------------------------------------------------------------------------

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
    let utxos = fetch_utxos_retry(client, address).await?;
    utxos
        .into_iter()
        .find(|(_, _, v)| *v == gross)
        .map(|(t, i, v)| Utxo { transaction_id: t, index: i, value: v })
        .ok_or_else(|| format!("no jury covenant UTXO of exactly {gross} sompi at {address} — fund it first (mode `utxos`)"))
}

async fn find_fee_utxo(client: &KaspaWrpcClient, address: &str, min_fee: u64, label: &str) -> Result<Utxo, String> {
    let mut utxos = fetch_utxos_retry(client, address).await?;
    utxos.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    utxos
        .into_iter()
        .find(|(_, _, v)| *v > min_fee + 1)
        .map(|(t, i, v)| Utxo { transaction_id: t, index: i, value: v })
        .ok_or_else(|| format!("no {label} fee UTXO > {min_fee} sompi at {address}"))
}

async fn broadcast_or_dry_run(client: &KaspaWrpcClient, spend: &SignedSpend) -> Result<(), String> {
    let params = rpc_submit_params(spend);
    if env_str("SMOKE_BROADCAST").as_deref() == Some("1") {
        println!("Broadcasting…");
        let tx_id = client.submit_transaction(params).await.map_err(|e| e.to_string())?;
        println!("\n  ✅ ACCEPTED. txid = {tx_id}");
        println!("     explorer: https://explorer-tn10.kaspa.org/txs/{tx_id}");
        Ok(())
    } else {
        println!("\n  [dry-run] set SMOKE_BROADCAST=1 to submit. submitTransaction params:");
        println!("{}", serde_json::to_string_pretty(&params).unwrap_or_else(|_| params.to_string()));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Env / hex helpers.
// ---------------------------------------------------------------------------

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

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
