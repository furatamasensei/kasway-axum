//! TN10 on-chain proof harness for the Kasway **juror bond** (commit-reveal + slashing).
//!
//! Proves the last Tier-3 covenant on a live rusty-kaspa v2.0.1 (Toccata) node:
//! a juror "commits" by funding a `JurorBond` whose `commit_hash =
//! blake2b(verdict_digest||salt)` is baked in, and the bond UTXO's block DAA score
//! (read in-script via `OpTxInputDaaScore`) is the consensus record of WHEN they
//! committed. Then either:
//!   - `claim`: honest juror reclaims the bond (K-of-N committee verdict proof +
//!     `salt` reveal + committed-in-time + reveal window open via CLTV), or
//!   - `slash`: after the claim deadline, permissionless slash to the treasury.
//!
//! The commit/reveal/claim windows are DAA scores passed via env so they stay
//! stable across `address` (funding) and `claim`/`slash` (settlement) runs.
//!
//! # Usage
//! ```text
//! KASPA_NODE_URL=ws://… SMOKE_COMMIT_DEADLINE=… SMOKE_REVEAL_OPEN=… SMOKE_CLAIM_DEADLINE=… \
//! cargo run -p kasway-api --example juror_bond_tn10_smoke -- <mode>
//! ```
//! Modes: `status` | `address` | `utxos` | `claim` | `slash`.
//!
//! Env: `SMOKE_BOND_SOMPI` (default 50_000_000), `SMOKE_COMMIT_VERDICT`
//! (`merchant`|`customer`, which digest the juror committed to), `SMOKE_BOND_DAA`
//! (real block DAA score of the funded bond UTXO — from REST; only affects the
//! local UtxoEntry, node uses the real one), `SMOKE_JURY_N`/`_K`, secrets
//! `SMOKE_CUSTOMER_SECRET` (payout), `SMOKE_MERCHANT_SECRET` (treasury),
//! `COVENANT_KEEPER_FEE_SECRET` (gas), `SMOKE_JUROR_SECRET_0..N-1`.

use kasway_api::chain_source::ChainSource;
use kasway_api::kaspa_wrpc::KaspaWrpcClient;
use kasway_covenant::juror_bond::{
    commit_hash, compile_juror_bond, complete_claim_honest, complete_slash, prepare_claim_honest, prepare_slash,
    JurorBondParams,
};
use kasway_covenant::jury_escrow::{VERDICT_CUSTOMER, VERDICT_MERCHANT, VERDICT_TAG};
use kasway_covenant::{
    covenant_address, network_prefix, rpc_submit_params, Destination, KeeperKey, Prefix, SignedSpend, Utxo,
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
    let client = KaspaWrpcClient::from_env().ok_or("KASPA_NODE_URL is not set")?;
    match mode.as_str() {
        "status" => {
            let daa = client.virtual_daa_score().await.map_err(|e| e.to_string())?;
            println!("OK — node reachable. virtualDaaScore = {daa}");
            Ok(())
        }
        "address" => {
            BondCtx::from_env()?.print_address();
            Ok(())
        }
        "utxos" => {
            let ctx = BondCtx::from_env()?;
            ctx.print_address();
            let utxos = client.fetch_utxos(&ctx.bond_addr).await.map_err(|e| e.to_string())?;
            if utxos.is_empty() {
                println!("No UTXOs at the bond address yet — fund it (EXACTLY {} sompi), then re-run.", ctx.params.bond_amount);
            } else {
                for (t, i, v) in &utxos {
                    println!("  {}:{i}  value={v} sompi", hex_encode(t));
                }
            }
            Ok(())
        }
        "claim" => settle(&client, Action::Claim).await,
        "slash" => settle(&client, Action::Slash).await,
        other => Err(format!("unknown mode {other:?}. Modes: status | address | utxos | claim | slash")),
    }
}

fn verdict_digest(dispute_id: &[u8; 32], verdict_byte: u8, evidence_root: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(VERDICT_TAG);
    h.update(dispute_id);
    h.update([verdict_byte]);
    h.update(evidence_root);
    h.finalize().into()
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

struct BondCtx {
    params: JurorBondParams,
    prefix: Prefix,
    bond_addr: String,
    keeper: KeeperKey,
    jurors: Vec<KeeperKey>,
    k: u32,
    digest_merchant: [u8; 32],
    salt: [u8; 32],
    bond_daa: u64,
}

impl BondCtx {
    fn from_env() -> Result<Self, String> {
        let network = env_str("SMOKE_NETWORK").unwrap_or_else(|| "tn10".to_string());
        let prefix = network_prefix(&network).map_err(|e| e.to_string())?;
        let bond_amount = env_u64("SMOKE_BOND_SOMPI", 50_000_000);
        let n = env_u64("SMOKE_JURY_N", 5) as usize;
        let k = env_u64("SMOKE_JURY_K", 3) as u32;
        let commit_deadline = env_u64("SMOKE_COMMIT_DEADLINE", 0);
        let reveal_open = env_u64("SMOKE_REVEAL_OPEN", 0);
        let claim_deadline = env_u64("SMOKE_CLAIM_DEADLINE", 0);
        let bond_daa = env_u64("SMOKE_BOND_DAA", commit_deadline.saturating_sub(1));
        if commit_deadline == 0 || reveal_open == 0 || claim_deadline == 0 {
            return Err("SMOKE_COMMIT_DEADLINE, SMOKE_REVEAL_OPEN and SMOKE_CLAIM_DEADLINE (DAA scores) are required".to_string());
        }

        let payout = env_key("SMOKE_CUSTOMER_SECRET")?; // honest-claim payout
        let treasury = env_key("SMOKE_MERCHANT_SECRET")?; // slashed-bond treasury
        let keeper = env_key("COVENANT_KEEPER_FEE_SECRET")?;
        let mut jurors = Vec::with_capacity(n);
        for i in 0..n {
            jurors.push(env_key(&format!("SMOKE_JUROR_SECRET_{i}"))?);
        }

        let dispute_id = sha256_bytes(b"kasway-jury-smoke/dispute-1");
        let evidence_root = sha256_bytes(b"kasway-jury-smoke/evidence-root-1");
        let digest_merchant = verdict_digest(&dispute_id, VERDICT_MERCHANT, &evidence_root);
        let digest_customer = verdict_digest(&dispute_id, VERDICT_CUSTOMER, &evidence_root);
        let salt = env_hex32("SMOKE_SALT").unwrap_or([0x77; 32]);

        // Which verdict this juror committed to (winner=merchant for claim; the
        // loser=customer for a slash demo, so the bond can't be claimed honest).
        let committed = match env_str("SMOKE_COMMIT_VERDICT").as_deref() {
            Some("customer") => digest_customer,
            _ => digest_merchant,
        };

        let params = JurorBondParams {
            committee: jurors.iter().map(|j| j.x_only_pubkey()).collect(),
            jury_threshold: k,
            verdict_digest_merchant: digest_merchant,
            verdict_digest_customer: digest_customer,
            commit_hash: commit_hash(&committed, &salt),
            commit_deadline,
            reveal_open,
            claim_deadline,
            bond_amount,
            payout: dest(&payout, prefix)?,
            treasury: dest(&treasury, prefix)?,
        };
        let compiled = compile_juror_bond(&params).map_err(|e| e.to_string())?;
        let bond_addr = covenant_address(&compiled, prefix).map_err(|e| e.to_string())?.to_string();

        Ok(Self { params, prefix, bond_addr, keeper, jurors, k, digest_merchant, salt, bond_daa })
    }

    fn print_address(&self) {
        println!("Juror bond (JurorBond) parameters:");
        println!("  bond_amount      {} sompi", self.params.bond_amount);
        println!("  committee        {}-of-{}", self.k, self.jurors.len());
        println!("  commit_deadline  {} (DAA)", self.params.commit_deadline);
        println!("  reveal_open      {} (DAA)", self.params.reveal_open);
        println!("  claim_deadline   {} (DAA)", self.params.claim_deadline);
        println!("  payout (honest)  -> {}", self.params.payout.address());
        println!("  treasury (slash) -> {}", self.params.treasury.address());
        println!("  keeper (gas)     -> {}", self.keeper.address(self.prefix));
        println!("\n  >>> FUND the bond, EXACTLY {} sompi:", self.params.bond_amount);
        println!("      {}", self.bond_addr);
    }
}

enum Action {
    Claim,
    Slash,
}

async fn settle(client: &KaspaWrpcClient, action: Action) -> Result<(), String> {
    let ctx = BondCtx::from_env()?;
    ctx.print_address();
    let compiled = compile_juror_bond(&ctx.params).map_err(|e| e.to_string())?;

    let bond_utxo = find_utxo(client, &ctx.bond_addr, ctx.params.bond_amount, "bond").await?;
    let keeper_addr = ctx.keeper.address(ctx.prefix).to_string();
    let fee_utxo = find_fee_utxo(client, &keeper_addr, 1_200_000).await?;

    // The winning verdict = merchant; K committee members attest it (checkSigFromStack).
    let signer_idx: Vec<u32> = (0..ctx.k).collect();
    let datasigs: Vec<Vec<u8>> = signer_idx
        .iter()
        .map(|&i| ctx.jurors[i as usize].sign_datasig(&ctx.digest_merchant).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;

    let (label, spend) = match action {
        Action::Claim => {
            let draft = prepare_claim_honest(&compiled, &ctx.params, &bond_utxo, ctx.bond_daa, &fee_utxo, 1_200_000, &ctx.keeper, ctx.prefix)
                .map_err(|e| e.to_string())?;
            let spend = complete_claim_honest(&compiled, draft, &datasigs, &signer_idx, &ctx.digest_merchant, &ctx.salt)
                .map_err(|e| e.to_string())?;
            ("claim_honest → bond returned to juror payout", spend)
        }
        Action::Slash => {
            let draft = prepare_slash(&compiled, &ctx.params, &bond_utxo, ctx.bond_daa, &fee_utxo, 1_200_000, &ctx.keeper, ctx.prefix)
                .map_err(|e| e.to_string())?;
            let spend = complete_slash(&compiled, draft, &datasigs, &signer_idx, &ctx.digest_merchant).map_err(|e| e.to_string())?;
            ("slash → bond forfeited to treasury", spend)
        }
    };

    println!("\nSettlement: {label}  [{}-of-{} committee datasigs]", ctx.k, ctx.jurors.len());
    broadcast_or_dry_run(client, &spend).await
}

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

async fn find_utxo(client: &KaspaWrpcClient, address: &str, value: u64, label: &str) -> Result<Utxo, String> {
    let utxos = fetch_utxos_retry(client, address).await?;
    utxos
        .into_iter()
        .find(|(_, _, v)| *v == value)
        .map(|(t, i, v)| Utxo { transaction_id: t, index: i, value: v })
        .ok_or_else(|| format!("no {label} UTXO of exactly {value} sompi at {address} — fund it first"))
}

async fn find_fee_utxo(client: &KaspaWrpcClient, address: &str, min_fee: u64) -> Result<Utxo, String> {
    let mut utxos = fetch_utxos_retry(client, address).await?;
    utxos.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    utxos
        .into_iter()
        .find(|(_, _, v)| *v > min_fee + 1)
        .map(|(t, i, v)| Utxo { transaction_id: t, index: i, value: v })
        .ok_or_else(|| format!("no keeper fee UTXO > {min_fee} sompi at {address}"))
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
        println!("\n  [dry-run] set SMOKE_BROADCAST=1 to submit.");
        println!("{}", serde_json::to_string_pretty(&params).unwrap_or_else(|_| params.to_string()));
        Ok(())
    }
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
    let bytes = hex_decode32(&hex).ok_or_else(|| format!("{name} must be 64 hex chars"))?;
    KeeperKey::from_secret_bytes(&bytes).map_err(|e| format!("{name}: {e}"))
}

fn env_hex32(name: &str) -> Option<[u8; 32]> {
    env_str(name).and_then(|s| hex_decode32(&s))
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
