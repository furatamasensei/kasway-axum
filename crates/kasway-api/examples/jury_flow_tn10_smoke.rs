//! End-to-end Tier-3 jury FLOW harness — drives the whole backend orchestration
//! in one run and settles on live TN10.
//!
//! Unlike `jury_tn10_smoke` (which hard-codes the committee), this exercises the
//! real `kasway_api::dispute` orchestration: register a bonded juror POOL, draw a
//! K-of-N committee deterministically from a beacon seed (excluding the parties),
//! derive the `JuryEscrow` covenant for that drawn committee, collect the
//! committee's verdict datasigs, `tally` them, and broadcast the on-chain
//! settlement. One funding, whole flow.
//!
//! ```text
//! KASPA_NODE_URL=ws://… cargo run -p kasway-api --example jury_flow_tn10_smoke -- <address|settle> [merchant|customer]
//! ```
//! Env: `SMOKE_POOL_SIZE` (default 8), `SMOKE_JURY_N` (default 5), `SMOKE_JURY_K`
//! (default 3), `SMOKE_BEACON_SEED` (32-byte hex; default fixed so the committee
//! — and thus the covenant address — is stable across `address`/`settle`),
//! `SMOKE_GROSS_SOMPI`, `SMOKE_FEE_SOMPI`, `SMOKE_MINER_FEE_SOMPI`, secrets
//! `SMOKE_CUSTOMER_SECRET`, `SMOKE_MERCHANT_SECRET`, `COVENANT_KEEPER_FEE_SECRET`,
//! and `SMOKE_JUROR_SECRET_0..POOL_SIZE-1`.

use kasway_api::dispute::{
    jury_escrow_params, select_committee, settle_jury_onchain, tally, verdict_digest, Vote, VERDICT_CUSTOMER_BIT,
    VERDICT_MERCHANT_BIT,
};
use kasway_api::kaspa_wrpc::KaspaWrpcClient;
use kasway_covenant::jury_escrow::compile_jury_escrow;
use kasway_covenant::{covenant_address, network_prefix, Destination, KeeperKey, Payout, Prefix};
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
    let verdict_arg = std::env::args().nth(2).unwrap_or_else(|| "merchant".to_string());
    let client = KaspaWrpcClient::from_env().ok_or("KASPA_NODE_URL is not set")?;
    let flow = Flow::from_env()?;
    match mode.as_str() {
        "address" => {
            flow.print();
            Ok(())
        }
        "settle" => {
            flow.print();
            let verdict = if verdict_arg == "customer" { VERDICT_CUSTOMER_BIT } else { VERDICT_MERCHANT_BIT };
            flow.settle(&client, verdict).await
        }
        other => Err(format!("unknown mode {other:?}. Modes: address | settle [merchant|customer]")),
    }
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

struct Flow {
    prefix: Prefix,
    gross: u64,
    miner_fee: u64,
    customer: KeeperKey,
    merchant: KeeperKey,
    keeper: KeeperKey,
    /// Full bonded pool.
    pool: Vec<KeeperKey>,
    k: u32,
    n: usize,
    seed: [u8; 32],
    dispute_id: [u8; 32],
    evidence_root: [u8; 32],
    /// The drawn committee (pubkeys, in draw order).
    committee: Vec<[u8; 32]>,
    covenant_addr: String,
    params: kasway_covenant::jury_escrow::JuryEscrowParams,
}

impl Flow {
    fn from_env() -> Result<Self, String> {
        let network = env_str("SMOKE_NETWORK").unwrap_or_else(|| "tn10".to_string());
        let prefix = network_prefix(&network).map_err(|e| e.to_string())?;
        let gross = env_u64("SMOKE_GROSS_SOMPI", 100_000_000);
        let fee = env_u64("SMOKE_FEE_SOMPI", 10_000_000);
        let miner_fee = env_u64("SMOKE_MINER_FEE_SOMPI", 1_200_000);
        let merchant_net = gross.checked_sub(fee).ok_or("fee >= gross")?;
        let pool_size = env_u64("SMOKE_POOL_SIZE", 8) as usize;
        let n = env_u64("SMOKE_JURY_N", 5) as usize;
        let k = env_u64("SMOKE_JURY_K", 3) as u32;

        let customer = env_key("SMOKE_CUSTOMER_SECRET")?;
        let merchant = env_key("SMOKE_MERCHANT_SECRET")?;
        let keeper = env_key("COVENANT_KEEPER_FEE_SECRET")?;
        let mut pool = Vec::with_capacity(pool_size);
        for i in 0..pool_size {
            pool.push(env_key(&format!("SMOKE_JUROR_SECRET_{i}"))?);
        }

        let seed = env_hex32("SMOKE_BEACON_SEED").unwrap_or_else(|| sha256_bytes(b"kasway-jury-flow/beacon-seed-1"));
        let dispute_id = sha256_bytes(b"kasway-jury-flow/dispute-1");
        let evidence_root = kasway_api::dispute::evidence_root(
            &sha256_bytes(b"customer-evidence-blob"),
            &sha256_bytes(b"merchant-evidence-blob"),
        );

        // Draw the committee from the pool, excluding both disputing parties.
        let pool_pks: Vec<[u8; 32]> = pool.iter().map(|j| j.x_only_pubkey()).collect();
        let exclude = [customer.x_only_pubkey(), merchant.x_only_pubkey()];
        let committee = select_committee(&pool_pks, &seed, &dispute_id, &exclude, n);
        if (committee.len() as u32) < k {
            return Err(format!("pool too small: drew {} < K={k}", committee.len()));
        }

        // Payouts for a merchant verdict: merchant_net to merchant, fee slice to keeper.
        let payouts = vec![
            Payout { destination: dest(&merchant, prefix)?, value: merchant_net },
            Payout { destination: dest(&keeper, prefix)?, value: fee },
        ];
        let params = jury_escrow_params(
            payouts,
            dest(&customer, prefix)?,
            committee.clone(),
            k,
            &dispute_id,
            &evidence_root,
            gross,
        );
        let compiled = compile_jury_escrow(&params).map_err(|e| e.to_string())?;
        let covenant_addr = covenant_address(&compiled, prefix).map_err(|e| e.to_string())?.to_string();

        Ok(Self {
            prefix, gross, miner_fee, customer, merchant, keeper, pool, k, n, seed, dispute_id, evidence_root,
            committee, covenant_addr, params,
        })
    }

    fn print(&self) {
        println!("Jury FLOW — full orchestration");
        println!("  pool size       {}", self.pool.len());
        println!("  committee       {}-of-{} (drawn from pool via beacon seed)", self.k, self.n);
        println!("  beacon seed     {}", hex_encode(&self.seed));
        println!("  dispute_id      {}", hex_encode(&self.dispute_id));
        println!("  evidence_root   {}", hex_encode(&self.evidence_root));
        println!("  drawn committee (excludes customer+merchant):");
        for (i, pk) in self.committee.iter().enumerate() {
            let which = self.pool.iter().position(|j| &j.x_only_pubkey() == pk);
            println!("    seat[{i}] = pool juror #{}  {}", which.map(|x| x.to_string()).unwrap_or_default(), hex_encode(pk));
        }
        println!("  gross_amount    {} sompi", self.gross);
        println!("\n  >>> FUND the jury covenant, EXACTLY {} sompi:", self.gross);
        println!("      {}", self.covenant_addr);
        println!("\n  Then run `settle merchant` (or `settle customer`).");
    }

    async fn settle(&self, client: &KaspaWrpcClient, verdict: u8) -> Result<(), String> {
        // Each drawn committee member votes for `verdict` by signing its digest.
        let digest = verdict_digest(&self.dispute_id, verdict, &self.evidence_root);
        let mut votes: Vec<Vote> = Vec::new();
        for (seat, pk) in self.committee.iter().enumerate() {
            // Find the pool key for this committee seat and sign.
            let juror = self
                .pool
                .iter()
                .find(|j| &j.x_only_pubkey() == pk)
                .ok_or("drawn committee member not found in pool")?;
            let datasig = juror.sign_datasig(&digest).map_err(|e| e.to_string())?;
            votes.push(Vote { committee_index: seat as u32, verdict_byte: verdict, datasig });
            // Only the first K seats need to vote to reach the threshold, but we
            // collect all to exercise the tally.
            if votes.len() as u32 >= self.k + 1 {
                break;
            }
        }

        let (verdict_byte, signer_idx, datasigs) =
            tally(&votes, self.k).ok_or("votes did not reach a K-of-N verdict")?;
        println!(
            "\nTally: verdict={} reached {}-of-{} — seats {:?}",
            if verdict_byte == VERDICT_MERCHANT_BIT { "MERCHANT" } else { "CUSTOMER" },
            self.k,
            self.n,
            signer_idx
        );

        if env_str("SMOKE_BROADCAST").as_deref() != Some("1") {
            println!("  [dry-run] set SMOKE_BROADCAST=1 to broadcast the jury settlement.");
            return Ok(());
        }
        println!("Broadcasting jury settlement…");
        let txid = settle_jury_onchain(
            client,
            &self.params,
            self.prefix,
            &self.keeper,
            &self.customer,
            self.miner_fee,
            verdict_byte,
            &signer_idx,
            &datasigs,
        )
        .await
        .map_err(|e| format!("{e:?}"))?;
        println!("\n  ✅ ACCEPTED. txid = {txid}");
        println!("     explorer: https://explorer-tn10.kaspa.org/txs/{txid}");
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
