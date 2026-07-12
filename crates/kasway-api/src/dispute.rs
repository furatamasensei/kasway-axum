//! Tier-3 community-jury dispute orchestration.
//!
//! The off-chain coordination layer that turns a dispute into an on-chain
//! `JuryEscrow` settlement:
//!   1. **open** — record the dispute + both parties' evidence hashes; freeze the
//!      candidate juror pool root and the `evidence_root`.
//!   2. **select** — deterministically draw a K-of-N committee from the bonded
//!      pool using a beacon seed (a future block hash), excluding the parties.
//!   3. **vote** — collect each committee member's 64-byte `datasig` over the
//!      chosen verdict digest (published, verifiable).
//!   4. **settle** — once K datasigs agree on one verdict, assemble and broadcast
//!      `release_jury` (merchant) or `refund_jury` (customer). The covenant
//!      verifies the K committee sigs on-chain via `checkSigFromStack`.
//!
//! The committee-selection function and the digest derivations are pure and
//! deterministic so anyone can recompute and audit them; they are the reusable
//! core shared by the HTTP handlers and the on-chain smoke harness.
//!
//! Residual trust (see the project plan): binding the drawn committee to the
//! escrow is coordinator-attested until a chain-randomness builtin lands; the
//! VERDICT itself is trustless (K-of-N, K > N/2 ⇒ unique).

use crate::error::{AppError, AppResult};
use crate::kaspa_wrpc::KaspaWrpcClient;
use crate::state::AppState;
use crate::util::now_iso;
use kasway_covenant::jury_escrow::{
    compile_jury_escrow, complete_refund_jury, complete_release_jury, prepare_refund_jury, prepare_release_jury,
    JuryEscrowParams, VERDICT_CUSTOMER, VERDICT_MERCHANT, VERDICT_TAG,
};
use kasway_covenant::{covenant_address, network_prefix, rpc_submit_params, Destination, KeeperKey, Payout, Prefix, Utxo};
use sha2::{Digest, Sha256};

/// 1 = customer wins, 2 = merchant wins.
pub const VERDICT_CUSTOMER_BIT: u8 = VERDICT_CUSTOMER;
pub const VERDICT_MERCHANT_BIT: u8 = VERDICT_MERCHANT;

fn sha256_bytes(chunks: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for c in chunks {
        h.update(c);
    }
    h.finalize().into()
}

/// `evidence_root = sha256(customer_evidence_hash || merchant_evidence_hash)`.
/// Binds a verdict to the exact evidence set both parties anchored.
pub fn evidence_root(customer_hash: &[u8; 32], merchant_hash: &[u8; 32]) -> [u8; 32] {
    sha256_bytes(&[customer_hash, merchant_hash])
}

/// The verdict digest a juror signs: `sha256(TAG || dispute_id || verdict_byte || evidence_root)`.
pub fn verdict_digest(dispute_id: &[u8; 32], verdict_byte: u8, evidence_root: &[u8; 32]) -> [u8; 32] {
    sha256_bytes(&[VERDICT_TAG, dispute_id, &[verdict_byte], evidence_root])
}

/// Deterministically draw an `n`-member committee from `pool`, excluding the
/// disputing parties, driven by `seed` (a beacon / future block hash). Publicly
/// recomputable: a partial Fisher–Yates shuffle keyed by `sha256(seed ||
/// dispute_id || "select" || j)`. Returns the drawn juror pubkeys in draw order.
pub fn select_committee(
    pool: &[[u8; 32]],
    seed: &[u8; 32],
    dispute_id: &[u8; 32],
    exclude: &[[u8; 32]],
    n: usize,
) -> Vec<[u8; 32]> {
    let mut cand: Vec<[u8; 32]> = pool.iter().copied().filter(|p| !exclude.contains(p)).collect();
    let target = n.min(cand.len());
    for j in 0..target {
        let r = sha256_bytes(&[seed, dispute_id, b"KASWAY/jury/select", &(j as u32).to_le_bytes()]);
        let rem = cand.len() - j;
        let pick = j + (u32::from_le_bytes([r[0], r[1], r[2], r[3]]) as usize % rem);
        cand.swap(j, pick);
    }
    cand.truncate(target);
    cand
}

/// Build the `JuryEscrow` covenant parameters for a dispute: the merchant-win
/// payout split, the drawn committee + threshold, and the two baked verdict
/// digests. The covenant address is a pure function of these.
#[allow(clippy::too_many_arguments)]
pub fn jury_escrow_params(
    payouts: Vec<Payout>,
    customer_refund: Destination,
    committee: Vec<[u8; 32]>,
    jury_threshold: u32,
    dispute_id: &[u8; 32],
    evidence_root: &[u8; 32],
    gross_amount: u64,
) -> JuryEscrowParams {
    JuryEscrowParams {
        payouts,
        customer_refund,
        committee,
        jury_threshold,
        verdict_digest_merchant: verdict_digest(dispute_id, VERDICT_MERCHANT, evidence_root),
        verdict_digest_customer: verdict_digest(dispute_id, VERDICT_CUSTOMER, evidence_root),
        gross_amount,
    }
}

/// A collected committee vote: which committee slot signed, and their datasig
/// over the verdict digest for `verdict_byte`.
#[derive(Debug, Clone)]
pub struct Vote {
    pub committee_index: u32,
    pub verdict_byte: u8,
    pub datasig: Vec<u8>,
}

/// Tally the collected votes; return the verdict that reached `k` datasigs (if
/// any) together with the `k` (index, datasig) pairs to feed the covenant.
pub fn tally(votes: &[Vote], k: u32) -> Option<(u8, Vec<u32>, Vec<Vec<u8>>)> {
    for verdict in [VERDICT_MERCHANT, VERDICT_CUSTOMER] {
        let mut chosen: Vec<&Vote> = votes.iter().filter(|v| v.verdict_byte == verdict).collect();
        chosen.sort_by_key(|v| v.committee_index);
        chosen.dedup_by_key(|v| v.committee_index);
        if chosen.len() as u32 >= k {
            let picked = &chosen[..k as usize];
            let idx = picked.iter().map(|v| v.committee_index).collect();
            let sigs = picked.iter().map(|v| v.datasig.clone()).collect();
            return Some((verdict, idx, sigs));
        }
    }
    None
}

/// Errors from the dispute settlement path.
fn derr(msg: impl AsRef<str>) -> AppError {
    AppError::commerce(422, msg.as_ref())
}

/// Assemble and broadcast the on-chain jury settlement for a dispute whose votes
/// have reached a K-of-N verdict. `keeper` subsidizes gas on a merchant verdict;
/// the customer pays gas (external fee) on a customer verdict — mirroring the
/// base escrow's release/refund gas policy. Returns the accepted txid.
#[allow(clippy::too_many_arguments)]
pub async fn settle_jury_onchain(
    client: &KaspaWrpcClient,
    params: &JuryEscrowParams,
    prefix: Prefix,
    keeper: &KeeperKey,
    customer: &KeeperKey,
    miner_fee: u64,
    verdict_byte: u8,
    signer_idx: &[u32],
    datasigs: &[Vec<u8>],
) -> AppResult<String> {
    let compiled = compile_jury_escrow(params).map_err(|e| derr(e.to_string()))?;
    let covenant_addr = covenant_address(&compiled, prefix).map_err(|e| derr(e.to_string()))?.to_string();

    let gross = params.gross_amount;
    let cov_utxos = client.fetch_utxos(&covenant_addr).await.map_err(|e| derr(e.to_string()))?;
    let cov = cov_utxos
        .into_iter()
        .find(|(_, _, v)| *v == gross)
        .map(|(t, i, v)| Utxo { transaction_id: t, index: i, value: v })
        .ok_or_else(|| derr("jury covenant funding UTXO not visible yet"))?;

    let spend = if verdict_byte == VERDICT_MERCHANT {
        // Merchant verdict: keeper subsidizes gas (mirrors the base escrow release).
        let keeper_addr = keeper.address(prefix).to_string();
        let fee = pick_fee_utxo(client, &keeper_addr, miner_fee).await?;
        let draft = prepare_release_jury(&compiled, params, &cov, &fee, miner_fee, keeper, prefix)
            .map_err(|e| derr(e.to_string()))?;
        complete_release_jury(&compiled, draft, datasigs, signer_idx).map_err(|e| derr(e.to_string()))?
    } else {
        // Customer verdict: the customer pays their own gas (external fee input).
        let fee_addr = customer.address(prefix).to_string();
        let fee = pick_fee_utxo(client, &fee_addr, miner_fee).await?;
        let draft = prepare_refund_jury(&compiled, params, &cov, &fee, miner_fee, &customer.address(prefix))
            .map_err(|e| derr(e.to_string()))?;
        let fee_sig = customer.sign_sighash(&draft.fee_sighash).map_err(|e| derr(e.to_string()))?;
        complete_refund_jury(&compiled, draft, datasigs, signer_idx, &fee_sig).map_err(|e| derr(e.to_string()))?
    };

    client.submit_transaction(rpc_submit_params(&spend)).await.map_err(|e| derr(e.to_string()))
}

async fn pick_fee_utxo(client: &KaspaWrpcClient, address: &str, min_fee: u64) -> AppResult<Utxo> {
    let mut utxos = client.fetch_utxos(address).await.map_err(|e| derr(e.to_string()))?;
    utxos.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    utxos
        .into_iter()
        .find(|(_, _, v)| *v > min_fee + 1)
        .map(|(t, i, v)| Utxo { transaction_id: t, index: i, value: v })
        .ok_or_else(|| derr(format!("no fee UTXO > {min_fee} sompi at {address}")))
}

// ---------------------------------------------------------------------------
// DB-backed lifecycle (uses the 0034_dispute_layer tables).
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Open a dispute for a funded intent: record the tier, evidence hashes and
/// `evidence_root`, and move the intent to `disputed`. Returns the dispute id.
pub async fn open_dispute(
    state: &AppState,
    intent_id: i64,
    tier: &str,
    customer_hash: &[u8; 32],
    merchant_hash: &[u8; 32],
) -> AppResult<i64> {
    let root = evidence_root(customer_hash, merchant_hash);
    let now = now_iso();
    let rec = sqlx::query_scalar::<_, i64>(
        "INSERT INTO kpr1_disputes (intent_id, tier, state, evidence_customer_hash, evidence_merchant_hash, \
         evidence_root, opened_at, updated_at) VALUES ($1,$2,'open',$3,$4,$5,$6,$6) RETURNING id",
    )
    .bind(intent_id)
    .bind(tier)
    .bind(hex(customer_hash))
    .bind(hex(merchant_hash))
    .bind(hex(&root))
    .bind(&now)
    .fetch_one(&state.db.pool)
    .await
    .map_err(AppError::Database)?;
    sqlx::query("UPDATE kpr1_payment_intents SET covenant_state = 'disputed', updated_at = $1 WHERE id = $2")
        .bind(&now)
        .bind(intent_id)
        .execute(&state.db.pool)
        .await
        .map_err(AppError::Database)?;
    Ok(rec)
}

/// Record a committee member's published vote (commit or reveal datasig).
pub async fn record_vote(
    state: &AppState,
    dispute_id: i64,
    juror_pubkey: &[u8; 32],
    committee_index: u32,
    verdict_byte: u8,
    reveal_datasig: &[u8],
) -> AppResult<()> {
    let now = now_iso();
    sqlx::query(
        "INSERT INTO kpr1_dispute_votes (dispute_id, juror_pubkey, committee_idx, reveal_bit, reveal_datasig, \
         created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$6) \
         ON CONFLICT (dispute_id, juror_pubkey) DO UPDATE SET reveal_bit = $4, reveal_datasig = $5, updated_at = $6",
    )
    .bind(dispute_id)
    .bind(hex(juror_pubkey))
    .bind(committee_index as i32)
    .bind(verdict_byte as i16)
    .bind(hex(reveal_datasig))
    .bind(&now)
    .execute(&state.db.pool)
    .await
    .map_err(AppError::Database)?;
    Ok(())
}

/// Load the recorded reveal votes for a dispute.
pub async fn load_votes(state: &AppState, dispute_id: i64) -> AppResult<Vec<Vote>> {
    let rows = sqlx::query_as::<_, (i32, Option<i16>, Option<String>)>(
        "SELECT committee_idx, reveal_bit, reveal_datasig FROM kpr1_dispute_votes WHERE dispute_id = $1",
    )
    .bind(dispute_id)
    .fetch_all(&state.db.pool)
    .await
    .map_err(AppError::Database)?;
    let mut votes = Vec::new();
    for (idx, bit, sig) in rows {
        if let (Some(bit), Some(sig)) = (bit, sig) {
            if let Some(bytes) = decode_hex(&sig) {
                votes.push(Vote { committee_index: idx as u32, verdict_byte: bit as u8, datasig: bytes });
            }
        }
    }
    Ok(votes)
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()).collect()
}

/// Convenience: the network prefix helper, re-exported for handlers/harness.
pub fn prefix_for(network: &str) -> AppResult<Prefix> {
    network_prefix(network).map_err(|e| derr(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn select_committee_is_deterministic_and_sized() {
        let pool: Vec<[u8; 32]> = (1..=10).map(pk).collect();
        let seed = [0xAB; 32];
        let dispute = [0xCD; 32];
        let a = select_committee(&pool, &seed, &dispute, &[], 5);
        let b = select_committee(&pool, &seed, &dispute, &[], 5);
        assert_eq!(a, b, "same inputs -> same committee");
        assert_eq!(a.len(), 5);
        // all distinct
        let mut sorted = a.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 5, "committee members are distinct");
    }

    #[test]
    fn select_committee_excludes_parties() {
        let pool: Vec<[u8; 32]> = (1..=6).map(pk).collect();
        let exclude = [pk(2), pk(4)];
        let c = select_committee(&pool, &[1; 32], &[2; 32], &exclude, 4);
        assert_eq!(c.len(), 4, "6 pool - 2 excluded = 4 selectable");
        assert!(!c.contains(&pk(2)) && !c.contains(&pk(4)), "excluded parties never selected");
    }

    #[test]
    fn different_seed_gives_different_committee() {
        let pool: Vec<[u8; 32]> = (1..=12).map(pk).collect();
        let a = select_committee(&pool, &[1; 32], &[9; 32], &[], 5);
        let b = select_committee(&pool, &[2; 32], &[9; 32], &[], 5);
        assert_ne!(a, b, "a different beacon seed reshuffles the committee");
    }

    #[test]
    fn tally_reaches_verdict_at_threshold() {
        let sig = |b: u8| vec![b; 64];
        let votes = vec![
            Vote { committee_index: 0, verdict_byte: VERDICT_MERCHANT, datasig: sig(0) },
            Vote { committee_index: 1, verdict_byte: VERDICT_MERCHANT, datasig: sig(1) },
            Vote { committee_index: 2, verdict_byte: VERDICT_CUSTOMER, datasig: sig(2) },
            Vote { committee_index: 3, verdict_byte: VERDICT_MERCHANT, datasig: sig(3) },
        ];
        let (verdict, idx, sigs) = tally(&votes, 3).expect("3 merchant votes reach threshold");
        assert_eq!(verdict, VERDICT_MERCHANT);
        assert_eq!(idx, vec![0, 1, 3]);
        assert_eq!(sigs.len(), 3);
        assert!(tally(&votes, 4).is_none(), "no verdict reaches 4");
    }
}
