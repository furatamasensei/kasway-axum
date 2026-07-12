//! Kasway Tier-3 **juror bond** — commit-reveal + slashing, with NO on-chain
//! state transition.
//!
//! A juror commits by funding a `JurorBond` whose `commit_hash =
//! blake2b(chosen_verdict_digest || salt)` is baked in. The bond UTXO's block DAA
//! score (read via `OpTxInputDaaScore`) is the consensus record of when they
//! committed. `claim_honest` returns the bond to a juror who reveals `salt` for
//! the winning verdict (proven by K-of-N committee datasigs) and committed in
//! time; `slash` sends an unclaimed bond to the treasury after the claim window.

use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::units::ComputeBudget;
use kaspa_consensus_core::tx::{
    ComputeCommit, MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput,
    TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{pay_to_address_script, pay_to_script_hash_script};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions, CompiledContract};

use crate::{
    covenant_signature_script, push_change, to_i64, CovenantError, Destination, KeeperKey, Prefix, SignedSpend,
    Utxo, COVENANT_COMPUTE_BUDGET, FEE_COMPUTE_BUDGET,
};

/// JurorBond covenant source.
pub const JUROR_BOND_SRC: &str = include_str!("../contracts/juror_bond.sil");

pub const EP_CLAIM_HONEST: &str = "claim_honest";
pub const EP_SLASH: &str = "slash";

/// Compute `commit_hash = blake2b256(winner_digest || salt)` exactly as the
/// covenant's `blake2b(byte[](winner_digest) + byte[](salt))` does. This is the
/// value the juror bakes into their bond when committing their vote.
pub fn commit_hash(verdict_digest: &[u8; 32], salt: &[u8; 32]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(64);
    pre.extend_from_slice(verdict_digest);
    pre.extend_from_slice(salt);
    let h = kaspa_hashes::blake2b_simd::Params::new().hash_length(32).to_state().update(&pre).finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// Parameters that determine a JurorBond covenant instance (and its P2SH address).
#[derive(Debug, Clone)]
pub struct JurorBondParams {
    pub committee: Vec<[u8; 32]>,
    pub jury_threshold: u32,
    pub verdict_digest_merchant: [u8; 32],
    pub verdict_digest_customer: [u8; 32],
    /// `blake2b(chosen_verdict_digest || salt)` — the juror's baked commitment.
    pub commit_hash: [u8; 32],
    /// DAA score before which the bond must be funded (committed).
    pub commit_deadline: u64,
    /// DAA score at/after which `claim_honest` is allowed (== commit_deadline).
    pub reveal_open: u64,
    /// DAA score at/after which `slash` is allowed.
    pub claim_deadline: u64,
    pub bond_amount: u64,
    /// The juror's honest-claim payout target — MUST be schnorr P2PK.
    pub payout: Destination,
    /// The treasury target for slashed bonds — MUST be schnorr P2PK.
    pub treasury: Destination,
}

fn p2pk_pubkey(dest: &Destination) -> Result<Vec<u8>, CovenantError> {
    if dest.kind() != 0 {
        return Err(CovenantError::UnsupportedAddressKind(
            "payout/treasury must be a schnorr P2PK address".to_string(),
        ));
    }
    Ok(dest.payload32())
}

impl JurorBondParams {
    fn constructor_args(&self) -> Result<Vec<Expr<'static>>, CovenantError> {
        if self.committee.is_empty() {
            return Err(CovenantError::UnsupportedAddressKind("committee must not be empty".to_string()));
        }
        let n = self.committee.len();
        if self.jury_threshold == 0 || self.jury_threshold as usize > n {
            return Err(CovenantError::UnsupportedAddressKind(format!(
                "jury threshold {} must be in 1..={}",
                self.jury_threshold, n
            )));
        }
        let committee: Vec<Vec<u8>> = self.committee.iter().map(|k| k.to_vec()).collect();
        Ok(vec![
            committee.into(),                              // byte[32][] committee_pubkeys
            to_i64(n as u64)?.into(),                      // int        committee_count
            to_i64(self.jury_threshold as u64)?.into(),    // int        jury_threshold
            self.verdict_digest_merchant.to_vec().into(),  // byte[32]   verdict_digest_merchant
            self.verdict_digest_customer.to_vec().into(),  // byte[32]   verdict_digest_customer
            self.commit_hash.to_vec().into(),              // byte[32]   commit_hash
            to_i64(self.commit_deadline)?.into(),          // int        commit_deadline
            to_i64(self.reveal_open)?.into(),              // int        reveal_open
            to_i64(self.claim_deadline)?.into(),           // int        claim_deadline
            to_i64(self.bond_amount)?.into(),              // int        bond_amount
            p2pk_pubkey(&self.payout)?.into(),             // byte[32]   payout_pubkey
            p2pk_pubkey(&self.treasury)?.into(),           // byte[32]   slash_pubkey
        ])
    }
}

pub fn compile_juror_bond(params: &JurorBondParams) -> Result<CompiledContract<'static>, CovenantError> {
    let args = params.constructor_args()?;
    Ok(compile_contract(JUROR_BOND_SRC, &args, CompileOptions::default())?)
}

/// Assemble a bond spend: input 0 = the bond covenant (P2SH; its UTXO was created
/// at `bond_daa`), input 1 = a keeper-signed fee input. `lock_time` gates the
/// CLTV window. Returns the tx, its UTXO entries, and the covenant input sighash.
fn assemble_bond_spend(
    redeem: &[u8],
    outputs: Vec<TransactionOutput>,
    lock_time: u64,
    bond_utxo: &Utxo,
    bond_daa: u64,
    fee_utxo: &Utxo,
    keeper: &KeeperKey,
    prefix: Prefix,
) -> Result<(Transaction, Vec<UtxoEntry>, [u8; 32]), CovenantError> {
    let cov_input = TransactionInput {
        previous_outpoint: TransactionOutpoint {
            transaction_id: TransactionId::from_bytes(bond_utxo.transaction_id),
            index: bond_utxo.index,
        },
        signature_script: vec![],
        sequence: 0,
        compute_commit: ComputeCommit::ComputeBudget(ComputeBudget(COVENANT_COMPUTE_BUDGET)),
    };
    let fee_input = TransactionInput {
        previous_outpoint: TransactionOutpoint {
            transaction_id: TransactionId::from_bytes(fee_utxo.transaction_id),
            index: fee_utxo.index,
        },
        signature_script: vec![],
        sequence: 0,
        compute_commit: ComputeCommit::ComputeBudget(ComputeBudget(FEE_COMPUTE_BUDGET)),
    };

    let cov_entry = UtxoEntry::new(bond_utxo.value, pay_to_script_hash_script(redeem), bond_daa, false, None);
    let fee_spk: ScriptPublicKey = pay_to_address_script(&keeper.address(prefix));
    let fee_entry = UtxoEntry::new(fee_utxo.value, fee_spk, 0, false, None);

    let tx = Transaction::new(1, vec![cov_input, fee_input], outputs, lock_time, Default::default(), 0, vec![]);
    let mut mtx = MutableTransaction::with_entries(tx, vec![cov_entry.clone(), fee_entry.clone()]);

    let reused = SigHashReusedValuesUnsync::new();
    let cov_sighash: [u8; 32] =
        calc_schnorr_signature_hash(&mtx.as_verifiable(), 0, SIG_HASH_ALL, &reused).as_bytes();
    let fee_sighash: [u8; 32] =
        calc_schnorr_signature_hash(&mtx.as_verifiable(), 1, SIG_HASH_ALL, &reused).as_bytes();

    let fee_sig = keeper.sign_sighash(&fee_sighash)?;
    mtx.tx.inputs[1].signature_script = ScriptBuilder::new()
        .add_data(&fee_sig)
        .map_err(|e| CovenantError::Compile(format!("fee sigscript: {e}")))?
        .drain();
    Ok((mtx.tx, vec![cov_entry, fee_entry], cov_sighash))
}

fn single_output(spk: &ScriptPublicKey, value: u64, fee_utxo: &Utxo, miner_fee: u64, change_addr: &kaspa_addresses::Address) -> Vec<TransactionOutput> {
    let mut outputs = vec![TransactionOutput { value, script_public_key: spk.clone(), covenant: None }];
    push_change(&mut outputs, fee_utxo, miner_fee, change_addr);
    outputs
}

/// A prepared bond spend whose covenant input needs the K-of-N committee datasigs
/// (and, for a claim, the reveal `salt`).
pub struct BondSpendDraft {
    transaction: Transaction,
    entries: Vec<UtxoEntry>,
    pub covenant_sighash: [u8; 32],
}

/// Prepare a `claim_honest` spend returning `bond_amount` to the juror's payout.
pub fn prepare_claim_honest(
    compiled: &CompiledContract<'_>,
    params: &JurorBondParams,
    bond_utxo: &Utxo,
    bond_daa: u64,
    fee_utxo: &Utxo,
    miner_fee: u64,
    keeper: &KeeperKey,
    prefix: Prefix,
) -> Result<BondSpendDraft, CovenantError> {
    let outputs = single_output(&params.payout.script_public_key(), params.bond_amount, fee_utxo, miner_fee, &keeper.address(prefix));
    let (transaction, entries, covenant_sighash) =
        assemble_bond_spend(&compiled.script, outputs, params.reveal_open, bond_utxo, bond_daa, fee_utxo, keeper, prefix)?;
    Ok(BondSpendDraft { transaction, entries, covenant_sighash })
}

pub fn complete_claim_honest(
    compiled: &CompiledContract<'_>,
    mut draft: BondSpendDraft,
    committee_sigs: &[Vec<u8>],
    signer_idx: &[u32],
    winner_digest: &[u8; 32],
    salt: &[u8; 32],
) -> Result<SignedSpend, CovenantError> {
    let sigs_arr: Vec<Vec<u8>> = committee_sigs.to_vec();
    let idx_arr: Vec<i64> = signer_idx.iter().map(|i| *i as i64).collect();
    let entrypoint_sig = compiled.build_sig_script(
        EP_CLAIM_HONEST,
        vec![sigs_arr.into(), idx_arr.into(), winner_digest.to_vec().into(), salt.to_vec().into()],
    )?;
    draft.transaction.inputs[0].signature_script = covenant_signature_script(&compiled.script, entrypoint_sig)?;
    Ok(SignedSpend { transaction: draft.transaction, entries: draft.entries })
}

/// Prepare a `slash` spend sending `bond_amount` to the treasury.
pub fn prepare_slash(
    compiled: &CompiledContract<'_>,
    params: &JurorBondParams,
    bond_utxo: &Utxo,
    bond_daa: u64,
    fee_utxo: &Utxo,
    miner_fee: u64,
    keeper: &KeeperKey,
    prefix: Prefix,
) -> Result<BondSpendDraft, CovenantError> {
    let outputs = single_output(&params.treasury.script_public_key(), params.bond_amount, fee_utxo, miner_fee, &keeper.address(prefix));
    let (transaction, entries, covenant_sighash) =
        assemble_bond_spend(&compiled.script, outputs, params.claim_deadline, bond_utxo, bond_daa, fee_utxo, keeper, prefix)?;
    Ok(BondSpendDraft { transaction, entries, covenant_sighash })
}

pub fn complete_slash(
    compiled: &CompiledContract<'_>,
    mut draft: BondSpendDraft,
    committee_sigs: &[Vec<u8>],
    signer_idx: &[u32],
    winner_digest: &[u8; 32],
) -> Result<SignedSpend, CovenantError> {
    let sigs_arr: Vec<Vec<u8>> = committee_sigs.to_vec();
    let idx_arr: Vec<i64> = signer_idx.iter().map(|i| *i as i64).collect();
    let entrypoint_sig =
        compiled.build_sig_script(EP_SLASH, vec![sigs_arr.into(), idx_arr.into(), winner_digest.to_vec().into()])?;
    draft.transaction.inputs[0].signature_script = covenant_signature_script(&compiled.script, entrypoint_sig)?;
    Ok(SignedSpend { transaction: draft.transaction, entries: draft.entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::covenant_address;
    use kaspa_consensus_core::tx::PopulatedTransaction;
    use kaspa_txscript::caches::Cache;
    use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
    use kaspa_txscript_errors::TxScriptError;

    fn key(byte: u8) -> KeeperKey {
        KeeperKey::from_secret_bytes(&[byte; 32]).unwrap()
    }
    fn juror(i: u8) -> KeeperKey { key(20 + i) }
    fn keeper() -> KeeperKey { key(7) }
    fn juror_payout() -> KeeperKey { key(30) }
    fn treasury() -> KeeperKey { key(31) }

    fn dest_of(k: &KeeperKey) -> Destination {
        Destination::from_address(k.address(Prefix::Testnet)).unwrap()
    }

    const DIGEST_MERCHANT: [u8; 32] = [0xAA; 32];
    const DIGEST_CUSTOMER: [u8; 32] = [0xBB; 32];
    const SALT: [u8; 32] = [0x77; 32];
    const BOND: u64 = 500;
    const MINER_FEE: u64 = 1000;
    const COMMIT_DEADLINE: u64 = 1000;
    const REVEAL_OPEN: u64 = 1000;
    const CLAIM_DEADLINE: u64 = 2000;

    // A bond whose juror committed to `chosen` verdict.
    fn params(chosen: &[u8; 32]) -> JurorBondParams {
        JurorBondParams {
            committee: (0..5).map(|i| juror(i).x_only_pubkey()).collect(),
            jury_threshold: 3,
            verdict_digest_merchant: DIGEST_MERCHANT,
            verdict_digest_customer: DIGEST_CUSTOMER,
            commit_hash: commit_hash(chosen, &SALT),
            commit_deadline: COMMIT_DEADLINE,
            reveal_open: REVEAL_OPEN,
            claim_deadline: CLAIM_DEADLINE,
            bond_amount: BOND,
            payout: dest_of(&juror_payout()),
            treasury: dest_of(&treasury()),
        }
    }

    fn bond_utxo() -> Utxo { Utxo { transaction_id: [1u8; 32], index: 0, value: BOND } }
    fn fee_utxo() -> Utxo { Utxo { transaction_id: [2u8; 32], index: 1, value: 100_000 } }

    fn verify(spend: &SignedSpend) -> Result<(), TxScriptError> {
        let reused = SigHashReusedValuesUnsync::new();
        let sig_cache = Cache::new(10_000);
        let populated = PopulatedTransaction::new(&spend.transaction, spend.entries.clone());
        for idx in 0..spend.transaction.inputs.len() {
            let mut vm = TxScriptEngine::from_transaction_input(
                &populated,
                &spend.transaction.inputs[idx],
                idx,
                &spend.entries[idx],
                EngineCtx::new(&sig_cache).with_reused(&reused),
                EngineFlags { covenants_enabled: true, ..Default::default() },
            );
            vm.execute()?;
        }
        Ok(())
    }

    // K-of-N committee datasigs over `digest`.
    fn committee_sigs(digest: &[u8; 32]) -> (Vec<Vec<u8>>, Vec<u32>) {
        let signers = [(juror(0), 0u32), (juror(1), 1), (juror(3), 3)];
        let sigs = signers.iter().map(|(k, _)| k.sign_datasig(digest).unwrap()).collect();
        let idx = signers.iter().map(|(_, i)| *i).collect();
        (sigs, idx)
    }

    fn claim(chosen: &[u8; 32], winner: &[u8; 32], salt: &[u8; 32], bond_daa: u64) -> SignedSpend {
        let p = params(chosen);
        let compiled = compile_juror_bond(&p).unwrap();
        let draft = prepare_claim_honest(&compiled, &p, &bond_utxo(), bond_daa, &fee_utxo(), MINER_FEE, &keeper(), Prefix::Testnet).unwrap();
        let (sigs, idx) = committee_sigs(winner);
        complete_claim_honest(&compiled, draft, &sigs, &idx, winner, salt).unwrap()
    }

    fn slash_spend(chosen: &[u8; 32], winner: &[u8; 32], lock_daa: u64) -> SignedSpend {
        let p = params(chosen);
        let compiled = compile_juror_bond(&p).unwrap();
        // Reuse prepare_slash but override lock_time via claim_deadline param already = CLAIM_DEADLINE.
        let mut draft = prepare_slash(&compiled, &p, &bond_utxo(), 0, &fee_utxo(), MINER_FEE, &keeper(), Prefix::Testnet).unwrap();
        draft.transaction.lock_time = lock_daa;
        // Re-sign fee input for the changed lock_time.
        let (sigs, idx) = committee_sigs(winner);
        // fee input must be re-signed because lock_time changed the sighash.
        resign_fee(&mut draft);
        complete_slash(&compiled, draft, &sigs, &idx, winner).unwrap()
    }

    // Re-sign the keeper fee input after mutating the tx (e.g. lock_time).
    fn resign_fee(draft: &mut BondSpendDraft) {
        let reused = SigHashReusedValuesUnsync::new();
        let mtx = kaspa_consensus_core::tx::MutableTransaction::with_entries(draft.transaction.clone(), draft.entries.clone());
        let fee_sighash: [u8; 32] = calc_schnorr_signature_hash(&mtx.as_verifiable(), 1, SIG_HASH_ALL, &reused).as_bytes();
        let fee_sig = keeper().sign_sighash(&fee_sighash).unwrap();
        draft.transaction.inputs[1].signature_script =
            ScriptBuilder::new().add_data(&fee_sig).unwrap().drain();
    }

    #[test]
    fn compiles_and_derives_address() {
        let compiled = compile_juror_bond(&params(&DIGEST_MERCHANT)).unwrap();
        assert_eq!(compiled.contract_name, "JurorBond");
        assert_eq!(covenant_address(&compiled, Prefix::Testnet).unwrap().prefix, Prefix::Testnet);
    }

    #[test]
    fn honest_juror_reclaims_bond() {
        // Committed to merchant, merchant won, committed in time (daa 500 < 1000).
        let spend = claim(&DIGEST_MERCHANT, &DIGEST_MERCHANT, &SALT, 500);
        assert_eq!(spend.transaction.outputs[0].value, BOND);
        assert!(verify(&spend).is_ok());
    }

    #[test]
    fn dissenter_cannot_claim_honest() {
        // Committed to customer, but merchant won: commit_hash won't open for the winner.
        assert!(verify(&claim(&DIGEST_CUSTOMER, &DIGEST_MERCHANT, &SALT, 500)).is_err());
    }

    #[test]
    fn wrong_salt_cannot_claim() {
        assert!(verify(&claim(&DIGEST_MERCHANT, &DIGEST_MERCHANT, &[0x66; 32], 500)).is_err());
    }

    #[test]
    fn late_commit_cannot_claim() {
        // Bond funded at daa 1500 > commit_deadline 1000.
        assert!(verify(&claim(&DIGEST_MERCHANT, &DIGEST_MERCHANT, &SALT, 1500)).is_err());
    }

    #[test]
    fn claim_before_reveal_open_is_rejected() {
        // Force lock_time below reveal_open.
        let p = params(&DIGEST_MERCHANT);
        let compiled = compile_juror_bond(&p).unwrap();
        let mut draft = prepare_claim_honest(&compiled, &p, &bond_utxo(), 500, &fee_utxo(), MINER_FEE, &keeper(), Prefix::Testnet).unwrap();
        draft.transaction.lock_time = REVEAL_OPEN - 1;
        resign_fee(&mut draft);
        let (sigs, idx) = committee_sigs(&DIGEST_MERCHANT);
        let spend = complete_claim_honest(&compiled, draft, &sigs, &idx, &DIGEST_MERCHANT, &SALT).unwrap();
        assert!(verify(&spend).is_err());
    }

    #[test]
    fn claim_rejects_below_committee_threshold() {
        let p = params(&DIGEST_MERCHANT);
        let compiled = compile_juror_bond(&p).unwrap();
        let draft = prepare_claim_honest(&compiled, &p, &bond_utxo(), 500, &fee_utxo(), MINER_FEE, &keeper(), Prefix::Testnet).unwrap();
        // Only 2 committee sigs for a 3-of-5 threshold.
        let signers = [(juror(0), 0u32), (juror(1), 1)];
        let sigs: Vec<Vec<u8>> = signers.iter().map(|(k, _)| k.sign_datasig(&DIGEST_MERCHANT).unwrap()).collect();
        let idx: Vec<u32> = signers.iter().map(|(_, i)| *i).collect();
        let spend = complete_claim_honest(&compiled, draft, &sigs, &idx, &DIGEST_MERCHANT, &SALT).unwrap();
        assert!(verify(&spend).is_err());
    }

    #[test]
    fn slash_after_deadline_pays_treasury() {
        let spend = slash_spend(&DIGEST_CUSTOMER, &DIGEST_MERCHANT, CLAIM_DEADLINE);
        assert_eq!(spend.transaction.outputs[0].value, BOND);
        // Output goes to the treasury spk.
        assert_eq!(
            spend.transaction.outputs[0].script_public_key.script(),
            dest_of(&treasury()).script_public_key_bytes().as_slice()
        );
        assert!(verify(&spend).is_ok());
    }

    #[test]
    fn slash_before_deadline_is_rejected() {
        assert!(verify(&slash_spend(&DIGEST_CUSTOMER, &DIGEST_MERCHANT, CLAIM_DEADLINE - 1)).is_err());
    }
}
