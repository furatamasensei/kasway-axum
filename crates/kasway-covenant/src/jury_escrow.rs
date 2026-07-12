//! Kasway Tier-3 **jury dispute-escrow** covenant.
//!
//! The disputed principal is re-locked into one `JuryEscrow` instance carrying
//! the drawn committee and the two verdict digests. A K-of-N threshold of
//! committee `datasig`s (verified in-script via `checkSigFromStack`) honors a
//! verdict — `release_jury` (merchant wins) or `refund_jury` (customer wins).
//! Kasway holds none of the committee keys.

use kaspa_consensus_core::tx::{Transaction, TransactionOutput, UtxoEntry};
use kaspa_txscript::pay_to_address_script;
use kaspa_txscript::script_builder::ScriptBuilder;
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions, CompiledContract};

use crate::{
    assemble_unsigned, build_fee_signed_tx, covenant_signature_script, push_change, to_i64, CovenantError,
    Destination, KeeperKey, Payout, Prefix, SignedSpend, Utxo, MAX_PAYOUTS,
};

/// JuryEscrow covenant source.
pub const JURY_ESCROW_SRC: &str = include_str!("../contracts/jury_escrow.sil");

const KIND_P2PK: i64 = 0;

pub const EP_RELEASE_JURY: &str = "release_jury";
pub const EP_REFUND_JURY: &str = "refund_jury";

/// Domain-separation tag folded into the verdict digest (must match the covenant
/// doc and the juror-client). `verdict_digest_*` = sha256(TAG || dispute_id ||
/// verdict_byte || evidence_root). Verdict bytes: customer = 0x01, merchant = 0x02.
pub const VERDICT_TAG: &[u8] = b"KASWAY/escrow/v1/verdict";
pub const VERDICT_CUSTOMER: u8 = 0x01;
pub const VERDICT_MERCHANT: u8 = 0x02;

/// Parameters that determine a JuryEscrow covenant instance (and its P2SH address).
#[derive(Debug, Clone)]
pub struct JuryEscrowParams {
    /// Ordered merchant-win payouts (same shape as the base escrow).
    pub payouts: Vec<Payout>,
    /// Customer refund destination — MUST be schnorr P2PK.
    pub customer_refund: Destination,
    /// The drawn committee: N x-only schnorr juror pubkeys.
    pub committee: Vec<[u8; 32]>,
    /// K in the K-of-N jury threshold. `1 <= threshold <= committee.len()`; choose
    /// `K > N/2` so the honored verdict is unique.
    pub jury_threshold: u32,
    /// Baked verdict digest a juror signs to rule for the MERCHANT.
    pub verdict_digest_merchant: [u8; 32],
    /// Baked verdict digest a juror signs to rule for the CUSTOMER.
    pub verdict_digest_customer: [u8; 32],
    /// Value the covenant holds.
    pub gross_amount: u64,
}

impl JuryEscrowParams {
    fn constructor_args(&self) -> Result<Vec<Expr<'static>>, CovenantError> {
        if self.payouts.is_empty() {
            return Err(CovenantError::NoPayouts);
        }
        if self.payouts.len() > MAX_PAYOUTS {
            return Err(CovenantError::TooManyPayouts { got: self.payouts.len(), max: MAX_PAYOUTS });
        }
        if self.customer_refund.kind() != KIND_P2PK {
            return Err(CovenantError::UnsupportedAddressKind(
                "customer refund address must be a schnorr P2PK address".to_string(),
            ));
        }
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
        // Defense-in-depth: the payout values must exactly account for the gross
        // the covenant holds. A covenant funded with sum < gross would leak the
        // surplus (permissionless `release_captured` could sweep it).
        let sum: u128 = self.payouts.iter().map(|p| p.value as u128).sum();
        if sum != self.gross_amount as u128 {
            return Err(CovenantError::PayoutSumMismatch { sum, gross: self.gross_amount as u128 });
        }

        let payloads: Vec<Vec<u8>> = self.payouts.iter().map(|p| p.destination.payload32()).collect();
        let kinds: Vec<i64> = self.payouts.iter().map(|p| p.destination.kind()).collect();
        let values: Vec<i64> = self.payouts.iter().map(|p| to_i64(p.value)).collect::<Result<_, _>>()?;
        let committee: Vec<Vec<u8>> = self.committee.iter().map(|k| k.to_vec()).collect();
        Ok(vec![
            payloads.into(),                              // byte[32][] payout_payloads
            kinds.into(),                                 // int[]      payout_kinds
            values.into(),                                // int[]      payout_values
            to_i64(self.payouts.len() as u64)?.into(),    // int        payout_count
            self.customer_refund.payload32().into(),      // byte[32]   customer_pubkey
            committee.into(),                             // byte[32][] committee_pubkeys
            to_i64(n as u64)?.into(),                     // int        committee_count
            to_i64(self.jury_threshold as u64)?.into(),   // int        jury_threshold
            self.verdict_digest_merchant.to_vec().into(), // byte[32]   verdict_digest_merchant
            self.verdict_digest_customer.to_vec().into(), // byte[32]   verdict_digest_customer
            to_i64(self.gross_amount)?.into(),            // int        gross_amount
        ])
    }
}

/// Compile the JuryEscrow covenant for one dispute's parameters.
pub fn compile_jury_escrow(params: &JuryEscrowParams) -> Result<CompiledContract<'static>, CovenantError> {
    let args = params.constructor_args()?;
    Ok(compile_contract(JURY_ESCROW_SRC, &args, CompileOptions::default())?)
}

fn merchant_split_outputs(
    params: &JuryEscrowParams,
    fee_utxo: &Utxo,
    miner_fee: u64,
    fee_payer_address: &kaspa_addresses::Address,
) -> Vec<TransactionOutput> {
    let mut outputs: Vec<TransactionOutput> = params
        .payouts
        .iter()
        .map(|p| TransactionOutput { value: p.value, script_public_key: p.destination.script_public_key(), covenant: None })
        .collect();
    push_change(&mut outputs, fee_utxo, miner_fee, fee_payer_address);
    outputs
}

fn customer_refund_outputs(
    params: &JuryEscrowParams,
    fee_utxo: &Utxo,
    miner_fee: u64,
    fee_payer_address: &kaspa_addresses::Address,
) -> Vec<TransactionOutput> {
    let mut outputs = vec![TransactionOutput {
        value: params.gross_amount,
        script_public_key: params.customer_refund.script_public_key(),
        covenant: None,
    }];
    push_change(&mut outputs, fee_utxo, miner_fee, fee_payer_address);
    outputs
}

/// Build the covenant sig-script for a jury entrypoint: the ordered `datasigs`
/// (each 64 bytes) and their committee `signer_idx`.
fn jury_sigscript(
    compiled: &CompiledContract<'_>,
    entrypoint: &str,
    datasigs: &[Vec<u8>],
    signer_idx: &[u32],
) -> Result<Vec<u8>, CovenantError> {
    let sigs_arr: Vec<Vec<u8>> = datasigs.to_vec();
    let idx_arr: Vec<i64> = signer_idx.iter().map(|i| *i as i64).collect();
    Ok(compiled.build_sig_script(entrypoint, vec![sigs_arr.into(), idx_arr.into()])?)
}

/// A prepared jury release (merchant split, keeper-subsidized gas). The covenant
/// input needs the K-of-N committee datasigs over `verdict_digest_merchant`.
pub struct JuryReleaseDraft {
    transaction: Transaction,
    entries: Vec<UtxoEntry>,
    pub covenant_sighash: [u8; 32],
}

pub fn prepare_release_jury(
    compiled: &CompiledContract<'_>,
    params: &JuryEscrowParams,
    covenant_utxo: &Utxo,
    fee_utxo: &Utxo,
    miner_fee: u64,
    keeper: &KeeperKey,
    prefix: Prefix,
) -> Result<JuryReleaseDraft, CovenantError> {
    let outputs = merchant_split_outputs(params, fee_utxo, miner_fee, &keeper.address(prefix));
    let (transaction, entries, covenant_sighash) =
        build_fee_signed_tx(&compiled.script, outputs, 0, covenant_utxo, fee_utxo, keeper, prefix)?;
    Ok(JuryReleaseDraft { transaction, entries, covenant_sighash })
}

pub fn complete_release_jury(
    compiled: &CompiledContract<'_>,
    mut draft: JuryReleaseDraft,
    datasigs: &[Vec<u8>],
    signer_idx: &[u32],
) -> Result<SignedSpend, CovenantError> {
    let entrypoint_sig = jury_sigscript(compiled, EP_RELEASE_JURY, datasigs, signer_idx)?;
    draft.transaction.inputs[0].signature_script = covenant_signature_script(&compiled.script, entrypoint_sig)?;
    Ok(SignedSpend { transaction: draft.transaction, entries: draft.entries })
}

/// A prepared jury refund (full gross to customer; fee signed externally by the
/// initiator). The covenant input needs the K-of-N committee datasigs over
/// `verdict_digest_customer`.
pub struct JuryRefundDraft {
    transaction: Transaction,
    entries: Vec<UtxoEntry>,
    pub covenant_sighash: [u8; 32],
    pub fee_sighash: [u8; 32],
}

pub fn prepare_refund_jury(
    compiled: &CompiledContract<'_>,
    params: &JuryEscrowParams,
    covenant_utxo: &Utxo,
    fee_utxo: &Utxo,
    miner_fee: u64,
    fee_payer_address: &kaspa_addresses::Address,
) -> Result<JuryRefundDraft, CovenantError> {
    let outputs = customer_refund_outputs(params, fee_utxo, miner_fee, fee_payer_address);
    let fee_spk = pay_to_address_script(fee_payer_address);
    let (transaction, entries, covenant_sighash, fee_sighash) =
        assemble_unsigned(&compiled.script, outputs, 0, covenant_utxo, fee_utxo, fee_spk);
    Ok(JuryRefundDraft { transaction, entries, covenant_sighash, fee_sighash })
}

pub fn complete_refund_jury(
    compiled: &CompiledContract<'_>,
    mut draft: JuryRefundDraft,
    datasigs: &[Vec<u8>],
    signer_idx: &[u32],
    fee_sig: &[u8],
) -> Result<SignedSpend, CovenantError> {
    let entrypoint_sig = jury_sigscript(compiled, EP_REFUND_JURY, datasigs, signer_idx)?;
    draft.transaction.inputs[0].signature_script = covenant_signature_script(&compiled.script, entrypoint_sig)?;
    draft.transaction.inputs[1].signature_script = ScriptBuilder::new()
        .add_data(fee_sig)
        .map_err(|e| CovenantError::Compile(format!("fee sigscript: {e}")))?
        .drain();
    Ok(SignedSpend { transaction: draft.transaction, entries: draft.entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::covenant_address;
    use kaspa_addresses::{Address, Version};
    use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
    use kaspa_consensus_core::tx::PopulatedTransaction;
    use kaspa_txscript::caches::Cache;
    use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
    use kaspa_txscript_errors::TxScriptError;

    fn key(byte: u8) -> KeeperKey {
        KeeperKey::from_secret_bytes(&[byte; 32]).unwrap()
    }
    fn customer() -> KeeperKey { key(3) }
    fn merchant() -> KeeperKey { key(4) }
    fn keeper() -> KeeperKey { key(7) }
    fn impostor() -> KeeperKey { key(9) }
    // A committee of 5 jurors (indices 0..5).
    fn juror(i: u8) -> KeeperKey { key(20 + i) }

    fn dest_of(k: &KeeperKey) -> Destination {
        Destination::from_address(k.address(Prefix::Testnet)).unwrap()
    }
    fn p2sh(byte: u8) -> Destination {
        Destination::from_address(Address::new(Prefix::Testnet, Version::ScriptHash, &[byte; 32])).unwrap()
    }

    const GROSS: u64 = 1000;
    const MINER_FEE: u64 = 1000;
    // Two distinct opaque verdict digests (in production, sha256(TAG||dispute_id||bit||root)).
    const DIGEST_MERCHANT: [u8; 32] = [0xAA; 32];
    const DIGEST_CUSTOMER: [u8; 32] = [0xBB; 32];

    // N=5, K=3 committee.
    fn params() -> JuryEscrowParams {
        JuryEscrowParams {
            payouts: vec![
                Payout { destination: dest_of(&merchant()), value: 700 },
                Payout { destination: dest_of(&key(0x22)), value: 250 },
                Payout { destination: p2sh(0x33), value: 50 },
            ],
            customer_refund: dest_of(&customer()),
            committee: (0..5).map(|i| juror(i).x_only_pubkey()).collect(),
            jury_threshold: 3,
            verdict_digest_merchant: DIGEST_MERCHANT,
            verdict_digest_customer: DIGEST_CUSTOMER,
            gross_amount: GROSS,
        }
    }

    fn cov_utxo(value: u64) -> Utxo { Utxo { transaction_id: [1u8; 32], index: 0, value } }
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

    // Build a release_jury spend where each (juror, idx) signs `digest`.
    fn release_jury(signers: &[(KeeperKey, u32)], digest: &[u8; 32]) -> SignedSpend {
        let p = params();
        let compiled = compile_jury_escrow(&p).unwrap();
        let draft = prepare_release_jury(&compiled, &p, &cov_utxo(GROSS), &fee_utxo(), MINER_FEE, &keeper(), Prefix::Testnet).unwrap();
        let sigs: Vec<Vec<u8>> = signers.iter().map(|(k, _)| k.sign_datasig(digest).unwrap()).collect();
        let idx: Vec<u32> = signers.iter().map(|(_, i)| *i).collect();
        complete_release_jury(&compiled, draft, &sigs, &idx).unwrap()
    }

    fn refund_jury(signers: &[(KeeperKey, u32)], digest: &[u8; 32]) -> SignedSpend {
        let p = params();
        let compiled = compile_jury_escrow(&p).unwrap();
        let fee_payer = customer();
        let draft = prepare_refund_jury(&compiled, &p, &cov_utxo(GROSS), &fee_utxo(), MINER_FEE, &fee_payer.address(Prefix::Testnet)).unwrap();
        let sigs: Vec<Vec<u8>> = signers.iter().map(|(k, _)| k.sign_datasig(digest).unwrap()).collect();
        let idx: Vec<u32> = signers.iter().map(|(_, i)| *i).collect();
        let fee_sig = fee_payer.sign_sighash(&draft.fee_sighash).unwrap();
        complete_refund_jury(&compiled, draft, &sigs, &idx, &fee_sig).unwrap()
    }

    #[test]
    fn compiles_and_derives_address() {
        let compiled = compile_jury_escrow(&params()).unwrap();
        assert_eq!(compiled.contract_name, "JuryEscrow");
        assert_eq!(covenant_address(&compiled, Prefix::Testnet).unwrap().prefix, Prefix::Testnet);
    }

    #[test]
    fn jury_release_3_of_5_is_valid() {
        assert!(verify(&release_jury(&[(juror(0), 0), (juror(1), 1), (juror(3), 3)], &DIGEST_MERCHANT)).is_ok());
    }

    #[test]
    fn jury_refund_3_of_5_is_valid() {
        assert!(verify(&refund_jury(&[(juror(1), 1), (juror(2), 2), (juror(4), 4)], &DIGEST_CUSTOMER)).is_ok());
    }

    #[test]
    fn jury_release_rejects_below_threshold() {
        assert!(verify(&release_jury(&[(juror(0), 0), (juror(1), 1)], &DIGEST_MERCHANT)).is_err());
    }

    #[test]
    fn jury_release_rejects_double_counted_juror() {
        assert!(verify(&release_jury(&[(juror(0), 0), (juror(0), 0), (juror(1), 1)], &DIGEST_MERCHANT)).is_err());
    }

    #[test]
    fn jury_release_rejects_non_committee_signer() {
        // Impostor claims committee index 2 but is not that juror's key.
        assert!(verify(&release_jury(&[(juror(0), 0), (juror(1), 1), (impostor(), 2)], &DIGEST_MERCHANT)).is_err());
    }

    #[test]
    fn jury_release_rejects_wrong_verdict_digest() {
        // Jurors sign the CUSTOMER digest but submit to release_jury (merchant digest).
        assert!(verify(&release_jury(&[(juror(0), 0), (juror(1), 1), (juror(3), 3)], &DIGEST_CUSTOMER)).is_err());
    }

    #[test]
    fn jury_refund_rejects_wrong_verdict_digest() {
        // Jurors sign the MERCHANT digest but submit to refund_jury (customer digest).
        assert!(verify(&refund_jury(&[(juror(1), 1), (juror(2), 2), (juror(4), 4)], &DIGEST_MERCHANT)).is_err());
    }
}
