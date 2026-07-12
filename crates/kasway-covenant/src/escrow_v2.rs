//! Kasway escrow **V2** — tiered dispute resolution covenant.
//!
//! Adds, on top of the optimistic release/capture
//! and merchant-refund paths:
//!   * **Tier 1** `release_settled` — customer + merchant co-sign an arbitrary split.
//!   * **Tier 2** `release_arbitrated` / `refund_by_arbiter` — an **M-of-N** panel
//!     of per-trade arbiters (Kasway is never a member) rules the dispute.
//!
//! Every covenant script byte still comes from the SilverScript compiler; the
//! shared transaction-assembly helpers are reused from the crate root.

use kaspa_consensus_core::tx::{Transaction, TransactionOutput, UtxoEntry};
use kaspa_txscript::pay_to_address_script;
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions, CompiledContract};

use crate::{
    assemble_unsigned, build_fee_signed_tx, covenant_signature_script, customer_refund_outputs, fee_signature_script,
    merchant_split_outputs, push_change, to_i64, CovenantError, Destination, KeeperKey, Payout, Prefix, SignedSpend,
    Utxo, KIND_P2PK, MAX_PAYOUTS,
};

/// EscrowV2 covenant source.
pub const ESCROW_V2_SRC: &str = include_str!("../contracts/escrow_v2.sil");

/// Covenant entrypoints (see `contracts/escrow_v2.sil`).
pub const EP_RELEASE_CONFIRMED: &str = "release_confirmed";
pub const EP_RELEASE_CAPTURED: &str = "release_captured";
pub const EP_RELEASE_SETTLED: &str = "release_settled";
pub const EP_RELEASE_ARBITRATED: &str = "release_arbitrated";
pub const EP_REFUND_BY_ARBITER: &str = "refund_by_arbiter";
pub const EP_REFUND_BY_MERCHANT: &str = "refund_by_merchant";

/// Parameters that determine an EscrowV2 covenant instance (and its P2SH address).
#[derive(Debug, Clone)]
pub struct EscrowV2Params {
    /// Ordered release payouts (merchant_net, kasway_fee, tax, splits…).
    pub payouts: Vec<Payout>,
    /// Customer refund destination — MUST be schnorr P2PK; its payload is the
    /// customer's public key (receives refunds, gates `release_confirmed`).
    pub customer_refund: Destination,
    /// Merchant signing identity — MUST be schnorr P2PK; authorizes
    /// `refund_by_merchant` and co-signs `release_settled`.
    pub merchant: Destination,
    /// The per-trade arbiter panel: N x-only schnorr pubkeys chosen and consented
    /// to by both parties at funding time. **Kasway's key MUST NOT be included** —
    /// that is what keeps Kasway out of the decider seat (enforced by the caller
    /// that assembles the panel).
    pub arbiter_panel: Vec<[u8; 32]>,
    /// M in the M-of-N arbiter threshold. `1 <= threshold <= arbiter_panel.len()`.
    pub arbiter_threshold: u32,
    /// Value the covenant holds; every branch requires the input value to equal it.
    pub gross_amount: u64,
    /// Unix time after which `release_captured()` auto-captures to the merchant.
    pub capture_time: u64,
}

impl EscrowV2Params {
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
        if self.merchant.kind() != KIND_P2PK {
            return Err(CovenantError::UnsupportedAddressKind(
                "merchant address must be a schnorr P2PK address".to_string(),
            ));
        }
        if self.arbiter_panel.is_empty() {
            return Err(CovenantError::UnsupportedAddressKind("arbiter panel must not be empty".to_string()));
        }
        let n = self.arbiter_panel.len();
        if self.arbiter_threshold == 0 || self.arbiter_threshold as usize > n {
            return Err(CovenantError::UnsupportedAddressKind(format!(
                "arbiter threshold {} must be in 1..={}",
                self.arbiter_threshold, n
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
        let panel: Vec<Vec<u8>> = self.arbiter_panel.iter().map(|k| k.to_vec()).collect();
        Ok(vec![
            payloads.into(),                             // byte[32][] payout_payloads
            kinds.into(),                                // int[]      payout_kinds
            values.into(),                               // int[]      payout_values
            to_i64(self.payouts.len() as u64)?.into(),   // int        payout_count
            self.customer_refund.payload32().into(),     // byte[32]   customer_pubkey
            self.merchant.payload32().into(),            // byte[32]   merchant_pubkey
            panel.into(),                                // byte[32][] arbiter_pubkeys
            to_i64(n as u64)?.into(),                    // int        arbiter_count
            to_i64(self.arbiter_threshold as u64)?.into(),// int       arbiter_threshold
            to_i64(self.gross_amount)?.into(),           // int        gross_amount
            to_i64(self.capture_time)?.into(),           // int        capture_time
        ])
    }
}

/// Compile the EscrowV2 covenant for one invoice's parameters.
pub fn compile_escrow_v2(params: &EscrowV2Params) -> Result<CompiledContract<'static>, CovenantError> {
    let args = params.constructor_args()?;
    Ok(compile_contract(ESCROW_V2_SRC, &args, CompileOptions::default())?)
}

// ---------------------------------------------------------------------------
// Output builders
// ---------------------------------------------------------------------------

/// The mutual-settlement outputs: the caller-supplied split (any destinations /
/// amounts summing to `gross_amount`) plus the fee payer's change. The covenant
/// does not constrain these — both parties' SIG_HASH_ALL signatures do.
fn settlement_outputs(
    split: &[(Destination, u64)],
    fee_utxo: &Utxo,
    miner_fee: u64,
    fee_payer_address: &kaspa_addresses::Address,
) -> Vec<TransactionOutput> {
    let mut outputs: Vec<TransactionOutput> = split
        .iter()
        .map(|(dest, value)| TransactionOutput { value: *value, script_public_key: dest.script_public_key(), covenant: None })
        .collect();
    push_change(&mut outputs, fee_utxo, miner_fee, fee_payer_address);
    outputs
}

// ---------------------------------------------------------------------------
// Entrypoint sig-script args
// ---------------------------------------------------------------------------

/// Build the covenant sig-script for an M-of-N arbiter entrypoint: the ordered
/// `sigs` (each a 65-byte SIG_HASH_ALL signature) and their panel `signer_idx`.
fn arbiter_sigscript(
    compiled: &CompiledContract<'_>,
    entrypoint: &str,
    sigs: &[Vec<u8>],
    signer_idx: &[u32],
) -> Result<Vec<u8>, CovenantError> {
    let sigs_arr: Vec<Vec<u8>> = sigs.to_vec();
    let idx_arr: Vec<i64> = signer_idx.iter().map(|i| *i as i64).collect();
    let args = vec![sigs_arr.into(), idx_arr.into()];
    Ok(compiled.build_sig_script(entrypoint, args)?)
}

// ---------------------------------------------------------------------------
// Tier 1: mutual settlement (customer + merchant co-sign; initiator pays gas)
// ---------------------------------------------------------------------------

/// A prepared mutual-settlement spend. The covenant input needs BOTH the
/// customer's and merchant's signatures over `covenant_sighash`; the fee input
/// needs the fee payer's signature over `fee_sighash`.
pub struct SettlementDraft {
    transaction: Transaction,
    entries: Vec<UtxoEntry>,
    pub covenant_sighash: [u8; 32],
    pub fee_sighash: [u8; 32],
}

/// Prepare a `release_settled` spend for an arbitrary agreed split. The fee input
/// is signed externally by `fee_payer_address` (the initiating party) — Kasway
/// subsidizes nothing.
pub fn prepare_settlement(
    compiled: &CompiledContract<'_>,
    split: &[(Destination, u64)],
    covenant_utxo: &Utxo,
    fee_utxo: &Utxo,
    miner_fee: u64,
    fee_payer_address: &kaspa_addresses::Address,
) -> Result<SettlementDraft, CovenantError> {
    let outputs = settlement_outputs(split, fee_utxo, miner_fee, fee_payer_address);
    let fee_spk = pay_to_address_script(fee_payer_address);
    let (transaction, entries, covenant_sighash, fee_sighash) =
        assemble_unsigned(&compiled.script, outputs, 0, covenant_utxo, fee_utxo, fee_spk);
    Ok(SettlementDraft { transaction, entries, covenant_sighash, fee_sighash })
}

/// Complete a mutual-settlement spend: customer sig + merchant sig on the covenant
/// input, fee-payer sig on the fee input.
pub fn complete_settlement(
    compiled: &CompiledContract<'_>,
    mut draft: SettlementDraft,
    customer_sig: &[u8],
    merchant_sig: &[u8],
    fee_sig: &[u8],
) -> Result<SignedSpend, CovenantError> {
    let entrypoint_sig = compiled
        .build_sig_script(EP_RELEASE_SETTLED, vec![customer_sig.to_vec().into(), merchant_sig.to_vec().into()])?;
    draft.transaction.inputs[0].signature_script = covenant_signature_script(&compiled.script, entrypoint_sig)?;
    draft.transaction.inputs[1].signature_script = fee_signature_script(fee_sig)?;
    Ok(SignedSpend { transaction: draft.transaction, entries: draft.entries })
}

// ---------------------------------------------------------------------------
// Tier 2: M-of-N arbiter release to merchant (keeper-subsidized gas)
// ---------------------------------------------------------------------------

/// A prepared release whose covenant input needs the M-of-N arbiter signatures.
/// The fee input is already signed by the keeper.
pub struct ArbiterReleaseDraft {
    transaction: Transaction,
    entries: Vec<UtxoEntry>,
    pub covenant_sighash: [u8; 32],
}

/// Prepare a `release_arbitrated` spend (merchant split, keeper subsidizes gas).
pub fn prepare_release_arbitrated(
    compiled: &CompiledContract<'_>,
    params: &EscrowV2Params,
    covenant_utxo: &Utxo,
    fee_utxo: &Utxo,
    miner_fee: u64,
    keeper: &KeeperKey,
    prefix: Prefix,
) -> Result<ArbiterReleaseDraft, CovenantError> {
    prepare_release(compiled, params, covenant_utxo, fee_utxo, miner_fee, keeper, prefix, 0)
}

/// Complete an arbiter release with `signer_idx`-labelled panel signatures.
pub fn complete_release_arbitrated(
    compiled: &CompiledContract<'_>,
    mut draft: ArbiterReleaseDraft,
    sigs: &[Vec<u8>],
    signer_idx: &[u32],
) -> Result<SignedSpend, CovenantError> {
    let entrypoint_sig = arbiter_sigscript(compiled, EP_RELEASE_ARBITRATED, sigs, signer_idx)?;
    draft.transaction.inputs[0].signature_script = covenant_signature_script(&compiled.script, entrypoint_sig)?;
    Ok(SignedSpend { transaction: draft.transaction, entries: draft.entries })
}

// ---------------------------------------------------------------------------
// Tier 2: M-of-N arbiter refund to customer (initiator pays gas, external fee)
// ---------------------------------------------------------------------------

/// A prepared arbiter refund whose covenant input needs the M-of-N arbiter
/// signatures and whose fee input needs the fee payer's external signature.
pub struct ArbiterRefundDraft {
    transaction: Transaction,
    entries: Vec<UtxoEntry>,
    pub covenant_sighash: [u8; 32],
    pub fee_sighash: [u8; 32],
}

/// Prepare a `refund_by_arbiter` spend (full gross to customer; fee signed
/// externally by `fee_payer_address`).
pub fn prepare_refund_by_arbiter(
    compiled: &CompiledContract<'_>,
    params: &EscrowV2Params,
    covenant_utxo: &Utxo,
    fee_utxo: &Utxo,
    miner_fee: u64,
    fee_payer_address: &kaspa_addresses::Address,
) -> Result<ArbiterRefundDraft, CovenantError> {
    let outputs = customer_refund_outputs(&params.customer_refund, params.gross_amount, fee_utxo, miner_fee, fee_payer_address);
    let fee_spk = pay_to_address_script(fee_payer_address);
    let (transaction, entries, covenant_sighash, fee_sighash) =
        assemble_unsigned(&compiled.script, outputs, 0, covenant_utxo, fee_utxo, fee_spk);
    Ok(ArbiterRefundDraft { transaction, entries, covenant_sighash, fee_sighash })
}

/// Complete an arbiter refund: M-of-N panel sigs on the covenant input, fee-payer
/// sig on the fee input.
pub fn complete_refund_by_arbiter(
    compiled: &CompiledContract<'_>,
    mut draft: ArbiterRefundDraft,
    sigs: &[Vec<u8>],
    signer_idx: &[u32],
    fee_sig: &[u8],
) -> Result<SignedSpend, CovenantError> {
    let entrypoint_sig = arbiter_sigscript(compiled, EP_REFUND_BY_ARBITER, sigs, signer_idx)?;
    draft.transaction.inputs[0].signature_script = covenant_signature_script(&compiled.script, entrypoint_sig)?;
    draft.transaction.inputs[1].signature_script = fee_signature_script(fee_sig)?;
    Ok(SignedSpend { transaction: draft.transaction, entries: draft.entries })
}

// ---------------------------------------------------------------------------
// Tier 0 / merchant refund: parity paths (exact-value output checks)
// ---------------------------------------------------------------------------

/// Prepare a merchant-split release (keeper-subsidized gas). `lock_time` is 0 for
/// `release_confirmed`, or `capture_time` for `release_captured`.
pub fn prepare_release(
    compiled: &CompiledContract<'_>,
    params: &EscrowV2Params,
    covenant_utxo: &Utxo,
    fee_utxo: &Utxo,
    miner_fee: u64,
    keeper: &KeeperKey,
    prefix: Prefix,
    lock_time: u64,
) -> Result<ArbiterReleaseDraft, CovenantError> {
    let outputs = merchant_split_outputs(&params.payouts, fee_utxo, miner_fee, &keeper.address(prefix));
    let (transaction, entries, covenant_sighash) =
        build_fee_signed_tx(&compiled.script, outputs, lock_time, covenant_utxo, fee_utxo, keeper, prefix)?;
    Ok(ArbiterReleaseDraft { transaction, entries, covenant_sighash })
}

/// Complete a merchant-split release: `EP_RELEASE_CONFIRMED` with the customer's
/// signature, or `EP_RELEASE_CAPTURED` with `None`.
pub fn complete_release(
    compiled: &CompiledContract<'_>,
    mut draft: ArbiterReleaseDraft,
    entrypoint: &str,
    sig: Option<&[u8]>,
) -> Result<SignedSpend, CovenantError> {
    let args = match sig {
        Some(s) => vec![s.to_vec().into()],
        None => vec![],
    };
    let entrypoint_sig = compiled.build_sig_script(entrypoint, args)?;
    draft.transaction.inputs[0].signature_script = covenant_signature_script(&compiled.script, entrypoint_sig)?;
    Ok(SignedSpend { transaction: draft.transaction, entries: draft.entries })
}

/// Prepare a merchant voluntary refund (full gross to customer; fee signed
/// externally by the initiator).
pub fn prepare_refund_by_merchant(
    compiled: &CompiledContract<'_>,
    params: &EscrowV2Params,
    covenant_utxo: &Utxo,
    fee_utxo: &Utxo,
    miner_fee: u64,
    fee_payer_address: &kaspa_addresses::Address,
) -> Result<ArbiterRefundDraft, CovenantError> {
    prepare_refund_by_arbiter(compiled, params, covenant_utxo, fee_utxo, miner_fee, fee_payer_address)
}

/// Complete a merchant refund: merchant sig on the covenant input, fee-payer sig
/// on the fee input.
pub fn complete_refund_by_merchant(
    compiled: &CompiledContract<'_>,
    mut draft: ArbiterRefundDraft,
    merchant_sig: &[u8],
    fee_sig: &[u8],
) -> Result<SignedSpend, CovenantError> {
    let entrypoint_sig = compiled.build_sig_script(EP_REFUND_BY_MERCHANT, vec![merchant_sig.to_vec().into()])?;
    draft.transaction.inputs[0].signature_script = covenant_signature_script(&compiled.script, entrypoint_sig)?;
    draft.transaction.inputs[1].signature_script = fee_signature_script(fee_sig)?;
    Ok(SignedSpend { transaction: draft.transaction, entries: draft.entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{covenant_address, Utxo as CrateUtxo};
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
    // Three independent arbiters — none of them is Kasway.
    fn arb_a() -> KeeperKey { key(10) }
    fn arb_b() -> KeeperKey { key(11) }
    fn arb_c() -> KeeperKey { key(12) }
    fn keeper() -> KeeperKey { key(7) }
    fn impostor() -> KeeperKey { key(9) }

    fn dest_of(k: &KeeperKey) -> Destination {
        Destination::from_address(k.address(Prefix::Testnet)).unwrap()
    }
    fn p2sh(byte: u8) -> Destination {
        Destination::from_address(Address::new(Prefix::Testnet, Version::ScriptHash, &[byte; 32])).unwrap()
    }

    const GROSS: u64 = 1000;
    const CAPTURE_TIME: u64 = 5000;
    const MINER_FEE: u64 = 1000;

    // 2-of-3 arbiter panel (a, b, c).
    fn params() -> EscrowV2Params {
        EscrowV2Params {
            payouts: vec![
                Payout { destination: dest_of(&merchant()), value: 700 },
                Payout { destination: dest_of(&key(0x22)), value: 250 },
                Payout { destination: p2sh(0x33), value: 50 },
            ],
            customer_refund: dest_of(&customer()),
            merchant: dest_of(&merchant()),
            arbiter_panel: vec![arb_a().x_only_pubkey(), arb_b().x_only_pubkey(), arb_c().x_only_pubkey()],
            arbiter_threshold: 2,
            gross_amount: GROSS,
            capture_time: CAPTURE_TIME,
        }
    }

    fn cov_utxo(value: u64) -> CrateUtxo { CrateUtxo { transaction_id: [1u8; 32], index: 0, value } }
    fn fee_utxo() -> CrateUtxo { CrateUtxo { transaction_id: [2u8; 32], index: 1, value: 100_000 } }

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

    #[test]
    fn compiles_and_derives_address() {
        let p = params();
        let compiled = compile_escrow_v2(&p).unwrap();
        assert_eq!(compiled.contract_name, "EscrowV2");
        let addr = covenant_address(&compiled, Prefix::Testnet).unwrap();
        assert_eq!(addr.prefix, Prefix::Testnet);
    }

    // ---- Tier 1: mutual settlement ----

    // Build a mutual-settlement spend for a given split, signed by the two given keys.
    fn settle(split: &[(Destination, u64)], cust: &KeeperKey, merch: &KeeperKey, cov_value: u64) -> SignedSpend {
        let p = params();
        let compiled = compile_escrow_v2(&p).unwrap();
        let fee_payer = customer();
        let draft = prepare_settlement(&compiled, split, &cov_utxo(cov_value), &fee_utxo(), MINER_FEE, &fee_payer.address(Prefix::Testnet)).unwrap();
        let cust_sig = cust.sign_sighash(&draft.covenant_sighash).unwrap();
        let merch_sig = merch.sign_sighash(&draft.covenant_sighash).unwrap();
        let fee_sig = fee_payer.sign_sighash(&draft.fee_sighash).unwrap();
        complete_settlement(&compiled, draft, &cust_sig, &merch_sig, &fee_sig).unwrap()
    }

    #[test]
    fn settled_split_60_40_is_valid() {
        // Arbitrary agreed split: 600 to merchant, 400 back to customer.
        let split = vec![(dest_of(&merchant()), 600), (dest_of(&customer()), 400)];
        assert!(verify(&settle(&split, &customer(), &merchant(), GROSS)).is_ok());
    }

    #[test]
    fn settled_rejects_missing_merchant_signature() {
        // Customer signs, but an impostor signs the "merchant" slot.
        let split = vec![(dest_of(&merchant()), 600), (dest_of(&customer()), 400)];
        assert!(verify(&settle(&split, &customer(), &impostor(), GROSS)).is_err());
    }

    #[test]
    fn settled_rejects_missing_customer_signature() {
        let split = vec![(dest_of(&merchant()), 600), (dest_of(&customer()), 400)];
        assert!(verify(&settle(&split, &impostor(), &merchant(), GROSS)).is_err());
    }

    #[test]
    fn settled_rejects_underfunded_covenant() {
        let split = vec![(dest_of(&merchant()), 600), (dest_of(&customer()), 400)];
        assert!(verify(&settle(&split, &customer(), &merchant(), GROSS - 1)).is_err());
    }

    // ---- Tier 2: M-of-N arbiter ----

    fn release_arbitrated(signers: &[(&KeeperKey, u32)]) -> SignedSpend {
        let p = params();
        let compiled = compile_escrow_v2(&p).unwrap();
        let draft = prepare_release_arbitrated(&compiled, &p, &cov_utxo(GROSS), &fee_utxo(), MINER_FEE, &keeper(), Prefix::Testnet).unwrap();
        let sigs: Vec<Vec<u8>> = signers.iter().map(|(k, _)| k.sign_sighash(&draft.covenant_sighash).unwrap()).collect();
        let idx: Vec<u32> = signers.iter().map(|(_, i)| *i).collect();
        complete_release_arbitrated(&compiled, draft, &sigs, &idx).unwrap()
    }

    fn refund_by_arbiter(signers: &[(&KeeperKey, u32)]) -> SignedSpend {
        let p = params();
        let compiled = compile_escrow_v2(&p).unwrap();
        let fee_payer = customer();
        let draft = prepare_refund_by_arbiter(&compiled, &p, &cov_utxo(GROSS), &fee_utxo(), MINER_FEE, &fee_payer.address(Prefix::Testnet)).unwrap();
        let sigs: Vec<Vec<u8>> = signers.iter().map(|(k, _)| k.sign_sighash(&draft.covenant_sighash).unwrap()).collect();
        let idx: Vec<u32> = signers.iter().map(|(_, i)| *i).collect();
        let fee_sig = fee_payer.sign_sighash(&draft.fee_sighash).unwrap();
        complete_refund_by_arbiter(&compiled, draft, &sigs, &idx, &fee_sig).unwrap()
    }

    #[test]
    fn arbiter_release_2_of_3_is_valid() {
        assert!(verify(&release_arbitrated(&[(&arb_a(), 0), (&arb_b(), 1)])).is_ok());
    }

    #[test]
    fn arbiter_refund_2_of_3_is_valid() {
        assert!(verify(&refund_by_arbiter(&[(&arb_a(), 0), (&arb_c(), 2)])).is_ok());
    }

    #[test]
    fn arbiter_release_rejects_below_threshold() {
        // Only one signature provided for a 2-of-3 panel.
        assert!(verify(&release_arbitrated(&[(&arb_a(), 0)])).is_err());
    }

    #[test]
    fn arbiter_release_rejects_double_counted_signer() {
        // Same arbiter (index 0) used twice — signer_idx not strictly increasing.
        assert!(verify(&release_arbitrated(&[(&arb_a(), 0), (&arb_a(), 0)])).is_err());
    }

    #[test]
    fn arbiter_release_rejects_non_panel_signer() {
        // Impostor claims to be panel index 1 but signs with a non-panel key.
        assert!(verify(&release_arbitrated(&[(&arb_a(), 0), (&impostor(), 1)])).is_err());
    }

    #[test]
    fn kasway_impostor_cannot_rule() {
        // The keeper/impostor key is not in the panel at all -> cannot form a threshold.
        assert!(verify(&release_arbitrated(&[(&impostor(), 0), (&keeper(), 1)])).is_err());
    }

    #[test]
    fn arbiter_refund_customer_still_cannot_authorize() {
        // Even paying gas, the customer is not on the panel.
        assert!(verify(&refund_by_arbiter(&[(&customer(), 0), (&customer(), 1)])).is_err());
    }
}
