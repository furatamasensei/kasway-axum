//! Kasway subscription **V1** — non-custodial recurring-claim autopay covenant.
//!
//! One subscription funds one P2SH covenant cell holding several periods' worth
//! of value. The split (merchant/fee/tax/splits) is snapshotted into the cell as
//! pinned payouts (exact escrow_v2 encoding). Two spend paths:
//!   * `claim(keeper_sig)` — the keeper, at most once per `period_daa` (CSV
//!     relative lock, DAA-score delta), pays every pinned payout exactly and
//!     returns the remainder to the covenant's own scriptPubKey (the cell
//!     self-replicates). Below `sweep_threshold` the remainder output may be
//!     omitted and the dust becomes miner fee.
//!   * `withdraw(customer_sig)` — the customer exits any time, to anywhere.
//!
//! Every covenant script byte still comes from the SilverScript compiler; the
//! shared transaction-assembly helpers are reused from the crate root.

use kaspa_consensus_core::tx::{Transaction, TransactionOutput, UtxoEntry};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions, CompiledContract};

use crate::{
    build_fee_signed_tx, covenant_script_public_key, covenant_signature_script, push_change, to_i64, CovenantError,
    Destination, KeeperKey, Payout, Prefix, SignedSpend, Utxo, KIND_P2PK, MAX_PAYOUTS,
};

/// SubscriptionV1 covenant source.
pub const SUBSCRIPTION_V1_SRC: &str = include_str!("../contracts/subscription_v1.sil");

/// Covenant entrypoints (see `contracts/subscription_v1.sil`).
pub const EP_CLAIM: &str = "claim";
pub const EP_WITHDRAW: &str = "withdraw";

/// Parameters that determine a SubscriptionV1 covenant instance (and its P2SH
/// address).
#[derive(Debug, Clone)]
pub struct SubscriptionV1Params {
    /// Ordered per-period payouts (merchant_net, kasway_fee, tax, splits…),
    /// snapshotted when the cell is created. Their sum is the per-claim total.
    pub payouts: Vec<Payout>,
    /// The keeper's 32-byte x-only schnorr pubkey — the only key that can `claim`.
    pub keeper_pubkey: [u8; 32],
    /// Customer signing identity — MUST be schnorr P2PK; its payload is the
    /// customer's pubkey, which alone authorizes `withdraw`.
    pub customer: Destination,
    /// Claim period as a relative lock in DAA-score delta (~10 blocks/sec on
    /// mainnet; 1 day ≈ 864_000). Must be `1..=u32::MAX` — CSV only compares the
    /// low 32 bits of the sequence, so larger values would silently weaken the lock.
    pub period_daa: u64,
    /// If, after a claim, less than this remains, the claim may omit the
    /// remainder output and terminate the cell (the dust becomes miner fee, so
    /// the leak is bounded by this threshold).
    pub sweep_threshold: u64,
}

impl SubscriptionV1Params {
    /// The exact value one claim removes from the cell: the payout sum.
    pub fn claim_total(&self) -> Result<u64, CovenantError> {
        let sum: u128 = self.payouts.iter().map(|p| p.value as u128).sum();
        u64::try_from(sum)
            .ok()
            .filter(|v| i64::try_from(*v).is_ok())
            .ok_or(CovenantError::AmountOverflow(sum.min(u64::MAX as u128) as u64))
    }

    fn constructor_args(&self) -> Result<Vec<Expr<'static>>, CovenantError> {
        if self.payouts.is_empty() {
            return Err(CovenantError::NoPayouts);
        }
        if self.payouts.len() > MAX_PAYOUTS {
            return Err(CovenantError::TooManyPayouts { got: self.payouts.len(), max: MAX_PAYOUTS });
        }
        if self.customer.kind() != KIND_P2PK {
            return Err(CovenantError::UnsupportedAddressKind(
                "customer address must be a schnorr P2PK address".to_string(),
            ));
        }
        if self.period_daa == 0 || self.period_daa > u32::MAX as u64 {
            return Err(CovenantError::InvalidPeriod(self.period_daa));
        }
        let claim_total = self.claim_total()?;

        let payloads: Vec<Vec<u8>> = self.payouts.iter().map(|p| p.destination.payload32()).collect();
        let kinds: Vec<i64> = self.payouts.iter().map(|p| p.destination.kind()).collect();
        let values: Vec<i64> = self.payouts.iter().map(|p| to_i64(p.value)).collect::<Result<_, _>>()?;
        Ok(vec![
            payloads.into(),                           // byte[32][] payout_payloads
            kinds.into(),                              // int[]      payout_kinds
            values.into(),                             // int[]      payout_values
            to_i64(self.payouts.len() as u64)?.into(), // int        payout_count
            self.keeper_pubkey.to_vec().into(),        // byte[32]   keeper_pubkey
            self.customer.payload32().into(),          // byte[32]   customer_pubkey
            to_i64(claim_total)?.into(),               // int        claim_total
            to_i64(self.period_daa)?.into(),           // int        period_daa
            to_i64(self.sweep_threshold)?.into(),      // int        sweep_threshold
        ])
    }
}

/// Compile the SubscriptionV1 covenant for one subscription's parameters.
pub fn compile_subscription_v1(params: &SubscriptionV1Params) -> Result<CompiledContract<'static>, CovenantError> {
    let args = params.constructor_args()?;
    Ok(compile_contract(SUBSCRIPTION_V1_SRC, &args, CompileOptions::default())?)
}

/// A prepared subscription spend: the fee input is already keeper-signed, the
/// covenant input awaits the authorizing signature over `covenant_sighash`
/// (keeper for `claim`, customer for `withdraw`).
pub struct SubscriptionDraft {
    transaction: Transaction,
    entries: Vec<UtxoEntry>,
    pub covenant_sighash: [u8; 32],
}

/// The claim outputs: the pinned payouts, the self-replicating remainder (unless
/// it falls below the sweep threshold), and the keeper's fee change.
fn claim_outputs(
    compiled: &CompiledContract<'_>,
    params: &SubscriptionV1Params,
    covenant_value: u64,
    fee_utxo: &Utxo,
    miner_fee: u64,
    fee_payer_address: &kaspa_addresses::Address,
) -> Result<Vec<TransactionOutput>, CovenantError> {
    let claim_total = params.claim_total()?;
    let remainder = covenant_value
        .checked_sub(claim_total)
        .ok_or(CovenantError::InsufficientCovenantValue { value: covenant_value, claim_total })?;
    let mut outputs: Vec<TransactionOutput> = params
        .payouts
        .iter()
        .map(|p| TransactionOutput { value: p.value, script_public_key: p.destination.script_public_key(), covenant: None })
        .collect();
    if remainder >= params.sweep_threshold {
        outputs.push(TransactionOutput {
            value: remainder,
            script_public_key: covenant_script_public_key(compiled),
            covenant: None,
        });
    }
    push_change(&mut outputs, fee_utxo, miner_fee, fee_payer_address);
    Ok(outputs)
}

/// Prepare a `claim` spend for one period: covenant input with
/// `sequence = period_daa` (the CSV relative lock), keeper-signed fee input,
/// pinned payouts + remainder outputs. The keeper then signs `covenant_sighash`.
pub fn prepare_claim(
    compiled: &CompiledContract<'_>,
    params: &SubscriptionV1Params,
    covenant_utxo: &Utxo,
    fee_utxo: &Utxo,
    miner_fee: u64,
    keeper: &KeeperKey,
    prefix: Prefix,
) -> Result<SubscriptionDraft, CovenantError> {
    let outputs = claim_outputs(compiled, params, covenant_utxo.value, fee_utxo, miner_fee, &keeper.address(prefix))?;
    let (transaction, entries, covenant_sighash) =
        build_fee_signed_tx(&compiled.script, outputs, 0, covenant_utxo, params.period_daa, fee_utxo, keeper, prefix)?;
    Ok(SubscriptionDraft { transaction, entries, covenant_sighash })
}

/// Complete a claim with the keeper's 65-byte signature over `covenant_sighash`.
pub fn complete_claim(
    compiled: &CompiledContract<'_>,
    mut draft: SubscriptionDraft,
    keeper_sig: &[u8],
) -> Result<SignedSpend, CovenantError> {
    let entrypoint_sig = compiled.build_sig_script(EP_CLAIM, vec![keeper_sig.to_vec().into()])?;
    draft.transaction.inputs[0].signature_script = covenant_signature_script(&compiled.script, entrypoint_sig)?;
    Ok(SignedSpend { transaction: draft.transaction, entries: draft.entries })
}

/// Prepare a `withdraw` spend: the caller-supplied split (any destinations /
/// amounts — the covenant does not constrain them, the customer's SIG_HASH_ALL
/// signature does) plus keeper fee change; keeper subsidizes gas. The customer
/// signs `covenant_sighash` externally (65-byte schnorr + SIG_HASH_ALL).
pub fn prepare_withdraw(
    compiled: &CompiledContract<'_>,
    split: &[(Destination, u64)],
    covenant_utxo: &Utxo,
    fee_utxo: &Utxo,
    miner_fee: u64,
    keeper: &KeeperKey,
    prefix: Prefix,
) -> Result<SubscriptionDraft, CovenantError> {
    let mut outputs: Vec<TransactionOutput> = split
        .iter()
        .map(|(dest, value)| TransactionOutput { value: *value, script_public_key: dest.script_public_key(), covenant: None })
        .collect();
    push_change(&mut outputs, fee_utxo, miner_fee, &keeper.address(prefix));
    let (transaction, entries, covenant_sighash) =
        build_fee_signed_tx(&compiled.script, outputs, 0, covenant_utxo, 0, fee_utxo, keeper, prefix)?;
    Ok(SubscriptionDraft { transaction, entries, covenant_sighash })
}

/// Complete a withdraw with the customer's externally produced 65-byte signature.
pub fn complete_withdraw(
    compiled: &CompiledContract<'_>,
    mut draft: SubscriptionDraft,
    customer_sig: &[u8],
) -> Result<SignedSpend, CovenantError> {
    let entrypoint_sig = compiled.build_sig_script(EP_WITHDRAW, vec![customer_sig.to_vec().into()])?;
    draft.transaction.inputs[0].signature_script = covenant_signature_script(&compiled.script, entrypoint_sig)?;
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
    use kaspa_txscript::pay_to_address_script;
    use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
    use kaspa_txscript_errors::TxScriptError;

    fn key(byte: u8) -> KeeperKey {
        KeeperKey::from_secret_bytes(&[byte; 32]).unwrap()
    }
    fn customer() -> KeeperKey { key(3) }
    fn merchant() -> KeeperKey { key(4) }
    fn keeper() -> KeeperKey { key(7) }
    fn impostor() -> KeeperKey { key(9) }

    fn dest_of(k: &KeeperKey) -> Destination {
        Destination::from_address(k.address(Prefix::Testnet)).unwrap()
    }
    fn p2sh(byte: u8) -> Destination {
        Destination::from_address(Address::new(Prefix::Testnet, Version::ScriptHash, &[byte; 32])).unwrap()
    }

    // 700 merchant (P2PK) + 250 kasway fee (P2PK) + 50 tax (P2SH) per period.
    const CLAIM_TOTAL: u64 = 1000;
    const PERIOD_DAA: u64 = 8_640;
    const SWEEP: u64 = 500;
    const MINER_FEE: u64 = 1000;

    fn params() -> SubscriptionV1Params {
        SubscriptionV1Params {
            payouts: vec![
                Payout { destination: dest_of(&merchant()), value: 700 },
                Payout { destination: dest_of(&key(0x22)), value: 250 },
                Payout { destination: p2sh(0x33), value: 50 },
            ],
            keeper_pubkey: keeper().x_only_pubkey(),
            customer: dest_of(&customer()),
            period_daa: PERIOD_DAA,
            sweep_threshold: SWEEP,
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
        let compiled = compile_subscription_v1(&p).unwrap();
        assert_eq!(compiled.contract_name, "SubscriptionV1");
        let addr = covenant_address(&compiled, Prefix::Testnet).unwrap();
        assert_eq!(addr.prefix, Prefix::Testnet);
    }

    // Build a claim spend with a chosen covenant-input sequence, signer, and an
    // output tamper applied BEFORE signing (so both signatures stay consistent
    // and the covenant checks are what fails, not signature validation).
    fn claim(
        cov_value: u64,
        sequence: u64,
        signer: &KeeperKey,
        tamper: impl FnOnce(&mut Vec<TransactionOutput>),
    ) -> SignedSpend {
        let p = params();
        let compiled = compile_subscription_v1(&p).unwrap();
        let mut outputs =
            claim_outputs(&compiled, &p, cov_value, &fee_utxo(), MINER_FEE, &keeper().address(Prefix::Testnet)).unwrap();
        tamper(&mut outputs);
        let (transaction, entries, covenant_sighash) = build_fee_signed_tx(
            &compiled.script,
            outputs,
            0,
            &cov_utxo(cov_value),
            sequence,
            &fee_utxo(),
            &keeper(),
            Prefix::Testnet,
        )
        .unwrap();
        let sig = signer.sign_sighash(&covenant_sighash).unwrap();
        complete_claim(&compiled, SubscriptionDraft { transaction, entries, covenant_sighash }, &sig).unwrap()
    }

    // (a) A well-formed periodic claim passes: pinned payouts exact, remainder
    // back to the covenant's own scriptPubKey (proves OpTxInputSpk compiles and
    // introspects the P2SH input correctly).
    #[test]
    fn claim_valid_replicates_cell() {
        let spend = claim(3_500, PERIOD_DAA, &keeper(), |_| {});
        // 3 payouts + remainder + keeper change.
        assert_eq!(spend.transaction.outputs.len(), 5);
        assert_eq!(spend.transaction.outputs[3].value, 2_500);
        assert!(verify(&spend).is_ok());
    }

    // prepare_claim/complete_claim (the production path) build the same passing spend.
    #[test]
    fn prepare_complete_claim_roundtrip_is_valid() {
        let p = params();
        let compiled = compile_subscription_v1(&p).unwrap();
        let draft = prepare_claim(&compiled, &p, &cov_utxo(3_500), &fee_utxo(), MINER_FEE, &keeper(), Prefix::Testnet).unwrap();
        assert_eq!(draft.transaction.inputs[0].sequence, PERIOD_DAA);
        let sig = keeper().sign_sighash(&draft.covenant_sighash).unwrap();
        let spend = complete_claim(&compiled, draft, &sig).unwrap();
        assert!(verify(&spend).is_ok());
    }

    // (b) A claim whose input sequence is below the period fails the CSV check.
    #[test]
    fn claim_rejects_premature_age() {
        assert!(verify(&claim(3_500, PERIOD_DAA - 1, &keeper(), |_| {})).is_err());
    }

    // (c) Inflating the merchant payout value fails the pinned-value check.
    #[test]
    fn claim_rejects_inflated_merchant_value() {
        assert!(verify(&claim(3_500, PERIOD_DAA, &keeper(), |o| o[0].value += 1)).is_err());
    }

    // (d) Redirecting the remainder to a different scriptPubKey fails the
    // self-replication check (OpTxInputSpk == OpTxOutputSpk).
    #[test]
    fn claim_rejects_remainder_to_other_spk() {
        let steal = pay_to_address_script(&impostor().address(Prefix::Testnet));
        assert!(verify(&claim(3_500, PERIOD_DAA, &keeper(), |o| o[3].script_public_key = steal)).is_err());
    }

    // (e) Shorting the remainder value fails the exact-remainder check.
    #[test]
    fn claim_rejects_wrong_remainder_value() {
        assert!(verify(&claim(3_500, PERIOD_DAA, &keeper(), |o| o[3].value -= 1)).is_err());
    }

    // (f) When the leftover is below the sweep threshold, the claim may omit the
    // remainder output; the dust (< threshold) becomes miner fee.
    #[test]
    fn claim_sweep_branch_below_threshold_is_valid() {
        let spend = claim(CLAIM_TOTAL + SWEEP - 1, PERIOD_DAA, &keeper(), |_| {});
        // 3 payouts + keeper change; NO remainder output.
        assert_eq!(spend.transaction.outputs.len(), 4);
        assert!(verify(&spend).is_ok());
    }

    // (h) A claim signed by anyone but the keeper fails checkSig.
    #[test]
    fn claim_rejects_wrong_signer() {
        assert!(verify(&claim(3_500, PERIOD_DAA, &impostor(), |_| {})).is_err());
    }

    fn withdraw(signer: &KeeperKey) -> SignedSpend {
        let p = params();
        let compiled = compile_subscription_v1(&p).unwrap();
        // Customer pulls the whole cell to themselves, any time (sequence 0).
        let split = vec![(dest_of(&customer()), 3_500)];
        let draft =
            prepare_withdraw(&compiled, &split, &cov_utxo(3_500), &fee_utxo(), MINER_FEE, &keeper(), Prefix::Testnet).unwrap();
        assert_eq!(draft.transaction.inputs[0].sequence, 0);
        let sig = signer.sign_sighash(&draft.covenant_sighash).unwrap();
        complete_withdraw(&compiled, draft, &sig).unwrap()
    }

    // (g) The customer can withdraw everything at any age (no CSV on this path).
    #[test]
    fn withdraw_customer_valid_at_age_zero() {
        assert!(verify(&withdraw(&customer())).is_ok());
    }

    #[test]
    fn withdraw_rejects_non_customer() {
        assert!(verify(&withdraw(&impostor())).is_err());
    }
}
