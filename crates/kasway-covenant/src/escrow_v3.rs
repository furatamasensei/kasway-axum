//! Kasway escrow V3 — evaluator marketplace settlement covenant.
//!
//! An invoice reserves a fixed evaluator fee and commits to a terminal dispute
//! covenant before it is funded. Opening a dispute is a real UTXO transition:
//! the complete value moves out of EscrowV3 into DisputeV1, so the old
//! permissionless capture branch no longer has an output to spend.

use kaspa_addresses::{Address, Version};
use kaspa_consensus_core::tx::{Transaction, TransactionOutput, UtxoEntry};
use kaspa_txscript::pay_to_address_script;
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{compile_contract, CompileOptions, CompiledContract};

use crate::{
    assemble_unsigned, build_fee_signed_tx, covenant_script_hash, covenant_signature_script,
    fee_signature_script, push_change, to_i64, CovenantError, Destination, KeeperKey, Payout,
    Prefix, SignedSpend, Utxo, KIND_P2PK, MAX_PAYOUTS,
};

pub const ESCROW_V3_SRC: &str = include_str!("../contracts/escrow_v3.sil");
pub const DISPUTE_V1_SRC: &str = include_str!("../contracts/dispute_v1.sil");

pub const EP_RELEASE_CONFIRMED: &str = "release_confirmed";
pub const EP_RELEASE_CAPTURED: &str = "release_captured";
pub const EP_OPEN_DISPUTE: &str = "open_dispute";
pub const EP_RELEASE_SETTLED: &str = "release_settled";
pub const EP_REFUND_BY_MERCHANT: &str = "refund_by_merchant";
pub const EP_RELEASE_BY_EVALUATOR: &str = "release_by_evaluator";
pub const EP_REFUND_BY_EVALUATOR: &str = "refund_by_evaluator";

#[derive(Debug, Clone)]
pub struct DisputeV1Params {
    pub payouts: Vec<Payout>,
    pub customer_refund: Destination,
    pub merchant: Destination,
    pub evaluator_pubkey: [u8; 32],
    pub evaluator_reward: Destination,
    pub gross_amount: u64,
    pub evaluator_fee: u64,
}

impl DisputeV1Params {
    fn validate(&self) -> Result<(), CovenantError> {
        if self.payouts.is_empty() {
            return Err(CovenantError::NoPayouts);
        }
        if self.payouts.len() > MAX_PAYOUTS {
            return Err(CovenantError::TooManyPayouts {
                got: self.payouts.len(),
                max: MAX_PAYOUTS,
            });
        }
        if self.customer_refund.kind() != KIND_P2PK || self.merchant.kind() != KIND_P2PK {
            return Err(CovenantError::UnsupportedAddressKind(
                "customer refund and merchant identities must be Schnorr P2PK".into(),
            ));
        }
        if self.evaluator_fee == 0 {
            return Err(CovenantError::UnsupportedAddressKind(
                "evaluator fee must be positive".into(),
            ));
        }
        self.gross_amount
            .checked_add(self.evaluator_fee)
            .ok_or(CovenantError::AmountOverflow(self.gross_amount))?;
        let sum: u128 = self.payouts.iter().map(|p| p.value as u128).sum();
        if sum != self.gross_amount as u128 {
            return Err(CovenantError::PayoutSumMismatch {
                sum,
                gross: self.gross_amount as u128,
            });
        }
        Ok(())
    }

    fn constructor_args(&self) -> Result<Vec<Expr<'static>>, CovenantError> {
        self.validate()?;
        let payloads: Vec<Vec<u8>> = self
            .payouts
            .iter()
            .map(|p| p.destination.payload32())
            .collect();
        let kinds: Vec<i64> = self.payouts.iter().map(|p| p.destination.kind()).collect();
        let values: Vec<i64> = self
            .payouts
            .iter()
            .map(|p| to_i64(p.value))
            .collect::<Result<_, _>>()?;
        Ok(vec![
            payloads.into(),
            kinds.into(),
            values.into(),
            to_i64(self.payouts.len() as u64)?.into(),
            self.customer_refund.payload32().into(),
            self.merchant.payload32().into(),
            self.evaluator_pubkey.to_vec().into(),
            self.evaluator_reward.payload32().into(),
            self.evaluator_reward.kind().into(),
            to_i64(self.gross_amount)?.into(),
            to_i64(self.evaluator_fee)?.into(),
        ])
    }

    fn total(&self) -> Result<u64, CovenantError> {
        self.gross_amount
            .checked_add(self.evaluator_fee)
            .ok_or(CovenantError::AmountOverflow(self.gross_amount))
    }
}

#[derive(Debug, Clone)]
pub struct EscrowV3Params {
    pub dispute: DisputeV1Params,
    pub capture_time: u64,
    pub dispute_deadline: u64,
}

impl EscrowV3Params {
    fn constructor_args(
        &self,
        dispute_script_hash: &[u8],
    ) -> Result<Vec<Expr<'static>>, CovenantError> {
        self.dispute.validate()?;
        if self.dispute_deadline > self.capture_time {
            return Err(CovenantError::UnsupportedAddressKind(
                "dispute deadline must not be later than capture time".into(),
            ));
        }
        if dispute_script_hash.len() != 32 {
            return Err(CovenantError::Address(
                "dispute script hash must be 32 bytes".into(),
            ));
        }
        let payloads: Vec<Vec<u8>> = self
            .dispute
            .payouts
            .iter()
            .map(|p| p.destination.payload32())
            .collect();
        let kinds: Vec<i64> = self
            .dispute
            .payouts
            .iter()
            .map(|p| p.destination.kind())
            .collect();
        let values: Vec<i64> = self
            .dispute
            .payouts
            .iter()
            .map(|p| to_i64(p.value))
            .collect::<Result<_, _>>()?;
        Ok(vec![
            payloads.into(),
            kinds.into(),
            values.into(),
            to_i64(self.dispute.payouts.len() as u64)?.into(),
            self.dispute.customer_refund.payload32().into(),
            self.dispute.merchant.payload32().into(),
            dispute_script_hash.to_vec().into(),
            to_i64(self.dispute.gross_amount)?.into(),
            to_i64(self.dispute.evaluator_fee)?.into(),
            to_i64(self.capture_time)?.into(),
        ])
    }
}

pub struct EscrowV3Contracts {
    pub escrow: CompiledContract<'static>,
    pub dispute: CompiledContract<'static>,
}

/// Compile the terminal covenant first, then bind its exact P2SH hash into the
/// initial escrow. Wallets can reproduce this pair byte-for-byte.
pub fn compile_escrow_v3(params: &EscrowV3Params) -> Result<EscrowV3Contracts, CovenantError> {
    let dispute = compile_contract(
        DISPUTE_V1_SRC,
        &params.dispute.constructor_args()?,
        CompileOptions::default(),
    )?;
    let hash = covenant_script_hash(&dispute);
    let escrow = compile_contract(
        ESCROW_V3_SRC,
        &params.constructor_args(&hash)?,
        CompileOptions::default(),
    )?;
    Ok(EscrowV3Contracts { escrow, dispute })
}

pub struct SpendDraft {
    transaction: Transaction,
    entries: Vec<UtxoEntry>,
    pub covenant_sighash: [u8; 32],
    pub fee_sighash: Option<[u8; 32]>,
}

fn payout_with_reserve_refund(
    params: &EscrowV3Params,
    fee_utxo: &Utxo,
    miner_fee: u64,
    fee_payer: &Address,
) -> Vec<TransactionOutput> {
    let mut outputs = params
        .dispute
        .payouts
        .iter()
        .map(|p| TransactionOutput {
            value: p.value,
            script_public_key: p.destination.script_public_key(),
            covenant: None,
        })
        .collect::<Vec<_>>();
    outputs.push(TransactionOutput {
        value: params.dispute.evaluator_fee,
        script_public_key: params.dispute.customer_refund.script_public_key(),
        covenant: None,
    });
    push_change(&mut outputs, fee_utxo, miner_fee, fee_payer);
    outputs
}

pub fn prepare_release(
    contracts: &EscrowV3Contracts,
    params: &EscrowV3Params,
    covenant_utxo: &Utxo,
    fee_utxo: &Utxo,
    miner_fee: u64,
    keeper: &KeeperKey,
    prefix: Prefix,
    lock_time: u64,
) -> Result<SpendDraft, CovenantError> {
    let outputs = payout_with_reserve_refund(params, fee_utxo, miner_fee, &keeper.address(prefix));
    let (transaction, entries, covenant_sighash) = build_fee_signed_tx(
        &contracts.escrow.script,
        outputs,
        lock_time,
        covenant_utxo,
        0,
        fee_utxo,
        keeper,
        prefix,
    )?;
    Ok(SpendDraft {
        transaction,
        entries,
        covenant_sighash,
        fee_sighash: None,
    })
}

pub fn complete_release(
    contracts: &EscrowV3Contracts,
    mut draft: SpendDraft,
    entrypoint: &str,
    customer_sig: Option<&[u8]>,
) -> Result<SignedSpend, CovenantError> {
    let args = customer_sig.map_or_else(Vec::new, |s| vec![s.to_vec().into()]);
    let ep = contracts.escrow.build_sig_script(entrypoint, args)?;
    draft.transaction.inputs[0].signature_script =
        covenant_signature_script(&contracts.escrow.script, ep)?;
    Ok(SignedSpend {
        transaction: draft.transaction,
        entries: draft.entries,
    })
}

/// Build the transition into the precommitted dispute covenant. `role` is 0 for
/// customer and 1 for merchant.
pub fn prepare_open_dispute(
    contracts: &EscrowV3Contracts,
    params: &EscrowV3Params,
    covenant_utxo: &Utxo,
    fee_utxo: &Utxo,
    miner_fee: u64,
    fee_payer_address: &Address,
) -> Result<SpendDraft, CovenantError> {
    let dispute_hash = covenant_script_hash(&contracts.dispute);
    let dispute_address =
        Address::new(fee_payer_address.prefix, Version::ScriptHash, &dispute_hash);
    let mut outputs = vec![TransactionOutput {
        value: params.dispute.total()?,
        script_public_key: pay_to_address_script(&dispute_address),
        covenant: None,
    }];
    push_change(&mut outputs, fee_utxo, miner_fee, fee_payer_address);
    let fee_spk = pay_to_address_script(fee_payer_address);
    let (transaction, entries, covenant_sighash, fee_sighash) = assemble_unsigned(
        &contracts.escrow.script,
        outputs,
        0,
        covenant_utxo,
        0,
        fee_utxo,
        fee_spk,
    );
    Ok(SpendDraft {
        transaction,
        entries,
        covenant_sighash,
        fee_sighash: Some(fee_sighash),
    })
}

pub fn complete_open_dispute(
    contracts: &EscrowV3Contracts,
    mut draft: SpendDraft,
    participant_sig: &[u8],
    role: u32,
    fee_sig: &[u8],
) -> Result<SignedSpend, CovenantError> {
    if role > 1 {
        return Err(CovenantError::Address(
            "dispute participant role must be 0 or 1".into(),
        ));
    }
    let ep = contracts.escrow.build_sig_script(
        EP_OPEN_DISPUTE,
        vec![participant_sig.to_vec().into(), (role as i64).into()],
    )?;
    draft.transaction.inputs[0].signature_script =
        covenant_signature_script(&contracts.escrow.script, ep)?;
    draft.transaction.inputs[1].signature_script = fee_signature_script(fee_sig)?;
    Ok(SignedSpend {
        transaction: draft.transaction,
        entries: draft.entries,
    })
}

fn evaluator_outputs(
    params: &DisputeV1Params,
    release: bool,
    fee_utxo: &Utxo,
    miner_fee: u64,
    fee_payer: &Address,
) -> Vec<TransactionOutput> {
    let mut outputs = if release {
        params
            .payouts
            .iter()
            .map(|p| TransactionOutput {
                value: p.value,
                script_public_key: p.destination.script_public_key(),
                covenant: None,
            })
            .collect::<Vec<_>>()
    } else {
        vec![TransactionOutput {
            value: params.gross_amount,
            script_public_key: params.customer_refund.script_public_key(),
            covenant: None,
        }]
    };
    outputs.push(TransactionOutput {
        value: params.evaluator_fee,
        script_public_key: params.evaluator_reward.script_public_key(),
        covenant: None,
    });
    push_change(&mut outputs, fee_utxo, miner_fee, fee_payer);
    outputs
}

pub fn prepare_evaluator_decision(
    contracts: &EscrowV3Contracts,
    params: &DisputeV1Params,
    release: bool,
    dispute_utxo: &Utxo,
    fee_utxo: &Utxo,
    miner_fee: u64,
    fee_payer_address: &Address,
) -> Result<SpendDraft, CovenantError> {
    let outputs = evaluator_outputs(params, release, fee_utxo, miner_fee, fee_payer_address);
    let fee_spk = pay_to_address_script(fee_payer_address);
    let (transaction, entries, covenant_sighash, fee_sighash) = assemble_unsigned(
        &contracts.dispute.script,
        outputs,
        0,
        dispute_utxo,
        0,
        fee_utxo,
        fee_spk,
    );
    Ok(SpendDraft {
        transaction,
        entries,
        covenant_sighash,
        fee_sighash: Some(fee_sighash),
    })
}

pub fn complete_evaluator_decision(
    contracts: &EscrowV3Contracts,
    mut draft: SpendDraft,
    release: bool,
    evaluator_sig: &[u8],
    fee_sig: &[u8],
) -> Result<SignedSpend, CovenantError> {
    let entrypoint = if release {
        EP_RELEASE_BY_EVALUATOR
    } else {
        EP_REFUND_BY_EVALUATOR
    };
    let ep = contracts
        .dispute
        .build_sig_script(entrypoint, vec![evaluator_sig.to_vec().into()])?;
    draft.transaction.inputs[0].signature_script =
        covenant_signature_script(&contracts.dispute.script, ep)?;
    draft.transaction.inputs[1].signature_script = fee_signature_script(fee_sig)?;
    Ok(SignedSpend {
        transaction: draft.transaction,
        entries: draft.entries,
    })
}

/// Prepare the always-available customer+seller escape hatch after a dispute.
/// Both parties sign the complete transaction, so `split` may express any
/// allocation they mutually accept, including how to handle the fee reserve.
pub fn prepare_dispute_settlement(
    contracts: &EscrowV3Contracts,
    split: &[(Destination, u64)],
    dispute_utxo: &Utxo,
    fee_utxo: &Utxo,
    miner_fee: u64,
    fee_payer_address: &Address,
) -> Result<SpendDraft, CovenantError> {
    let mut outputs = split
        .iter()
        .map(|(destination, value)| TransactionOutput {
            value: *value,
            script_public_key: destination.script_public_key(),
            covenant: None,
        })
        .collect::<Vec<_>>();
    push_change(&mut outputs, fee_utxo, miner_fee, fee_payer_address);
    let (transaction, entries, covenant_sighash, fee_sighash) = assemble_unsigned(
        &contracts.dispute.script,
        outputs,
        0,
        dispute_utxo,
        0,
        fee_utxo,
        pay_to_address_script(fee_payer_address),
    );
    Ok(SpendDraft {
        transaction,
        entries,
        covenant_sighash,
        fee_sighash: Some(fee_sighash),
    })
}

pub fn complete_dispute_settlement(
    contracts: &EscrowV3Contracts,
    mut draft: SpendDraft,
    customer_sig: &[u8],
    merchant_sig: &[u8],
    fee_sig: &[u8],
) -> Result<SignedSpend, CovenantError> {
    let ep = contracts.dispute.build_sig_script(
        EP_RELEASE_SETTLED,
        vec![customer_sig.to_vec().into(), merchant_sig.to_vec().into()],
    )?;
    draft.transaction.inputs[0].signature_script =
        covenant_signature_script(&contracts.dispute.script, ep)?;
    draft.transaction.inputs[1].signature_script = fee_signature_script(fee_sig)?;
    Ok(SignedSpend {
        transaction: draft.transaction,
        entries: draft.entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::covenant_address;
    use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
    use kaspa_consensus_core::tx::PopulatedTransaction;
    use kaspa_txscript::caches::Cache;
    use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};

    fn key(byte: u8) -> KeeperKey {
        KeeperKey::from_secret_bytes(&[byte; 32]).unwrap()
    }
    fn dest(k: &KeeperKey) -> Destination {
        Destination::from_address(k.address(Prefix::Testnet)).unwrap()
    }
    fn params() -> EscrowV3Params {
        let customer = key(3);
        let merchant = key(4);
        let evaluator = key(5);
        EscrowV3Params {
            dispute: DisputeV1Params {
                payouts: vec![Payout {
                    destination: dest(&merchant),
                    value: 10_000,
                }],
                customer_refund: dest(&customer),
                merchant: dest(&merchant),
                evaluator_pubkey: evaluator.x_only_pubkey(),
                evaluator_reward: dest(&key(6)),
                gross_amount: 10_000,
                evaluator_fee: 1_000,
            },
            capture_time: 5_000,
            dispute_deadline: 5_000,
        }
    }
    fn cov(byte: u8, value: u64) -> Utxo {
        Utxo {
            transaction_id: [byte; 32],
            index: 0,
            value,
        }
    }
    fn verify(spend: &SignedSpend) -> bool {
        let reused = SigHashReusedValuesUnsync::new();
        let cache = Cache::new(10_000);
        let populated = PopulatedTransaction::new(&spend.transaction, spend.entries.clone());
        spend
            .transaction
            .inputs
            .iter()
            .enumerate()
            .all(|(idx, input)| {
                TxScriptEngine::from_transaction_input(
                    &populated,
                    input,
                    idx,
                    &spend.entries[idx],
                    EngineCtx::new(&cache).with_reused(&reused),
                    EngineFlags {
                        covenants_enabled: true,
                        ..Default::default()
                    },
                )
                .execute()
                .is_ok()
            })
    }

    #[test]
    fn compiles_pair_and_binds_dispute_hash() {
        let contracts = compile_escrow_v3(&params()).unwrap();
        assert_eq!(contracts.escrow.contract_name, "EscrowV3");
        assert_eq!(contracts.dispute.contract_name, "DisputeV1");
        assert_ne!(
            covenant_address(&contracts.escrow, Prefix::Testnet).unwrap(),
            covenant_address(&contracts.dispute, Prefix::Testnet).unwrap(),
        );
    }

    #[test]
    fn opening_dispute_moves_value_and_invalidates_old_capture_utxo() {
        let p = params();
        let contracts = compile_escrow_v3(&p).unwrap();
        let customer = key(3);
        let fee = cov(9, 100_000);
        let draft = prepare_open_dispute(
            &contracts,
            &p,
            &cov(1, 11_000),
            &fee,
            1_000,
            &customer.address(Prefix::Testnet),
        )
        .unwrap();
        let participant_sig = customer.sign_sighash(&draft.covenant_sighash).unwrap();
        let fee_sig = customer.sign_sighash(&draft.fee_sighash.unwrap()).unwrap();
        let spend =
            complete_open_dispute(&contracts, draft, &participant_sig, 0, &fee_sig).unwrap();
        assert!(verify(&spend));
        assert_eq!(spend.transaction.outputs[0].value, 11_000);
    }

    #[test]
    fn evaluator_release_pays_fixed_reward() {
        let p = params();
        let contracts = compile_escrow_v3(&p).unwrap();
        let evaluator = key(5);
        let fee_payer = key(8);
        let draft = prepare_evaluator_decision(
            &contracts,
            &p.dispute,
            true,
            &cov(2, 11_000),
            &cov(7, 100_000),
            1_000,
            &fee_payer.address(Prefix::Testnet),
        )
        .unwrap();
        let eval_sig = evaluator.sign_sighash(&draft.covenant_sighash).unwrap();
        let fee_sig = fee_payer.sign_sighash(&draft.fee_sighash.unwrap()).unwrap();
        let spend =
            complete_evaluator_decision(&contracts, draft, true, &eval_sig, &fee_sig).unwrap();
        assert!(verify(&spend));
        assert_eq!(spend.transaction.outputs[1].value, 1_000);
    }

    #[test]
    fn evaluator_refund_returns_gross_and_still_pays_fixed_reward() {
        let p = params();
        let contracts = compile_escrow_v3(&p).unwrap();
        let evaluator = key(5);
        let fee_payer = key(8);
        let draft = prepare_evaluator_decision(
            &contracts,
            &p.dispute,
            false,
            &cov(2, 11_000),
            &cov(7, 100_000),
            1_000,
            &fee_payer.address(Prefix::Testnet),
        )
        .unwrap();
        let eval_sig = evaluator.sign_sighash(&draft.covenant_sighash).unwrap();
        let fee_sig = fee_payer.sign_sighash(&draft.fee_sighash.unwrap()).unwrap();
        let spend =
            complete_evaluator_decision(&contracts, draft, false, &eval_sig, &fee_sig).unwrap();
        assert!(verify(&spend));
        assert_eq!(spend.transaction.outputs[0].value, 10_000);
        assert_eq!(spend.transaction.outputs[1].value, 1_000);
    }

    #[test]
    fn normal_release_returns_unused_evaluator_reserve() {
        let p = params();
        let contracts = compile_escrow_v3(&p).unwrap();
        let customer = key(3);
        let keeper = key(8);
        let draft = prepare_release(
            &contracts,
            &p,
            &cov(1, 11_000),
            &cov(7, 100_000),
            1_000,
            &keeper,
            Prefix::Testnet,
            0,
        )
        .unwrap();
        let customer_sig = customer.sign_sighash(&draft.covenant_sighash).unwrap();
        let spend =
            complete_release(&contracts, draft, EP_RELEASE_CONFIRMED, Some(&customer_sig)).unwrap();
        assert!(verify(&spend));
        assert_eq!(spend.transaction.outputs[0].value, 10_000);
        assert_eq!(spend.transaction.outputs[1].value, 1_000);
    }

    #[test]
    fn bilateral_dispute_settlement_requires_both_parties() {
        let p = params();
        let contracts = compile_escrow_v3(&p).unwrap();
        let customer = key(3);
        let merchant = key(4);
        let fee_payer = key(8);
        let split = vec![(dest(&customer), 5_500), (dest(&merchant), 5_500)];
        let draft = prepare_dispute_settlement(
            &contracts,
            &split,
            &cov(2, 11_000),
            &cov(7, 100_000),
            1_000,
            &fee_payer.address(Prefix::Testnet),
        )
        .unwrap();
        let customer_sig = customer.sign_sighash(&draft.covenant_sighash).unwrap();
        let merchant_sig = merchant.sign_sighash(&draft.covenant_sighash).unwrap();
        let fee_sig = fee_payer.sign_sighash(&draft.fee_sighash.unwrap()).unwrap();
        let spend =
            complete_dispute_settlement(&contracts, draft, &customer_sig, &merchant_sig, &fee_sig)
                .unwrap();
        assert!(verify(&spend));
    }

    #[test]
    fn non_evaluator_cannot_decide() {
        let p = params();
        let contracts = compile_escrow_v3(&p).unwrap();
        let impostor = key(9);
        let fee_payer = key(8);
        let draft = prepare_evaluator_decision(
            &contracts,
            &p.dispute,
            false,
            &cov(2, 11_000),
            &cov(7, 100_000),
            1_000,
            &fee_payer.address(Prefix::Testnet),
        )
        .unwrap();
        let eval_sig = impostor.sign_sighash(&draft.covenant_sighash).unwrap();
        let fee_sig = fee_payer.sign_sighash(&draft.fee_sighash.unwrap()).unwrap();
        let spend =
            complete_evaluator_decision(&contracts, draft, false, &eval_sig, &fee_sig).unwrap();
        assert!(!verify(&spend));
    }
}
