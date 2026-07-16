//! Kasway covenant crate.
//!
//! Compiles the Kasway escrow covenant ([`escrow_v2`], tiers 0–2) and derives its
//! P2SH address and spend sig scripts. **Every covenant script byte comes from the SilverScript
//! compiler** (`silverscript_lang`); there is no hand-assembled opcode anywhere in
//! Kasway. All Kaspa consensus crypto (address parsing, script building, P2SH
//! derivation) is confined to this crate so the rest of the backend never touches
//! rusty-kaspa directly.

use kaspa_addresses::{Address, Version};
pub use kaspa_addresses::Prefix;
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_txscript::{extract_script_pub_key_address, pay_to_address_script, pay_to_script_hash_script};
use silverscript_lang::compiler::CompilerError;
pub use silverscript_lang::compiler::CompiledContract;

/// Escrow — tiered dispute-resolution covenant (optimistic release/capture +
/// mutual settlement + M-of-N arbiter panel); see `escrow_v2.sil`.
pub mod escrow_v2;
/// Subscription — non-custodial recurring-claim autopay covenant (periodic
/// keeper claim + self-replicating remainder + customer withdraw); see
/// `subscription_v1.sil`.
pub mod subscription_v1;

/// Map a Kasway network label to the Kaspa address prefix. Keeps rusty-kaspa's
/// `Prefix` out of the rest of the backend.
pub fn network_prefix(network: &str) -> Result<Prefix, CovenantError> {
    match network.trim().to_ascii_lowercase().as_str() {
        "mainnet" | "kaspa" => Ok(Prefix::Mainnet),
        "tn10" | "testnet" | "testnet-10" | "testnet10" | "kaspatest" => Ok(Prefix::Testnet),
        "simnet" => Ok(Prefix::Simnet),
        "devnet" => Ok(Prefix::Devnet),
        other => Err(CovenantError::Address(format!("unknown network: {other}"))),
    }
}

/// Maximum payouts the release branch unrolls: merchant_net + kasway_fee + tax +
/// up to 5 split destinations. Must match the `for(... , 8)` bound in the `.sil`.
pub const MAX_PAYOUTS: usize = 8;

/// Address kind, matching the covenant's `payout_kinds` / `refund_kind` encoding.
pub(crate) const KIND_P2PK: i64 = 0;
const KIND_P2SH: i64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum CovenantError {
    #[error("silverscript compile error: {0}")]
    Compile(String),
    #[error("no payouts supplied")]
    NoPayouts,
    #[error("too many payouts: {got} (max {max})")]
    TooManyPayouts { got: usize, max: usize },
    #[error("amount does not fit in i64: {0}")]
    AmountOverflow(u64),
    #[error("invalid kaspa address: {0}")]
    Address(String),
    #[error("unsupported address kind (only schnorr P2PK and P2SH are supported): {0}")]
    UnsupportedAddressKind(String),
    #[error("payout values ({sum}) do not sum to gross_amount ({gross})")]
    PayoutSumMismatch { sum: u128, gross: u128 },
    #[error("covenant value ({value}) cannot cover the claim total ({claim_total})")]
    InsufficientCovenantValue { value: u64, claim_total: u64 },
    #[error("claim period must be 1..=u32::MAX DAA scores, got {0}")]
    InvalidPeriod(u64),
}

impl From<CompilerError> for CovenantError {
    fn from(e: CompilerError) -> Self {
        CovenantError::Compile(e.to_string())
    }
}

/// A payout/refund destination: a 32-byte address payload plus its kind. Parsed
/// from a Kaspa address so the covenant can rebuild and check its scriptPubKey.
#[derive(Debug, Clone)]
pub struct Destination {
    address: Address,
}

impl Destination {
    /// Parse a Kaspa address string (e.g. `kaspatest:…`). Only schnorr P2PK and
    /// P2SH (both 32-byte payloads) are supported; ECDSA addresses are rejected.
    pub fn parse(addr: &str) -> Result<Self, CovenantError> {
        let address = Address::try_from(addr).map_err(|e| CovenantError::Address(e.to_string()))?;
        match address.version {
            Version::PubKey | Version::ScriptHash if address.payload.len() == 32 => Ok(Self { address }),
            _ => Err(CovenantError::UnsupportedAddressKind(addr.to_string())),
        }
    }

    /// Build a destination directly from parts (used by tests and callers that
    /// already hold a parsed address).
    pub fn from_address(address: Address) -> Result<Self, CovenantError> {
        match address.version {
            Version::PubKey | Version::ScriptHash if address.payload.len() == 32 => Ok(Self { address }),
            _ => Err(CovenantError::UnsupportedAddressKind(address.to_string())),
        }
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    fn kind(&self) -> i64 {
        match self.address.version {
            Version::ScriptHash => KIND_P2SH,
            _ => KIND_P2PK,
        }
    }

    fn payload32(&self) -> Vec<u8> {
        self.address.payload.to_vec()
    }

    /// The scriptPubKey funds to this destination carry.
    pub fn script_public_key(&self) -> ScriptPublicKey {
        pay_to_address_script(&self.address)
    }
}

/// One ordered release payout, in transaction-output order.
#[derive(Debug, Clone)]
pub struct Payout {
    pub destination: Destination,
    /// Exact value in sompi.
    pub value: u64,
}

fn to_i64(v: u64) -> Result<i64, CovenantError> {
    i64::try_from(v).map_err(|_| CovenantError::AmountOverflow(v))
}

/// The P2SH scriptPubKey that locks funds into this covenant.
pub fn covenant_script_public_key(compiled: &CompiledContract<'_>) -> ScriptPublicKey {
    pay_to_script_hash_script(&compiled.script)
}

/// The Kaspa address (e.g. `kaspatest:…`) the customer funds.
pub fn covenant_address(compiled: &CompiledContract<'_>, prefix: Prefix) -> Result<Address, CovenantError> {
    let spk = covenant_script_public_key(compiled);
    extract_script_pub_key_address(&spk, prefix).map_err(|e| CovenantError::Address(e.to_string()))
}

/// The 32-byte P2SH redeem-script hash committed by this covenant (for storage/audit).
pub fn covenant_script_hash(compiled: &CompiledContract<'_>) -> Vec<u8> {
    // P2SH script pubkey is [OP_BLAKE2B, OP_DATA_32, <32-byte hash>, OP_EQUAL].
    covenant_script_public_key(compiled).script().get(2..34).map(<[u8]>::to_vec).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Transaction assembly — building broadcastable release / refund spends.
//
// A spend has two inputs: the covenant UTXO (P2SH, revealed + spent via the
// entrypoint sig script) and a keeper-owned fee UTXO (an ordinary P2PK the
// keeper signs to pay the miner fee). Payout values are checked exactly by the
// covenant, so the miner fee is taken from the keeper input's change, never
// from the covenant value.
// ---------------------------------------------------------------------------

use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::mass::units::ComputeBudget;
use kaspa_consensus_core::tx::{
    ComputeCommit, MutableTransaction, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry,
};

/// Compute budget committed on the covenant input (v1). 1 unit = 10,000 script
/// units; the release loop rebuilds up to `MAX_PAYOUTS` scriptPubKeys, so this is
/// sized well above that. Sits in the tx hash, outside the (empty) signature.
pub const COVENANT_COMPUTE_BUDGET: u16 = 50;
/// Compute budget for the ordinary P2PK fee input. Measured on TN10: a single
/// Schnorr `OP_CHECKSIG` consumes ~100,000 script units (≈10 budget; 1 unit =
/// 10,000 script units), so this is set to 20 for headroom. A v1 tx must commit a
/// compute budget on EVERY input (never `sig_op_count`), so the fee input carries
/// this instead of a sigop count.
pub const FEE_COMPUTE_BUDGET: u16 = 20;
use kaspa_txscript::pay_to_script_hash_signature_script_with_flags;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::EngineFlags;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};

/// A UTXO reference (outpoint + value) the keeper spends.
#[derive(Debug, Clone)]
pub struct Utxo {
    pub transaction_id: [u8; 32],
    pub index: u32,
    pub value: u64,
}

/// The keeper's fee-paying key. It only ever signs the keeper's own fee input —
/// never anything that touches the covenant value.
pub struct KeeperKey {
    keypair: Keypair,
}

impl KeeperKey {
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, CovenantError> {
        let sk = SecretKey::from_slice(bytes).map_err(|e| CovenantError::Address(format!("bad keeper key: {e}")))?;
        Ok(Self { keypair: Keypair::from_secret_key(&Secp256k1::new(), &sk) })
    }

    /// The schnorr P2PK address for this key (keeper fee-change, or the customer's).
    pub fn address(&self, prefix: Prefix) -> Address {
        Address::new(prefix, Version::PubKey, &self.keypair.x_only_public_key().0.serialize())
    }

    /// The 32-byte x-only public key.
    pub fn x_only_pubkey(&self) -> [u8; 32] {
        self.keypair.x_only_public_key().0.serialize()
    }

    /// Sign a sighash, returning the 65-byte covenant signature (schnorr +
    /// `SIG_HASH_ALL`). Used by the customer to authorize a release.
    pub fn sign_sighash(&self, sighash: &[u8; 32]) -> Result<Vec<u8>, CovenantError> {
        let msg = Message::from_digest_slice(sighash).map_err(|e| CovenantError::Address(format!("sighash: {e}")))?;
        let mut sig = self.keypair.sign_schnorr(msg).as_ref().to_vec();
        sig.push(SIG_HASH_ALL.to_u8());
        Ok(sig)
    }

    /// Sign a raw 32-byte digest, returning a 64-byte BIP340 schnorr `datasig`
    /// (NO sighash-type byte). This is the juror-vote / attestation signature that
    /// a covenant verifies with `checkSigFromStack(datasig, digest, pubkey)` —
    /// it commits to `digest` directly, not to a transaction sighash.
    pub fn sign_datasig(&self, digest: &[u8; 32]) -> Result<Vec<u8>, CovenantError> {
        let msg = Message::from_digest_slice(digest).map_err(|e| CovenantError::Address(format!("digest: {e}")))?;
        Ok(self.keypair.sign_schnorr(msg).as_ref().to_vec())
    }
}

/// A signed release/refund transaction plus the UTXO entries it spends (needed
/// for local verification and for RPC submission).
pub struct SignedSpend {
    pub transaction: Transaction,
    pub entries: Vec<UtxoEntry>,
}

fn covenant_signature_script(redeem: &[u8], entrypoint_sig: Vec<u8>) -> Result<Vec<u8>, CovenantError> {
    pay_to_script_hash_signature_script_with_flags(
        redeem.to_vec(),
        entrypoint_sig,
        EngineFlags { covenants_enabled: true, ..Default::default() },
    )
    .map_err(|e| CovenantError::Compile(format!("p2sh sigscript: {e}")))
}

/// The fee input's signature script: the fee payer's pushed 65-byte signature.
fn fee_signature_script(fee_sig: &[u8]) -> Result<Vec<u8>, CovenantError> {
    Ok(ScriptBuilder::new()
        .add_data(fee_sig)
        .map_err(|e| CovenantError::Compile(format!("fee sigscript: {e}")))?
        .drain())
}

/// Assemble the two-input spend (covenant input 0 + fee input 1) with BOTH
/// signature scripts still empty, returning the tx, its UTXO entries, and both
/// input sighashes. `SIG_HASH_ALL` excludes signature scripts, so these sighashes
/// are final regardless of the order the two inputs are later signed in — which
/// is what lets the covenant authorizer and the fee payer be different parties
/// signing independently.
///
/// `covenant_sequence` is the covenant input's sequence number: 0 for untimed
/// branches, or the CSV relative lock (in DAA-score delta) for branches gated by
/// `this.age >= N` — OP_CHECKSEQUENCEVERIFY requires the spend's sequence >= N.
fn assemble_unsigned(
    redeem: &[u8],
    outputs: Vec<TransactionOutput>,
    lock_time: u64,
    covenant_utxo: &Utxo,
    covenant_sequence: u64,
    fee_utxo: &Utxo,
    fee_payer_spk: ScriptPublicKey,
) -> (Transaction, Vec<UtxoEntry>, [u8; 32], [u8; 32]) {
    let cov_input = TransactionInput {
        previous_outpoint: TransactionOutpoint {
            transaction_id: TransactionId::from_bytes(covenant_utxo.transaction_id),
            index: covenant_utxo.index,
        },
        signature_script: vec![],
        sequence: covenant_sequence,
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

    let cov_entry = UtxoEntry::new(covenant_utxo.value, pay_to_script_hash_script(redeem), 0, false, None);
    let fee_entry = UtxoEntry::new(fee_utxo.value, fee_payer_spk, 0, false, None);

    let tx = Transaction::new(1, vec![cov_input, fee_input], outputs, lock_time, Default::default(), 0, vec![]);
    let mtx = MutableTransaction::with_entries(tx, vec![cov_entry.clone(), fee_entry.clone()]);

    let reused = SigHashReusedValuesUnsync::new();
    let cov_sighash: [u8; 32] = calc_schnorr_signature_hash(&mtx.as_verifiable(), 0, SIG_HASH_ALL, &reused).as_bytes();
    let fee_sighash: [u8; 32] = calc_schnorr_signature_hash(&mtx.as_verifiable(), 1, SIG_HASH_ALL, &reused).as_bytes();
    (mtx.tx, vec![cov_entry, fee_entry], cov_sighash, fee_sighash)
}

/// Build the transaction with the keeper fee input signed and the covenant input
/// still empty; returns it, its UTXO entries, and the covenant input's sighash
/// (index 0) for whoever must authorize the spend.
fn build_fee_signed_tx(
    redeem: &[u8],
    outputs: Vec<TransactionOutput>,
    lock_time: u64,
    covenant_utxo: &Utxo,
    covenant_sequence: u64,
    fee_utxo: &Utxo,
    keeper: &KeeperKey,
    prefix: Prefix,
) -> Result<(Transaction, Vec<UtxoEntry>, [u8; 32]), CovenantError> {
    let fee_spk = pay_to_address_script(&keeper.address(prefix));
    let (mut tx, entries, cov_sighash, fee_sighash) =
        assemble_unsigned(redeem, outputs, lock_time, covenant_utxo, covenant_sequence, fee_utxo, fee_spk);
    let fee_sig = keeper.sign_sighash(&fee_sighash)?;
    tx.inputs[1].signature_script = fee_signature_script(&fee_sig)?;
    Ok((tx, entries, cov_sighash))
}

fn push_change(outputs: &mut Vec<TransactionOutput>, fee_utxo: &Utxo, miner_fee: u64, fee_payer_address: &Address) {
    if let Some(change) = fee_utxo.value.checked_sub(miner_fee).filter(|c| *c > 0) {
        outputs.push(TransactionOutput { value: change, script_public_key: pay_to_address_script(fee_payer_address), covenant: None });
    }
}

/// The merchant-win release outputs: the ordered payouts plus fee-payer change.
pub(crate) fn merchant_split_outputs(
    payouts: &[Payout],
    fee_utxo: &Utxo,
    miner_fee: u64,
    fee_payer_address: &Address,
) -> Vec<TransactionOutput> {
    let mut outputs: Vec<TransactionOutput> = payouts
        .iter()
        .map(|p| TransactionOutput { value: p.value, script_public_key: p.destination.script_public_key(), covenant: None })
        .collect();
    push_change(&mut outputs, fee_utxo, miner_fee, fee_payer_address);
    outputs
}

/// The customer-refund outputs: the full gross back to the customer plus
/// fee-payer change.
pub(crate) fn customer_refund_outputs(
    customer_refund: &Destination,
    gross_amount: u64,
    fee_utxo: &Utxo,
    miner_fee: u64,
    fee_payer_address: &Address,
) -> Vec<TransactionOutput> {
    let mut outputs = vec![TransactionOutput {
        value: gross_amount,
        script_public_key: customer_refund.script_public_key(),
        covenant: None,
    }];
    push_change(&mut outputs, fee_utxo, miner_fee, fee_payer_address);
    outputs
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// kaspad serializes a `ScriptPublicKey` in JSON as a single hex string:
/// the big-endian u16 version (4 hex chars) concatenated with the script bytes.
fn script_public_key_hex(spk: &ScriptPublicKey) -> String {
    format!("{:04x}{}", spk.version(), to_hex(spk.script()))
}

/// Serialize a signed spend into wRPC `submitTransaction` params
/// (`{ "transaction": RpcTransaction, "allowOrphan": false }`), matching kaspad's
/// camelCase JSON model. Keeps all Kaspa/rusty-kaspa types inside this crate.
pub fn rpc_submit_params(spend: &SignedSpend) -> serde_json::Value {
    let tx = &spend.transaction;
    let inputs: Vec<serde_json::Value> = tx
        .inputs
        .iter()
        .map(|i| {
            serde_json::json!({
                "previousOutpoint": {
                    "transactionId": to_hex(&i.previous_outpoint.transaction_id.as_bytes()),
                    "index": i.previous_outpoint.index,
                },
                "signatureScript": to_hex(&i.signature_script),
                "sequence": i.sequence,
                "sigOpCount": i.compute_commit.sig_op_count().unwrap_or(0),
                "computeBudget": i.compute_commit.compute_budget().unwrap_or(0),
                "verboseData": serde_json::Value::Null,
            })
        })
        .collect();
    let outputs: Vec<serde_json::Value> = tx
        .outputs
        .iter()
        .map(|o| {
            serde_json::json!({
                "value": o.value,
                // kaspad's ScriptPublicKey human-readable form: a hex string of
                // the big-endian u16 version (4 hex chars) followed by the script.
                "scriptPublicKey": script_public_key_hex(&o.script_public_key),
                "verboseData": serde_json::Value::Null,
                "covenant": serde_json::Value::Null,
            })
        })
        .collect();
    serde_json::json!({
        "transaction": {
            "version": tx.version,
            "inputs": inputs,
            "outputs": outputs,
            "lockTime": tx.lock_time,
            "subnetworkId": to_hex(tx.subnetwork_id.as_bytes()),
            "gas": tx.gas,
            "payload": to_hex(&tx.payload),
            // Newer builds (v2.0.1) renamed `mass` -> `storageMass` with a compat
            // shim that accepts either (but requires they match if both present);
            // older Toccata nodes (e.g. 1.2.1-toc.3) still require `mass`. Emit
            // both (equal) so the same payload deserializes on either.
            "mass": 0,
            "storageMass": 0,
            "verboseData": serde_json::Value::Null,
        },
        "allowOrphan": false,
    })
}
