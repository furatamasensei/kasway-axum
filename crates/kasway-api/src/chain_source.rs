//! `ChainSource` — the minimal abstraction over a Kaspa node that the chain
//! observer needs for this slice (txid-driven verification of wallet-submitted
//! KPR-1 payments):
//!
//! - look up a submitted transaction's outputs to a known set of addresses
//!   (the intent's required output addresses), including the DAA score at
//!   which the transaction was accepted, and
//! - read the current virtual DAA score, so confirmations can be computed as
//!   `virtual_daa_score - accepting_daa_score`.
//!
//! The production implementation is [`crate::kaspa_wrpc::KaspaWrpcClient`];
//! tests drive the observer with an in-memory implementation.

/// One transaction output observed on chain (address + amount in sompi).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedOutput {
    pub address: String,
    pub amount_sompi: u64,
}

/// On-chain facts about a submitted transaction, restricted to the watched
/// addresses that were passed to [`ChainSource::transaction_outputs`].
#[derive(Clone, Debug)]
pub struct ObservedTransaction {
    pub tx_id: String,
    /// Outputs of the transaction paying any of the watched addresses.
    pub outputs: Vec<ObservedOutput>,
    /// DAA score at which the transaction was accepted; `None` while it is
    /// only in the mempool (0 confirmations).
    pub accepting_daa_score: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChainSourceError {
    /// Connection/IO problem talking to the node.
    #[error("chain source transport error: {0}")]
    Transport(String),
    /// The node answered, but not in the shape we expect.
    #[error("chain source protocol error: {0}")]
    Protocol(String),
}

/// Minimal node abstraction for the chain observer. Kept deliberately small:
/// this slice only verifies wallet-submitted txids against intent outputs and
/// tracks confirmations — no address watching / streaming yet.
pub trait ChainSource: Send + Sync {
    /// Look up transaction `tx_id`'s outputs paying any of `addresses`.
    /// Returns `Ok(None)` when the transaction is not (yet) visible on chain.
    fn transaction_outputs(
        &self,
        tx_id: &str,
        addresses: &[String],
    ) -> impl std::future::Future<Output = Result<Option<ObservedTransaction>, ChainSourceError>> + Send;

    /// Current virtual DAA score (confirmations reference point).
    fn virtual_daa_score(
        &self,
    ) -> impl std::future::Future<Output = Result<u64, ChainSourceError>> + Send;
}
