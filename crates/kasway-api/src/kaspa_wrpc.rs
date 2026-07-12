//! Thin JSON-RPC-over-websocket client for a Kaspa node's **wRPC JSON**
//! endpoint — the production [`ChainSource`] implementation.
//!
//! ## Endpoint / encoding
//!
//! `KASPA_NODE_URL` must point at a kaspad (rusty-kaspa) websocket listener
//! running the **JSON** protocol encoding (NOT Borsh), e.g. `ws://<ip>:17210`
//! for a TN10 node started with `--rpclisten-json=0.0.0.0:17210`. By default
//! rusty-kaspa serves wRPC JSON on 18110 (mainnet) / 18210 (testnet-10) and
//! wRPC Borsh on 17110 / 17210 — deployments often remap, so always configure
//! the full `ws://host:port` URL of the JSON listener.
//!
//! ## Wire format
//!
//! wRPC JSON framing (workflow-rpc `serde_json` protocol; similar to JSON-RPC
//! 1.0 but with server-side notifications):
//!
//! - request:  `{"id": <u64>, "method": "<camelCaseOp>", "params": {...}}`
//! - response: `{"id": <same u64>, "method": "...", "params": <result>}` on
//!   success, or `{"id": ..., "error": {"code", "message", "data"}}`
//! - notifications carry no `id` and are ignored here.
//!
//! ## RPC methods used
//!
//! - `getBlockDagInfo` → `virtualDaaScore` (confirmations reference point).
//! - `getUtxosByAddresses` → UTXO entries for the intent's required output
//!   addresses; entries whose `outpoint.transactionId` equals the submitted
//!   txid prove the transaction was accepted and give each output's address,
//!   amount (sompi) and `utxoEntry.blockDaaScore` (accepted DAA score).
//!
//! This deliberately avoids a `getTransactionsByAddresses`-style call (not
//! part of the node RPC) and the full rusty-kaspa crate stack. Limitation:
//! if a payment UTXO is spent again before the observer sees it, the lookup
//! no longer returns it — acceptable for the confirmation window this slice
//! targets, and superseded by the address-watching phase.
//!
//! One websocket connection is dialed per call (the observer polls every few
//! seconds; connection reuse is not worth the reconnect bookkeeping yet).

use crate::chain_source::{ChainSource, ChainSourceError, ObservedOutput, ObservedTransaction};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio_tungstenite::tungstenite::Message;

/// Per-request timeout (dial + roundtrip), seconds. Generous to tolerate an
/// intermittently slow public TN10 node.
const REQUEST_TIMEOUT_SECS: u64 = 30;

pub struct KaspaWrpcClient {
    url: String,
    next_id: AtomicU64,
}

impl KaspaWrpcClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into(), next_id: AtomicU64::new(1) }
    }

    /// Build from `KASPA_NODE_URL`; `None` when unset/empty.
    pub fn from_env() -> Option<Self> {
        std::env::var("KASPA_NODE_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(Self::new)
    }

    /// One JSON-RPC call over a fresh websocket connection: send the request,
    /// skip notifications, return the matching response's `params` payload.
    async fn call(&self, method: &str, params: Value) -> Result<Value, ChainSourceError> {
        let fut = async {
            let (mut ws, _) = tokio_tungstenite::connect_async(&self.url)
                .await
                .map_err(|e| ChainSourceError::Transport(format!("connect {}: {e}", self.url)))?;

            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let request = json!({ "id": id, "method": method, "params": params });
            ws.send(Message::Text(request.to_string()))
                .await
                .map_err(|e| ChainSourceError::Transport(format!("send {method}: {e}")))?;

            let result = loop {
                let msg = match ws.next().await {
                    Some(Ok(m)) => m,
                    Some(Err(e)) => {
                        return Err(ChainSourceError::Transport(format!("recv {method}: {e}")))
                    }
                    None => {
                        return Err(ChainSourceError::Transport(format!(
                            "connection closed before {method} response"
                        )))
                    }
                };
                let text = match msg {
                    Message::Text(t) => t,
                    Message::Binary(b) => String::from_utf8_lossy(&b).into_owned(),
                    Message::Close(_) => {
                        return Err(ChainSourceError::Transport(format!(
                            "connection closed before {method} response"
                        )))
                    }
                    _ => continue, // ping/pong/frame
                };
                let value: Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                // Notifications have no id; unrelated responses a different one.
                if value.get("id").and_then(Value::as_u64) != Some(id) {
                    continue;
                }
                if let Some(err) = value.get("error").filter(|e| !e.is_null()) {
                    return Err(ChainSourceError::Protocol(format!("{method} failed: {err}")));
                }
                break value.get("params").cloned().unwrap_or(Value::Null);
            };
            let _ = ws.close(None).await;
            Ok(result)
        };

        tokio::time::timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS), fut)
            .await
            .map_err(|_| ChainSourceError::Transport(format!("{method} timed out")))?
    }

    /// Fetch spendable UTXOs for one address as `(transaction_id, index, amount)`.
    /// Used by the covenant keeper to locate the covenant funding UTXO and a
    /// keeper-owned fee UTXO.
    pub async fn fetch_utxos(&self, address: &str) -> Result<Vec<([u8; 32], u32, u64)>, ChainSourceError> {
        let response = self.call("getUtxosByAddresses", json!({ "addresses": [address] })).await?;
        let entries = response
            .get("entries")
            .and_then(Value::as_array)
            .ok_or_else(|| ChainSourceError::Protocol("getUtxosByAddresses response missing entries".into()))?;
        let mut utxos = Vec::new();
        for entry in entries {
            let outpoint = entry.get("outpoint");
            let txid_hex = outpoint.and_then(|o| o.get("transactionId")).and_then(Value::as_str).unwrap_or("");
            let index = outpoint.and_then(|o| o.get("index")).and_then(as_u64_lenient).unwrap_or(0) as u32;
            let amount = entry.get("utxoEntry").and_then(|u| u.get("amount")).and_then(as_u64_lenient).unwrap_or(0);
            let Some(txid) = hex32(txid_hex) else { continue };
            if amount == 0 {
                continue;
            }
            utxos.push((txid, index, amount));
        }
        Ok(utxos)
    }

    /// Raw wRPC call (debug/calibration): returns the method's `params` payload.
    pub async fn raw_call(&self, method: &str, params: Value) -> Result<Value, ChainSourceError> {
        self.call(method, params).await
    }

    /// Submit a fully-signed transaction (params already in kaspad's
    /// `submitTransaction` shape); returns its transaction id.
    pub async fn submit_transaction(&self, params: Value) -> Result<String, ChainSourceError> {
        let response = self.call("submitTransaction", params).await?;
        response
            .get("transactionId")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| ChainSourceError::Protocol(format!("submitTransaction response missing transactionId: {response}")))
    }
}

/// Decode a 64-char hex string into 32 bytes.
fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// u64 that may arrive as a JSON number or a decimal string.
fn as_u64_lenient(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

impl ChainSource for KaspaWrpcClient {
    async fn transaction_outputs(
        &self,
        tx_id: &str,
        addresses: &[String],
    ) -> Result<Option<ObservedTransaction>, ChainSourceError> {
        let response = self
            .call("getUtxosByAddresses", json!({ "addresses": addresses }))
            .await?;
        let entries = response
            .get("entries")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                ChainSourceError::Protocol("getUtxosByAddresses response missing entries".into())
            })?;

        let mut outputs = Vec::new();
        let mut accepting_daa_score: Option<u64> = None;
        for entry in entries {
            let entry_tx = entry
                .get("outpoint")
                .and_then(|o| o.get("transactionId"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if !entry_tx.eq_ignore_ascii_case(tx_id) {
                continue;
            }
            let address = entry.get("address").and_then(Value::as_str).unwrap_or("");
            let utxo = entry.get("utxoEntry").cloned().unwrap_or(Value::Null);
            let amount = utxo.get("amount").and_then(as_u64_lenient).unwrap_or(0);
            if address.is_empty() || amount == 0 {
                continue;
            }
            if let Some(daa) = utxo.get("blockDaaScore").and_then(as_u64_lenient) {
                accepting_daa_score =
                    Some(accepting_daa_score.map_or(daa, |cur| cur.min(daa)));
            }
            outputs.push(ObservedOutput { address: address.to_string(), amount_sompi: amount });
        }

        if outputs.is_empty() {
            return Ok(None);
        }
        Ok(Some(ObservedTransaction {
            tx_id: tx_id.to_string(),
            outputs,
            accepting_daa_score,
        }))
    }

    async fn virtual_daa_score(&self) -> Result<u64, ChainSourceError> {
        let info = self.call("getBlockDagInfo", json!({})).await?;
        info.get("virtualDaaScore")
            .and_then(as_u64_lenient)
            .ok_or_else(|| {
                ChainSourceError::Protocol(
                    "getBlockDagInfo response missing virtualDaaScore".into(),
                )
            })
    }
}
