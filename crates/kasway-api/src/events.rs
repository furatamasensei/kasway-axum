//! Invoice state changes, broadcast to whoever is watching that invoice.
//!
//! The event carries no invoice data — only "this invoice changed". A watcher
//! re-reads the authoritative state from the public checkout endpoint it already
//! uses. That keeps one source of truth, keeps the SSE stream free of anything
//! worth authorizing, and lets the stream fail without breaking correctness: a
//! client that misses an event just falls back to its slow poll.

use serde::Serialize;
use tokio::sync::broadcast;

/// Bounded: a slow subscriber lags and misses events rather than growing the
/// buffer forever. Missing an event is survivable — the client re-reads state.
const CHANNEL_CAPACITY: usize = 256;

#[derive(Clone, Debug, Serialize)]
pub struct InvoiceEvent {
    #[serde(rename = "publicId")]
    pub public_id: String,
    /// The new covenant state, purely so a client can skip a redundant refetch.
    #[serde(rename = "covenantState")]
    pub covenant_state: String,
}

#[derive(Clone, Debug)]
pub struct InvoiceEvents(broadcast::Sender<InvoiceEvent>);

impl Default for InvoiceEvents {
    fn default() -> Self {
        Self::new()
    }
}

impl InvoiceEvents {
    pub fn new() -> Self {
        Self(broadcast::channel(CHANNEL_CAPACITY).0)
    }

    /// Fire-and-forget: no subscribers is the normal case, not an error.
    pub fn publish(&self, public_id: &str, covenant_state: &str) {
        let _ = self.0.send(InvoiceEvent {
            public_id: public_id.to_string(),
            covenant_state: covenant_state.to_string(),
        });
    }

    pub fn subscribe(&self) -> broadcast::Receiver<InvoiceEvent> {
        self.0.subscribe()
    }
}
