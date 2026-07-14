//! Per-IP rate limit for the public, unauthenticated surface.
//!
//! The checkout endpoints are keyed only by a 128-bit invoice id — that id IS the
//! capability, and it is meant to be handed to a stranger with a QR code. So they
//! cannot be put behind auth, which leaves one lever: cost. This bounds how fast
//! any single IP can hammer them.
//!
//! ponytail: fixed window, not a sliding one. A caller can spend its whole budget
//! at the end of one window and again at the start of the next, so the real worst
//! case is 2x the limit over a window boundary. That is fine for "stop someone
//! scraping" — swap in `tower_governor` (GCRA) if the burst ever matters.

use axum::extract::{ConnectInfo, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW_LEN: Duration = Duration::from_secs(60);
/// Requests per IP per window. A wallet watching a payment does a handful; a
/// scraper does thousands.
const MAX_PER_WINDOW: u32 = 120;

struct Window {
    started: Instant,
    hits: HashMap<String, u32>,
}

/// The whole map is dropped every window, so memory cannot grow without bound —
/// no eviction policy, no LRU, nothing to tune.
static WINDOW: Mutex<Option<Window>> = Mutex::new(None);

/// Caller IP. Behind a proxy the socket address is the proxy, so trust the
/// forwarded headers first — the deployment (Fly) sets them and does not let a
/// client forge them.
fn client_ip(req: &Request) -> String {
    let headers = req.headers();
    for header in ["fly-client-ip", "x-forwarded-for"] {
        if let Some(value) = headers.get(header).and_then(|v| v.to_str().ok()) {
            if let Some(first) = value.split(',').next() {
                let ip = first.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// True when this IP has already spent its budget for the current window.
fn over_limit(ip: &str) -> bool {
    let mut guard = WINDOW.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();
    let window = guard.get_or_insert_with(|| Window { started: now, hits: HashMap::new() });
    if now.duration_since(window.started) >= WINDOW_LEN {
        window.started = now;
        window.hits.clear();
    }
    let hits = window.hits.entry(ip.to_string()).or_insert(0);
    *hits += 1;
    *hits > MAX_PER_WINDOW
}

pub async fn limit(req: Request, next: Next) -> Response {
    let ip = client_ip(&req);
    if over_limit(&ip) {
        tracing::warn!("rate limit: {ip} exceeded {MAX_PER_WINDOW} requests/min on the public API");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "message": "Too many requests. Slow down and try again shortly." })),
        )
            .into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::{over_limit, MAX_PER_WINDOW};

    #[test]
    fn blocks_only_after_the_budget_is_spent() {
        let ip = "test-ip-1";
        for i in 1..=MAX_PER_WINDOW {
            assert!(!over_limit(ip), "request {i} should pass");
        }
        assert!(over_limit(ip), "the request past the budget must be refused");
    }

    #[test]
    fn one_ip_cannot_spend_another_ip_budget() {
        let noisy = "test-ip-2";
        for _ in 0..=MAX_PER_WINDOW {
            over_limit(noisy);
        }
        assert!(over_limit(noisy));
        // A different caller is untouched by the noisy one.
        assert!(!over_limit("test-ip-3"));
    }
}
