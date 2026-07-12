//! Small shared helpers.

use chrono::{DateTime, Utc};
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Hex-encoded SHA-256 of the input.
pub fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    encode_hex(&hasher.finalize())
}

/// Lowercase hex encoding.
pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode an even-length hex string. Returns `None` on any malformed input.
pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()).collect()
}

/// Decode a 64-char hex string into a fixed 32-byte array. Returns `None` on
/// any malformed input.
pub fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// `n` cryptographically random bytes, hex-encoded (`2n` chars).
pub fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    encode_hex(&b)
}

/// TEXT column holding JSON -> `Value`; `Null` when absent or unparseable.
pub fn json_or_null(raw: &Option<String>) -> Value {
    match raw {
        None => Value::Null,
        Some(s) => serde_json::from_str(s).unwrap_or(Value::Null),
    }
}

/// VineJS `^(0|[1-9]\d*)$` — a non-negative decimal integer with no leading zeros.
pub fn is_atomic_amount(s: &str) -> bool {
    s == "0" || (!s.is_empty() && !s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit()))
}

/// Build a Lucid `SimplePaginator` `meta` object (same keys/order/URLs).
pub fn paginator_meta(total: i64, per_page: i64, current_page: i64) -> Value {
    let last_page = std::cmp::max(((total as f64) / (per_page as f64)).ceil() as i64, 1);
    json!({
        "total": total,
        "perPage": per_page,
        "currentPage": current_page,
        "lastPage": last_page,
        "firstPage": 1,
        "firstPageUrl": "/?page=1",
        "lastPageUrl": format!("/?page={last_page}"),
        "nextPageUrl": if current_page < last_page {
            Value::String(format!("/?page={}", current_page + 1))
        } else {
            Value::Null
        },
        "previousPageUrl": if current_page > 1 {
            Value::String(format!("/?page={}", current_page - 1))
        } else {
            Value::Null
        },
    })
}

/// ISO8601 with milliseconds + explicit UTC offset, matching luxon's `toISO()`
/// shape used by Lucid's `autoCreate`/`autoUpdate` timestamps.
pub fn to_iso(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string()
}

/// [`to_iso`] of the current time.
pub fn now_iso() -> String {
    to_iso(Utc::now())
}

/// Process-wide HTTP client, so call sites reuse one connection pool instead
/// of paying a fresh TLS/pool setup per request. (Webhook deliveries build
/// their own IP-pinned clients in `webhook_worker` and must not use this.)
pub fn http_client() -> &'static reqwest::Client {
    static HTTP: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    HTTP.get_or_init(reqwest::Client::new)
}

/// Length-aware constant-time byte comparison.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
