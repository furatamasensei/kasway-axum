//! Small shared helpers.

use chrono::Utc;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Hex-encoded SHA-256 of the input.
pub fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
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
pub fn now_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string()
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
