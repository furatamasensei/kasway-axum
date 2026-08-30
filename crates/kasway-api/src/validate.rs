//! Shared request-body validation helpers used by the invoices, payment-links
//! and subscriptions handlers.

use crate::error::ValidationFailure;
use crate::util::is_atomic_amount;
use serde_json::Value;

pub(crate) fn vpush(errors: &mut Vec<ValidationFailure>, field: &str, rule: &str, message: &str) {
    errors.push(ValidationFailure::new(field, rule, message));
}

/// Optional trimmed non-empty string field.
pub(crate) fn opt_string(body: &Value, key: &str) -> Option<String> {
    body.get(key).and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Required trimmed string with a length range; pushes a `required` failure otherwise.
pub(crate) fn req_string(body: &Value, key: &str, min: usize, max: usize, errors: &mut Vec<ValidationFailure>) -> Option<String> {
    match body.get(key).and_then(|v| v.as_str()) {
        Some(s) if s.trim().chars().count() >= min && s.trim().chars().count() <= max => Some(s.trim().to_string()),
        _ => { vpush(errors, key, "required", &format!("The {key} field is required")); None }
    }
}

/// Required atomic-amount string; pushes a `regex` failure otherwise.
pub(crate) fn atomic_amount(body: &Value, key: &str, errors: &mut Vec<ValidationFailure>) -> Option<String> {
    match body.get(key) {
        Some(Value::String(s)) if is_atomic_amount(s) => Some(s.clone()),
        _ => { vpush(errors, key, "regex", &format!("The {key} field format is invalid")); None }
    }
}

/// Parse an already-format-validated atomic string, enforcing the i64 range so
/// an over-range value can't silently become a free (0) amount via `as i64`.
pub(crate) fn parse_atomic_i64(s: &str) -> Option<i64> {
    s.parse::<i128>().ok().filter(|v| *v <= i64::MAX as i128).map(|v| v as i64)
}

/// Required integer within `min..=max`; pushes a `range` failure otherwise.
pub(crate) fn req_int(body: &Value, key: &str, min: i64, max: i64, errors: &mut Vec<ValidationFailure>) -> Option<i64> {
    match body.get(key).and_then(|v| v.as_i64()) {
        Some(n) if n >= min && n <= max => Some(n),
        _ => { vpush(errors, key, "range", &format!("The {key} field is invalid")); None }
    }
}

/// Enum membership check; pushes an `enum` failure on mismatch (or on absence
/// when `required`).
pub(crate) fn validate_enum(body: &Value, key: &str, allowed: &[&str], required: bool, errors: &mut Vec<ValidationFailure>) {
    match body.get(key).and_then(|v| v.as_str()) {
        Some(s) if allowed.contains(&s) => {}
        None if !required => {}
        _ => vpush(errors, key, "enum", &format!("The selected {key} is invalid")),
    }
}
