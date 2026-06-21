//! `/internal/payment-ops/tocatta/silverscript/templates` (index) —
//! InternalSilverScriptTemplatesController.index → static SilverScript template
//! catalog (internal-token tier). `show`/`compile` need the WASM compiler (external).

use crate::auth::InternalToken;
use crate::util::now_iso;
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SPLIT_SETTLEMENT_SRC: &str = r#"
pragma silverscript ^0.1.0;

contract SplitSettlement(int grossAmount, int taxBps, int splitBps, int platformFeeBps) {
  entrypoint function spend() {
    require(grossAmount > 0);
    require(taxBps >= 0);
    require(splitBps >= 0);
    require(platformFeeBps >= 0);
    require(taxBps + splitBps + platformFeeBps <= 10000);

    int taxAmount = grossAmount * taxBps / 10000;
    int splitAmount = grossAmount * splitBps / 10000;
    int platformFeeAmount = grossAmount * platformFeeBps / 10000;
    int merchantNet = grossAmount - taxAmount - splitAmount - platformFeeAmount;

    require(merchantNet > 0);
    require(tx.outputs[0].value >= merchantNet);
  }
}
"#;

const REFUND_WINDOW_SRC: &str = r#"
template refund_window(gross_amount, hold_reason, timeout_seconds, responsible_actor) {
  require(gross_amount > 0)
  require(timeout_seconds > 0)
  require(responsible_actor in ["merchant", "support", "system"])
  hold gross_amount with reason hold_reason
  release to merchant when responsible_actor approves before timeout_seconds
  refund to wallet_refund_address after timeout_seconds
}
"#;

const CONDITIONAL_RELEASE_SRC: &str = r#"
template conditional_release(gross_amount, release_condition, responsible_actor) {
  require(gross_amount > 0)
  require(release_condition in ["timeout", "merchant_confirmed", "support_approved"])
  require(responsible_actor in ["merchant", "support", "system"])
  hold gross_amount until release_condition
  release to merchant when responsible_actor satisfies release_condition
}
"#;

fn sha256_hex(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}

fn template(id: &str, title: &str, use_case: &str, src_raw: &str, schema: Value) -> Value {
    let source = src_raw.trim();
    let hash = sha256_hex(source);
    json!({
        "id": id,
        "version": "v1",
        "title": title,
        "status": "active",
        "useCase": use_case,
        "source": source,
        "sourceHash": hash,
        "approvedSourceHash": hash,
        "argumentSchema": schema,
        "warnings": [],
    })
}

/// `GET /internal/payment-ops/tocatta/silverscript/templates`
pub async fn index(_token: InternalToken) -> Json<Value> {
    let templates = json!([
        template("split_settlement", "Split Settlement", "split", SPLIT_SETTLEMENT_SRC, json!([
            { "name": "grossAmount", "kind": "atomic_amount", "required": true },
            { "name": "taxBps", "kind": "basis_points", "required": true },
            { "name": "splitBps", "kind": "basis_points", "required": true },
            { "name": "platformFeeBps", "kind": "basis_points", "required": true },
            { "name": "merchantDestination", "kind": "address", "required": true },
            { "name": "taxDestination", "kind": "address", "required": false },
            { "name": "platformFeeDestination", "kind": "address", "required": false },
        ])),
        template("refund_window", "Refund Window", "refund", REFUND_WINDOW_SRC, json!([
            { "name": "grossAmount", "kind": "atomic_amount", "required": true },
            { "name": "holdReason", "kind": "text", "required": true },
            { "name": "timeoutSeconds", "kind": "seconds", "required": true },
            { "name": "responsibleActor", "kind": "enum", "required": true, "allowedValues": ["merchant", "support", "system"] },
        ])),
        template("conditional_release", "Conditional Release", "release", CONDITIONAL_RELEASE_SRC, json!([
            { "name": "grossAmount", "kind": "atomic_amount", "required": true },
            { "name": "releaseCondition", "kind": "enum", "required": true, "allowedValues": ["timeout", "merchant_confirmed", "support_approved"] },
            { "name": "responsibleActor", "kind": "enum", "required": true, "allowedValues": ["merchant", "support", "system"] },
        ])),
    ]);
    Json(json!({
        "sandboxOnly": true,
        "freeFormScriptsAccepted": false,
        "generatedAt": now_iso(),
        "templates": templates,
    }))
}

/// `GET /internal/payment-ops/tocatta/silverscript/status` —
/// SilverScriptCompatibilityService.getStatus(). Disabled in the shipped config
/// (SILVERSCRIPT_COMPATIBILITY_ENABLED unset) → static disabled report.
pub async fn status(_token: InternalToken) -> Json<Value> {
    let now = now_iso();
    Json(json!({
        "status": "disabled",
        "ready": false,
        "compatibilityOutcome": "blocked",
        "targetNetwork": "tn10",
        "generatedAt": now,
        "sourceCheckedAt": now,
        "checks": [{ "key": "silverscript.enabled", "status": "fail", "message": "SilverScript status is disabled by default" }],
        "tn10NodeStatus": Value::Null,
        "metadata": {
            "enabled": false, "repoPath": Value::Null, "compilerCommand": Value::Null, "compilerCommit": Value::Null,
            "expectedNetwork": "tn10", "rustyKaspaSdkPath": Value::Null, "rustyKaspaSdkSha256": Value::Null, "rustyKaspaCommit": Value::Null,
        },
    }))
}

// ---- compile (#13) ---------------------------------------------------------

use crate::error::AppResult;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

// (name, kind, required, allowed_values)
fn schema_for(id: &str) -> Option<Vec<(&'static str, &'static str, bool, &'static [&'static str])>> {
    let empty: &[&str] = &[];
    match id {
        "split_settlement" => Some(vec![
            ("grossAmount", "atomic_amount", true, empty),
            ("taxBps", "basis_points", true, empty),
            ("splitBps", "basis_points", true, empty),
            ("platformFeeBps", "basis_points", true, empty),
            ("merchantDestination", "address", true, empty),
            ("taxDestination", "address", false, empty),
            ("platformFeeDestination", "address", false, empty),
        ]),
        "refund_window" => Some(vec![
            ("grossAmount", "atomic_amount", true, empty),
            ("holdReason", "text", true, empty),
            ("timeoutSeconds", "seconds", true, empty),
            ("responsibleActor", "enum", true, &["merchant", "support", "system"]),
        ]),
        "conditional_release" => Some(vec![
            ("grossAmount", "atomic_amount", true, empty),
            ("releaseCondition", "enum", true, &["timeout", "merchant_confirmed", "support_approved"]),
            ("responsibleActor", "enum", true, &["merchant", "support", "system"]),
        ]),
        _ => None,
    }
}

fn compiler_err(code: &str, message: String, metadata: Option<Value>) -> Response {
    let mut body = json!({ "code": code, "message": message });
    if let Some(m) = metadata { body["metadata"] = m; }
    (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
}

fn is_empty_arg(v: &Value) -> bool {
    matches!(v, Value::Null) || matches!(v, Value::String(s) if s.is_empty())
}

fn validate_value(id: &str, name: &str, kind: &str, allowed: &[&str], v: &Value) -> Result<(), Response> {
    let positive_int = |val: &Value| -> bool {
        let t = match val { Value::String(s) => s.clone(), Value::Number(n) => n.to_string(), _ => return false };
        !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()) && t.parse::<u128>().map(|n| n > 0).unwrap_or(false)
    };
    match kind {
        "atomic_amount" | "seconds" => {
            if !positive_int(v) {
                return Err(compiler_err("INVALID_SILVERSCRIPT_ARGUMENT", format!("{name} must be a positive integer"), None));
            }
        }
        "basis_points" => {
            let n = match v { Value::Number(n) => n.as_i64(), Value::String(s) => s.parse::<i64>().ok(), _ => None };
            match n { Some(b) if (0..=10000).contains(&b) => {}, _ => return Err(compiler_err("INVALID_SILVERSCRIPT_ARGUMENT", format!("{name} must be an integer between 0 and 10000"), None)) }
        }
        "address" | "text" => {
            match v { Value::String(s) if !s.trim().is_empty() => {}, _ => return Err(compiler_err("INVALID_SILVERSCRIPT_ARGUMENT", format!("{name} must be a non-empty string"), None)) }
        }
        "enum" => {
            let sv = match v { Value::String(s) => s.clone(), other => other.to_string() };
            if !allowed.contains(&sv.as_str()) {
                return Err(compiler_err("INVALID_SILVERSCRIPT_ARGUMENT", format!("{name} is not supported by {id}"), None));
            }
        }
        _ => {}
    }
    Ok(())
}

/// `POST /internal/payment-ops/tocatta/silverscript/templates/:id/compile`
pub async fn compile(_token: InternalToken, Path(id): Path<String>, Json(body): Json<Value>) -> AppResult<Response> {
    let schema = match schema_for(&id) {
        Some(s) => s,
        None => return Ok(compiler_err("UNSUPPORTED_SILVERSCRIPT_TEMPLATE", "Only allowlisted Kasway SilverScript templates can be compiled".into(), None)),
    };
    let args = body.get("args").cloned().unwrap_or(json!({}));
    let args_obj = args.as_object().cloned().unwrap_or_default();
    let allowed_names: Vec<&str> = schema.iter().map(|(n, ..)| *n).collect();

    // unknown argument names
    for key in args_obj.keys() {
        if !allowed_names.contains(&key.as_str()) {
            return Ok(compiler_err("UNSUPPORTED_SILVERSCRIPT_ARGUMENT", format!("{key} is not supported by {id}"), None));
        }
    }
    // required + per-kind validation
    for (name, kind, required, allowed) in &schema {
        let val = args_obj.get(*name);
        let present = val.map(|v| !is_empty_arg(v)).unwrap_or(false);
        if *required && !present {
            return Ok(compiler_err("MISSING_SILVERSCRIPT_ARGUMENT", format!("{name} is required"), None));
        }
        if present {
            if let Err(resp) = validate_value(&id, name, kind, allowed, val.unwrap()) {
                return Ok(resp);
            }
        }
    }

    // compiler unavailable in the shipped config (SilverScript status disabled → metadata missing)
    Ok(compiler_err("SILVERSCRIPT_STATUS_METADATA_MISSING", "compilerCommand is missing from SilverScript status metadata".into(), None))
}
