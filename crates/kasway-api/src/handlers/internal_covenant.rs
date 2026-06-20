//! `/internal/payment-ops/tocatta/covenants/*` (TN10/assembler) —
//! CovenantTransactionAssembler + Tn10CovenantExecution. In the shipped config
//! (KASPA_TN10_NODE_ENABLED unset, SILVERSCRIPT_RUSTY_KASPA_SDK_PATH empty) these
//! return the faithful deterministic responses: dry-run validates input then fails
//! "SDK not configured"; covenant execution is disabled (status) / not ready
//! (execute). The WASM/native-crate assembly + live TN10 submission are the
//! optional happy path (no Rust reference for the vendored WASM output).

use crate::auth::InternalToken;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::state::AppState;
use crate::util::now_iso;

fn err422(code: &str, message: &str, metadata: Option<Value>) -> Response {
    let mut body = json!({ "code": code, "message": message });
    if let Some(m) = metadata {
        body["metadata"] = m;
    }
    (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
}

fn is_positive_atomic(v: &Value) -> bool {
    let text = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return false,
    };
    text.chars().all(|c| c.is_ascii_digit()) && !text.is_empty() && text.parse::<u128>().map(|n| n > 0).unwrap_or(false)
}

/// `POST /internal/payment-ops/tocatta/covenants/transactions/dry-run`
pub async fn dry_run(_token: InternalToken, Json(body): Json<Value>) -> Response {
    // 1. grossAmount positive
    if !is_positive_atomic(body.get("grossAmount").unwrap_or(&Value::Null)) {
        return err422("INVALID_COVENANT_AMOUNT", "grossAmount must be a positive integer atomic amount", None);
    }
    let artifact = &body["compiledArtifact"];
    let network = body.get("network").and_then(|v| v.as_str()).map(|s| s.trim()).filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| artifact["networkTarget"].as_str().unwrap_or("").to_string());

    // 3. sandbox artifact
    if artifact["sandboxOnly"].as_bool() != Some(true) {
        return err422("NON_SANDBOX_ARTIFACT_REJECTED", "Only sandbox compiled artifacts are accepted for covenant dry-run assembly", None);
    }
    if artifact["networkTarget"].as_str().unwrap_or("") != network {
        return err422("COVENANT_NETWORK_MISMATCH", "Compiled artifact network does not match the dry-run network",
            Some(json!({ "artifactNetwork": artifact["networkTarget"], "dryRunNetwork": network })));
    }
    let has_script = artifact["scriptText"].as_str().map(|s| !s.is_empty()).unwrap_or(false)
        || artifact["scriptBytes"].as_str().map(|s| !s.is_empty()).unwrap_or(false);
    if !has_script {
        return err422("MISSING_COVENANT_SCRIPT_OUTPUT", "Compiled artifact must include script text or script bytes", None);
    }

    // 4. test-only wallet + change address
    let wallet_ref = body["testWalletReference"].as_str().unwrap_or("");
    if !(wallet_ref.starts_with("test:") || wallet_ref.starts_with("tn10-test:")) {
        return err422("PRODUCTION_WALLET_REJECTED", "Covenant dry-run assembly requires an explicit test wallet reference", None);
    }
    let change_addr = body["testChangeAddress"].as_str().unwrap_or("").trim();
    if !change_addr.starts_with("kaspatest:") {
        return err422("PRODUCTION_ADDRESS_REJECTED", "testChangeAddress must be a kaspatest address", None);
    }

    // 5. destinations → expectedOutputs
    let destinations = body["destinations"].as_array().cloned().unwrap_or_default();
    for d in &destinations {
        let dest = d["destination"].as_str().unwrap_or("").trim();
        if !dest.starts_with("kaspatest:") {
            return err422("PRODUCTION_ADDRESS_REJECTED", "destination must be a kaspatest address", None);
        }
        if !is_positive_atomic(d.get("amount").unwrap_or(&Value::Null)) {
            return err422("INVALID_COVENANT_AMOUNT", "destination.amount must be a positive integer atomic amount", None);
        }
    }
    // 6. at least one output
    if destinations.is_empty() {
        return err422("MISSING_COVENANT_OUTPUTS", "At least one expected output is required for covenant dry-run assembly", None);
    }

    // 7. assembleUnsignedPayload — no Rusty Kaspa WASM SDK configured
    err422("RUSTY_KASPA_WASM_SDK_NOT_CONFIGURED", "Pinned Rusty Kaspa WASM SDK path is required for covenant dry-run assembly", None)
}

/// `GET /internal/payment-ops/tocatta/covenants/tn10/status`
pub async fn tn10_status(_token: InternalToken) -> Json<Value> {
    Json(json!({
        "enabled": false,
        "ready": false,
        "generatedAt": now_iso(),
        "checks": [{
            "key": "tn10CovenantExecution.enabled",
            "status": "fail",
            "message": "Controlled TN10 covenant execution is disabled by default",
        }],
        "tn10NodeStatus": Value::Null,
        "silverScriptCompatibility": Value::Null,
    }))
}

fn execution_not_ready() -> Response {
    err422(
        "TN10_COVENANT_EXECUTION_NOT_READY",
        "Controlled TN10 covenant execution is not ready",
        Some(json!({ "failedChecks": ["tn10CovenantExecution.enabled"] })),
    )
}

/// `POST /internal/payment-ops/tocatta/covenants/tn10/split-executions`
pub async fn execute_split(_token: InternalToken, State(_state): State<AppState>, Json(_body): Json<Value>) -> Response {
    execution_not_ready()
}

/// `POST /internal/payment-ops/tocatta/covenants/tn10/hold-release-executions`
pub async fn execute_hold_release(_token: InternalToken, State(_state): State<AppState>, Json(_body): Json<Value>) -> Response {
    execution_not_ready()
}
