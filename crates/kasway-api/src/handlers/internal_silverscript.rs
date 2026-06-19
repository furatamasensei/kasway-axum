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
