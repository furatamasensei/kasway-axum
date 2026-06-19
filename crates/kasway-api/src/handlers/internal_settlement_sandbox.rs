//! `/internal/payment-ops/tocatta/sandbox/*` — InternalProgrammableSettlementSandboxController.
//! All actions retired → 410 Gone (internal-token tier).

use crate::auth::InternalToken;
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

fn retired() -> (StatusCode, Json<Value>) {
    (
        StatusCode::GONE,
        Json(json!({
            "message": "Programmable settlement sandbox has been retired. Use active pinned SilverScript templates, KPR-1 intent evidence, and controlled TN10 covenant execution status instead.",
            "code": "PROGRAMMABLE_SETTLEMENT_SANDBOX_RETIRED",
            "replacement": {
                "silverscriptTemplates": "/internal/payment-ops/tocatta/silverscript/templates",
                "kpr1Status": "/internal/payment-ops/kpr1/status",
                "kpr1Conformance": "/internal/payment-ops/kpr1/conformance",
            },
        })),
    )
}

pub async fn overview(_token: InternalToken) -> (StatusCode, Json<Value>) { retired() }
pub async fn split_preview(_token: InternalToken) -> (StatusCode, Json<Value>) { retired() }
pub async fn hold_preview(_token: InternalToken) -> (StatusCode, Json<Value>) { retired() }
pub async fn promotion_gates(_token: InternalToken) -> (StatusCode, Json<Value>) { retired() }
