//! `/internal/payment-ops/kpr1/*` — InternalKpr1PaymentOpsController.
//! `evidence` is a DB read over kpr1_payment_intents (internal-token tier).
//! `status` (SilverScript/TN10 probes) and `conformance` (fixture) are separate.

use crate::auth::InternalToken;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};

#[derive(sqlx::FromRow)]
struct IntentRow {
    intent_id: String,
    invoice_id: i64,
    status: String,
    tx_id: Option<String>,
    canonical_hash: String,
    signature_algorithm: String,
    signature_key_id: String,
    template_id: String,
    template_version: String,
    script_hash: String,
    required_outputs: String,
    verification_status: Option<String>,
    failure_reason: Option<String>,
    metadata: Option<String>,
}

/// `GET /internal/payment-ops/kpr1/intents/:intentId/evidence`
pub async fn evidence(
    _token: InternalToken,
    State(state): State<AppState>,
    Path(intent_id): Path<String>,
) -> AppResult<Json<Value>> {
    let row: IntentRow = sqlx::query_as::<_, IntentRow>(
        "SELECT intent_id, invoice_id, status, tx_id, canonical_hash, signature_algorithm, \
         signature_key_id, template_id, template_version, script_hash, required_outputs, \
         verification_status, failure_reason, metadata FROM kpr1_payment_intents \
         WHERE intent_id = ? OR canonical_hash = ?",
    )
    .bind(&intent_id)
    .bind(&intent_id)
    .fetch_optional(&state.db.pool)
    .await?
    .ok_or_else(|| AppError::commerce(404, "KPR-1 payment intent not found"))?;

    let required_outputs: Value = serde_json::from_str(&row.required_outputs).unwrap_or(json!([]));
    let metadata: Value = row.metadata.as_deref().and_then(|m| serde_json::from_str(m).ok()).unwrap_or(Value::Null);

    Ok(Json(json!({
        "intentId": row.intent_id,
        "invoiceId": row.invoice_id,
        "status": row.status,
        "txId": row.tx_id,
        "canonicalHash": row.canonical_hash,
        "signature": { "alg": row.signature_algorithm, "keyId": row.signature_key_id },
        "template": { "id": row.template_id, "version": row.template_version, "scriptHash": row.script_hash },
        "requiredOutputs": required_outputs,
        "verificationStatus": row.verification_status,
        "failureReason": row.failure_reason,
        "metadata": metadata,
    })))
}
