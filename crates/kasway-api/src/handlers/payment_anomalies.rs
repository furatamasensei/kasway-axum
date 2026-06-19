//! `/api/payments/ops/anomalies` — PaymentAnomaliesController.
//! CRUD-ish over anomaly signals (detection engine itself is a background job).

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::util::{now_iso, paginator_meta};
use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize, Default)]
pub struct AnomQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
    #[serde(rename = "type")]
    signal_type: Option<String>,
    status: Option<String>,
    severity: Option<String>,
    #[serde(rename = "resourceType")]
    resource_type: Option<String>,
}

#[derive(sqlx::FromRow)]
struct SignalRow {
    id: i64,
    user_id: i64,
    signal_type: String,
    severity: String,
    status: String,
    resource_type: String,
    resource_id: String,
    detected_at: String,
    window_start: String,
    window_end: String,
    score: Option<i64>,
    reason: String,
    metadata: String,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const SIGNAL_COLS: &str = "id, user_id, signal_type, severity, status, resource_type, resource_id, \
    detected_at, window_start, window_end, score, reason, metadata, created_at, updated_at";

fn serialize_signal(s: &SignalRow) -> Value {
    json!({
        "id": s.id,
        "userId": s.user_id,
        "signalType": s.signal_type,
        "severity": s.severity,
        "status": s.status,
        "resourceType": s.resource_type,
        "resourceId": s.resource_id,
        "detectedAt": s.detected_at,
        "windowStart": s.window_start,
        "windowEnd": s.window_end,
        "score": s.score,
        "reason": s.reason,
        "metadata": serde_json::from_str::<Value>(&s.metadata).unwrap_or(json!({})),
        "createdAt": s.created_at,
        "updatedAt": s.updated_at,
    })
}

async fn load_signal(state: &AppState, user_id: i64, id: i64) -> AppResult<SignalRow> {
    sqlx::query_as::<_, SignalRow>(&format!("SELECT {SIGNAL_COLS} FROM payment_anomaly_signals WHERE user_id = ? AND id = ?"))
        .bind(user_id).bind(id).fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::commerce(404, "Payment anomaly signal not found"))
}

/// `GET /api/payments/ops/anomalies`
pub async fn index(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<AnomQuery>) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).max(1);

    let mut filter = String::from("user_id = ?");
    if q.signal_type.is_some() { filter.push_str(" AND signal_type = ?"); }
    if q.status.is_some() { filter.push_str(" AND status = ?"); }
    if q.severity.is_some() { filter.push_str(" AND severity = ?"); }
    if q.resource_type.is_some() { filter.push_str(" AND resource_type = ?"); }

    let count_sql = format!("SELECT COUNT(*) FROM payment_anomaly_signals WHERE {filter}");
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql).bind(auth.user_id);
    if let Some(v) = &q.signal_type { cq = cq.bind(v.clone()); }
    if let Some(v) = &q.status { cq = cq.bind(v.clone()); }
    if let Some(v) = &q.severity { cq = cq.bind(v.clone()); }
    if let Some(v) = &q.resource_type { cq = cq.bind(v.clone()); }
    let total = cq.fetch_one(&state.db.pool).await?;

    let list_sql = format!("SELECT {SIGNAL_COLS} FROM payment_anomaly_signals WHERE {filter} ORDER BY detected_at DESC LIMIT {per_page} OFFSET {}", (page - 1) * per_page);
    let mut lq = sqlx::query_as::<_, SignalRow>(&list_sql).bind(auth.user_id);
    if let Some(v) = &q.signal_type { lq = lq.bind(v.clone()); }
    if let Some(v) = &q.status { lq = lq.bind(v.clone()); }
    if let Some(v) = &q.severity { lq = lq.bind(v.clone()); }
    if let Some(v) = &q.resource_type { lq = lq.bind(v.clone()); }
    let rows = lq.fetch_all(&state.db.pool).await?;

    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": rows.iter().map(serialize_signal).collect::<Vec<_>>() })))
}

/// `GET /api/payments/ops/anomalies/:id`
pub async fn show(auth: AuthMerchant, State(state): State<AppState>, Path(id): Path<i64>) -> AppResult<Json<Value>> {
    Ok(Json(serialize_signal(&load_signal(&state, auth.user_id, id).await?)))
}

async fn mark(auth_id: i64, state: &AppState, id: i64, action: &str, body: &Value) -> AppResult<Json<Value>> {
    let note = body.get("note").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::validation_field("note", "required", "The note field is required"))?;
    let signal = load_signal(state, auth_id, id).await?;
    let status = if action == "acknowledge" { "acknowledged" } else { "dismissed" };
    // merge audit metadata
    let mut meta: Value = serde_json::from_str(&signal.metadata).unwrap_or(json!({}));
    let entry = json!({ "action": action, "actorId": auth_id, "occurredAt": now_iso(), "note": note, "payload": body.get("metadata").cloned().unwrap_or(json!({})) });
    if let Value::Object(m) = &mut meta {
        let mut trail = m.get("auditTrail").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        trail.push(entry);
        m.insert("auditTrail".into(), Value::Array(trail));
    }
    sqlx::query("UPDATE payment_anomaly_signals SET status = ?, metadata = ?, updated_at = ? WHERE id = ?")
        .bind(status).bind(meta.to_string()).bind(now_iso()).bind(signal.id).execute(&state.db.pool).await?;
    Ok(Json(serialize_signal(&load_signal(state, auth_id, id).await?)))
}

/// `POST /api/payments/ops/anomalies/:id/acknowledge`
pub async fn acknowledge(auth: AuthMerchant, State(state): State<AppState>, Path(id): Path<i64>, Json(body): Json<Value>) -> AppResult<Json<Value>> {
    mark(auth.user_id, &state, id, "acknowledge", &body).await
}

/// `POST /api/payments/ops/anomalies/:id/dismiss`
pub async fn dismiss(auth: AuthMerchant, State(state): State<AppState>, Path(id): Path<i64>, Json(body): Json<Value>) -> AppResult<Json<Value>> {
    mark(auth.user_id, &state, id, "dismiss", &body).await
}
