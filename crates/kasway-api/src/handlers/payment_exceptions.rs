//! `/api/payments/ops/exceptions*` — PaymentOperationsExceptionsController.
//! index derives exceptions (invoice-backed: underpaid/overpaid + settlement
//! receipts) and filters out resolved ones; resolution read + resolve + dismiss
//! persist into payment_exception_resolutions. link-observation / ignore-observation
//! are deferred (they mutate observation rows whose extended columns aren't modeled yet).

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult};
use crate::handlers::invoices;
use crate::state::AppState;
use crate::util::now_iso;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize, Default)]
pub struct ExcQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
    #[serde(rename = "type")]
    exc_type: Option<String>,
    severity: Option<String>,
    status: Option<String>,
}

#[derive(sqlx::FromRow)]
struct InvRow {
    id: i64,
    public_id: String,
    external_id: Option<String>,
    status: String,
    payment_network: Option<String>,
    payment_asset: Option<String>,
    payment_address: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

fn exc_row(exc_type: &str, severity: &str, inv: &InvRow, summary: &Value) -> Value {
    let totals = &summary["totals"];
    let last_observed = summary["status"]["lastObservedAt"].clone();
    let occurred = if last_observed.is_string() { last_observed.clone() } else { json!(inv.updated_at) };
    json!({
        "id": format!("{exc_type}:invoice:{}", inv.id),
        "type": exc_type,
        "severity": severity,
        "invoice": { "id": inv.id, "publicId": inv.public_id, "externalId": inv.external_id, "status": inv.status },
        "amounts": {
            "invoice": totals["invoice"], "observed": totals["observed"], "credited": totals["credited"],
            "remaining": totals["remaining"], "overpaid": totals["overpaid"],
        },
        "sourceTimestamps": { "invoiceCreatedAt": inv.created_at, "lastObservedAt": last_observed, "occurredAt": occurred },
        "paymentState": summary["status"]["paymentState"],
        "network": inv.payment_network,
        "assetId": inv.payment_asset,
        "paymentAddress": inv.payment_address,
    })
}

/// Derive the active (non-resolved/dismissed) exception list for one merchant,
/// applying the type/severity/status filters. Shared by the merchant exceptions
/// index and the support cross-merchant exception listing.
/// Returns rows in invoice-created-desc order (callers re-sort as needed).
pub(crate) async fn derive_user_exceptions(
    state: &AppState,
    user_id: i64,
    exc_type: Option<&str>,
    severity: Option<&str>,
    status: Option<&str>,
) -> AppResult<Vec<Value>> {
    let invoices_rows = sqlx::query_as::<_, InvRow>(
        "SELECT id, public_id, external_id, status, payment_network, payment_asset, payment_address, created_at, updated_at \
         FROM invoices WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&state.db.pool)
    .await?;

    let mut rows: Vec<Value> = Vec::new();
    for inv in &invoices_rows {
        let summary = invoices::derive_payment_status_by_id(state, inv.id).await?;
        match summary["status"]["paymentState"].as_str() {
            Some("underpaid") => rows.push(exc_row("underpaid", "medium", inv, &summary)),
            Some("overpaid") => rows.push(exc_row("overpaid", "medium", inv, &summary)),
            _ => {}
        }
    }

    // filter out resolved/dismissed
    let keys: Vec<String> = rows.iter().map(|r| r["id"].as_str().unwrap().to_string()).collect();
    let mut closed = std::collections::HashSet::new();
    if !keys.is_empty() {
        let placeholders = keys.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!("SELECT DISTINCT exception_key FROM payment_exception_resolutions WHERE user_id = ? AND status IN ('resolved','dismissed') AND exception_key IN ({placeholders})");
        let mut qx = sqlx::query_scalar::<_, String>(&sql).bind(user_id);
        for k in &keys { qx = qx.bind(k.clone()); }
        for k in qx.fetch_all(&state.db.pool).await? { closed.insert(k); }
    }
    let mut active: Vec<Value> = rows.into_iter().filter(|r| !closed.contains(r["id"].as_str().unwrap())).collect();

    // filters
    if let Some(t) = exc_type { active.retain(|r| r["type"] == json!(t)); }
    if let Some(s) = severity { active.retain(|r| r["severity"] == json!(s)); }
    if let Some(s) = status { active.retain(|r| r["invoice"]["status"] == json!(s)); }

    Ok(active)
}

/// `GET /api/payments/ops/exceptions`
pub async fn index(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<ExcQuery>) -> AppResult<Json<Value>> {
    let active = derive_user_exceptions(
        &state,
        auth.user_id,
        q.exc_type.as_deref(),
        q.severity.as_deref(),
        q.status.as_deref(),
    )
    .await?;

    // paginate (manual, matching Adonis derived paginator)
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).max(1);
    let total = active.len() as i64;
    let first = ((page - 1) * per_page) as usize;
    let data: Vec<Value> = active.into_iter().skip(first).take(per_page as usize).collect();
    let last_page = std::cmp::max((total as f64 / per_page as f64).ceil() as i64, 1);

    Ok(Json(json!({
        "meta": {
            "total": total, "perPage": per_page, "currentPage": page, "lastPage": last_page, "firstPage": 1,
            "firstPageUrl": "/?page=1", "lastPageUrl": format!("/?page={last_page}"),
            "nextPageUrl": if page < last_page { Value::String(format!("/?page={}", page + 1)) } else { Value::Null },
            "previousPageUrl": if page > 1 { Value::String(format!("/?page={}", page - 1)) } else { Value::Null },
        },
        "data": data,
    })))
}

#[derive(sqlx::FromRow)]
struct ResolutionRow {
    id: i64,
    user_id: i64,
    exception_type: String,
    exception_key: String,
    invoice_id: Option<i64>,
    payment_observation_id: Option<i64>,
    action: String,
    status: String,
    note: Option<String>,
    metadata: String,
    resolved_by_user_id: Option<i64>,
    resolved_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const RES_COLS: &str = "id, user_id, exception_type, exception_key, invoice_id, payment_observation_id, \
    action, status, note, metadata, resolved_by_user_id, resolved_at, created_at, updated_at";

fn serialize_resolution(r: &ResolutionRow) -> Value {
    json!({
        "id": r.id,
        "userId": r.user_id,
        "exceptionType": r.exception_type,
        "exceptionKey": r.exception_key,
        "invoiceId": r.invoice_id,
        "paymentObservationId": r.payment_observation_id,
        "action": r.action,
        "status": r.status,
        "note": r.note,
        "metadata": serde_json::from_str::<Value>(&r.metadata).unwrap_or(json!({})),
        "resolvedByUserId": r.resolved_by_user_id,
        "resolvedAt": r.resolved_at,
        "createdAt": r.created_at,
        "updatedAt": r.updated_at,
    })
}

fn invoice_id_from_key(key: &str) -> Option<i64> {
    let parts: Vec<&str> = key.split(':').collect();
    parts.iter().position(|p| *p == "invoice").and_then(|i| parts.get(i + 1)).and_then(|s| s.parse().ok())
}

/// `GET /api/payments/ops/exceptions/:id/resolution`
pub async fn resolution(auth: AuthMerchant, State(state): State<AppState>, Path(key): Path<String>) -> AppResult<Json<Value>> {
    let row: Option<ResolutionRow> = sqlx::query_as::<_, ResolutionRow>(&format!(
        "SELECT {RES_COLS} FROM payment_exception_resolutions WHERE user_id = ? AND exception_key = ? ORDER BY created_at DESC, id DESC LIMIT 1"
    ))
    .bind(auth.user_id).bind(&key).fetch_optional(&state.db.pool).await?;
    let row = row.ok_or_else(|| AppError::commerce(404, "Payment exception resolution not found"))?;
    Ok(Json(serialize_resolution(&row)))
}

async fn create_resolution(state: &AppState, user_id: i64, key: &str, action: &str, status: &str, body: &Value) -> AppResult<Json<Value>> {
    let note = body.get("note").and_then(|v| v.as_str());
    if status == "dismissed" && note.map(|s| s.trim().is_empty()).unwrap_or(true) {
        return Err(AppError::validation_field("note", "required", "The note field is required"));
    }
    let metadata = body.get("metadata").filter(|v| v.is_object()).cloned().unwrap_or(json!({}));
    let exc_type = key.split(':').next().unwrap_or("unknown");
    let invoice_id = invoice_id_from_key(key);
    let now = now_iso();
    let r = sqlx::query(
        "INSERT INTO payment_exception_resolutions (user_id, exception_type, exception_key, invoice_id, action, status, note, metadata, resolved_by_user_id, resolved_at, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id).bind(exc_type).bind(key).bind(invoice_id).bind(action).bind(status).bind(note).bind(metadata.to_string()).bind(user_id).bind(&now).bind(&now).bind(&now)
    .execute(&state.db.pool).await?;
    // notifications.emit -> deferred no-op
    let row = sqlx::query_as::<_, ResolutionRow>(&format!("SELECT {RES_COLS} FROM payment_exception_resolutions WHERE id = ?")).bind(r.last_insert_rowid()).fetch_one(&state.db.pool).await?;
    Ok(Json(serialize_resolution(&row)))
}

/// `POST /api/payments/ops/exceptions/:id/resolve`
pub async fn resolve(auth: AuthMerchant, State(state): State<AppState>, Path(key): Path<String>, Json(body): Json<Value>) -> AppResult<(StatusCode, Json<Value>)> {
    Ok((StatusCode::CREATED, create_resolution(&state, auth.user_id, &key, "mark_reviewed", "resolved", &body).await?))
}

/// `POST /api/payments/ops/exceptions/:id/dismiss`
pub async fn dismiss(auth: AuthMerchant, State(state): State<AppState>, Path(key): Path<String>, Json(body): Json<Value>) -> AppResult<(StatusCode, Json<Value>)> {
    Ok((StatusCode::CREATED, create_resolution(&state, auth.user_id, &key, "dismiss", "dismissed", &body).await?))
}
