//! `/api/payments/ops/close-periods` — PaymentClosePeriodsController.
//! index/show/reopen/store are DB-backed. `store` (close) reuses or generates a
//! financial statement (see payment_financial_statements::generate). The
//! high-severity exception blocking check is a structural no-op in the port:
//! high-severity ("settlement receipt") exceptions derive from observation
//! columns not yet modeled, so the blocking set is always empty here.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult};
use crate::handlers::payment_financial_statements as statements;
use crate::state::AppState;
use crate::util::{now_iso, paginator_meta};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize, Default)]
pub struct PageQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct PeriodRow {
    id: i64,
    user_id: i64,
    period_start: String,
    period_end: String,
    status: String,
    statement_id: Option<i64>,
    totals_checksum: String,
    closed_by_user_id: Option<i64>,
    closed_at: Option<String>,
    reopened_at: Option<String>,
    metadata: String,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const COLS: &str = "id, user_id, period_start, period_end, status, statement_id, totals_checksum, \
    closed_by_user_id, closed_at, reopened_at, metadata, created_at, updated_at";

fn serialize_period(p: &PeriodRow) -> Value {
    json!({
        "id": p.id,
        "userId": p.user_id,
        "periodStart": p.period_start,
        "periodEnd": p.period_end,
        "status": p.status,
        "statementId": p.statement_id,
        "totalsChecksum": p.totals_checksum,
        "closedByUserId": p.closed_by_user_id,
        "closedAt": p.closed_at,
        "reopenedAt": p.reopened_at,
        "metadata": serde_json::from_str::<Value>(&p.metadata).unwrap_or(json!({})),
        "createdAt": p.created_at,
        "updatedAt": p.updated_at,
    })
}

async fn load(state: &AppState, user_id: i64, id: i64) -> AppResult<PeriodRow> {
    sqlx::query_as::<_, PeriodRow>(&format!("SELECT {COLS} FROM payment_close_periods WHERE user_id = ? AND id = ?"))
        .bind(user_id).bind(id).fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::commerce(404, "Payment close period not found"))
}

/// `GET /api/payments/ops/close-periods`
pub async fn index(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<PageQuery>) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).max(1);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_close_periods WHERE user_id = ?").bind(auth.user_id).fetch_one(&state.db.pool).await?;
    let rows = sqlx::query_as::<_, PeriodRow>(&format!("SELECT {COLS} FROM payment_close_periods WHERE user_id = ? ORDER BY period_start DESC LIMIT ? OFFSET ?"))
        .bind(auth.user_id).bind(per_page).bind((page - 1) * per_page).fetch_all(&state.db.pool).await?;
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": rows.iter().map(serialize_period).collect::<Vec<_>>() })))
}

#[derive(Deserialize)]
pub struct CloseBody {
    #[serde(rename = "periodStart")]
    period_start: Option<String>,
    #[serde(rename = "periodEnd")]
    period_end: Option<String>,
    #[serde(rename = "overrideHighSeverityExceptions")]
    override_high_severity_exceptions: Option<bool>,
    note: Option<String>,
}

/// `POST /api/payments/ops/close-periods`
pub async fn store(auth: AuthMerchant, State(state): State<AppState>, Json(body): Json<CloseBody>) -> AppResult<Response> {
    let raw_start = body.period_start.as_deref().map(str::trim).unwrap_or("");
    let raw_end = body.period_end.as_deref().map(str::trim).unwrap_or("");
    if raw_start.is_empty() {
        return Err(AppError::validation_field("periodStart", "required", "The periodStart field must be defined"));
    }
    if raw_end.is_empty() {
        return Err(AppError::validation_field("periodEnd", "required", "The periodEnd field must be defined"));
    }
    let (start, end) = match (statements::parse_day(raw_start), statements::parse_day(raw_end)) {
        (Some(s), Some(e)) if s <= e => (s, e),
        _ => return Err(AppError::commerce(422, "Payment reporting period is invalid")),
    };
    let start_date = start.format("%Y-%m-%d").to_string();
    let end_date = end.format("%Y-%m-%d").to_string();

    // ensureNoClosedOverlap
    let overlap: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM payment_close_periods WHERE user_id = ? AND status = 'closed' \
         AND period_start <= ? AND period_end >= ? LIMIT 1",
    )
    .bind(auth.user_id).bind(&end_date).bind(&start_date)
    .fetch_optional(&state.db.pool).await?;
    if overlap.is_some() {
        return Err(AppError::commerce(422, "Payment close period overlaps an existing closed period"));
    }

    // High-severity exception blocking: empty set in the port (see module doc).

    // Reuse an exact-period generated statement, else generate one.
    let existing: Option<(i64, String)> = sqlx::query_as(
        "SELECT id, checksum FROM payment_statements WHERE user_id = ? AND period_start = ? \
         AND period_end = ? AND status = 'generated' LIMIT 1",
    )
    .bind(auth.user_id).bind(&start_date).bind(&end_date)
    .fetch_optional(&state.db.pool).await?;
    let (statement_id, checksum) = match existing {
        Some(s) => s,
        None => {
            let st = statements::generate(&state, auth.user_id, raw_start, raw_end).await?;
            (st.id(), st.checksum().to_string())
        }
    };

    let metadata = json!({
        "note": body.note,
        "overrideHighSeverityExceptions": body.override_high_severity_exceptions.unwrap_or(false),
    });
    let now = now_iso();
    let id = sqlx::query(
        "INSERT INTO payment_close_periods \
         (user_id, period_start, period_end, status, statement_id, totals_checksum, closed_by_user_id, \
          closed_at, metadata, created_at, updated_at) \
         VALUES (?, ?, ?, 'closed', ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(auth.user_id)
    .bind(&start_date)
    .bind(&end_date)
    .bind(statement_id)
    .bind(&checksum)
    .bind(auth.user_id)
    .bind(&now)
    .bind(metadata.to_string())
    .bind(&now)
    .bind(&now)
    .execute(&state.db.pool)
    .await?
    .last_insert_rowid();

    Ok((StatusCode::CREATED, Json(serialize_period(&load(&state, auth.user_id, id).await?))).into_response())
}

/// `GET /api/payments/ops/close-periods/:id`
pub async fn show(auth: AuthMerchant, State(state): State<AppState>, Path(id): Path<i64>) -> AppResult<Json<Value>> {
    Ok(Json(serialize_period(&load(&state, auth.user_id, id).await?)))
}

/// `POST /api/payments/ops/close-periods/:id/reopen`
pub async fn reopen(auth: AuthMerchant, State(state): State<AppState>, Path(id): Path<i64>, Json(body): Json<Value>) -> AppResult<Json<Value>> {
    let note = body.get("note").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::validation_field("note", "required", "The note field is required"))?;
    let p = load(&state, auth.user_id, id).await?;
    if p.status != "closed" {
        return Err(AppError::commerce(422, "Only closed periods can be reopened"));
    }
    let mut meta: Value = serde_json::from_str(&p.metadata).unwrap_or(json!({}));
    if let Value::Object(m) = &mut meta { m.insert("reopenNote".into(), json!(note)); }
    let now = now_iso();
    sqlx::query("UPDATE payment_close_periods SET status = 'reopened', reopened_at = ?, metadata = ?, updated_at = ? WHERE id = ?")
        .bind(&now).bind(meta.to_string()).bind(&now).bind(p.id).execute(&state.db.pool).await?;
    Ok(Json(serialize_period(&load(&state, auth.user_id, id).await?)))
}
