//! `/api/payments/ops/audit-access` — PaymentAuditAccessController (merchant).
//! Grant CRUD (index/store/revoke) plus the public token-read endpoints
//! (`/api/payments/audit/:token/{statements,exports,evidence-packs,close-periods}`)
//! which authorize by grant token + scope and return the period-bounded rows.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::state::AppState;
use crate::util::{now_iso, paginator_meta};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};

const SCOPES: &[&str] = &["statements", "exports", "evidence_packs", "close_periods"];

#[derive(Deserialize, Default)]
pub struct PageQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct GrantRow {
    id: i64,
    user_id: i64,
    email: String,
    token: String,
    scope: String,
    period_start: String,
    period_end: String,
    expires_at: String,
    revoked_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const GRANT_COLS: &str = "id, user_id, email, token, scope, period_start, period_end, expires_at, revoked_at, created_at, updated_at";

fn serialize_grant(g: &GrantRow) -> Value {
    json!({
        "id": g.id,
        "userId": g.user_id,
        "email": g.email,
        "token": g.token,
        "scope": serde_json::from_str::<Value>(&g.scope).unwrap_or(json!([])),
        "periodStart": g.period_start,
        "periodEnd": g.period_end,
        "expiresAt": g.expires_at,
        "revokedAt": g.revoked_at,
        "createdAt": g.created_at,
        "updatedAt": g.updated_at,
    })
}

pub async fn index(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<PageQuery>) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).max(1);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_audit_access_grants WHERE user_id = ?").bind(auth.user_id).fetch_one(&state.db.pool).await?;
    let rows = sqlx::query_as::<_, GrantRow>(&format!("SELECT {GRANT_COLS} FROM payment_audit_access_grants WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?"))
        .bind(auth.user_id).bind(per_page).bind((page - 1) * per_page).fetch_all(&state.db.pool).await?;
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": rows.iter().map(serialize_grant).collect::<Vec<_>>() })))
}

pub async fn store(auth: AuthMerchant, State(state): State<AppState>, Json(body): Json<Value>) -> AppResult<(StatusCode, Json<Value>)> {
    // validation (createPaymentAuditAccessGrantValidator)
    let email = body.get("email").and_then(|v| v.as_str()).map(|s| s.trim().to_string())
        .filter(|s| s.contains('@') && s.len() <= 255)
        .ok_or_else(|| AppError::Validation(vec![ValidationFailure { message: "The email field must be a valid email address".into(), rule: "email".into(), field: "email".into() }]))?;
    let scope: Vec<String> = match body.get("scope") {
        Some(Value::Array(a)) if !a.is_empty() => {
            let mut out = Vec::new();
            for (i, item) in a.iter().enumerate() {
                match item.as_str() {
                    Some(s) if SCOPES.contains(&s) => out.push(s.to_string()),
                    _ => return Err(AppError::Validation(vec![ValidationFailure { message: format!("The selected scope.{i} is invalid"), rule: "enum".into(), field: format!("scope.{i}") }])),
                }
            }
            // dedup preserve order
            let mut seen = std::collections::HashSet::new();
            out.into_iter().filter(|s| seen.insert(s.clone())).collect()
        }
        _ => return Err(AppError::Validation(vec![ValidationFailure { message: "The scope field must have at least 1 items".into(), rule: "minLength".into(), field: "scope".into() }])),
    };
    let period_start = body.get("periodStart").and_then(|v| v.as_str()).map(|s| s.trim().to_string())
        .ok_or_else(|| AppError::Validation(vec![ValidationFailure { message: "The periodStart field is required".into(), rule: "required".into(), field: "periodStart".into() }]))?;
    let period_end = body.get("periodEnd").and_then(|v| v.as_str()).map(|s| s.trim().to_string())
        .ok_or_else(|| AppError::Validation(vec![ValidationFailure { message: "The periodEnd field is required".into(), rule: "required".into(), field: "periodEnd".into() }]))?;
    let expires_at = body.get("expiresAt").and_then(|v| v.as_str()).map(|s| s.trim().to_string())
        .ok_or_else(|| AppError::Validation(vec![ValidationFailure { message: "The expiresAt field is required".into(), rule: "required".into(), field: "expiresAt".into() }]))?;

    // semantic validation -> CommerceError 422
    let ps = chrono::NaiveDate::parse_from_str(&period_start, "%Y-%m-%d").ok();
    let pe = chrono::NaiveDate::parse_from_str(&period_end, "%Y-%m-%d").ok();
    let exp = chrono::DateTime::parse_from_rfc3339(&expires_at).ok();
    let dates_ok = match (ps, pe, exp) {
        (Some(ps), Some(pe), Some(exp)) => ps <= pe && exp.with_timezone(&chrono::Utc) > chrono::Utc::now(),
        _ => false,
    };
    if !dates_ok {
        return Err(AppError::commerce(422, "Payment audit access grant dates are invalid"));
    }

    let mut tb = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut tb);
    let token = format!("pay_audit_{}", tb.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    let now = now_iso();
    let r = sqlx::query("INSERT INTO payment_audit_access_grants (user_id, email, token, scope, period_start, period_end, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(auth.user_id).bind(&email).bind(&token).bind(serde_json::to_string(&scope).unwrap())
        .bind(&period_start).bind(&period_end).bind(&expires_at).bind(&now).bind(&now)
        .execute(&state.db.pool).await?;
    // auditEvents.record -> deferred no-op
    let grant = sqlx::query_as::<_, GrantRow>(&format!("SELECT {GRANT_COLS} FROM payment_audit_access_grants WHERE id = ?")).bind(r.last_insert_rowid()).fetch_one(&state.db.pool).await?;
    Ok((StatusCode::CREATED, Json(serialize_grant(&grant))))
}

// --- Public token-read endpoints (no merchant auth; authorized by grant token) ---

/// Load + validate a grant for `scope`; mirrors authorizeToken (403 on any failure).
async fn authorize_token(state: &AppState, token: &str, scope: &str) -> AppResult<GrantRow> {
    let grant: Option<GrantRow> = sqlx::query_as::<_, GrantRow>(&format!(
        "SELECT {GRANT_COLS} FROM payment_audit_access_grants WHERE token = ?"
    ))
    .bind(token)
    .fetch_optional(&state.db.pool)
    .await?;
    let inactive = match &grant {
        None => true,
        Some(g) => {
            let revoked = g.revoked_at.is_some();
            let expired = chrono::DateTime::parse_from_rfc3339(&g.expires_at)
                .map(|e| e.with_timezone(&chrono::Utc) <= chrono::Utc::now())
                .unwrap_or(true);
            let scopes: Vec<String> = serde_json::from_str(&g.scope).unwrap_or_default();
            revoked || expired || !scopes.iter().any(|s| s == scope)
        }
    };
    if inactive {
        return Err(AppError::commerce(403, "Payment audit access grant is not active for this resource"));
    }
    Ok(grant.unwrap())
}

fn end_plus_one(date: &str) -> String {
    chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d")
        .map(|d| (d + chrono::Duration::days(1)).format("%Y-%m-%d").to_string())
        .unwrap_or_else(|_| date.to_string())
}

fn json_or<T: AsRef<str>>(s: &Option<T>, default: Value) -> Value {
    s.as_ref().and_then(|v| serde_json::from_str(v.as_ref()).ok()).unwrap_or(default)
}

/// `GET /api/payments/audit/:token/statements`
pub async fn statements(State(state): State<AppState>, Path(token): Path<String>) -> AppResult<Json<Value>> {
    let grant = authorize_token(&state, &token, "statements").await?;
    #[derive(sqlx::FromRow)]
    struct StRow {
        id: i64, user_id: i64, period_start: String, period_end: String, status: String,
        totals: Option<String>, checksum: String, storage_disk: Option<String>, storage_path: Option<String>,
        content_type: Option<String>, byte_size: Option<i64>, generated_at: Option<String>,
        created_at: Option<String>, updated_at: Option<String>,
    }
    let rows = sqlx::query_as::<_, StRow>(
        "SELECT id, user_id, period_start, period_end, status, totals, checksum, storage_disk, storage_path, \
         content_type, byte_size, generated_at, created_at, updated_at FROM payment_statements \
         WHERE user_id = ? AND period_start >= ? AND period_end <= ? ORDER BY period_start DESC",
    )
    .bind(grant.user_id).bind(&grant.period_start).bind(&grant.period_end)
    .fetch_all(&state.db.pool).await?;
    let data: Vec<Value> = rows.iter().map(|s| json!({
        "id": s.id, "userId": s.user_id, "periodStart": s.period_start, "periodEnd": s.period_end,
        "status": s.status, "totals": json_or(&s.totals, json!({})), "checksum": s.checksum,
        "storageDisk": s.storage_disk, "storagePath": s.storage_path, "contentType": s.content_type,
        "byteSize": s.byte_size.map(|b| b.to_string()), "generatedAt": s.generated_at,
        "createdAt": s.created_at, "updatedAt": s.updated_at,
    })).collect();
    Ok(Json(json!(data)))
}

/// `GET /api/payments/audit/:token/exports`
pub async fn exports(State(state): State<AppState>, Path(token): Path<String>) -> AppResult<Json<Value>> {
    let grant = authorize_token(&state, &token, "exports").await?;
    #[derive(sqlx::FromRow)]
    struct ExRow {
        id: i64, user_id: i64, kind: String, format: String, profile_id: Option<i64>,
        filters: Option<String>, row_count: i64, checksum: String, status: String,
        content_type: Option<String>, byte_size: Option<i64>, expires_at: Option<String>,
        generated_at: Option<String>, created_at: Option<String>, updated_at: Option<String>,
    }
    let rows = sqlx::query_as::<_, ExRow>(
        "SELECT id, user_id, kind, format, profile_id, filters, row_count, checksum, status, content_type, \
         byte_size, expires_at, generated_at, created_at, updated_at FROM payment_operation_exports \
         WHERE user_id = ? AND generated_at >= ? AND generated_at <= ?",
    )
    .bind(grant.user_id).bind(&grant.period_start).bind(end_plus_one(&grant.period_end))
    .fetch_all(&state.db.pool).await?;
    let data: Vec<Value> = rows.iter().map(|e| json!({
        "id": e.id, "userId": e.user_id, "kind": e.kind, "format": e.format, "profileId": e.profile_id,
        "filters": json_or(&e.filters, json!({})), "rowCount": e.row_count, "checksum": e.checksum,
        "status": e.status, "contentType": e.content_type, "byteSize": e.byte_size.map(|b| b.to_string()),
        "expiresAt": e.expires_at, "generatedAt": e.generated_at, "createdAt": e.created_at, "updatedAt": e.updated_at,
    })).collect();
    Ok(Json(json!(data)))
}

/// `GET /api/payments/audit/:token/evidence-packs`
pub async fn evidence_packs(State(state): State<AppState>, Path(token): Path<String>) -> AppResult<Json<Value>> {
    let grant = authorize_token(&state, &token, "evidence_packs").await?;
    #[derive(sqlx::FromRow)]
    struct EvRow {
        id: i64, user_id: i64, invoice_id: i64, status: String, checksum: String,
        storage_disk: Option<String>, storage_path: Option<String>, byte_size: Option<i64>,
        generated_by_user_id: i64, generated_at: Option<String>, expires_at: Option<String>,
        error: Option<String>, created_at: Option<String>, updated_at: Option<String>,
    }
    let rows = sqlx::query_as::<_, EvRow>(
        "SELECT id, user_id, invoice_id, status, checksum, storage_disk, storage_path, byte_size, \
         generated_by_user_id, generated_at, expires_at, error, created_at, updated_at \
         FROM payment_evidence_packs WHERE user_id = ? AND generated_at >= ? AND generated_at <= ?",
    )
    .bind(grant.user_id).bind(&grant.period_start).bind(end_plus_one(&grant.period_end))
    .fetch_all(&state.db.pool).await?;
    let data: Vec<Value> = rows.iter().map(|p| json!({
        "id": p.id, "userId": p.user_id, "invoiceId": p.invoice_id, "status": p.status, "checksum": p.checksum,
        "storageDisk": p.storage_disk, "storagePath": p.storage_path, "byteSize": p.byte_size.map(|b| b.to_string()),
        "generatedByUserId": p.generated_by_user_id, "generatedAt": p.generated_at, "expiresAt": p.expires_at,
        "error": p.error, "createdAt": p.created_at, "updatedAt": p.updated_at,
    })).collect();
    Ok(Json(json!(data)))
}

/// `GET /api/payments/audit/:token/close-periods`
pub async fn close_periods(State(state): State<AppState>, Path(token): Path<String>) -> AppResult<Json<Value>> {
    let grant = authorize_token(&state, &token, "close_periods").await?;
    #[derive(sqlx::FromRow)]
    struct CpRow {
        id: i64, user_id: i64, period_start: String, period_end: String, status: String,
        statement_id: Option<i64>, totals_checksum: String, closed_by_user_id: Option<i64>,
        closed_at: Option<String>, reopened_at: Option<String>, metadata: String,
        created_at: Option<String>, updated_at: Option<String>,
    }
    let rows = sqlx::query_as::<_, CpRow>(
        "SELECT id, user_id, period_start, period_end, status, statement_id, totals_checksum, \
         closed_by_user_id, closed_at, reopened_at, metadata, created_at, updated_at \
         FROM payment_close_periods WHERE user_id = ? AND period_start >= ? AND period_end <= ?",
    )
    .bind(grant.user_id).bind(&grant.period_start).bind(&grant.period_end)
    .fetch_all(&state.db.pool).await?;
    let data: Vec<Value> = rows.iter().map(|c| json!({
        "id": c.id, "userId": c.user_id, "periodStart": c.period_start, "periodEnd": c.period_end,
        "status": c.status, "statementId": c.statement_id, "totalsChecksum": c.totals_checksum,
        "closedByUserId": c.closed_by_user_id, "closedAt": c.closed_at, "reopenedAt": c.reopened_at,
        "metadata": serde_json::from_str::<Value>(&c.metadata).unwrap_or(json!({})),
        "createdAt": c.created_at, "updatedAt": c.updated_at,
    })).collect();
    Ok(Json(json!(data)))
}

pub async fn revoke(auth: AuthMerchant, State(state): State<AppState>, Path(id): Path<i64>) -> AppResult<Json<Value>> {
    let grant: Option<GrantRow> = sqlx::query_as::<_, GrantRow>(&format!("SELECT {GRANT_COLS} FROM payment_audit_access_grants WHERE user_id = ? AND id = ?"))
        .bind(auth.user_id).bind(id).fetch_optional(&state.db.pool).await?;
    let grant = grant.ok_or_else(|| AppError::commerce(404, "Payment audit access grant not found"))?;
    sqlx::query("UPDATE payment_audit_access_grants SET revoked_at = ?, updated_at = ? WHERE id = ?").bind(now_iso()).bind(now_iso()).bind(grant.id).execute(&state.db.pool).await?;
    let grant = sqlx::query_as::<_, GrantRow>(&format!("SELECT {GRANT_COLS} FROM payment_audit_access_grants WHERE id = ?")).bind(grant.id).fetch_one(&state.db.pool).await?;
    Ok(Json(serialize_grant(&grant)))
}
