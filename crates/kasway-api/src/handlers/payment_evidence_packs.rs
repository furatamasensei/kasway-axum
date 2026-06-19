//! `/api/payments/ops/evidence-packs*` + `/api/payments/ops/invoices/:id/evidence-packs`
//! — PaymentEvidencePacksController. `store` enqueues a manifest (the bundle build
//! job and the drive-backed bytes are external), `index`/`show` are DB reads, and
//! `download` only ever reaches the 404 / not-downloadable branches because the
//! port never produces a succeeded manifest with a storage path.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult};
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
struct PackRow {
    id: i64,
    user_id: i64,
    invoice_id: i64,
    status: String,
    checksum: String,
    storage_disk: Option<String>,
    storage_path: Option<String>,
    byte_size: Option<i64>,
    generated_by_user_id: i64,
    generated_at: Option<String>,
    expires_at: Option<String>,
    error: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

fn serialize_pack(p: &PackRow) -> Value {
    json!({
        "id": p.id,
        "userId": p.user_id,
        "invoiceId": p.invoice_id,
        "status": p.status,
        "checksum": p.checksum,
        "storageDisk": p.storage_disk,
        "storagePath": p.storage_path,
        "byteSize": p.byte_size.map(|b| b.to_string()),
        "generatedByUserId": p.generated_by_user_id,
        "generatedAt": p.generated_at,
        "expiresAt": p.expires_at,
        "error": p.error,
        "createdAt": p.created_at,
        "updatedAt": p.updated_at,
    })
}

async fn load(state: &AppState, user_id: i64, id: &str) -> AppResult<Option<PackRow>> {
    Ok(sqlx::query_as::<_, PackRow>(
        "SELECT * FROM payment_evidence_packs WHERE user_id = ? AND id = ?",
    )
    .bind(user_id)
    .bind(id)
    .fetch_optional(&state.db.pool)
    .await?)
}

/// `GET /api/payments/ops/evidence-packs`
pub async fn index(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Query(q): Query<PageQuery>,
) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).clamp(1, 100);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_evidence_packs WHERE user_id = ?")
        .bind(auth.user_id)
        .fetch_one(&state.db.pool)
        .await?;
    let rows = sqlx::query_as::<_, PackRow>(
        "SELECT * FROM payment_evidence_packs WHERE user_id = ? ORDER BY generated_at DESC, id DESC LIMIT ? OFFSET ?",
    )
    .bind(auth.user_id)
    .bind(per_page)
    .bind((page - 1) * per_page)
    .fetch_all(&state.db.pool)
    .await?;
    let data: Vec<Value> = rows.iter().map(serialize_pack).collect();
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}

/// `POST /api/payments/ops/invoices/:id/evidence-packs`
pub async fn store(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let invoice_id = match id.parse::<i64>() {
        Ok(n) if n > 0 => n,
        _ => return Err(AppError::commerce(422, "Invalid invoice id")),
    };
    let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM invoices WHERE user_id = ? AND id = ?")
        .bind(auth.user_id)
        .bind(invoice_id)
        .fetch_optional(&state.db.pool)
        .await?;
    if exists.is_none() {
        return Err(AppError::commerce(404, "Invoice not found"));
    }
    let now = now_iso();
    let new_id = sqlx::query(
        "INSERT INTO payment_evidence_packs \
         (user_id, invoice_id, status, checksum, generated_by_user_id, generated_at, created_at, updated_at) \
         VALUES (?, ?, 'queued', '', ?, ?, ?, ?)",
    )
    .bind(auth.user_id)
    .bind(invoice_id)
    .bind(auth.user_id)
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .execute(&state.db.pool)
    .await?
    .last_insert_rowid();
    let row = load(&state, auth.user_id, &new_id.to_string()).await?.expect("just inserted");
    Ok((StatusCode::ACCEPTED, Json(serialize_pack(&row))).into_response())
}

/// `GET /api/payments/ops/evidence-packs/:id`
pub async fn show(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let p = load(&state, auth.user_id, &id)
        .await?
        .ok_or_else(|| AppError::commerce(404, "Payment evidence pack not found"))?;
    Ok(Json(serialize_pack(&p)))
}

/// `GET /api/payments/ops/evidence-packs/:id/download`
pub async fn download(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let p = load(&state, auth.user_id, &id)
        .await?
        .ok_or_else(|| AppError::commerce(404, "Payment evidence pack not found"))?;
    if p.status != "succeeded" || p.storage_path.as_deref().unwrap_or("").is_empty() {
        return Err(AppError::commerce(422, "Payment evidence pack is not downloadable"));
    }
    // Drive-backed bytes are external; manifests here never reach this branch.
    Err(AppError::commerce(410, "Payment evidence pack has expired"))
}
