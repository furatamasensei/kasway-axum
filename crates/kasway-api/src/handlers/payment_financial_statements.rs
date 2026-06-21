//! `/api/payments/ops/statements/*` — PaymentFinancialStatementsController +
//! PaymentStatementService. Period totals are fully DB-derived; the artifact
//! that Adonis writes to a storage disk is regenerated deterministically from
//! the persisted `totals`, so `download` serves identical bytes without drive.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::util::{now_iso, paginator_meta};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Deserialize, Default)]
pub struct ListQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
}

#[derive(Deserialize)]
pub struct StoreBody {
    #[serde(rename = "periodStart")]
    period_start: Option<String>,
    #[serde(rename = "periodEnd")]
    period_end: Option<String>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct StatementRow {
    id: i64,
    user_id: i64,
    period_start: String,
    period_end: String,
    status: String,
    totals: Option<String>,
    checksum: String,
    storage_disk: Option<String>,
    storage_path: Option<String>,
    content_type: Option<String>,
    byte_size: Option<i64>,
    generated_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

fn serialize_statement(s: &StatementRow) -> Value {
    let totals: Value = s.totals.as_ref().and_then(|t| serde_json::from_str(t).ok()).unwrap_or(json!({}));
    json!({
        "id": s.id,
        "userId": s.user_id,
        "periodStart": s.period_start,
        "periodEnd": s.period_end,
        "status": s.status,
        "totals": totals,
        "checksum": s.checksum,
        "storageDisk": s.storage_disk,
        "storagePath": s.storage_path,
        "contentType": s.content_type,
        "byteSize": s.byte_size.map(|b| b.to_string()),
        "generatedAt": s.generated_at,
        "createdAt": s.created_at,
        "updatedAt": s.updated_at,
    })
}

impl StatementRow {
    pub(crate) fn id(&self) -> i64 {
        self.id
    }
    pub(crate) fn checksum(&self) -> &str {
        &self.checksum
    }
}

/// Parse an ISO date/datetime to a `YYYY-MM-DD` day string.
pub(crate) fn parse_day(s: &str) -> Option<chrono::NaiveDate> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.date_naive());
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt.date());
    }
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
}

/// Deterministic artifact string (sorted keys, no spaces) — matches stableStringify.
fn build_artifact(user_id: i64, period_start: &str, period_end: &str, totals: &Value) -> String {
    // serde_json serializes object keys in sorted (BTreeMap) order by default,
    // which mirrors the Adonis stableStringify key sort.
    serde_json::to_string(&json!({
        "userId": user_id,
        "periodStart": period_start,
        "periodEnd": period_end,
        "totals": totals,
    }))
    .unwrap()
}

async fn build_totals(
    state: &AppState,
    user_id: i64,
    start_sql: &str,
    end_sql: &str,
) -> AppResult<Value> {
    // invoices
    let (gross, paid, invoice_count): (i64, i64, i64) = sqlx::query_as(
        "SELECT CAST(COALESCE(SUM(total_amount), 0) AS BIGINT), \
         CAST(COALESCE(SUM(CASE WHEN status = 'paid' THEN total_amount ELSE 0 END), 0) AS BIGINT), \
         COUNT(*) FROM invoices WHERE user_id = $1 AND created_at >= $2 AND created_at < $3",
    )
    .bind(user_id).bind(start_sql).bind(end_sql)
    .fetch_one(&state.db.pool).await?;

    // credits
    let (credited, credit_count): (i64, i64) = sqlx::query_as(
        "SELECT CAST(COALESCE(SUM(amount), 0) AS BIGINT), COUNT(*) FROM payment_credits \
         WHERE user_id = $1 AND credited_at >= $2 AND credited_at < $3",
    )
    .bind(user_id).bind(start_sql).bind(end_sql)
    .fetch_one(&state.db.pool).await?;

    // adjustments
    let adjustments = sqlx::query_as::<_, (String, String, i64, Option<String>)>(
        "SELECT kind, direction, amount, reporting_category_code FROM payment_adjustments \
         WHERE user_id = $1 AND COALESCE(accounting_date, created_at) >= $2 \
         AND COALESCE(accounting_date, created_at) < $3",
    )
    .bind(user_id).bind(start_sql).bind(end_sql)
    .fetch_all(&state.db.pool).await?;

    #[derive(Default, Clone)]
    struct Bucket {
        credit: i128,
        debit: i128,
        net: i128,
        count: i64,
    }
    use std::collections::BTreeMap;
    let mut by_kind: BTreeMap<String, Bucket> = BTreeMap::new();
    let mut by_category: BTreeMap<String, Bucket> = BTreeMap::new();
    let mut adj_credit: i128 = 0;
    let mut adj_debit: i128 = 0;
    let mut refund_records: i128 = 0;
    let mut write_offs: i128 = 0;

    for (kind, direction, amount, category) in &adjustments {
        let amount = *amount as i128;
        let b = by_kind.entry(kind.clone()).or_default();
        b.count += 1;
        if direction == "credit" {
            adj_credit += amount;
            b.credit += amount;
            b.net += amount;
        } else {
            adj_debit += amount;
            b.debit += amount;
            b.net -= amount;
        }
        if kind == "refund_record" {
            refund_records += amount;
        }
        if kind == "write_off" {
            write_offs += amount;
        }
        if let Some(code) = category.as_ref().filter(|c| !c.is_empty()) {
            let c = by_category.entry(code.clone()).or_default();
            c.count += 1;
            if direction == "credit" {
                c.credit += amount;
                c.net += amount;
            } else {
                c.debit += amount;
                c.net -= amount;
            }
        }
    }

    let bucket_json = |b: &Bucket| {
        json!({
            "credit": b.credit.to_string(),
            "debit": b.debit.to_string(),
            "net": b.net.to_string(),
            "count": b.count,
        })
    };
    let adjustments_by_kind: Value =
        Value::Object(by_kind.iter().map(|(k, v)| (k.clone(), bucket_json(v))).collect());
    let category_totals: Value =
        Value::Object(by_category.iter().map(|(k, v)| (k.clone(), bucket_json(v))).collect());

    // exceptions
    let resolved: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_exception_resolutions \
         WHERE user_id = $1 AND created_at >= $2 AND created_at < $3",
    )
    .bind(user_id).bind(start_sql).bind(end_sql)
    .fetch_one(&state.db.pool).await?;

    let net = gross as i128 + credited as i128 + adj_credit - adj_debit;

    Ok(json!({
        "grossInvoiceAmount": gross.to_string(),
        "paidAmount": paid.to_string(),
        "creditedAmount": credited.to_string(),
        "adjustmentsByKind": adjustments_by_kind,
        "refundRecords": refund_records.to_string(),
        "writeOffs": write_offs.to_string(),
        "netAmount": net.to_string(),
        "exceptionCounts": { "resolved": resolved },
        "categoryTotals": category_totals,
        "counts": {
            "invoices": invoice_count,
            "credits": credit_count,
            "adjustments": adjustments.len(),
        },
    }))
}

pub async fn index(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).clamp(1, 100);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_statements WHERE user_id = $1")
        .bind(auth.user_id)
        .fetch_one(&state.db.pool)
        .await?;
    let rows = sqlx::query_as::<_, StatementRow>(
        "SELECT * FROM payment_statements WHERE user_id = $1 ORDER BY period_start DESC, id DESC LIMIT $2 OFFSET $3",
    )
    .bind(auth.user_id)
    .bind(per_page)
    .bind((page - 1) * per_page)
    .fetch_all(&state.db.pool)
    .await?;
    let data: Vec<Value> = rows.iter().map(serialize_statement).collect();
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}

/// Validate the period, enforce no statement overlap, build totals, persist the
/// statement + (regenerable) artifact path. Shared by `store` and the close-period
/// flow. `raw_start` / `raw_end` are the user-supplied period bounds.
pub(crate) async fn generate(
    state: &AppState,
    user_id: i64,
    raw_start: &str,
    raw_end: &str,
) -> AppResult<StatementRow> {
    let (start, end) = match (parse_day(raw_start.trim()), parse_day(raw_end.trim())) {
        (Some(s), Some(e)) if s <= e => (s, e),
        _ => return Err(AppError::commerce(422, "Payment reporting period is invalid")),
    };
    let start_date = start.format("%Y-%m-%d").to_string();
    let end_date = end.format("%Y-%m-%d").to_string();
    let end_plus1 = (end + chrono::Duration::days(1)).format("%Y-%m-%d").to_string();

    // ensureNoOverlap
    let overlap: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM payment_statements WHERE user_id = $1 AND status = 'generated' \
         AND period_start <= $2 AND period_end >= $3 LIMIT 1",
    )
    .bind(user_id).bind(&end_date).bind(&start_date)
    .fetch_optional(&state.db.pool).await?;
    if overlap.is_some() {
        return Err(AppError::commerce(422, "Payment statement period overlaps an existing statement"));
    }

    let totals = build_totals(state, user_id, &start_date, &end_plus1).await?;
    let artifact = build_artifact(user_id, &start_date, &end_date, &totals);
    let checksum = format!("sha256:{:x}", Sha256::digest(artifact.as_bytes()));
    let byte_size = artifact.len() as i64;
    let now = now_iso();

    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO payment_statements \
         (user_id, period_start, period_end, status, totals, checksum, storage_disk, storage_path, \
          content_type, byte_size, generated_at, created_at, updated_at) \
         VALUES ($1, $2, $3, 'generated', $4, $5, 'default', '', 'application/json', $6, $7, $8, $9) RETURNING id",
    )
    .bind(user_id)
    .bind(&start_date)
    .bind(&end_date)
    .bind(totals.to_string())
    .bind(&checksum)
    .bind(byte_size)
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .fetch_one(&state.db.pool)
    .await?;

    let storage_path = format!("payment-statements/{}/{}.json", user_id, id);
    sqlx::query("UPDATE payment_statements SET storage_path = $1 WHERE id = $2")
        .bind(&storage_path)
        .bind(id)
        .execute(&state.db.pool)
        .await?;

    Ok(sqlx::query_as::<_, StatementRow>("SELECT * FROM payment_statements WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db.pool)
        .await?)
}

pub async fn store(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Json(body): Json<StoreBody>,
) -> AppResult<Response> {
    let raw_start = body.period_start.as_deref().map(str::trim).unwrap_or("");
    let raw_end = body.period_end.as_deref().map(str::trim).unwrap_or("");
    if raw_start.is_empty() {
        return Err(AppError::validation_field("periodStart", "required", "The periodStart field must be defined"));
    }
    if raw_end.is_empty() {
        return Err(AppError::validation_field("periodEnd", "required", "The periodEnd field must be defined"));
    }
    let row = generate(&state, auth.user_id, raw_start, raw_end).await?;
    Ok((StatusCode::CREATED, Json(serialize_statement(&row))).into_response())
}

async fn load(state: &AppState, user_id: i64, id: &str) -> AppResult<Option<StatementRow>> {
    Ok(sqlx::query_as::<_, StatementRow>(
        "SELECT * FROM payment_statements WHERE user_id = $1 AND id = $2",
    )
    .bind(user_id)
    .bind(id)
    .fetch_optional(&state.db.pool)
    .await?)
}

pub async fn show(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let s = load(&state, auth.user_id, &id)
        .await?
        .ok_or_else(|| AppError::commerce(404, "Payment statement not found"))?;
    Ok(Json(serialize_statement(&s)))
}

pub async fn download(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let s = load(&state, auth.user_id, &id)
        .await?
        .ok_or_else(|| AppError::commerce(404, "Payment statement not found"))?;
    if s.storage_path.as_deref().unwrap_or("").is_empty() {
        return Err(AppError::commerce(422, "Payment statement artifact is unavailable"));
    }
    let totals: Value = s.totals.as_ref().and_then(|t| serde_json::from_str(t).ok()).unwrap_or(json!({}));
    let artifact = build_artifact(s.user_id, &s.period_start, &s.period_end, &totals);

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(s.content_type.as_deref().unwrap_or("application/json")).unwrap(),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"payment-statement-{}.json\"", s.id)).unwrap(),
    );
    headers.insert("x-kasway-statement-checksum", HeaderValue::from_str(&s.checksum).unwrap());
    Ok((StatusCode::OK, headers, artifact).into_response())
}
