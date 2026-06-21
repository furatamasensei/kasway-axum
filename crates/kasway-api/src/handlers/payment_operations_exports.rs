//! `/api/payments/ops/exports/*` — PaymentOperationsExportsController +
//! PaymentOperationsExportService. Synchronous CSV streams (invoices /
//! observations / credits) plus the manifest CRUD (index/store/show/download).
//!
//! The async queue path (GeneratePaymentOperationExportJob) and the drive-backed
//! download bytes are external — `store` persists a `queued` manifest without
//! dispatching a worker, and `download` therefore only ever reaches the
//! 404 / "not downloadable" branches (storagePath stays null).

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

const EXPORT_LIMIT: i64 = 10_000;

#[derive(Debug, Deserialize, Default)]
pub struct ExportQuery {
    from: Option<String>,
    to: Option<String>,
    status: Option<String>,
    network: Option<String>,
    #[serde(rename = "assetId")]
    asset_id: Option<String>,
    #[serde(rename = "invoiceId")]
    invoice_id: Option<String>,
    #[serde(rename = "paymentAddress")]
    payment_address: Option<String>,
    #[serde(rename = "publicId")]
    public_id: Option<String>,
    #[serde(rename = "externalId")]
    external_id: Option<String>,
    #[serde(rename = "storeId")]
    store_id: Option<String>,
}

enum Bind {
    Str(String),
    Int(i64),
}

/// A single CSV cell value formatter (mirrors serializeValue).
fn cell(v: Option<String>) -> String {
    v.unwrap_or_default()
}

fn escape_csv(value: &str) -> String {
    if value.contains(['"', ',', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn to_csv(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut lines = Vec::with_capacity(rows.len() + 1);
    lines.push(headers.iter().map(|h| escape_csv(h)).collect::<Vec<_>>().join(","));
    for row in rows {
        lines.push(row.iter().map(|c| escape_csv(c)).collect::<Vec<_>>().join(","));
    }
    format!("{}\n", lines.join("\n"))
}

fn checksum(csv: &str) -> String {
    let digest = Sha256::digest(csv.as_bytes());
    format!("sha256:{:x}", digest)
}

/// Parse + validate the from/to/invoiceId filters the way the Adonis service does.
fn validate_query(q: &ExportQuery) -> AppResult<()> {
    let parse_date = |val: &Option<String>, name: &str| -> AppResult<Option<String>> {
        match val.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            None => Ok(None),
            Some(s) => {
                // Accept anything chrono can read as an ISO datetime.
                if chrono::DateTime::parse_from_rfc3339(s).is_err()
                    && chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").is_err()
                    && chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_err()
                {
                    return Err(AppError::commerce(
                        422,
                        format!("Payment operations export `{name}` date must be a valid ISO date."),
                    ));
                }
                Ok(Some(s.to_string()))
            }
        }
    };
    let from = parse_date(&q.from, "from")?;
    let to = parse_date(&q.to, "to")?;
    if let (Some(f), Some(t)) = (&from, &to) {
        if f > t {
            return Err(AppError::commerce(
                422,
                "Payment operations export `from` date must be before or equal to `to` date.",
            ));
        }
    }
    if let Some(raw) = q.invoice_id.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        match raw.parse::<i64>() {
            Ok(n) if n > 0 => {}
            _ => {
                return Err(AppError::commerce(
                    422,
                    "Payment operations export `invoiceId` filter must be a positive integer.",
                ))
            }
        }
    }
    Ok(())
}

fn push_filters(sql: &mut String, binds: &mut Vec<Bind>, n: &mut usize, q: &ExportQuery, cols: &FilterCols) {
    if let Some(f) = q.from.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        sql.push_str(&format!(" AND {} >= ${n}", cols.date));
        *n += 1;
        binds.push(Bind::Str(f.to_string()));
    }
    if let Some(t) = q.to.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        sql.push_str(&format!(" AND {} <= ${n}", cols.date));
        *n += 1;
        binds.push(Bind::Str(t.to_string()));
    }
    let mut str_filter = |val: &Option<String>, col: Option<&str>| {
        if let (Some(col), Some(v)) = (col, val.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty())) {
            sql.push_str(&format!(" AND {col} = ${n}"));
            *n += 1;
            binds.push(Bind::Str(v.to_string()));
        }
    };
    str_filter(&q.status, cols.status);
    str_filter(&q.network, cols.network);
    str_filter(&q.asset_id, cols.asset_id);
    str_filter(&q.payment_address, cols.payment_address);
    str_filter(&q.public_id, cols.public_id);
    str_filter(&q.external_id, cols.external_id);
    if let (Some(col), Some(v)) =
        (cols.invoice_id, q.invoice_id.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()))
    {
        if let Ok(parsed) = v.parse::<i64>() {
            sql.push_str(&format!(" AND {col} = ${n}"));
            *n += 1;
            binds.push(Bind::Int(parsed));
        }
    }
}

struct FilterCols {
    date: &'static str,
    status: Option<&'static str>,
    network: Option<&'static str>,
    asset_id: Option<&'static str>,
    payment_address: Option<&'static str>,
    public_id: Option<&'static str>,
    external_id: Option<&'static str>,
    invoice_id: Option<&'static str>,
}

async fn fetch_rows(
    state: &AppState,
    sql: String,
    binds: Vec<Bind>,
) -> AppResult<Vec<sqlx::postgres::PgRow>> {
    let mut q = sqlx::query(&sql);
    for b in binds {
        q = match b {
            Bind::Str(s) => q.bind(s),
            Bind::Int(i) => q.bind(i),
        };
    }
    Ok(q.fetch_all(&state.db.pool).await?)
}

fn too_broad(kind: &str) -> AppError {
    AppError::commerce(
        422,
        format!("Payment operations {kind} export is too broad. Narrow filters to 10,000 rows or fewer."),
    )
}

// ---- per-kind CSV builders -------------------------------------------------

use sqlx::Row as _;

fn opt_int(row: &sqlx::postgres::PgRow, idx: &str) -> Option<String> {
    row.try_get::<Option<i64>, _>(idx).ok().flatten().map(|v| v.to_string())
}
fn opt_str(row: &sqlx::postgres::PgRow, idx: &str) -> Option<String> {
    row.try_get::<Option<String>, _>(idx).ok().flatten()
}
fn req_int(row: &sqlx::postgres::PgRow, idx: &str) -> Option<String> {
    Some(row.try_get::<i64, _>(idx).unwrap_or_default().to_string())
}

async fn build_invoices_csv(
    state: &AppState,
    user_id: i64,
    q: &ExportQuery,
) -> AppResult<(String, i64)> {
    let mut sql = String::from(
        "SELECT id, public_id, external_id, status, payment_network, payment_asset, payment_address, \
         payment_reference, subtotal_amount, total_amount, currency, pricing_country_code, \
         (SELECT string_agg(ps, ',') FROM (SELECT DISTINCT ii.pricing_source AS ps FROM invoice_items ii \
            WHERE ii.invoice_id = invoices.id AND ii.pricing_source IS NOT NULL ORDER BY ii.pricing_source) sub) \
            AS regional_pricing_sources, \
         expires_at, paid_at, cancelled_at, created_at, updated_at \
         FROM invoices WHERE user_id = $1",
    );
    let mut n = 2;
    let mut binds = vec![Bind::Int(user_id)];
    if let Some(s) = q.store_id.as_ref().and_then(|s| s.trim().parse::<i64>().ok()) {
        sql.push_str(&format!(" AND store_id = ${n}"));
        n += 1;
        binds.push(Bind::Int(s));
    }
    push_filters(
        &mut sql,
        &mut binds,
        &mut n,
        q,
        &FilterCols {
            date: "created_at",
            status: Some("status"),
            network: Some("payment_network"),
            asset_id: Some("payment_asset"),
            payment_address: Some("payment_address"),
            public_id: Some("public_id"),
            external_id: Some("external_id"),
            invoice_id: Some("id"),
        },
    );
    sql.push_str(&format!(" ORDER BY created_at DESC, id DESC LIMIT {}", EXPORT_LIMIT + 1));
    let rows = fetch_rows(state, sql, binds).await?;
    if rows.len() as i64 > EXPORT_LIMIT {
        return Err(too_broad("invoices"));
    }
    let headers = [
        "id", "public_id", "external_id", "status", "payment_network", "payment_asset",
        "payment_address", "payment_reference", "subtotal_amount", "total_amount", "currency",
        "pricing_country_code", "regional_pricing_sources", "expires_at", "paid_at", "cancelled_at",
        "created_at", "updated_at",
    ];
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                cell(req_int(r, "id")),
                cell(opt_str(r, "public_id")),
                cell(opt_str(r, "external_id")),
                cell(opt_str(r, "status")),
                cell(opt_str(r, "payment_network")),
                cell(opt_str(r, "payment_asset")),
                cell(opt_str(r, "payment_address")),
                cell(opt_str(r, "payment_reference")),
                cell(req_int(r, "subtotal_amount")),
                cell(req_int(r, "total_amount")),
                cell(opt_str(r, "currency")),
                cell(opt_str(r, "pricing_country_code")),
                cell(opt_str(r, "regional_pricing_sources")),
                cell(opt_str(r, "expires_at")),
                cell(opt_str(r, "paid_at")),
                cell(opt_str(r, "cancelled_at")),
                cell(opt_str(r, "created_at")),
                cell(opt_str(r, "updated_at")),
            ]
        })
        .collect();
    Ok((to_csv(&headers, &body), rows.len() as i64))
}

async fn build_observations_csv(
    state: &AppState,
    user_id: i64,
    q: &ExportQuery,
) -> AppResult<(String, i64)> {
    let mut sql = String::from(
        "SELECT po.id, po.network, po.asset_id, po.tx_id, po.output_index, po.payment_address, \
         po.amount, po.payer_address, po.invoice_id, i.public_id AS invoice_public_id, po.block_hash, \
         po.block_daa_score, po.confirmations, po.status, po.accepted_at, po.matched_at, po.settled_at, \
         po.created_at, po.updated_at \
         FROM payment_observations po LEFT JOIN invoices i ON i.id = po.invoice_id \
         WHERE EXISTS (SELECT 1 FROM invoices owner_invoice WHERE owner_invoice.user_id = $1",
    );
    let mut n = 2;
    let mut binds = vec![Bind::Int(user_id)];
    if let Some(s) = q.store_id.as_ref().and_then(|s| s.trim().parse::<i64>().ok()) {
        sql.push_str(&format!(" AND owner_invoice.store_id = ${n}"));
        n += 1;
        binds.push(Bind::Int(s));
    }
    sql.push_str(
        " AND (po.invoice_id = owner_invoice.id OR (po.payment_address = owner_invoice.payment_address \
         AND po.network = owner_invoice.payment_network AND po.asset_id = owner_invoice.payment_asset)))",
    );
    push_filters(
        &mut sql,
        &mut binds,
        &mut n,
        q,
        &FilterCols {
            date: "COALESCE(po.accepted_at, po.created_at)",
            status: Some("po.status"),
            network: Some("po.network"),
            asset_id: Some("po.asset_id"),
            payment_address: Some("po.payment_address"),
            public_id: None,
            external_id: None,
            invoice_id: Some("po.invoice_id"),
        },
    );
    sql.push_str(&format!(
        " ORDER BY COALESCE(po.accepted_at, po.created_at) DESC, po.id DESC LIMIT {}",
        EXPORT_LIMIT + 1
    ));
    let rows = fetch_rows(state, sql, binds).await?;
    if rows.len() as i64 > EXPORT_LIMIT {
        return Err(too_broad("observations"));
    }
    let headers = [
        "id", "network", "asset_id", "tx_id", "output_index", "payment_address", "amount",
        "payer_address", "invoice_id", "invoice_public_id", "block_hash", "block_daa_score",
        "confirmations", "status", "accepted_at", "matched_at", "settled_at", "created_at",
        "updated_at",
    ];
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                cell(req_int(r, "id")),
                cell(opt_str(r, "network")),
                cell(opt_str(r, "asset_id")),
                cell(opt_str(r, "tx_id")),
                cell(opt_int(r, "output_index")),
                cell(opt_str(r, "payment_address")),
                cell(req_int(r, "amount")),
                cell(opt_str(r, "payer_address")),
                cell(opt_int(r, "invoice_id")),
                cell(opt_str(r, "invoice_public_id")),
                cell(opt_str(r, "block_hash")),
                cell(opt_int(r, "block_daa_score")),
                cell(req_int(r, "confirmations")),
                cell(opt_str(r, "status")),
                cell(opt_str(r, "accepted_at")),
                cell(opt_str(r, "matched_at")),
                cell(opt_str(r, "settled_at")),
                cell(opt_str(r, "created_at")),
                cell(opt_str(r, "updated_at")),
            ]
        })
        .collect();
    Ok((to_csv(&headers, &body), rows.len() as i64))
}

async fn build_credits_csv(
    state: &AppState,
    user_id: i64,
    q: &ExportQuery,
) -> AppResult<(String, i64)> {
    let mut sql = String::from(
        "SELECT pc.id, pc.payment_observation_id, pc.invoice_id, i.public_id AS invoice_public_id, \
         pc.network, pc.asset_id, pc.amount, pc.credited_at, pc.created_at, pc.updated_at \
         FROM payment_credits pc LEFT JOIN invoices i ON i.id = pc.invoice_id WHERE pc.user_id = $1",
    );
    let mut n = 2;
    let mut binds = vec![Bind::Int(user_id)];
    if let Some(s) = q.store_id.as_ref().and_then(|s| s.trim().parse::<i64>().ok()) {
        sql.push_str(&format!(" AND i.store_id = ${n}"));
        n += 1;
        binds.push(Bind::Int(s));
    }
    push_filters(
        &mut sql,
        &mut binds,
        &mut n,
        q,
        &FilterCols {
            date: "pc.credited_at",
            status: None,
            network: Some("pc.network"),
            asset_id: Some("pc.asset_id"),
            payment_address: None,
            public_id: None,
            external_id: None,
            invoice_id: Some("pc.invoice_id"),
        },
    );
    sql.push_str(&format!(" ORDER BY pc.credited_at DESC, pc.id DESC LIMIT {}", EXPORT_LIMIT + 1));
    let rows = fetch_rows(state, sql, binds).await?;
    if rows.len() as i64 > EXPORT_LIMIT {
        return Err(too_broad("credits"));
    }
    let headers = [
        "id", "payment_observation_id", "invoice_id", "invoice_public_id", "network", "asset_id",
        "amount", "credited_at", "created_at", "updated_at",
    ];
    let body: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                cell(req_int(r, "id")),
                cell(opt_int(r, "payment_observation_id")),
                cell(opt_int(r, "invoice_id")),
                cell(opt_str(r, "invoice_public_id")),
                cell(opt_str(r, "network")),
                cell(opt_str(r, "asset_id")),
                cell(req_int(r, "amount")),
                cell(opt_str(r, "credited_at")),
                cell(opt_str(r, "created_at")),
                cell(opt_str(r, "updated_at")),
            ]
        })
        .collect();
    Ok((to_csv(&headers, &body), rows.len() as i64))
}

// ---- manifest persistence + serialization ----------------------------------

fn normalize_filters(q: &ExportQuery) -> Value {
    let mut map = serde_json::Map::new();
    let mut put = |k: &str, v: &Option<String>| {
        if let Some(s) = v.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            map.insert(k.to_string(), json!(s));
        }
    };
    put("from", &q.from);
    put("to", &q.to);
    put("status", &q.status);
    put("network", &q.network);
    put("assetId", &q.asset_id);
    put("invoiceId", &q.invoice_id);
    put("paymentAddress", &q.payment_address);
    put("publicId", &q.public_id);
    put("externalId", &q.external_id);
    put("storeId", &q.store_id);
    Value::Object(map)
}

async fn insert_manifest(
    state: &AppState,
    user_id: i64,
    kind: &str,
    format: &str,
    status: &str,
    filters: &Value,
    row_count: i64,
    checksum: &str,
    actor_id: i64,
) -> AppResult<i64> {
    let now = now_iso();
    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO payment_operation_exports \
         (user_id, kind, format, profile_id, filters, mapping_metadata, row_count, checksum, status, \
          actor_type, actor_id, generated_at, created_at, updated_at) \
         VALUES ($1, $2, $3, NULL, $4, '{}', $5, $6, $7, 'merchant', $8, $9, $10, $11) RETURNING id",
    )
    .bind(user_id)
    .bind(kind)
    .bind(format)
    .bind(filters.to_string())
    .bind(row_count)
    .bind(checksum)
    .bind(status)
    .bind(actor_id.to_string())
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .fetch_one(&state.db.pool)
    .await?;
    Ok(id)
}

#[derive(sqlx::FromRow)]
struct ManifestRow {
    id: i64,
    user_id: i64,
    kind: String,
    format: String,
    profile_id: Option<i64>,
    filters: Option<String>,
    mapping_metadata: Option<String>,
    row_count: i64,
    checksum: String,
    status: String,
    storage_disk: Option<String>,
    storage_path: Option<String>,
    content_type: Option<String>,
    byte_size: Option<i64>,
    expires_at: Option<String>,
    error: Option<String>,
    actor_type: String,
    actor_id: Option<String>,
    generated_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

fn serialize_manifest(m: &ManifestRow) -> Value {
    let parse = |s: &Option<String>| -> Value {
        s.as_ref().and_then(|v| serde_json::from_str(v).ok()).unwrap_or(json!({}))
    };
    json!({
        "id": m.id,
        "userId": m.user_id,
        "kind": m.kind,
        "format": m.format,
        "profileId": m.profile_id,
        "filters": parse(&m.filters),
        "mappingMetadata": parse(&m.mapping_metadata),
        "rowCount": m.row_count,
        "checksum": m.checksum,
        "status": m.status,
        "storageDisk": m.storage_disk,
        "storagePath": m.storage_path,
        "contentType": m.content_type,
        "byteSize": m.byte_size.map(|b| b.to_string()),
        "expiresAt": m.expires_at,
        "error": m.error,
        "actorType": m.actor_type,
        "actorId": m.actor_id,
        "generatedAt": m.generated_at,
        "createdAt": m.created_at,
        "updatedAt": m.updated_at,
    })
}

async fn load_manifest(state: &AppState, user_id: i64, id: i64) -> AppResult<Option<ManifestRow>> {
    Ok(sqlx::query_as::<_, ManifestRow>(
        "SELECT * FROM payment_operation_exports WHERE user_id = $1 AND id = $2",
    )
    .bind(user_id)
    .bind(id)
    .fetch_optional(&state.db.pool)
    .await?)
}

fn csv_response(filename: &str, id: i64, checksum: &str, row_count: i64, csv: String) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/csv; charset=utf-8"));
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")).unwrap(),
    );
    headers.insert("x-kasway-export-id", HeaderValue::from_str(&id.to_string()).unwrap());
    headers.insert("x-kasway-export-checksum", HeaderValue::from_str(checksum).unwrap());
    headers.insert("x-kasway-export-row-count", HeaderValue::from_str(&row_count.to_string()).unwrap());
    (StatusCode::OK, headers, csv).into_response()
}

// ---- handlers --------------------------------------------------------------

macro_rules! csv_handler {
    ($name:ident, $build:ident, $kind:literal, $file:literal) => {
        pub async fn $name(
            auth: AuthMerchant,
            State(state): State<AppState>,
            Query(q): Query<ExportQuery>,
        ) -> AppResult<Response> {
            validate_query(&q)?;
            let (csv, row_count) = $build(&state, auth.user_id, &q).await?;
            let sum = checksum(&csv);
            let filters = normalize_filters(&q);
            let id = insert_manifest(
                &state, auth.user_id, $kind, "csv", "succeeded", &filters, row_count, &sum, auth.user_id,
            )
            .await?;
            Ok(csv_response($file, id, &sum, row_count, csv))
        }
    };
}

csv_handler!(invoices, build_invoices_csv, "invoices", "invoices.csv");
csv_handler!(observations, build_observations_csv, "observations", "observations.csv");
csv_handler!(credits, build_credits_csv, "credits", "credits.csv");

#[derive(Deserialize, Default)]
pub struct ListQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
}

pub async fn index(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).clamp(1, 100);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_operation_exports WHERE user_id = $1")
        .bind(auth.user_id)
        .fetch_one(&state.db.pool)
        .await?;
    let rows = sqlx::query_as::<_, ManifestRow>(
        "SELECT * FROM payment_operation_exports WHERE user_id = $1 ORDER BY generated_at DESC, id DESC LIMIT $2 OFFSET $3",
    )
    .bind(auth.user_id)
    .bind(per_page)
    .bind((page - 1) * per_page)
    .fetch_all(&state.db.pool)
    .await?;
    let data: Vec<Value> = rows.iter().map(serialize_manifest).collect();
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}

#[derive(Deserialize)]
pub struct StoreBody {
    kind: Option<String>,
    format: Option<String>,
    #[serde(rename = "profileId")]
    profile_id: Option<i64>,
    filters: Option<ExportQuery>,
}

pub async fn store(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Json(body): Json<StoreBody>,
) -> AppResult<Response> {
    let kind = body.kind.as_deref().unwrap_or("");
    if !matches!(kind, "invoices" | "observations" | "credits") {
        return Err(AppError::validation_field("kind", "enum", "The selected kind is invalid"));
    }
    let format = body.format.as_deref().unwrap_or("csv");
    if !matches!(format, "csv" | "json" | "quickbooks_csv" | "xero_csv") {
        return Err(AppError::validation_field("format", "enum", "The selected format is invalid"));
    }
    if let Some(p) = body.profile_id {
        if p <= 0 {
            return Err(AppError::validation_field("profileId", "positive", "The profileId field must be positive"));
        }
    }
    let filters_q = body.filters.unwrap_or_default();
    let filters = normalize_filters(&filters_q);
    let id = insert_manifest(
        &state, auth.user_id, kind, format, "queued", &filters, 0, "", auth.user_id,
    )
    .await?;
    let m = load_manifest(&state, auth.user_id, id).await?.expect("just inserted");
    Ok((StatusCode::ACCEPTED, Json(serialize_manifest(&m))).into_response())
}

pub async fn show(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let id: i64 = id.parse().map_err(|_| AppError::commerce(404, "Payment operation export not found"))?;
    let m = load_manifest(&state, auth.user_id, id)
        .await?
        .ok_or_else(|| AppError::commerce(404, "Payment operation export not found"))?;
    Ok(Json(serialize_manifest(&m)))
}

pub async fn download(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let id: i64 = id.parse().map_err(|_| AppError::commerce(404, "Payment operation export not found"))?;
    let m = load_manifest(&state, auth.user_id, id)
        .await?
        .ok_or_else(|| AppError::commerce(404, "Payment operation export not found"))?;
    if m.status != "succeeded" || m.storage_path.is_none() {
        return Err(AppError::commerce(422, "Payment operation export is not downloadable"));
    }
    // The drive-backed byte fetch is external; manifests produced here never set
    // storage_path, so this branch is unreachable in the ported surface.
    Err(AppError::commerce(410, "Payment operation export has expired"))
}
