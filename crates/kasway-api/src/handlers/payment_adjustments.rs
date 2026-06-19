//! `/api/payments/ops/invoices/:id/adjustments` + `/adjustments/:id`
//! — PaymentAdjustmentsController + PaymentAdjustmentService.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::handlers::invoices;
use crate::state::AppState;
use crate::util::now_iso;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

const KINDS: &[&str] = &["manual_credit", "write_off", "refund_record", "correction"];
const DIRECTIONS: &[&str] = &["credit", "debit"];

#[derive(Deserialize, Default)]
pub struct PageQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct AdjRow {
    id: i64,
    user_id: i64,
    invoice_id: i64,
    kind: String,
    direction: String,
    amount: i64,
    currency: String,
    network: Option<String>,
    asset_id: Option<String>,
    external_reference: Option<String>,
    reporting_category_code: Option<String>,
    accounting_date: Option<String>,
    reason: String,
    metadata: String,
    created_by_user_id: i64,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const ADJ_COLS: &str = "id, user_id, invoice_id, kind, direction, amount, currency, network, asset_id, \
    external_reference, reporting_category_code, accounting_date, reason, metadata, created_by_user_id, created_at, updated_at";

fn serialize_adj(a: &AdjRow, invoice: Option<Value>) -> Value {
    let mut obj = json!({
        "id": a.id,
        "userId": a.user_id,
        "invoiceId": a.invoice_id,
        "kind": a.kind,
        "direction": a.direction,
        "amount": a.amount.to_string(),
        "currency": a.currency,
        "network": a.network,
        "assetId": a.asset_id,
        "externalReference": a.external_reference,
        "reportingCategoryCode": a.reporting_category_code,
        "accountingDate": a.accounting_date,
        "reason": a.reason,
        "metadata": serde_json::from_str::<Value>(&a.metadata).unwrap_or(json!({})),
        "createdByUserId": a.created_by_user_id,
        "createdAt": a.created_at,
        "updatedAt": a.updated_at,
    });
    if let (Value::Object(m), Some(inv)) = (&mut obj, invoice) {
        m.insert("invoice".into(), inv);
    }
    obj
}

/// invoiceForMerchant: by numeric id or public_id, user-scoped.
async fn invoice_for_merchant(state: &AppState, user_id: i64, id_param: &str) -> AppResult<i64> {
    let found: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM invoices WHERE user_id = ? AND (CAST(id AS TEXT) = ? OR public_id = ?)",
    )
    .bind(user_id)
    .bind(id_param)
    .bind(id_param)
    .fetch_optional(&state.db.pool)
    .await?;
    found.ok_or_else(|| AppError::commerce(404, "Invoice not found"))
}

pub async fn index(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<PageQuery>,
) -> AppResult<Json<Value>> {
    let invoice_id = invoice_for_merchant(&state, auth.user_id, &id).await?;
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).max(1);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_adjustments WHERE user_id = ? AND invoice_id = ?")
        .bind(auth.user_id).bind(invoice_id).fetch_one(&state.db.pool).await?;
    let rows = sqlx::query_as::<_, AdjRow>(&format!("SELECT {ADJ_COLS} FROM payment_adjustments WHERE user_id = ? AND invoice_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?"))
        .bind(auth.user_id).bind(invoice_id).bind(per_page).bind((page - 1) * per_page).fetch_all(&state.db.pool).await?;
    Ok(Json(json!({
        "meta": crate::util::paginator_meta(total, per_page, page),
        "data": rows.iter().map(|a| serialize_adj(a, None)).collect::<Vec<_>>(),
    })))
}

pub async fn store(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<(StatusCode, Json<Value>)> {
    let invoice_id = invoice_for_merchant(&state, auth.user_id, &id).await?;

    // validation (createPaymentAdjustmentValidator)
    let kind = body.get("kind").and_then(|v| v.as_str()).filter(|s| KINDS.contains(s))
        .ok_or_else(|| vf("kind", "enum", "The selected kind is invalid"))?.to_string();
    let direction = body.get("direction").and_then(|v| v.as_str()).filter(|s| DIRECTIONS.contains(s))
        .ok_or_else(|| vf("direction", "enum", "The selected direction is invalid"))?.to_string();
    let amount = body.get("amount").and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && !s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| vf("amount", "regex", "The amount field format is invalid"))?.to_string();
    let currency = body.get("currency").and_then(|v| v.as_str()).map(|s| s.trim().to_string())
        .filter(|s| s.len() >= 2 && s.len() <= 16)
        .ok_or_else(|| vf("currency", "minLength", "The currency field is invalid"))?;
    let reason = body.get("reason").and_then(|v| v.as_str()).map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.chars().count() <= 2000)
        .ok_or_else(|| vf("reason", "required", "The reason field is required"))?;
    let external_reference = opt_str(&body, "externalReference");
    let reporting_category_code = opt_str(&body, "reportingCategoryCode");
    let metadata = body.get("metadata").filter(|v| v.is_object()).cloned().unwrap_or(json!({}));

    // tenant settings: allowed manual adjustment kinds (default = all 4)
    let allowed: Option<String> = sqlx::query_scalar("SELECT allowed_manual_adjustment_kinds FROM payment_tenant_settings WHERE user_id = ?")
        .bind(auth.user_id).fetch_optional(&state.db.pool).await?;
    let allowed_kinds: Vec<String> = allowed.and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| KINDS.iter().map(|s| s.to_string()).collect());
    if !allowed_kinds.contains(&kind) {
        return Err(AppError::commerce(422, &format!("Manual adjustment kind '{kind}' is not allowed for this merchant")));
    }
    if kind == "refund_record" && external_reference.is_none() {
        return Err(AppError::commerce(422, "Refund record adjustments require an external reference"));
    }
    if kind == "correction" && metadata.as_object().map(|m| m.is_empty()).unwrap_or(true) {
        return Err(AppError::commerce(422, "Correction adjustments require metadata"));
    }
    // reporting category must be active when provided
    if let Some(code) = &reporting_category_code {
        let active: Option<i64> = sqlx::query_scalar("SELECT id FROM payment_reporting_categories WHERE user_id = ? AND code = ? AND is_active = 1")
            .bind(auth.user_id).bind(code).fetch_optional(&state.db.pool).await?;
        if active.is_none() {
            return Err(AppError::commerce(422, &format!("Reporting category '{code}' is not active")));
        }
    }
    // accounting date (default invoice created_at date)
    let accounting_date = match opt_str(&body, "accountingDate") {
        Some(d) => {
            let parsed = chrono::DateTime::parse_from_rfc3339(&d).map(|x| x.date_naive())
                .or_else(|_| chrono::NaiveDate::parse_from_str(&d, "%Y-%m-%d"));
            match parsed {
                Ok(date) => date.format("%Y-%m-%d").to_string(),
                Err(_) => return Err(AppError::commerce(422, "Adjustment accounting date must be a valid ISO date")),
            }
        }
        None => {
            let created: Option<String> = sqlx::query_scalar("SELECT created_at FROM invoices WHERE id = ?").bind(invoice_id).fetch_one(&state.db.pool).await?;
            created.and_then(|c| chrono::DateTime::parse_from_rfc3339(&c).ok()).map(|d| d.date_naive().format("%Y-%m-%d").to_string()).unwrap_or_else(|| "2026-01-01".into())
        }
    };
    // assertMutableAccountingDate (close periods) -> deferred no-op

    let now = now_iso();
    let r = sqlx::query(
        "INSERT INTO payment_adjustments (user_id, invoice_id, kind, direction, amount, currency, network, asset_id, external_reference, reporting_category_code, accounting_date, reason, metadata, created_by_user_id, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(auth.user_id).bind(invoice_id).bind(&kind).bind(&direction).bind(amount.parse::<i64>().unwrap_or(0)).bind(&currency)
    .bind(opt_str(&body, "network")).bind(opt_str(&body, "assetId")).bind(&external_reference).bind(&reporting_category_code)
    .bind(&accounting_date).bind(&reason).bind(metadata.to_string()).bind(auth.user_id).bind(&now).bind(&now)
    .execute(&state.db.pool).await?;

    let adj = sqlx::query_as::<_, AdjRow>(&format!("SELECT {ADJ_COLS} FROM payment_adjustments WHERE id = ?")).bind(r.last_insert_rowid()).fetch_one(&state.db.pool).await?;
    Ok((StatusCode::CREATED, Json(serialize_adj(&adj, None))))
}

pub async fn show(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    let adj = sqlx::query_as::<_, AdjRow>(&format!("SELECT {ADJ_COLS} FROM payment_adjustments WHERE user_id = ? AND id = ?"))
        .bind(auth.user_id).bind(id).fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::commerce(404, "Payment adjustment not found"))?;
    // preload invoice
    let inv = invoices::load_by_id(&state, adj.invoice_id).await.ok();
    let invoice = match inv {
        Some(inv) => {
            let (items, intent) = invoices::load_relations(&state, inv.id()).await?;
            Some(invoices::serialize_invoice(&inv, &items, intent.as_ref()))
        }
        None => None,
    };
    Ok(Json(serialize_adj(&adj, invoice)))
}

fn opt_str(body: &Value, key: &str) -> Option<String> {
    body.get(key).and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn vf(field: &str, rule: &str, msg: &str) -> AppError {
    AppError::Validation(vec![ValidationFailure { message: msg.into(), rule: rule.into(), field: field.into() }])
}
