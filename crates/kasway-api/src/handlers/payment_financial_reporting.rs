//! `/api/payments/ops/reporting-categories` + `/accounting-profiles`
//! — PaymentReportingCategoriesController + PaymentAccountingProfilesController.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::state::AppState;
use crate::util::{now_iso, paginator_meta};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

const CATEGORY_TYPES: &[&str] = &["tax", "platform_fee", "merchant_fee", "discount", "other"];
const CALC_MODES: &[&str] = &["manual", "percentage", "fixed"];
const CURRENCY_HANDLING: &[&str] = &["source", "home_currency"];

#[derive(Deserialize, Default)]
pub struct PageQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
}

fn vf(field: &str, rule: &str, msg: &str) -> AppError {
    AppError::Validation(vec![ValidationFailure { message: msg.into(), rule: rule.into(), field: field.into() }])
}

// ---------------- reporting categories ----------------

#[derive(sqlx::FromRow)]
struct CategoryRow {
    id: i64,
    user_id: i64,
    label: String,
    code: String,
    r#type: String,
    calculation_mode: String,
    rate: Option<String>,
    amount: Option<i64>,
    is_active: bool,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const CATEGORY_COLS: &str = "id, user_id, label, code, type, calculation_mode, rate, amount, is_active, created_at, updated_at";

fn serialize_category(c: &CategoryRow) -> Value {
    json!({
        "id": c.id,
        "userId": c.user_id,
        "label": c.label,
        "code": c.code,
        "type": c.r#type,
        "calculationMode": c.calculation_mode,
        "rate": c.rate,
        "amount": c.amount.map(|a| a.to_string()),
        "isActive": c.is_active,
        "createdAt": c.created_at,
        "updatedAt": c.updated_at,
    })
}

fn validate_category(body: &Value) -> AppResult<(String, String, String, String, Option<String>, Option<i64>, bool)> {
    let label = body.get("label").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty() && s.chars().count() <= 120)
        .ok_or_else(|| vf("label", "required", "The label field is required"))?;
    let code = body.get("code").and_then(|v| v.as_str()).map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-')))
        .ok_or_else(|| vf("code", "regex", "The code field format is invalid"))?;
    let type_ = body.get("type").and_then(|v| v.as_str()).filter(|s| CATEGORY_TYPES.contains(s))
        .ok_or_else(|| vf("type", "enum", "The selected type is invalid"))?.to_string();
    let calc = body.get("calculationMode").and_then(|v| v.as_str()).filter(|s| CALC_MODES.contains(s))
        .ok_or_else(|| vf("calculationMode", "enum", "The selected calculationMode is invalid"))?.to_string();
    let rate = body.get("rate").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let amount = match body.get("amount") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s == "0" || (!s.is_empty() && !s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit())) => Some(s.parse().unwrap_or(0)),
        Some(_) => return Err(vf("amount", "regex", "The amount field format is invalid")),
    };
    let is_active = body.get("isActive").and_then(|v| v.as_bool()).unwrap_or(true);
    Ok((label, code, type_, calc, rate, amount, is_active))
}

async fn category_code_taken(state: &AppState, user_id: i64, code: &str, except: Option<i64>) -> AppResult<bool> {
    let found: Option<i64> = sqlx::query_scalar("SELECT id FROM payment_reporting_categories WHERE user_id = ? AND code = ? AND id != ?")
        .bind(user_id).bind(code).bind(except.unwrap_or(0)).fetch_optional(&state.db.pool).await?;
    Ok(found.is_some())
}

async fn load_category(state: &AppState, user_id: i64, id: i64) -> AppResult<CategoryRow> {
    sqlx::query_as::<_, CategoryRow>(&format!("SELECT {CATEGORY_COLS} FROM payment_reporting_categories WHERE user_id = ? AND id = ?"))
        .bind(user_id).bind(id).fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::commerce(404, "Payment reporting category not found"))
}

pub async fn categories_index(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<PageQuery>) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).max(1);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_reporting_categories WHERE user_id = ?").bind(auth.user_id).fetch_one(&state.db.pool).await?;
    let rows = sqlx::query_as::<_, CategoryRow>(&format!("SELECT {CATEGORY_COLS} FROM payment_reporting_categories WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?"))
        .bind(auth.user_id).bind(per_page).bind((page - 1) * per_page).fetch_all(&state.db.pool).await?;
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": rows.iter().map(serialize_category).collect::<Vec<_>>() })))
}

pub async fn categories_store(auth: AuthMerchant, State(state): State<AppState>, Json(body): Json<Value>) -> AppResult<(StatusCode, Json<Value>)> {
    let (label, code, type_, calc, rate, amount, is_active) = validate_category(&body)?;
    if category_code_taken(&state, auth.user_id, &code, None).await? {
        return Err(AppError::commerce(422, &format!("Reporting category code '{code}' already exists")));
    }
    let now = now_iso();
    let r = sqlx::query("INSERT INTO payment_reporting_categories (user_id, label, code, type, calculation_mode, rate, amount, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(auth.user_id).bind(&label).bind(&code).bind(&type_).bind(&calc).bind(&rate).bind(amount).bind(is_active as i64).bind(&now).bind(&now)
        .execute(&state.db.pool).await?;
    Ok((StatusCode::CREATED, Json(serialize_category(&load_category(&state, auth.user_id, r.last_insert_rowid()).await?))))
}

pub async fn categories_update(auth: AuthMerchant, State(state): State<AppState>, Path(id): Path<i64>, Json(body): Json<Value>) -> AppResult<Json<Value>> {
    let cat = load_category(&state, auth.user_id, id).await?;
    let (label, code, type_, calc, rate, amount, is_active) = validate_category(&body)?;
    if code != cat.code && category_code_taken(&state, auth.user_id, &code, Some(cat.id)).await? {
        return Err(AppError::commerce(422, &format!("Reporting category code '{code}' already exists")));
    }
    sqlx::query("UPDATE payment_reporting_categories SET label = ?, code = ?, type = ?, calculation_mode = ?, rate = ?, amount = ?, is_active = ?, updated_at = ? WHERE id = ?")
        .bind(&label).bind(&code).bind(&type_).bind(&calc).bind(&rate).bind(amount).bind(is_active as i64).bind(now_iso()).bind(cat.id)
        .execute(&state.db.pool).await?;
    Ok(Json(serialize_category(&load_category(&state, auth.user_id, id).await?)))
}

pub async fn categories_destroy(auth: AuthMerchant, State(state): State<AppState>, Path(id): Path<i64>) -> AppResult<Json<Value>> {
    let cat = load_category(&state, auth.user_id, id).await?;
    sqlx::query("UPDATE payment_reporting_categories SET is_active = 0, updated_at = ? WHERE id = ?").bind(now_iso()).bind(cat.id).execute(&state.db.pool).await?;
    Ok(Json(serialize_category(&load_category(&state, auth.user_id, id).await?)))
}

// ---------------- accounting profiles ----------------

#[derive(sqlx::FromRow)]
struct ProfileRow {
    id: i64,
    user_id: i64,
    name: String,
    account_codes: String,
    category_mappings: String,
    currency_handling: String,
    date_format: String,
    timezone: String,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const PROFILE_COLS: &str = "id, user_id, name, account_codes, category_mappings, currency_handling, date_format, timezone, created_at, updated_at";

fn serialize_profile(p: &ProfileRow) -> Value {
    json!({
        "id": p.id,
        "userId": p.user_id,
        "name": p.name,
        "accountCodes": serde_json::from_str::<Value>(&p.account_codes).unwrap_or(json!({})),
        "categoryMappings": serde_json::from_str::<Value>(&p.category_mappings).unwrap_or(json!({})),
        "currencyHandling": p.currency_handling,
        "dateFormat": p.date_format,
        "timezone": p.timezone,
        "createdAt": p.created_at,
        "updatedAt": p.updated_at,
    })
}

fn validate_profile(body: &Value) -> AppResult<(String, String, String, String, String, String)> {
    let name = body.get("name").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty() && s.chars().count() <= 120)
        .ok_or_else(|| vf("name", "required", "The name field is required"))?;
    let account_codes = body.get("accountCodes").filter(|v| v.is_object()).cloned().unwrap_or(json!({})).to_string();
    let category_mappings = body.get("categoryMappings").filter(|v| v.is_object()).cloned().unwrap_or(json!({})).to_string();
    let currency_handling = body.get("currencyHandling").and_then(|v| v.as_str()).filter(|s| CURRENCY_HANDLING.contains(s)).unwrap_or("source").to_string();
    let date_format = body.get("dateFormat").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "yyyy-MM-dd".into());
    let timezone = body.get("timezone").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "UTC".into());
    Ok((name, account_codes, category_mappings, currency_handling, date_format, timezone))
}

async fn profile_name_taken(state: &AppState, user_id: i64, name: &str, except: Option<i64>) -> AppResult<bool> {
    let found: Option<i64> = sqlx::query_scalar("SELECT id FROM payment_accounting_profiles WHERE user_id = ? AND name = ? AND id != ?")
        .bind(user_id).bind(name).bind(except.unwrap_or(0)).fetch_optional(&state.db.pool).await?;
    Ok(found.is_some())
}

async fn load_profile(state: &AppState, user_id: i64, id: i64) -> AppResult<ProfileRow> {
    sqlx::query_as::<_, ProfileRow>(&format!("SELECT {PROFILE_COLS} FROM payment_accounting_profiles WHERE user_id = ? AND id = ?"))
        .bind(user_id).bind(id).fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::commerce(404, "Payment accounting profile not found"))
}

pub async fn profiles_index(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<PageQuery>) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).max(1);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_accounting_profiles WHERE user_id = ?").bind(auth.user_id).fetch_one(&state.db.pool).await?;
    let rows = sqlx::query_as::<_, ProfileRow>(&format!("SELECT {PROFILE_COLS} FROM payment_accounting_profiles WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?"))
        .bind(auth.user_id).bind(per_page).bind((page - 1) * per_page).fetch_all(&state.db.pool).await?;
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": rows.iter().map(serialize_profile).collect::<Vec<_>>() })))
}

pub async fn profiles_store(auth: AuthMerchant, State(state): State<AppState>, Json(body): Json<Value>) -> AppResult<(StatusCode, Json<Value>)> {
    let (name, ac, cm, ch, df, tz) = validate_profile(&body)?;
    if profile_name_taken(&state, auth.user_id, &name, None).await? {
        return Err(AppError::commerce(422, &format!("Accounting profile '{name}' already exists")));
    }
    let now = now_iso();
    let r = sqlx::query("INSERT INTO payment_accounting_profiles (user_id, name, account_codes, category_mappings, currency_handling, date_format, timezone, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(auth.user_id).bind(&name).bind(&ac).bind(&cm).bind(&ch).bind(&df).bind(&tz).bind(&now).bind(&now)
        .execute(&state.db.pool).await?;
    Ok((StatusCode::CREATED, Json(serialize_profile(&load_profile(&state, auth.user_id, r.last_insert_rowid()).await?))))
}

pub async fn profiles_update(auth: AuthMerchant, State(state): State<AppState>, Path(id): Path<i64>, Json(body): Json<Value>) -> AppResult<Json<Value>> {
    let profile = load_profile(&state, auth.user_id, id).await?;
    let (name, ac, cm, ch, df, tz) = validate_profile(&body)?;
    if name != profile.name && profile_name_taken(&state, auth.user_id, &name, Some(profile.id)).await? {
        return Err(AppError::commerce(422, &format!("Accounting profile '{name}' already exists")));
    }
    sqlx::query("UPDATE payment_accounting_profiles SET name = ?, account_codes = ?, category_mappings = ?, currency_handling = ?, date_format = ?, timezone = ?, updated_at = ? WHERE id = ?")
        .bind(&name).bind(&ac).bind(&cm).bind(&ch).bind(&df).bind(&tz).bind(now_iso()).bind(profile.id)
        .execute(&state.db.pool).await?;
    Ok(Json(serialize_profile(&load_profile(&state, auth.user_id, id).await?)))
}
