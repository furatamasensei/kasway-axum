//! `/api/commerce/subscription-plans` + `/api/commerce/subscription-customers`
//! — CommerceSubscriptionPlansController / CommerceSubscriptionCustomersController.
//! (Subscriptions-proper billing endpoints are ported separately.)

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::handlers::invoices;
use crate::state::AppState;
use crate::util::{is_atomic_amount, json_or_null, now_iso, paginator_meta, random_hex, ser_amount, ser_json, to_iso};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const INTERVAL_UNITS: &[&str] = &["day", "week", "month", "year"];

#[derive(Deserialize, Default)]
pub struct PageQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
}

// ---------------- plans ----------------

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct PlanRow {
    id: i64,
    user_id: i64,
    public_id: String,
    external_id: Option<String>,
    status: String,
    name: String,
    description: Option<String>,
    #[serde(serialize_with = "ser_amount")]
    amount: i64,
    currency: String,
    payment_network: String,
    payment_asset: String,
    interval_unit: String,
    interval_count: i64,
    invoice_expires_after_seconds: Option<i64>,
    #[serde(serialize_with = "ser_json")]
    metadata: Option<String>,
    archived_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const PLAN_COLS: &str = "id, user_id, public_id, external_id, status, name, description, amount, \
    currency, payment_network, payment_asset, interval_unit, interval_count, \
    invoice_expires_after_seconds, metadata, archived_at, created_at, updated_at";

fn serialize_plan(p: &PlanRow) -> Value {
    serde_json::to_value(p).unwrap_or(Value::Null)
}

async fn load_plan(state: &AppState, user_id: i64, public_id: &str) -> AppResult<PlanRow> {
    sqlx::query_as::<_, PlanRow>(&format!("SELECT {PLAN_COLS} FROM subscription_plans WHERE user_id = $1 AND public_id = $2"))
        .bind(user_id).bind(public_id)
        .fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::commerce(404, "Subscription plan not found"))
}

async fn plan_external_id_taken(state: &AppState, user_id: i64, ext: &str, except: Option<i64>) -> AppResult<bool> {
    let found: Option<i64> = sqlx::query_scalar("SELECT id FROM subscription_plans WHERE user_id = $1 AND external_id = $2 AND id != $3")
        .bind(user_id).bind(ext).bind(except.unwrap_or(0))
        .fetch_optional(&state.db.pool).await?;
    Ok(found.is_some())
}

pub async fn plans_index(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<PageQuery>) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).clamp(1, 100_000);
    let per_page = q.per_page.unwrap_or(10).clamp(1, 100);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subscription_plans WHERE user_id = $1").bind(auth.user_id).fetch_one(&state.db.pool).await?;
    let rows = sqlx::query_as::<_, PlanRow>(&format!("SELECT {PLAN_COLS} FROM subscription_plans WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3"))
        .bind(auth.user_id).bind(per_page).bind((page - 1) * per_page).fetch_all(&state.db.pool).await?;
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": rows.iter().map(serialize_plan).collect::<Vec<_>>() })))
}

pub async fn plans_store(auth: AuthMerchant, State(state): State<AppState>, Json(body): Json<Value>) -> AppResult<(StatusCode, Json<Value>)> {
    let mut errors = Vec::new();
    let name = req_string(&body, "name", 1, 255, &mut errors);
    let amount = atomic_amount(&body, "amount", &mut errors);
    // Enforce the i64 range in addition to the atomic format.
    let amount_i64 = amount.as_deref().and_then(parse_atomic_i64);
    if amount.is_some() && amount_i64.is_none() {
        errors.push(ValidationFailure { message: "The amount field exceeds the maximum".into(), rule: "max".into(), field: "amount".into() });
    }
    validate_enum(&body, "intervalUnit", INTERVAL_UNITS, true, &mut errors);
    let interval_count = req_int(&body, "intervalCount", 1, 365, &mut errors);
    if !errors.is_empty() { return Err(AppError::Validation(errors)); }

    let external_id = opt_string(&body, "externalId");
    if let Some(ext) = &external_id {
        if plan_external_id_taken(&state, auth.user_id, ext, None).await? {
            return Err(AppError::commerce(422, "External id has already been used"));
        }
    }
    let asset = opt_string(&body, "paymentAsset").unwrap_or_else(|| state.config.kpr1.default_asset.clone());
    let network = opt_string(&body, "paymentNetwork").unwrap_or_else(|| state.config.kpr1.default_network.clone());
    let currency = opt_string(&body, "currency").unwrap_or_else(|| asset.clone());
    let now = now_iso();
    let public_id = format!("plan_{}", random_hex(16));

    sqlx::query(
        "INSERT INTO subscription_plans (user_id, public_id, external_id, status, name, description, amount, currency, payment_network, payment_asset, interval_unit, interval_count, invoice_expires_after_seconds, metadata, created_at, updated_at) \
         VALUES ($1, $2, $3, 'active', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind(auth.user_id).bind(&public_id).bind(&external_id).bind(name.unwrap())
    .bind(opt_string(&body, "description")).bind(amount_i64.unwrap())
    .bind(&currency).bind(&network).bind(&asset)
    .bind(body.get("intervalUnit").and_then(|v| v.as_str()).unwrap())
    .bind(interval_count.unwrap())
    .bind(body.get("invoiceExpiresAfterSeconds").and_then(|v| v.as_i64()))
    .bind(body.get("metadata").filter(|v| !v.is_null()).map(|m| m.to_string()))
    .bind(&now).bind(&now)
    .execute(&state.db.pool).await?;

    let plan = load_plan(&state, auth.user_id, &public_id).await?;
    Ok((StatusCode::CREATED, Json(serialize_plan(&plan))))
}

pub async fn plans_show(auth: AuthMerchant, State(state): State<AppState>, Path(public_id): Path<String>) -> AppResult<Json<Value>> {
    Ok(Json(serialize_plan(&load_plan(&state, auth.user_id, &public_id).await?)))
}

pub async fn plans_update(auth: AuthMerchant, State(state): State<AppState>, Path(public_id): Path<String>, Json(body): Json<Value>) -> AppResult<Json<Value>> {
    let plan = load_plan(&state, auth.user_id, &public_id).await?;
    if plan.status == "archived" {
        return Err(AppError::commerce(422, "Archived subscription plans cannot be updated"));
    }
    let now = now_iso();
    macro_rules! set_str { ($k:expr, $col:expr) => {
        if let Some(v) = body.get($k).and_then(|v| v.as_str()) {
            sqlx::query(&format!("UPDATE subscription_plans SET {} = $1, updated_at = $2 WHERE id = $3", $col)).bind(v).bind(&now).bind(plan.id).execute(&state.db.pool).await?;
        }
    }}
    set_str!("name", "name");
    set_str!("description", "description");
    set_str!("currency", "currency");
    set_str!("paymentNetwork", "payment_network");
    set_str!("paymentAsset", "payment_asset");
    // intervalUnit: apply the same enum check the create path uses.
    if let Some(v) = body.get("intervalUnit").and_then(|v| v.as_str()) {
        if !INTERVAL_UNITS.contains(&v) {
            return Err(AppError::Validation(vec![ValidationFailure { message: "The selected intervalUnit is invalid".into(), rule: "enum".into(), field: "intervalUnit".into() }]));
        }
        sqlx::query("UPDATE subscription_plans SET interval_unit = $1, updated_at = $2 WHERE id = $3").bind(v).bind(&now).bind(plan.id).execute(&state.db.pool).await?;
    }
    // amount: validate atomic format and i64 range instead of silently zeroing.
    if let Some(a) = body.get("amount").and_then(|v| v.as_str()) {
        if !is_atomic_amount(a) {
            return Err(AppError::Validation(vec![ValidationFailure { message: "The amount field format is invalid".into(), rule: "regex".into(), field: "amount".into() }]));
        }
        let amt = parse_atomic_i64(a).ok_or_else(|| AppError::commerce(422, "amount exceeds maximum"))?;
        sqlx::query("UPDATE subscription_plans SET amount = $1, updated_at = $2 WHERE id = $3").bind(amt).bind(&now).bind(plan.id).execute(&state.db.pool).await?;
    }
    // intervalCount: apply the same 1..=365 range the create path uses.
    if let Some(c) = body.get("intervalCount").and_then(|v| v.as_i64()) {
        if !(1..=365).contains(&c) {
            return Err(AppError::Validation(vec![ValidationFailure { message: "The intervalCount field is invalid".into(), rule: "range".into(), field: "intervalCount".into() }]));
        }
        sqlx::query("UPDATE subscription_plans SET interval_count = $1, updated_at = $2 WHERE id = $3").bind(c).bind(&now).bind(plan.id).execute(&state.db.pool).await?;
    }
    Ok(Json(serialize_plan(&load_plan(&state, auth.user_id, &public_id).await?)))
}

pub async fn plans_archive(auth: AuthMerchant, State(state): State<AppState>, Path(public_id): Path<String>) -> AppResult<Json<Value>> {
    let plan = load_plan(&state, auth.user_id, &public_id).await?;
    if plan.status != "archived" {
        let now = now_iso();
        sqlx::query("UPDATE subscription_plans SET status = 'archived', archived_at = $1, updated_at = $2 WHERE id = $3")
            .bind(&now).bind(&now).bind(plan.id).execute(&state.db.pool).await?;
    }
    Ok(Json(serialize_plan(&load_plan(&state, auth.user_id, &public_id).await?)))
}

// ---------------- customers ----------------

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct CustomerRow {
    id: i64,
    user_id: i64,
    public_id: String,
    external_id: Option<String>,
    email: Option<String>,
    name: Option<String>,
    #[serde(serialize_with = "ser_json")]
    metadata: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const CUSTOMER_COLS: &str = "id, user_id, public_id, external_id, email, name, metadata, created_at, updated_at";

fn serialize_customer(c: &CustomerRow) -> Value {
    serde_json::to_value(c).unwrap_or(Value::Null)
}

async fn load_customer(state: &AppState, user_id: i64, public_id: &str) -> AppResult<CustomerRow> {
    sqlx::query_as::<_, CustomerRow>(&format!("SELECT {CUSTOMER_COLS} FROM subscription_customers WHERE user_id = $1 AND public_id = $2"))
        .bind(user_id).bind(public_id)
        .fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::commerce(404, "Subscription customer not found"))
}

async fn customer_external_id_taken(state: &AppState, user_id: i64, ext: &str, except: Option<i64>) -> AppResult<bool> {
    let found: Option<i64> = sqlx::query_scalar("SELECT id FROM subscription_customers WHERE user_id = $1 AND external_id = $2 AND id != $3")
        .bind(user_id).bind(ext).bind(except.unwrap_or(0))
        .fetch_optional(&state.db.pool).await?;
    Ok(found.is_some())
}

pub async fn customers_index(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<PageQuery>) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).clamp(1, 100_000);
    let per_page = q.per_page.unwrap_or(10).clamp(1, 100);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subscription_customers WHERE user_id = $1").bind(auth.user_id).fetch_one(&state.db.pool).await?;
    let rows = sqlx::query_as::<_, CustomerRow>(&format!("SELECT {CUSTOMER_COLS} FROM subscription_customers WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3"))
        .bind(auth.user_id).bind(per_page).bind((page - 1) * per_page).fetch_all(&state.db.pool).await?;
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": rows.iter().map(serialize_customer).collect::<Vec<_>>() })))
}

pub async fn customers_store(auth: AuthMerchant, State(state): State<AppState>, Json(body): Json<Value>) -> AppResult<(StatusCode, Json<Value>)> {
    let external_id = opt_string(&body, "externalId");
    if let Some(ext) = &external_id {
        if customer_external_id_taken(&state, auth.user_id, ext, None).await? {
            return Err(AppError::commerce(422, "External id has already been used"));
        }
    }
    let now = now_iso();
    let public_id = format!("cus_{}", random_hex(16));
    sqlx::query(
        "INSERT INTO subscription_customers (user_id, public_id, external_id, email, name, metadata, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(auth.user_id).bind(&public_id).bind(&external_id)
    .bind(opt_string(&body, "email")).bind(opt_string(&body, "name"))
    .bind(body.get("metadata").filter(|v| !v.is_null()).map(|m| m.to_string()))
    .bind(&now).bind(&now)
    .execute(&state.db.pool).await?;
    Ok((StatusCode::CREATED, Json(serialize_customer(&load_customer(&state, auth.user_id, &public_id).await?))))
}

pub async fn customers_show(auth: AuthMerchant, State(state): State<AppState>, Path(public_id): Path<String>) -> AppResult<Json<Value>> {
    Ok(Json(serialize_customer(&load_customer(&state, auth.user_id, &public_id).await?)))
}

pub async fn customers_update(auth: AuthMerchant, State(state): State<AppState>, Path(public_id): Path<String>, Json(body): Json<Value>) -> AppResult<Json<Value>> {
    let c = load_customer(&state, auth.user_id, &public_id).await?;
    let now = now_iso();
    macro_rules! set_str { ($k:expr, $col:expr) => {
        if let Some(v) = body.get($k).and_then(|v| v.as_str()) {
            sqlx::query(&format!("UPDATE subscription_customers SET {} = $1, updated_at = $2 WHERE id = $3", $col)).bind(v).bind(&now).bind(c.id).execute(&state.db.pool).await?;
        }
    }}
    set_str!("externalId", "external_id");
    set_str!("email", "email");
    set_str!("name", "name");
    Ok(Json(serialize_customer(&load_customer(&state, auth.user_id, &public_id).await?)))
}

// ---------------- validation helpers ----------------

fn opt_string(body: &Value, key: &str) -> Option<String> {
    body.get(key).and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn req_string(body: &Value, key: &str, min: usize, max: usize, errors: &mut Vec<ValidationFailure>) -> Option<String> {
    match body.get(key).and_then(|v| v.as_str()) {
        Some(s) if s.trim().chars().count() >= min && s.trim().chars().count() <= max => Some(s.trim().to_string()),
        _ => { errors.push(ValidationFailure { message: format!("The {key} field is required"), rule: "required".into(), field: key.into() }); None }
    }
}

fn atomic_amount(body: &Value, key: &str, errors: &mut Vec<ValidationFailure>) -> Option<String> {
    match body.get(key) {
        Some(Value::String(s)) if is_atomic_amount(s) => Some(s.clone()),
        _ => { errors.push(ValidationFailure { message: format!("The {key} field format is invalid"), rule: "regex".into(), field: key.into() }); None }
    }
}

/// Parse an already-format-validated atomic string, enforcing the i64 range so
/// an over-range value can't silently become a free (0) plan via `as i64`.
fn parse_atomic_i64(s: &str) -> Option<i64> {
    s.parse::<i128>().ok().filter(|v| *v <= i64::MAX as i128).map(|v| v as i64)
}

fn req_int(body: &Value, key: &str, min: i64, max: i64, errors: &mut Vec<ValidationFailure>) -> Option<i64> {
    match body.get(key).and_then(|v| v.as_i64()) {
        Some(n) if n >= min && n <= max => Some(n),
        _ => { errors.push(ValidationFailure { message: format!("The {key} field is invalid"), rule: "range".into(), field: key.into() }); None }
    }
}

fn validate_enum(body: &Value, key: &str, allowed: &[&str], required: bool, errors: &mut Vec<ValidationFailure>) {
    match body.get(key).and_then(|v| v.as_str()) {
        Some(s) if allowed.contains(&s) => {}
        None if !required => {}
        _ => errors.push(ValidationFailure { message: format!("The selected {key} is invalid"), rule: "enum".into(), field: key.into() }),
    }
}

// ================= subscriptions-proper =================

const SUPPORTED_PAYMENT_MODES: &[&str] = &["recurring_invoice", "wallet_autopay"];

#[derive(sqlx::FromRow)]
struct SubRow {
    id: i64,
    user_id: i64,
    subscription_plan_id: i64,
    subscription_customer_id: Option<i64>,
    public_id: String,
    external_id: Option<String>,
    status: String,
    payment_mode: String,
    plan_snapshot: String,
    current_period_start: Option<String>,
    current_period_end: Option<String>,
    next_billing_at: Option<String>,
    metadata: Option<String>,
    paused_at: Option<String>,
    cancelled_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const SUB_COLS: &str = "id, user_id, subscription_plan_id, subscription_customer_id, public_id, \
    external_id, status, payment_mode, plan_snapshot, current_period_start, current_period_end, \
    next_billing_at, metadata, paused_at, cancelled_at, created_at, updated_at";

#[derive(sqlx::FromRow)]
struct CycleRow {
    id: i64,
    user_id: i64,
    subscription_id: i64,
    invoice_id: Option<i64>,
    public_id: String,
    status: String,
    period_start: String,
    period_end: String,
    attempt_count: i64,
    metadata: Option<String>,
    invoiced_at: Option<String>,
    paid_at: Option<String>,
    past_due_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const CYCLE_COLS: &str = "id, user_id, subscription_id, invoice_id, public_id, status, period_start, \
    period_end, attempt_count, metadata, invoiced_at, paid_at, past_due_at, created_at, updated_at";

async fn serialize_cycle(state: &AppState, c: &CycleRow) -> AppResult<Value> {
    let invoice = match c.invoice_id {
        Some(iid) => {
            let inv = invoices::load_by_id(state, iid).await.ok();
            match inv {
                Some(inv) => {
                    let (items, intent) = invoices::load_relations(state, inv.id()).await?;
                    Some(invoices::serialize_invoice(&inv, &items, intent.as_ref()))
                }
                None => None,
            }
        }
        None => None,
    };
    Ok(json!({
        "id": c.id,
        "userId": c.user_id,
        "subscriptionId": c.subscription_id,
        "invoiceId": c.invoice_id,
        "publicId": c.public_id,
        "status": c.status,
        "periodStart": c.period_start,
        "periodEnd": c.period_end,
        "attemptCount": c.attempt_count,
        "metadata": json_or_null(&c.metadata),
        "invoicedAt": c.invoiced_at,
        "paidAt": c.paid_at,
        "pastDueAt": c.past_due_at,
        "createdAt": c.created_at,
        "updatedAt": c.updated_at,
        "invoice": invoice.unwrap_or(Value::Null),
    }))
}

async fn serialize_subscription(state: &AppState, s: &SubRow, with_cycles: bool) -> AppResult<Value> {
    let plan = sqlx::query_as::<_, PlanRow>(&format!("SELECT {PLAN_COLS} FROM subscription_plans WHERE id = $1"))
        .bind(s.subscription_plan_id).fetch_optional(&state.db.pool).await?;
    let customer = match s.subscription_customer_id {
        Some(cid) => sqlx::query_as::<_, CustomerRow>(&format!("SELECT {CUSTOMER_COLS} FROM subscription_customers WHERE id = $1"))
            .bind(cid).fetch_optional(&state.db.pool).await?,
        None => None,
    };
    let mut obj = json!({
        "id": s.id,
        "userId": s.user_id,
        "subscriptionPlanId": s.subscription_plan_id,
        "subscriptionCustomerId": s.subscription_customer_id,
        "publicId": s.public_id,
        "externalId": s.external_id,
        "status": s.status,
        "paymentMode": s.payment_mode,
        "planSnapshot": serde_json::from_str::<Value>(&s.plan_snapshot).unwrap_or(json!({})),
        "currentPeriodStart": s.current_period_start,
        "currentPeriodEnd": s.current_period_end,
        "nextBillingAt": s.next_billing_at,
        "metadata": json_or_null(&s.metadata),
        "pausedAt": s.paused_at,
        "cancelledAt": s.cancelled_at,
        "createdAt": s.created_at,
        "updatedAt": s.updated_at,
        "plan": plan.map(|p| serialize_plan(&p)).unwrap_or(Value::Null),
        "customer": customer.map(|c| serialize_customer(&c)).unwrap_or(Value::Null),
    });
    if with_cycles {
        let cycles = sqlx::query_as::<_, CycleRow>(&format!(
            "SELECT {CYCLE_COLS} FROM subscription_cycles WHERE subscription_id = $1 ORDER BY period_start DESC, id DESC LIMIT 20"
        )).bind(s.id).fetch_all(&state.db.pool).await?;
        let mut arr = Vec::new();
        for c in &cycles { arr.push(serialize_cycle(state, c).await?); }
        if let Value::Object(m) = &mut obj { m.insert("cycles".into(), Value::Array(arr)); }
    }
    Ok(obj)
}

async fn load_subscription(state: &AppState, user_id: i64, public_id: &str) -> AppResult<SubRow> {
    sqlx::query_as::<_, SubRow>(&format!("SELECT {SUB_COLS} FROM subscriptions WHERE user_id = $1 AND public_id = $2"))
        .bind(user_id).bind(public_id)
        .fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::commerce(404, "Subscription not found"))
}

fn add_interval(start: chrono::DateTime<chrono::Utc>, unit: &str, count: i64) -> chrono::DateTime<chrono::Utc> {
    match unit {
        "day" => start + chrono::Duration::days(count),
        "week" => start + chrono::Duration::weeks(count),
        "month" => start + chrono::Months::new(count as u32),
        "year" => start + chrono::Months::new((count * 12) as u32),
        _ => start,
    }
}

/// generateInvoiceForCycle.
async fn generate_invoice_for_cycle(state: &AppState, cycle_id: i64, is_retry: bool) -> AppResult<i64> {
    let cycle = sqlx::query_as::<_, CycleRow>(&format!("SELECT {CYCLE_COLS} FROM subscription_cycles WHERE id = $1"))
        .bind(cycle_id).fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::commerce(404, "Subscription cycle not found"))?;
    if cycle.status == "paid" || cycle.status == "cancelled" {
        return Err(AppError::commerce(422, "Subscription cycle cannot be invoiced"));
    }
    if !is_retry {
        if let Some(iid) = cycle.invoice_id { return Ok(iid); }
    }
    if is_retry && cycle.status != "past_due" {
        return Err(AppError::commerce(422, "Only past due subscription cycles can be retried"));
    }
    let sub = sqlx::query_as::<_, SubRow>(&format!("SELECT {SUB_COLS} FROM subscriptions WHERE id = $1"))
        .bind(cycle.subscription_id).fetch_one(&state.db.pool).await?;
    let snap: Value = serde_json::from_str(&sub.plan_snapshot).unwrap_or(json!({}));
    let attempt = cycle.attempt_count + 1;
    let expires_at = snap.get("invoiceExpiresAfterSeconds").and_then(|v| v.as_i64())
        .map(|secs| to_iso(chrono::Utc::now() + chrono::Duration::seconds(secs)));
    let mut body = json!({
        "externalId": format!("{}:{}:{}", sub.public_id, cycle.public_id, attempt),
        "paymentNetwork": snap["paymentNetwork"],
        "paymentAsset": snap["paymentAsset"],
        "items": [{ "name": snap["name"], "quantity": 1, "unitAmount": snap["amount"] }],
        "metadata": { "source": "subscription", "subscriptionId": sub.public_id, "subscriptionCycleId": cycle.public_id, "subscriptionAttempt": attempt },
    });
    if let (Value::Object(m), Some(exp)) = (&mut body, expires_at) {
        m.insert("expiresAt".into(), json!(exp));
    }
    let (invoice_id, _store) = invoices::create_for_merchant(state, sub.user_id, &body, None, Some(sub.id), Some(cycle.id)).await?;

    let now = now_iso();
    sqlx::query("UPDATE subscription_cycles SET invoice_id = $1, status = 'invoiced', attempt_count = $2, invoiced_at = $3, past_due_at = NULL, updated_at = $4 WHERE id = $5")
        .bind(invoice_id).bind(attempt).bind(&now).bind(&now).bind(cycle.id).execute(&state.db.pool).await?;
    Ok(invoice_id)
}

/// generateDueInvoiceForSubscription.
async fn generate_due_invoice(state: &AppState, sub_id: i64, now: chrono::DateTime<chrono::Utc>) -> AppResult<()> {
    let sub = sqlx::query_as::<_, SubRow>(&format!("SELECT {SUB_COLS} FROM subscriptions WHERE id = $1"))
        .bind(sub_id).fetch_one(&state.db.pool).await?;
    let next = sub.next_billing_at.as_deref().and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()).map(|d| d.with_timezone(&chrono::Utc));
    let Some(next) = next else { return Ok(()); };
    if sub.status != "active" || next > now { return Ok(()); }

    let snap: Value = serde_json::from_str(&sub.plan_snapshot).unwrap_or(json!({}));
    let unit = snap["intervalUnit"].as_str().unwrap_or("month");
    let count = snap["intervalCount"].as_i64().unwrap_or(1);
    let period_start = next;
    let period_end = add_interval(period_start, unit, count);
    let ps = to_iso(period_start);
    let pe = to_iso(period_end);

    let existing: Option<i64> = sqlx::query_scalar("SELECT id FROM subscription_cycles WHERE subscription_id = $1 AND period_start = $2")
        .bind(sub.id).bind(&ps).fetch_optional(&state.db.pool).await?;
    let cycle_id = match existing {
        Some(id) => id,
        None => {
            let now_s = now_iso();
            let public_id = format!("cycle_{}", random_hex(16));
            let r: i64 = sqlx::query_scalar::<_, i64>("INSERT INTO subscription_cycles (user_id, subscription_id, public_id, status, period_start, period_end, attempt_count, created_at, updated_at) VALUES ($1, $2, $3, 'pending', $4, $5, 0, $6, $7) RETURNING id")
                .bind(sub.user_id).bind(sub.id).bind(&public_id).bind(&ps).bind(&pe).bind(&now_s).bind(&now_s)
                .fetch_one(&state.db.pool).await?;
            r
        }
    };
    sqlx::query("UPDATE subscriptions SET current_period_start = $1, current_period_end = $2, next_billing_at = $3, updated_at = $4 WHERE id = $5")
        .bind(&ps).bind(&pe).bind(&pe).bind(now_iso()).bind(sub.id).execute(&state.db.pool).await?;
    generate_invoice_for_cycle(state, cycle_id, false).await?;
    Ok(())
}

pub async fn subs_index(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<PageQuery>) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).clamp(1, 100_000);
    let per_page = q.per_page.unwrap_or(10).clamp(1, 100);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subscriptions WHERE user_id = $1").bind(auth.user_id).fetch_one(&state.db.pool).await?;
    let rows = sqlx::query_as::<_, SubRow>(&format!("SELECT {SUB_COLS} FROM subscriptions WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3"))
        .bind(auth.user_id).bind(per_page).bind((page - 1) * per_page).fetch_all(&state.db.pool).await?;
    let mut data = Vec::new();
    for s in &rows { data.push(serialize_subscription(&state, s, false).await?); }
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}

pub async fn subs_store(auth: AuthMerchant, State(state): State<AppState>, Json(body): Json<Value>) -> AppResult<(StatusCode, Json<Value>)> {
    let payment_mode = body.get("paymentMode").and_then(|v| v.as_str()).unwrap_or("recurring_invoice").to_string();
    if payment_mode == "wallet_autopay" {
        return Err(AppError::commerce(422, "wallet_autopay is not supported yet"));
    }
    if !SUPPORTED_PAYMENT_MODES.contains(&payment_mode.as_str()) {
        return Err(AppError::commerce(422, "Unsupported subscription payment mode"));
    }
    let plan_public = match body.get("planPublicId").and_then(|v| v.as_str()) {
        Some(p) if !p.trim().is_empty() => p.trim().to_string(),
        _ => return Err(AppError::Validation(vec![ValidationFailure { message: "The planPublicId field is required".into(), rule: "required".into(), field: "planPublicId".into() }])),
    };
    let external_id = opt_string(&body, "externalId");
    if let Some(ext) = &external_id {
        let taken: Option<i64> = sqlx::query_scalar("SELECT id FROM subscriptions WHERE user_id = $1 AND external_id = $2").bind(auth.user_id).bind(ext).fetch_optional(&state.db.pool).await?;
        if taken.is_some() { return Err(AppError::commerce(422, "External id has already been used")); }
    }
    let plan = load_plan(&state, auth.user_id, &plan_public).await?;
    if plan.status != "active" {
        return Err(AppError::commerce(422, "Subscription plan is archived"));
    }
    // resolve customer
    let cust_public = opt_string(&body, "customerPublicId");
    let cust_inline = body.get("customer").filter(|v| v.is_object());
    let customer_id: i64 = if cust_public.is_some() && cust_inline.is_some() {
        return Err(AppError::commerce(422, "Provide either customerPublicId or customer, not both"));
    } else if let Some(cp) = cust_public {
        load_customer(&state, auth.user_id, &cp).await?.id
    } else if let Some(ci) = cust_inline {
        let now = now_iso();
        let public_id = format!("cus_{}", random_hex(16));
        let r: i64 = sqlx::query_scalar::<_, i64>("INSERT INTO subscription_customers (user_id, public_id, external_id, email, name, metadata, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id")
            .bind(auth.user_id).bind(&public_id).bind(opt_string(ci, "externalId")).bind(opt_string(ci, "email")).bind(opt_string(ci, "name"))
            .bind(ci.get("metadata").filter(|v| !v.is_null()).map(|m| m.to_string())).bind(&now).bind(&now)
            .fetch_one(&state.db.pool).await?;
        r
    } else {
        return Err(AppError::commerce(422, "A subscription customer is required"));
    };

    let now = chrono::Utc::now();
    let starts_at = match body.get("startsAt").and_then(|v| v.as_str()) {
        Some(s) => chrono::DateTime::parse_from_rfc3339(s).map(|d| d.with_timezone(&chrono::Utc))
            .map_err(|_| AppError::commerce(422, "startsAt must be a valid ISO 8601 date-time"))?,
        None => now,
    };
    let snapshot = json!({
        "planId": plan.id, "planPublicId": plan.public_id, "name": plan.name, "description": plan.description,
        "amount": plan.amount.to_string(), "currency": plan.currency, "paymentNetwork": plan.payment_network,
        "paymentAsset": plan.payment_asset, "intervalUnit": plan.interval_unit, "intervalCount": plan.interval_count,
        "invoiceExpiresAfterSeconds": plan.invoice_expires_after_seconds,
        "metadata": json_or_null(&plan.metadata),
    });
    let now_s = now_iso();
    let public_id = format!("sub_{}", random_hex(16));
    let sub_id: i64 = sqlx::query_scalar::<_, i64>("INSERT INTO subscriptions (user_id, subscription_plan_id, subscription_customer_id, public_id, external_id, status, payment_mode, plan_snapshot, next_billing_at, metadata, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, 'active', $6, $7, $8, $9, $10, $11) RETURNING id")
        .bind(auth.user_id).bind(plan.id).bind(customer_id).bind(&public_id).bind(&external_id).bind(&payment_mode)
        .bind(snapshot.to_string()).bind(to_iso(starts_at)).bind(body.get("metadata").filter(|v| !v.is_null()).map(|m| m.to_string()))
        .bind(&now_s).bind(&now_s).fetch_one(&state.db.pool).await?;

    if starts_at <= now {
        generate_due_invoice(&state, sub_id, now).await?;
    }

    let sub = load_subscription(&state, auth.user_id, &public_id).await?;
    Ok((StatusCode::CREATED, Json(serialize_subscription(&state, &sub, true).await?)))
}

pub async fn subs_show(auth: AuthMerchant, State(state): State<AppState>, Path(public_id): Path<String>) -> AppResult<Json<Value>> {
    let sub = load_subscription(&state, auth.user_id, &public_id).await?;
    Ok(Json(serialize_subscription(&state, &sub, true).await?))
}

async fn set_sub_status(state: &AppState, user_id: i64, public_id: &str, set: impl FnOnce(&SubRow) -> Result<String, AppError>) -> AppResult<Json<Value>> {
    let sub = load_subscription(state, user_id, public_id).await?;
    let sql_set = set(&sub)?;
    sqlx::query(&format!("UPDATE subscriptions SET {sql_set}, updated_at = $1 WHERE id = $2"))
        .bind(now_iso()).bind(sub.id).execute(&state.db.pool).await?;
    let sub = load_subscription(state, user_id, public_id).await?;
    Ok(Json(serialize_subscription(state, &sub, true).await?))
}

pub async fn subs_pause(auth: AuthMerchant, State(state): State<AppState>, Path(public_id): Path<String>) -> AppResult<Json<Value>> {
    set_sub_status(&state, auth.user_id, &public_id, |s| {
        if s.status == "cancelled" { return Err(AppError::commerce(422, "Cancelled subscriptions cannot be paused")); }
        Ok(format!("status = 'paused', paused_at = '{}'", now_iso()))
    }).await
}

pub async fn subs_resume(auth: AuthMerchant, State(state): State<AppState>, Path(public_id): Path<String>) -> AppResult<Json<Value>> {
    set_sub_status(&state, auth.user_id, &public_id, |s| {
        if s.status != "paused" { return Err(AppError::commerce(422, "Only paused subscriptions can be resumed")); }
        let nb = if s.next_billing_at.is_none() { format!(", next_billing_at = '{}'", now_iso()) } else { String::new() };
        Ok(format!("status = 'active', paused_at = NULL{nb}"))
    }).await
}

pub async fn subs_cancel(auth: AuthMerchant, State(state): State<AppState>, Path(public_id): Path<String>) -> AppResult<Json<Value>> {
    let sub = load_subscription(&state, auth.user_id, &public_id).await?;
    if sub.status != "cancelled" {
        sqlx::query("UPDATE subscriptions SET status = 'cancelled', cancelled_at = $1, next_billing_at = NULL, updated_at = $2 WHERE id = $3")
            .bind(now_iso()).bind(now_iso()).bind(sub.id).execute(&state.db.pool).await?;
    }
    let sub = load_subscription(&state, auth.user_id, &public_id).await?;
    Ok(Json(serialize_subscription(&state, &sub, true).await?))
}

pub async fn subs_invoices(auth: AuthMerchant, State(state): State<AppState>, Path(public_id): Path<String>, Query(q): Query<PageQuery>) -> AppResult<Json<Value>> {
    let sub = load_subscription(&state, auth.user_id, &public_id).await?;
    let page = q.page.unwrap_or(1).clamp(1, 100_000);
    let per_page = q.per_page.unwrap_or(10).clamp(1, 100);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE user_id = $1 AND subscription_id = $2")
        .bind(auth.user_id).bind(sub.id).fetch_one(&state.db.pool).await?;
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM invoices WHERE user_id = $1 AND subscription_id = $2 ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4")
        .bind(auth.user_id).bind(sub.id).bind(per_page).bind((page - 1) * per_page).fetch_all(&state.db.pool).await?;
    let mut data = Vec::new();
    for id in ids {
        let inv = invoices::load_by_id(&state, id).await?;
        let (items, intent) = invoices::load_relations(&state, inv.id()).await?;
        data.push(invoices::serialize_invoice(&inv, &items, intent.as_ref()));
    }
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}

pub async fn subs_retry_invoice(auth: AuthMerchant, State(state): State<AppState>, Path(public_id): Path<String>) -> AppResult<Json<Value>> {
    let sub = load_subscription(&state, auth.user_id, &public_id).await?;
    let cycle_id: Option<i64> = sqlx::query_scalar("SELECT id FROM subscription_cycles WHERE subscription_id = $1 AND status = 'past_due' ORDER BY period_start DESC, id DESC LIMIT 1")
        .bind(sub.id).fetch_optional(&state.db.pool).await?;
    let Some(cycle_id) = cycle_id else {
        return Err(AppError::commerce(422, "Subscription does not have a past due cycle to retry"));
    };
    let invoice_id = generate_invoice_for_cycle(&state, cycle_id, true).await?;
    let inv = invoices::load_by_id(&state, invoice_id).await?;
    let (items, intent) = invoices::load_relations(&state, inv.id()).await?;
    Ok(Json(invoices::serialize_invoice(&inv, &items, intent.as_ref())))
}
