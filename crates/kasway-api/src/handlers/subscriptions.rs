//! `/api/commerce/subscription-plans` + `/api/commerce/subscription-customers`
//! — CommerceSubscriptionPlansController / CommerceSubscriptionCustomersController.
//! (Subscriptions-proper billing endpoints are ported separately.)

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::handlers::invoices;
use crate::state::AppState;
use crate::util::{is_atomic_amount, json_or_null, now_iso, paginator_meta, random_hex, ser_amount, ser_json, to_iso};
use crate::validate::{atomic_amount, opt_string, parse_atomic_i64, req_int, req_string, validate_enum};
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
    .bind(Some(crate::kpr1::PAYMENT_WINDOW_SECONDS))
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

/// The subscription JSON shape shared by the single-row and batched paths.
fn sub_json(s: &SubRow, plan: Option<&PlanRow>, customer: Option<&CustomerRow>) -> Value {
    json!({
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
        "plan": plan.map(serialize_plan).unwrap_or(Value::Null),
        "customer": customer.map(serialize_customer).unwrap_or(Value::Null),
    })
}

async fn serialize_subscription(state: &AppState, s: &SubRow, with_cycles: bool) -> AppResult<Value> {
    let plan = sqlx::query_as::<_, PlanRow>(&format!("SELECT {PLAN_COLS} FROM subscription_plans WHERE id = $1"))
        .bind(s.subscription_plan_id).fetch_optional(&state.db.pool).await?;
    let customer = match s.subscription_customer_id {
        Some(cid) => sqlx::query_as::<_, CustomerRow>(&format!("SELECT {CUSTOMER_COLS} FROM subscription_customers WHERE id = $1"))
            .bind(cid).fetch_optional(&state.db.pool).await?,
        None => None,
    };
    let mut obj = sub_json(s, plan.as_ref(), customer.as_ref());
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

/// generateInvoiceForCycle. Emits `subscription.invoice.created` whenever a new
/// invoice is minted (creation, biller catch-up, and retry all route through
/// here, so every path emits consistently).
pub(crate) async fn generate_invoice_for_cycle(state: &AppState, cycle_id: i64, is_retry: bool) -> AppResult<i64> {
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
    let plan = sqlx::query_as::<_, PlanRow>(&format!("SELECT {PLAN_COLS} FROM subscription_plans WHERE id = $1"))
        .bind(sub.subscription_plan_id).fetch_one(&state.db.pool).await?;
    let attempt = cycle.attempt_count + 1;
    let previous_amount = snap.get("amount").and_then(Value::as_str).unwrap_or("0");
    let current_amount = plan.amount.to_string();
    let price_changed = previous_amount != current_amount;
    let body = json!({
        "externalId": format!("{}:{}:{}", sub.public_id, cycle.public_id, attempt),
        "paymentNetwork": plan.payment_network,
        "paymentAsset": plan.payment_asset,
        "items": [{ "name": plan.name, "quantity": 1, "unitAmount": current_amount }],
        "metadata": {
            "source": "subscription",
            "paymentType": "subscription",
            "subscriptionId": sub.public_id,
            "subscriptionCycleId": cycle.public_id,
            "subscriptionAttempt": attempt,
            "intervalUnit": plan.interval_unit,
            "intervalCount": plan.interval_count,
            "nextBillingAt": sub.next_billing_at,
            "priceChange": {
                "changed": price_changed,
                "previousAmountSompi": previous_amount,
                "currentAmountSompi": current_amount,
                "noticeRequired": price_changed,
            },
        },
    });
    let (invoice_id, store_id) = invoices::create_for_merchant(state, sub.user_id, &body, None, Some(sub.id), Some(cycle.id)).await?;

    let now = now_iso();
    sqlx::query("UPDATE subscription_cycles SET invoice_id = $1, status = 'invoiced', attempt_count = $2, invoiced_at = $3, past_due_at = NULL, updated_at = $4 WHERE id = $5")
        .bind(invoice_id).bind(attempt).bind(&now).bind(&now).bind(cycle.id).execute(&state.db.pool).await?;

    let current_snapshot = json!({
        "planId": plan.id, "planPublicId": plan.public_id, "name": plan.name, "description": plan.description,
        "amount": plan.amount.to_string(), "currency": plan.currency, "paymentNetwork": plan.payment_network,
        "paymentAsset": plan.payment_asset, "intervalUnit": plan.interval_unit, "intervalCount": plan.interval_count,
        "invoiceExpiresAfterSeconds": crate::kpr1::PAYMENT_WINDOW_SECONDS,
        "metadata": json_or_null(&plan.metadata),
    });
    sqlx::query("UPDATE subscriptions SET plan_snapshot = $1, updated_at = $2 WHERE id = $3")
        .bind(current_snapshot.to_string()).bind(&now).bind(sub.id).execute(&state.db.pool).await?;

    // Webhook: a delivery failure must never fail the billing itself.
    if let Ok(inv) = invoices::load_by_id(state, invoice_id).await {
        if let Ok((items, intent)) = invoices::load_relations(state, invoice_id).await {
            let payload = invoices::serialize_invoice(&inv, &items, intent.as_ref());
            let resource_id = payload["publicId"].as_str().unwrap_or_default().to_string();
            if let Err(e) = crate::handlers::webhooks::emit_event(
                state, sub.user_id, Some(store_id), "subscription.invoice.created", "invoice", &resource_id, &payload,
            ).await {
                tracing::warn!("subscription.invoice.created emit failed for invoice {invoice_id}: {e}");
            }
            if price_changed {
                let price_payload = json!({
                    "subscriptionId": sub.public_id,
                    "invoiceId": resource_id,
                    "previousAmountSompi": previous_amount,
                    "currentAmountSompi": current_amount,
                    "effectiveAt": cycle.period_start,
                });
                if let Err(e) = crate::handlers::webhooks::emit_event(
                    state, sub.user_id, Some(store_id), "subscription.price.changed", "subscription", &sub.public_id, &price_payload,
                ).await {
                    tracing::warn!("subscription.price.changed emit failed for subscription {}: {e}", sub.public_id);
                }
            }
        }
    }
    Ok(invoice_id)
}

/// generateDueInvoiceForSubscription. Bills ONE due period (advancing
/// `next_billing_at` one interval); returns whether it billed anything, so the
/// biller can loop until the subscription is caught up.
pub(crate) async fn generate_due_invoice(state: &AppState, sub_id: i64, now: chrono::DateTime<chrono::Utc>) -> AppResult<bool> {
    let sub = sqlx::query_as::<_, SubRow>(&format!("SELECT {SUB_COLS} FROM subscriptions WHERE id = $1"))
        .bind(sub_id).fetch_one(&state.db.pool).await?;
    let next = sub.next_billing_at.as_deref().and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()).map(|d| d.with_timezone(&chrono::Utc));
    let Some(next) = next else { return Ok(false); };
    if sub.status != "active" || next > now { return Ok(false); }

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
    Ok(true)
}

pub async fn subs_index(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<PageQuery>) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).clamp(1, 100_000);
    let per_page = q.per_page.unwrap_or(10).clamp(1, 100);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subscriptions WHERE user_id = $1").bind(auth.user_id).fetch_one(&state.db.pool).await?;
    let rows = sqlx::query_as::<_, SubRow>(&format!("SELECT {SUB_COLS} FROM subscriptions WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3"))
        .bind(auth.user_id).bind(per_page).bind((page - 1) * per_page).fetch_all(&state.db.pool).await?;

    // Preload the page's plans + customers in two queries instead of 2N.
    let plan_ids: Vec<i64> = rows.iter().map(|s| s.subscription_plan_id).collect();
    let customer_ids: Vec<i64> = rows.iter().filter_map(|s| s.subscription_customer_id).collect();
    let plans: std::collections::HashMap<i64, PlanRow> =
        sqlx::query_as::<_, PlanRow>(&format!("SELECT {PLAN_COLS} FROM subscription_plans WHERE id = ANY($1)"))
            .bind(&plan_ids).fetch_all(&state.db.pool).await?
            .into_iter().map(|p| (p.id, p)).collect();
    let customers: std::collections::HashMap<i64, CustomerRow> =
        sqlx::query_as::<_, CustomerRow>(&format!("SELECT {CUSTOMER_COLS} FROM subscription_customers WHERE id = ANY($1)"))
            .bind(&customer_ids).fetch_all(&state.db.pool).await?
            .into_iter().map(|c| (c.id, c)).collect();

    let data: Vec<Value> = rows.iter()
        .map(|s| sub_json(s, plans.get(&s.subscription_plan_id), s.subscription_customer_id.and_then(|cid| customers.get(&cid))))
        .collect();
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}

pub async fn subs_store(auth: AuthMerchant, State(state): State<AppState>, Json(body): Json<Value>) -> AppResult<(StatusCode, Json<Value>)> {
    let requested_mode = body.get("paymentMode").and_then(|v| v.as_str()).unwrap_or("recurring_invoice");
    if !SUPPORTED_PAYMENT_MODES.contains(&requested_mode) {
        return Err(AppError::commerce(422, "Unsupported subscription payment mode"));
    }
    // Legacy wallet_autopay input is accepted during migration, but all new
    // subscriptions use per-cycle invoices; renewal authority lives locally.
    let payment_mode = "recurring_invoice".to_string();
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
    // The initial invoice is part of subscription creation. Run all KPR-1
    // payout/setup validation before inserting even an inline customer, so a
    // rejected invoice cannot leave an active subscription and pending cycle
    // for the biller to retry forever.
    let store_id = crate::store_context::resolve_request_store(&state, auth.user_id, None).await?;
    crate::store_context::assert_can_create_new_payments(&state, store_id).await?;
    crate::kpr1::preflight_invoice(&state, auth.user_id, store_id, plan.amount).await?;
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
        "invoiceExpiresAfterSeconds": crate::kpr1::PAYMENT_WINDOW_SECONDS,
        "metadata": json_or_null(&plan.metadata),
    });
    let now_s = now_iso();
    let public_id = format!("sub_{}", random_hex(16));
    let status = "active";
    let next_billing_at = Some(to_iso(starts_at));
    let sub_id: i64 = sqlx::query_scalar::<_, i64>("INSERT INTO subscriptions (user_id, subscription_plan_id, subscription_customer_id, public_id, external_id, status, payment_mode, plan_snapshot, next_billing_at, metadata, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id")
        .bind(auth.user_id).bind(plan.id).bind(customer_id).bind(&public_id).bind(&external_id).bind(status).bind(&payment_mode)
        .bind(snapshot.to_string()).bind(next_billing_at).bind(body.get("metadata").filter(|v| !v.is_null()).map(|m| m.to_string()))
        .bind(&now_s).bind(&now_s).fetch_one(&state.db.pool).await?;

    if starts_at <= now {
        generate_due_invoice(&state, sub_id, now).await?;
    }

    let sub = load_subscription(&state, auth.user_id, &public_id).await?;
    let out = serialize_subscription(&state, &sub, true).await?;
    emit_subscription_event(&state, auth.user_id, "subscription.created", &public_id, &out).await;
    Ok((StatusCode::CREATED, Json(out)))
}

/// Emit a subscription lifecycle webhook event (failures are logged, never fatal).
async fn emit_subscription_event(state: &AppState, user_id: i64, event: &str, public_id: &str, payload: &Value) {
    if let Err(e) = crate::handlers::webhooks::emit_event(state, user_id, None, event, "subscription", public_id, payload).await {
        tracing::warn!("{event} emit failed for subscription {public_id}: {e}");
    }
}

pub async fn subs_show(auth: AuthMerchant, State(state): State<AppState>, Path(public_id): Path<String>) -> AppResult<Json<Value>> {
    let sub = load_subscription(&state, auth.user_id, &public_id).await?;
    Ok(Json(serialize_subscription(&state, &sub, true).await?))
}

async fn set_sub_status(state: &AppState, user_id: i64, public_id: &str, event: &str, set: impl FnOnce(&SubRow) -> Result<String, AppError>) -> AppResult<Json<Value>> {
    let sub = load_subscription(state, user_id, public_id).await?;
    let sql_set = set(&sub)?;
    sqlx::query(&format!("UPDATE subscriptions SET {sql_set}, updated_at = $1 WHERE id = $2"))
        .bind(now_iso()).bind(sub.id).execute(&state.db.pool).await?;
    let sub = load_subscription(state, user_id, public_id).await?;
    let out = serialize_subscription(state, &sub, true).await?;
    emit_subscription_event(state, user_id, event, public_id, &out).await;
    Ok(Json(out))
}

pub async fn subs_pause(auth: AuthMerchant, State(state): State<AppState>, Path(public_id): Path<String>) -> AppResult<Json<Value>> {
    set_sub_status(&state, auth.user_id, &public_id, "subscription.paused", |s| {
        if s.status == "cancelled" { return Err(AppError::commerce(422, "Cancelled subscriptions cannot be paused")); }
        Ok(format!("status = 'paused', paused_at = '{}'", now_iso()))
    }).await
}

pub async fn subs_resume(auth: AuthMerchant, State(state): State<AppState>, Path(public_id): Path<String>) -> AppResult<Json<Value>> {
    set_sub_status(&state, auth.user_id, &public_id, "subscription.resumed", |s| {
        if s.status != "paused" { return Err(AppError::commerce(422, "Only paused subscriptions can be resumed")); }
        let nb = if s.next_billing_at.is_none() { format!(", next_billing_at = '{}'", now_iso()) } else { String::new() };
        Ok(format!("status = 'active', paused_at = NULL{nb}"))
    }).await
}

pub async fn subs_cancel(auth: AuthMerchant, State(state): State<AppState>, Path(public_id): Path<String>) -> AppResult<Json<Value>> {
    Ok(Json(cancel_subscription(&state, auth.user_id, &public_id).await?))
}

/// Cancel a subscription: stop future invoice generation and emit the event.
/// Shared by the merchant endpoint and public checkout capability URL.
pub(crate) async fn cancel_subscription(state: &AppState, user_id: i64, public_id: &str) -> AppResult<Value> {
    let sub = load_subscription(state, user_id, public_id).await?;
    let transitioned = sub.status != "cancelled";
    if transitioned {
        sqlx::query("UPDATE subscriptions SET status = 'cancelled', cancelled_at = $1, next_billing_at = NULL, updated_at = $2 WHERE id = $3")
            .bind(now_iso()).bind(now_iso()).bind(sub.id).execute(&state.db.pool).await?;
    }
    let sub = load_subscription(state, user_id, public_id).await?;
    let out = serialize_subscription(state, &sub, true).await?;
    if transitioned {
        emit_subscription_event(state, user_id, "subscription.cancelled", public_id, &out).await;
    }
    Ok(out)
}

pub async fn subs_invoices(auth: AuthMerchant, State(state): State<AppState>, Path(public_id): Path<String>, Query(q): Query<PageQuery>) -> AppResult<Json<Value>> {
    let sub = load_subscription(&state, auth.user_id, &public_id).await?;
    let page = q.page.unwrap_or(1).clamp(1, 100_000);
    let per_page = q.per_page.unwrap_or(10).clamp(1, 100);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE user_id = $1 AND subscription_id = $2")
        .bind(auth.user_id).bind(sub.id).fetch_one(&state.db.pool).await?;
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM invoices WHERE user_id = $1 AND subscription_id = $2 ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4")
        .bind(auth.user_id).bind(sub.id).bind(per_page).bind((page - 1) * per_page).fetch_all(&state.db.pool).await?;
    let invs = invoices::load_many_by_ids(&state, &ids).await?;
    let (items_by, intents_by) = invoices::load_relations_many(&state, &ids).await?;
    let data: Vec<Value> = invs.iter()
        .map(|inv| invoices::serialize_invoice(inv, items_by.get(&inv.id()).map(Vec::as_slice).unwrap_or(&[]), intents_by.get(&inv.id())))
        .collect();
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
