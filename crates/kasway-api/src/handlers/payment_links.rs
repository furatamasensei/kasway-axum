//! `/api/payment-links` — PaymentLinksController + PaymentLinkService.
//! Reusable link templates; each checkout spawns a fresh invoice.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::handlers::invoices::{self, FEE_DELEGATIONS};
use crate::state::AppState;
use crate::store_context::resolve_request_store;
use crate::util::{is_atomic_amount, json_or_null, now_iso, paginator_meta, random_hex, ser_amount, ser_json};
use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LinkRow {
    id: i64,
    user_id: i64,
    store_id: Option<i64>,
    public_id: String,
    status: String,
    title: String,
    #[serde(serialize_with = "ser_amount")]
    amount: i64,
    currency: String,
    payment_network: String,
    payment_asset: String,
    fee_delegation: String,
    pricing_country_code: Option<String>,
    #[serde(serialize_with = "ser_json")]
    metadata: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const LINK_COLS: &str = "id, user_id, store_id, public_id, status, title, amount, currency, \
    payment_network, payment_asset, fee_delegation, pricing_country_code, \
    metadata, created_at, updated_at";

#[derive(Deserialize, Default)]
pub struct LinkQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
    #[serde(rename = "storeId")]
    store_id: Option<i64>,
}

fn serialize_link(link: &LinkRow, payments_count: Option<i64>) -> Value {
    let mut obj = serde_json::to_value(link).unwrap_or(Value::Null);
    // withCount('invoices') -> paymentsCount (omitted when not loaded).
    if let (Value::Object(map), Some(count)) = (&mut obj, payments_count) {
        map.insert("paymentsCount".into(), json!(count));
    }
    obj
}

async fn invoices_count(state: &AppState, link_id: i64) -> AppResult<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE payment_link_id = $1")
        .bind(link_id)
        .fetch_one(&state.db.pool)
        .await?)
}

async fn get_for_merchant(
    state: &AppState,
    user_id: i64,
    store_id: i64,
    id: i64,
) -> AppResult<LinkRow> {
    sqlx::query_as::<_, LinkRow>(&format!(
        "SELECT {LINK_COLS} FROM payment_links WHERE user_id = $1 AND store_id = $2 AND id = $3"
    ))
    .bind(user_id)
    .bind(store_id)
    .bind(id)
    .fetch_optional(&state.db.pool)
    .await?
    .ok_or_else(|| AppError::commerce(404, "Payment link not found"))
}

/// `GET /api/payment-links`
pub async fn index(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Query(q): Query<LinkQuery>,
) -> AppResult<Json<Value>> {
    let store_id = resolve_request_store(&state, auth.user_id, q.store_id).await?;
    // Clamp pagination params before multiplying so `offset` can't overflow i64.
    let page = q.page.unwrap_or(1).clamp(1, 100_000);
    let per_page = q.per_page.unwrap_or(10).clamp(1, 100);
    let offset = (page - 1) * per_page;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_links WHERE user_id = $1 AND store_id = $2",
    )
    .bind(auth.user_id)
    .bind(store_id)
    .fetch_one(&state.db.pool)
    .await?;

    let links = sqlx::query_as::<_, LinkRow>(&format!(
        "SELECT {LINK_COLS} FROM payment_links WHERE user_id = $1 AND store_id = $2 \
         ORDER BY created_at DESC, id DESC LIMIT $3 OFFSET $4"
    ))
    .bind(auth.user_id)
    .bind(store_id)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&state.db.pool)
    .await?;

    // withCount('invoices') for the whole page in one grouped query.
    let ids: Vec<i64> = links.iter().map(|l| l.id).collect();
    let counts: HashMap<i64, i64> = sqlx::query_as::<_, (i64, i64)>(
        "SELECT payment_link_id, COUNT(*) FROM invoices WHERE payment_link_id = ANY($1) \
         GROUP BY payment_link_id",
    )
    .bind(&ids)
    .fetch_all(&state.db.pool)
    .await?
    .into_iter()
    .collect();

    let data: Vec<Value> = links
        .iter()
        .map(|link| serialize_link(link, Some(counts.get(&link.id).copied().unwrap_or(0))))
        .collect();

    Ok(Json(json!({
        "meta": paginator_meta(total, per_page, page),
        "data": data,
    })))
}

/// `POST /api/payment-links`
pub async fn store(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let input = validate_create(&body)?;
    let store_id = resolve_request_store(&state, auth.user_id, input.store_id).await?;

    let amount: i128 = input.amount.parse().unwrap_or(0);
    if amount <= 0 {
        return Err(AppError::commerce(422, "Payment link amount must be greater than zero"));
    }
    // Bound to i64 before the DB cast so a value like 2^63 can't wrap negative.
    let amount_i64 = i64::try_from(amount)
        .map_err(|_| AppError::commerce(422, "Payment link amount exceeds maximum"))?;

    let network = input
        .payment_network
        .unwrap_or_else(|| state.config.kpr1.default_network.clone());
    let asset = input
        .payment_asset
        .unwrap_or_else(|| state.config.kpr1.default_asset.clone());
    let fee_delegation = input.fee_delegation.unwrap_or_else(|| "merchant_subsidized".to_string());
    let now = now_iso();
    let public_id = format!("plink_{}", random_hex(16));
    let metadata_str = input.metadata.as_ref().map(|m| m.to_string());

    let id: i64 = sqlx::query_scalar::<_, i64>(
        "INSERT INTO payment_links \
         (user_id, store_id, public_id, status, title, amount, currency, payment_network, \
          payment_asset, fee_delegation, pricing_country_code, metadata, created_at, updated_at) \
         VALUES ($1, $2, $3, 'active', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id",
    )
    .bind(auth.user_id)
    .bind(store_id)
    .bind(&public_id)
    .bind(&input.title)
    .bind(amount_i64)
    .bind(&asset)
    .bind(&network)
    .bind(&asset)
    .bind(&fee_delegation)
    .bind(&input.customer_country_code)
    .bind(&metadata_str)
    .bind(&now)
    .bind(&now)
    .fetch_one(&state.db.pool)
    .await?;

    let link = get_for_merchant(&state, auth.user_id, store_id, id).await?;
    let count = invoices_count(&state, id).await?;
    Ok(Json(serialize_link(&link, Some(count))))
}

/// `GET /api/payment-links/:id`
pub async fn show(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<LinkQuery>,
) -> AppResult<Json<Value>> {
    let store_id = resolve_request_store(&state, auth.user_id, q.store_id).await?;
    let link = get_for_merchant(&state, auth.user_id, store_id, id).await?;
    let count = invoices_count(&state, id).await?;
    Ok(Json(serialize_link(&link, Some(count))))
}

/// `POST /api/payment-links/:id/disable`
pub async fn disable(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<LinkQuery>,
) -> AppResult<Json<Value>> {
    set_status(&state, auth.user_id, id, "disabled", q.store_id).await
}

/// `POST /api/payment-links/:id/enable`
pub async fn enable(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<LinkQuery>,
) -> AppResult<Json<Value>> {
    set_status(&state, auth.user_id, id, "active", q.store_id).await
}

async fn set_status(
    state: &AppState,
    user_id: i64,
    id: i64,
    status: &str,
    store_id_q: Option<i64>,
) -> AppResult<Json<Value>> {
    let store_id = resolve_request_store(state, user_id, store_id_q).await?;
    let link = get_for_merchant(state, user_id, store_id, id).await?;
    sqlx::query("UPDATE payment_links SET status = $1, updated_at = $2 WHERE id = $3")
        .bind(status)
        .bind(now_iso())
        .bind(link.id)
        .execute(&state.db.pool)
        .await?;
    let link = get_for_merchant(state, user_id, store_id, id).await?;
    let count = invoices_count(state, id).await?;
    Ok(Json(serialize_link(&link, Some(count))))
}

// --- checkout-links (public) helpers ---

pub(crate) async fn get_active_by_public_id(
    state: &AppState,
    public_id: &str,
) -> AppResult<LinkRow> {
    let link = sqlx::query_as::<_, LinkRow>(&format!(
        "SELECT {LINK_COLS} FROM payment_links WHERE public_id = $1"
    ))
    .bind(public_id)
    .fetch_optional(&state.db.pool)
    .await?
    .ok_or_else(|| AppError::commerce(404, "Payment link not found"))?;

    if link.status != "active" {
        return Err(AppError::commerce(410, "This payment link is no longer active"));
    }
    Ok(link)
}

/// Public link landing summary (CheckoutLinksController.show).
pub(crate) async fn public_summary(state: &AppState, public_id: &str) -> AppResult<Value> {
    let link = get_active_by_public_id(state, public_id).await?;

    let merchant: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT full_name, avatar_url FROM users WHERE id = $1")
            .bind(link.user_id)
            .fetch_optional(&state.db.pool)
            .await?;
    let store_name: Option<String> = match link.store_id {
        Some(sid) => sqlx::query_scalar("SELECT name FROM stores WHERE id = $1")
            .bind(sid)
            .fetch_optional(&state.db.pool)
            .await?,
        None => None,
    };

    let metadata = json_or_null(&link.metadata);

    Ok(json!({
        "publicId": link.public_id,
        "status": link.status,
        "title": link.title,
        "amount": link.amount.to_string(),
        "currency": link.currency,
        "paymentNetwork": link.payment_network,
        "paymentAsset": link.payment_asset,
        "metadata": metadata,
        "merchant": merchant.map(|(name, avatar)| json!({
            "name": name,
            "avatarUrl": avatar,
            "verified": true,
        })),
        "store": store_name.map(|name| json!({ "name": name })),
    }))
}

/// Spawn a fresh invoice from a link (CheckoutLinksController.createInvoice).
/// Returns (invoice_id, store_id) of the spawned invoice.
pub(crate) async fn spawn_invoice_for_checkout(
    state: &AppState,
    public_id: &str,
) -> AppResult<(i64, i64)> {
    let link = get_active_by_public_id(state, public_id).await?;

    let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
        .bind(link.user_id)
        .fetch_optional(&state.db.pool)
        .await?;
    if exists.is_none() {
        return Err(AppError::commerce(404, "Payment link merchant not found"));
    }

    // Merge link.metadata with the payment-link channel markers.
    let mut metadata = match &link.metadata {
        Some(s) => serde_json::from_str::<Value>(s).unwrap_or(json!({})),
        None => json!({}),
    };
    if let Value::Object(map) = &mut metadata {
        map.insert("title".into(), json!(link.title));
        map.insert("source".into(), json!("payment_link"));
        map.insert("channel".into(), json!("payment_link"));
        map.insert("paymentLinkPublicId".into(), json!(link.public_id));
    }

    let mut body = json!({
        "items": [{ "name": link.title, "quantity": 1, "unitAmount": link.amount.to_string() }],
        "feeDelegation": link.fee_delegation,
        "paymentNetwork": link.payment_network,
        "paymentAsset": link.payment_asset,
        "metadata": metadata,
    });
    if let Value::Object(map) = &mut body {
        if let Some(cc) = &link.pricing_country_code {
            map.insert("customerCountryCode".into(), json!(cc));
        }
        if let Some(sid) = link.store_id {
            map.insert("storeId".into(), json!(sid));
        }
    }

    invoices::create_for_merchant(state, link.user_id, &body, Some(link.id), None, None).await
}

// --- validation (createPaymentLinkValidator) ---

struct CreateLinkInput {
    title: String,
    amount: String,
    metadata: Option<Value>,
    payment_network: Option<String>,
    payment_asset: Option<String>,
    fee_delegation: Option<String>,
    store_id: Option<i64>,
    customer_country_code: Option<String>,
}

fn vpush(errors: &mut Vec<ValidationFailure>, field: &str, rule: &str, message: &str) {
    errors.push(ValidationFailure::new(field, rule, message));
}

fn validate_create(body: &Value) -> AppResult<CreateLinkInput> {
    let mut errors = Vec::new();

    let title = match body.get("title").and_then(|v| v.as_str()) {
        Some(t) if !t.trim().is_empty() && t.trim().chars().count() <= 255 => Some(t.trim().to_string()),
        _ => {
            vpush(&mut errors, "title", "required", "The title field is required");
            None
        }
    };
    let amount = match body.get("amount") {
        Some(Value::String(s)) if is_atomic_amount(s.trim()) => Some(s.trim().to_string()),
        _ => {
            vpush(&mut errors, "amount", "regex", "The amount field format is invalid");
            None
        }
    };
    let fee_delegation = match body.get("feeDelegation") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if FEE_DELEGATIONS.contains(&s.as_str()) => Some(s.clone()),
        Some(_) => {
            vpush(&mut errors, "feeDelegation", "enum", "The selected feeDelegation is invalid");
            None
        }
    };
    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }

    let opt_string = |key: &str| body.get(key).and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());

    Ok(CreateLinkInput {
        title: title.unwrap(),
        amount: amount.unwrap(),
        metadata: body.get("metadata").filter(|v| !v.is_null()).cloned(),
        payment_network: opt_string("paymentNetwork"),
        payment_asset: opt_string("paymentAsset"),
        fee_delegation,
        store_id: body.get("storeId").and_then(|v| v.as_i64()),
        customer_country_code: opt_string("customerCountryCode").map(|s| s.to_uppercase()),
    })
}
