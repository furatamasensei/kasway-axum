//! Public subscription checkout surface.
//!
//! A subscription is a sequence of ordinary KPR-1 invoices. The wallet stores
//! the customer's optional auto-renew mandate locally; the backend never asks
//! the customer to pre-fund a keeper-controlled subscription cell.

use crate::error::{AppError, AppResult};
use crate::handlers::{invoices, subscriptions};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};

#[derive(sqlx::FromRow)]
struct PublicSubscription {
    id: i64,
    user_id: i64,
    public_id: String,
    status: String,
    payment_mode: String,
    plan_snapshot: String,
    current_period_start: Option<String>,
    current_period_end: Option<String>,
    next_billing_at: Option<String>,
}

async fn load(state: &AppState, public_id: &str) -> AppResult<PublicSubscription> {
    sqlx::query_as(
        "SELECT id, user_id, public_id, status, payment_mode, plan_snapshot, \
         current_period_start, current_period_end, next_billing_at \
         FROM subscriptions WHERE public_id = $1",
    )
    .bind(public_id)
    .fetch_optional(&state.db.pool)
    .await?
    .ok_or_else(|| AppError::commerce(404, "Subscription not found"))
}

async fn latest_invoice(state: &AppState, subscription_id: i64) -> AppResult<Option<Value>> {
    let id: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM invoices WHERE subscription_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(subscription_id)
    .fetch_optional(&state.db.pool)
    .await?;
    let Some(id) = id else { return Ok(None) };
    let mut invoice = invoices::load_by_id(state, id).await?;
    invoices::expire_if_needed(state, &mut invoice).await?;
    let (items, intent) = invoices::load_relations(state, invoice.id()).await?;
    Ok(Some(invoices::serialize_invoice(
        &invoice,
        &items,
        intent.as_ref(),
    )))
}

/// Public wallet status. `currentInvoice.paymentRequestUri` is the only thing
/// auto-renew executes; it is verified and paid through the normal KPR-1 path.
pub async fn show(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
) -> AppResult<Json<Value>> {
    let subscription = load(&state, &public_id).await?;
    let snapshot: Value =
        serde_json::from_str(&subscription.plan_snapshot).unwrap_or_else(|_| json!({}));
    let current_invoice = latest_invoice(&state, subscription.id).await?;
    let payment_request_uri = current_invoice
        .as_ref()
        .and_then(|invoice| invoice.get("paymentRequestUri"))
        .cloned()
        .unwrap_or(Value::Null);
    Ok(Json(json!({
        "publicId": subscription.public_id,
        "status": subscription.status,
        "paymentMode": subscription.payment_mode,
        "paymentType": "subscription",
        "autoRenewAuthority": "wallet_local",
        "paymentWindowSeconds": crate::kpr1::PAYMENT_WINDOW_SECONDS,
        "nextBillingAt": subscription.next_billing_at,
        "currentPeriodStart": subscription.current_period_start,
        "currentPeriodEnd": subscription.current_period_end,
        "plan": {
            "name": snapshot["name"],
            "amount": snapshot["amount"],
            "currency": snapshot["currency"],
            "paymentNetwork": snapshot["paymentNetwork"],
            "paymentAsset": snapshot["paymentAsset"],
            "intervalUnit": snapshot["intervalUnit"],
            "intervalCount": snapshot["intervalCount"],
        },
        "currentInvoice": current_invoice,
        "paymentRequestUri": payment_request_uri,
    })))
}

/// Compatibility endpoint for old subscription QR URLs. It returns the signed
/// intent of the current per-cycle invoice; no special funding contract exists.
pub async fn intent(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
) -> AppResult<Json<Value>> {
    let subscription = load(&state, &public_id).await?;
    let invoice_public_id: Option<String> = sqlx::query_scalar(
        "SELECT public_id FROM invoices WHERE subscription_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(subscription.id)
    .fetch_optional(&state.db.pool)
    .await?;
    let invoice_public_id = invoice_public_id
        .ok_or_else(|| AppError::commerce(404, "Subscription does not have a payable invoice"))?;
    Ok(Json(
        invoices::fetch_kpr1_intent(&state, &invoice_public_id).await?,
    ))
}

/// Stop future invoice generation. There are no subscription funds to withdraw.
pub async fn cancel(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    Json(_body): Json<Value>,
) -> AppResult<Json<Value>> {
    let subscription = load(&state, &public_id).await?;
    Ok(Json(
        subscriptions::cancel_subscription(&state, subscription.user_id, &public_id).await?,
    ))
}
