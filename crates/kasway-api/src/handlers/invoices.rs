//! `/api/invoices` — InvoicesController (index, show, store, cancel).
//!
//! `store` mints a KPR-1 intent via `crate::kpr1` (faithful fee/tax/split math +
//! canonical hash + ed25519; covenant compiler/WASM stubbed deterministically —
//! see that module). Response is the serialized invoice incl. the intent.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::kpr1::{self, IntentInvoiceCtx};
use crate::state::AppState;
use crate::store_context::resolve_request_store;
use crate::util::{now_iso, paginator_meta};
use axum::extract::{Path, Query, State};
use axum::Json;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Map, Value};

const FEE_DELEGATIONS: &[&str] = &["merchant_subsidized", "customer_pays"];
const PAYMENT_MODES: &[&str] = &["address", "covenant"];

#[derive(Deserialize, Default)]
pub struct InvoiceQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
    #[serde(rename = "storeId")]
    store_id: Option<i64>,
    source: Option<String>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct InvoiceRow {
    id: i64,
    user_id: i64,
    store_id: Option<i64>,
    public_id: String,
    external_id: Option<String>,
    subscription_id: Option<i64>,
    subscription_cycle_id: Option<i64>,
    payment_link_id: Option<i64>,
    status: String,
    payment_address: Option<String>,
    payment_network: Option<String>,
    payment_asset: Option<String>,
    payment_reference: Option<String>,
    subtotal_amount: i64,
    total_amount: i64,
    fee_delegation: Option<String>,
    payment_mode: Option<String>,
    service_fee_amount: i64,
    currency: String,
    pricing_country_code: Option<String>,
    metadata: Option<String>,
    expires_at: Option<String>,
    paid_at: Option<String>,
    cancelled_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

impl InvoiceRow {
    pub(crate) fn id(&self) -> i64 {
        self.id
    }
}

const INVOICE_COLS: &str = "id, user_id, store_id, public_id, external_id, subscription_id, \
    subscription_cycle_id, payment_link_id, status, payment_address, payment_network, \
    payment_asset, payment_reference, subtotal_amount, total_amount, fee_delegation, \
    payment_mode, service_fee_amount, currency, pricing_country_code, metadata, expires_at, \
    paid_at, cancelled_at, created_at, updated_at";

#[derive(sqlx::FromRow)]
pub(crate) struct ItemRow {
    id: i64,
    invoice_id: i64,
    name: String,
    quantity: i64,
    unit_amount: i64,
    total_amount: i64,
    pricing_country_code: Option<String>,
    pricing_currency: Option<String>,
    pricing_source: Option<String>,
    metadata: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct IntentRow {
    id: i64,
    invoice_id: i64,
    user_id: i64,
    intent_id: String,
    status: String,
    network: String,
    asset_id: String,
    amount_sompi: i64,
    platform_fee_bps: i64,
    platform_fee_amount: i64,
    tax_bps: Option<i64>,
    tax_amount: Option<i64>,
    tax_address: Option<String>,
    merchant_address: String,
    platform_fee_address: String,
    template_id: String,
    template_version: String,
    script_hash: String,
    canonical_hash: String,
    payment_request_uri: String,
    payment_intent_url: String,
    signature_algorithm: String,
    signature_key_id: String,
    signature_value: String,
    tx_id: Option<String>,
    verification_status: Option<String>,
    failure_reason: Option<String>,
    required_outputs: String,
    canonical_intent: String,
    metadata: Option<String>,
    expires_at: Option<String>,
    fetched_at: Option<String>,
    submitted_at: Option<String>,
    observed_at: Option<String>,
    verified_at: Option<String>,
    settled_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const INTENT_COLS: &str = "id, invoice_id, user_id, intent_id, status, network, asset_id, \
    amount_sompi, platform_fee_bps, platform_fee_amount, tax_bps, tax_amount, tax_address, \
    merchant_address, platform_fee_address, template_id, template_version, script_hash, \
    canonical_hash, payment_request_uri, payment_intent_url, signature_algorithm, \
    signature_key_id, signature_value, tx_id, verification_status, failure_reason, \
    required_outputs, canonical_intent, metadata, expires_at, fetched_at, submitted_at, \
    observed_at, verified_at, settled_at, created_at, updated_at";

fn parse_json_or_null(raw: &Option<String>) -> Value {
    match raw {
        None => Value::Null,
        Some(s) => serde_json::from_str(s).unwrap_or(Value::Null),
    }
}

fn amount_str(v: i64) -> Value {
    Value::String(v.to_string())
}

fn serialize_item(item: &ItemRow) -> Value {
    json!({
        "id": item.id,
        "invoiceId": item.invoice_id,
        "name": item.name,
        "quantity": item.quantity,
        "unitAmount": amount_str(item.unit_amount),
        "totalAmount": amount_str(item.total_amount),
        "pricingCountryCode": item.pricing_country_code,
        "pricingCurrency": item.pricing_currency,
        "pricingSource": item.pricing_source,
        "metadata": parse_json_or_null(&item.metadata),
        "createdAt": item.created_at,
        "updatedAt": item.updated_at,
    })
}

pub(crate) fn serialize_intent(intent: &IntentRow) -> Value {
    json!({
        "id": intent.id,
        "invoiceId": intent.invoice_id,
        "userId": intent.user_id,
        "intentId": intent.intent_id,
        "status": intent.status,
        "network": intent.network,
        "assetId": intent.asset_id,
        "amountSompi": amount_str(intent.amount_sompi),
        "platformFeeBps": intent.platform_fee_bps,
        "platformFeeAmount": amount_str(intent.platform_fee_amount),
        "taxBps": intent.tax_bps,
        "taxAmount": intent.tax_amount.map(amount_str).unwrap_or(Value::Null),
        "taxAddress": intent.tax_address,
        "merchantAddress": intent.merchant_address,
        "platformFeeAddress": intent.platform_fee_address,
        "templateId": intent.template_id,
        "templateVersion": intent.template_version,
        "scriptHash": intent.script_hash,
        "canonicalHash": intent.canonical_hash,
        "paymentRequestUri": intent.payment_request_uri,
        "paymentIntentUrl": intent.payment_intent_url,
        "signatureAlgorithm": intent.signature_algorithm,
        "signatureKeyId": intent.signature_key_id,
        "signatureValue": intent.signature_value,
        "txId": intent.tx_id,
        "verificationStatus": intent.verification_status,
        "failureReason": intent.failure_reason,
        "requiredOutputs": serde_json::from_str::<Value>(&intent.required_outputs).unwrap_or(json!([])),
        "canonicalIntent": serde_json::from_str::<Value>(&intent.canonical_intent).unwrap_or(json!({})),
        "metadata": parse_json_or_null(&intent.metadata),
        "expiresAt": intent.expires_at,
        "fetchedAt": intent.fetched_at,
        "submittedAt": intent.submitted_at,
        "observedAt": intent.observed_at,
        "verifiedAt": intent.verified_at,
        "settledAt": intent.settled_at,
        "createdAt": intent.created_at,
        "updatedAt": intent.updated_at,
    })
}

/// Replicates `Invoice.serialize()` including the KPR-1 hoisting logic.
pub(crate) fn serialize_invoice(inv: &InvoiceRow, items: &[ItemRow], intent: Option<&IntentRow>) -> Value {
    let mut obj = Map::new();
    obj.insert("id".into(), json!(inv.id));
    obj.insert("userId".into(), json!(inv.user_id));
    obj.insert("storeId".into(), json!(inv.store_id));
    obj.insert("publicId".into(), json!(inv.public_id));
    obj.insert("externalId".into(), json!(inv.external_id));
    obj.insert("subscriptionId".into(), json!(inv.subscription_id));
    obj.insert("subscriptionCycleId".into(), json!(inv.subscription_cycle_id));
    obj.insert("paymentLinkId".into(), json!(inv.payment_link_id));
    obj.insert("status".into(), json!(inv.status));
    obj.insert("paymentAddress".into(), json!(inv.payment_address));
    obj.insert("paymentNetwork".into(), json!(inv.payment_network));
    obj.insert("paymentAsset".into(), json!(inv.payment_asset));
    obj.insert("paymentReference".into(), json!(inv.payment_reference));
    obj.insert("subtotalAmount".into(), amount_str(inv.subtotal_amount));
    obj.insert("totalAmount".into(), amount_str(inv.total_amount));
    obj.insert("feeDelegation".into(), json!(inv.fee_delegation));
    obj.insert("paymentMode".into(), json!(inv.payment_mode));
    obj.insert("serviceFeeAmount".into(), amount_str(inv.service_fee_amount));
    obj.insert("currency".into(), json!(inv.currency));
    obj.insert("pricingCountryCode".into(), json!(inv.pricing_country_code));
    obj.insert("metadata".into(), parse_json_or_null(&inv.metadata));
    obj.insert("expiresAt".into(), json!(inv.expires_at));
    obj.insert("paidAt".into(), json!(inv.paid_at));
    obj.insert("cancelledAt".into(), json!(inv.cancelled_at));
    obj.insert("createdAt".into(), json!(inv.created_at));
    obj.insert("updatedAt".into(), json!(inv.updated_at));

    // preloaded relations
    obj.insert("items".into(), Value::Array(items.iter().map(serialize_item).collect()));
    // payments / paymentCredits relations are empty until those slices land.
    obj.insert("payments".into(), json!([]));
    let intent_value = intent.map(serialize_intent);
    obj.insert(
        "kpr1PaymentIntent".into(),
        intent_value.clone().unwrap_or(Value::Null),
    );
    obj.insert("paymentCredits".into(), json!([]));

    // Invoice.serialize() hoisting
    if let (Some(intent), Some(iv)) = (intent, intent_value) {
        obj.remove("paymentAddress");
        obj.insert("paymentRail".into(), json!("kpr1_covenant"));
        obj.insert("paymentRequestUri".into(), iv["paymentRequestUri"].clone());
        obj.insert("paymentIntentUrl".into(), iv["paymentIntentUrl"].clone());
        obj.insert("paymentIntentHash".into(), iv["canonicalHash"].clone());
        obj.insert(
            "platformFee".into(),
            json!({
                "bps": intent.platform_fee_bps,
                "amountSompi": amount_str(intent.platform_fee_amount),
                "address": intent.platform_fee_address,
            }),
        );
        let tax = if intent.tax_bps.unwrap_or(0) != 0 {
            json!({
                "bps": intent.tax_bps,
                "amountSompi": intent.tax_amount.map(amount_str).unwrap_or(Value::Null),
                "address": intent.tax_address,
            })
        } else {
            Value::Null
        };
        obj.insert("tax".into(), tax);
        let required = iv["requiredOutputs"].clone();
        let splits: Vec<Value> = required
            .as_array()
            .map(|a| a.iter().filter(|o| o["role"] == "split").cloned().collect())
            .unwrap_or_default();
        obj.insert("requiredOutputs".into(), required);
        obj.insert("splitOutputs".into(), Value::Array(splits));
    } else {
        obj.insert("paymentRail".into(), json!("unsupported"));
    }

    Value::Object(obj)
}

pub(crate) async fn load_relations(
    state: &AppState,
    invoice_id: i64,
) -> AppResult<(Vec<ItemRow>, Option<IntentRow>)> {
    let items = sqlx::query_as::<_, ItemRow>(&format!(
        "SELECT id, invoice_id, name, quantity, unit_amount, total_amount, pricing_country_code, \
         pricing_currency, pricing_source, metadata, created_at, updated_at \
         FROM invoice_items WHERE invoice_id = ? ORDER BY id ASC"
    ))
    .bind(invoice_id)
    .fetch_all(&state.db.pool)
    .await?;

    let intent = sqlx::query_as::<_, IntentRow>(&format!(
        "SELECT {INTENT_COLS} FROM kpr1_payment_intents WHERE invoice_id = ?"
    ))
    .bind(invoice_id)
    .fetch_optional(&state.db.pool)
    .await?;

    Ok((items, intent))
}

/// expireIfNeeded: flip open->expired when past `expires_at`.
pub(crate) async fn expire_if_needed(state: &AppState, inv: &mut InvoiceRow) -> AppResult<()> {
    if inv.status == "open" {
        if let Some(exp) = &inv.expires_at {
            if let Ok(exp_dt) = chrono::DateTime::parse_from_rfc3339(exp) {
                if exp_dt <= chrono::Utc::now() {
                    inv.status = "expired".to_string();
                    sqlx::query("UPDATE invoices SET status = 'expired' WHERE id = ?")
                        .bind(inv.id)
                        .execute(&state.db.pool)
                        .await?;
                }
            }
        }
    }
    Ok(())
}

pub(crate) async fn load_owned_invoice(
    state: &AppState,
    user_id: i64,
    store_id: i64,
    id: i64,
) -> AppResult<InvoiceRow> {
    sqlx::query_as::<_, InvoiceRow>(&format!(
        "SELECT {INVOICE_COLS} FROM invoices WHERE user_id = ? AND store_id = ? AND id = ?"
    ))
    .bind(user_id)
    .bind(store_id)
    .bind(id)
    .fetch_optional(&state.db.pool)
    .await?
    .ok_or_else(|| AppError::commerce(404, "Invoice not found"))
}

/// serializeKpr1PaymentContract: serialize() then always drop paymentAddress.
pub(crate) fn serialize_kpr1_contract(
    inv: &InvoiceRow,
    items: &[ItemRow],
    intent: Option<&IntentRow>,
) -> Value {
    let mut v = serialize_invoice(inv, items, intent);
    if let Value::Object(map) = &mut v {
        map.remove("paymentAddress");
    }
    v
}

/// Load an invoice by public_id (no user scope) — checkout getByPublicId.
pub(crate) async fn load_by_public_id(state: &AppState, public_id: &str) -> AppResult<InvoiceRow> {
    sqlx::query_as::<_, InvoiceRow>(&format!(
        "SELECT {INVOICE_COLS} FROM invoices WHERE public_id = ?"
    ))
    .bind(public_id)
    .fetch_optional(&state.db.pool)
    .await?
    .ok_or_else(|| AppError::commerce(404, "Invoice not found"))
}

/// Load an invoice owned by (user, store) by public_id — commerce show.
pub(crate) async fn load_owned_by_public_id(
    state: &AppState,
    user_id: i64,
    store_id: i64,
    public_id: &str,
) -> AppResult<InvoiceRow> {
    sqlx::query_as::<_, InvoiceRow>(&format!(
        "SELECT {INVOICE_COLS} FROM invoices WHERE user_id = ? AND store_id = ? AND public_id = ?"
    ))
    .bind(user_id)
    .bind(store_id)
    .bind(public_id)
    .fetch_optional(&state.db.pool)
    .await?
    .ok_or_else(|| AppError::commerce(404, "Invoice not found"))
}

fn meta_bool(metadata: &Option<String>, key: &str) -> Option<bool> {
    let raw = metadata.as_ref()?;
    let v: Value = serde_json::from_str(raw).ok()?;
    v.get(key).and_then(|x| x.as_bool())
}

fn meta_str(metadata: &Option<String>, key: &str) -> Option<String> {
    let raw = metadata.as_ref()?;
    let v: Value = serde_json::from_str(raw).ok()?;
    v.get(key).and_then(|x| x.as_str()).map(|s| s.to_string())
}

fn is_expired_now(inv: &InvoiceRow) -> bool {
    if inv.status != "open" {
        return false;
    }
    match &inv.expires_at {
        Some(e) => chrono::DateTime::parse_from_rfc3339(e)
            .map(|dt| dt <= chrono::Utc::now())
            .unwrap_or(false),
        None => false,
    }
}

/// Port of PaymentOperationsService.derivePaymentStatus. Confirmation policy is
/// simplified to the platform default (KASPA_MIN_CONFIRMATIONS = 10); merchant
/// tenant overrides arrive with the payment-tenant-settings slice.
pub(crate) async fn derive_payment_status(state: &AppState, inv: &InvoiceRow) -> AppResult<Value> {
    let required_confirmations: i64 = 10;
    let invoice_total = inv.total_amount as i128;

    let credits: Vec<i64> = sqlx::query_scalar("SELECT amount FROM payment_credits WHERE invoice_id = ?")
        .bind(inv.id)
        .fetch_all(&state.db.pool)
        .await?;
    let applied_credit_total: i128 = credits.iter().map(|a| *a as i128).sum();

    let payments = sqlx::query_as::<_, (String, i64, Option<String>)>(
        "SELECT status, amount, metadata FROM payments WHERE invoice_id = ? ORDER BY id DESC",
    )
    .bind(inv.id)
    .fetch_all(&state.db.pool)
    .await?;

    let confirmed: Vec<&(String, i64, Option<String>)> =
        payments.iter().filter(|(s, _, _)| s == "confirmed").collect();
    let applied_payment_total: i128 = confirmed
        .iter()
        .filter(|(_, _, m)| meta_bool(m, "appliedToInvoice") != Some(false))
        .map(|(_, a, _)| *a as i128)
        .sum();
    let applied_total = if applied_credit_total > 0 { applied_credit_total } else { applied_payment_total };
    let unapplied_receipt_total: i128 = confirmed
        .iter()
        .filter(|(_, _, m)| meta_bool(m, "appliedToInvoice") == Some(false))
        .map(|(_, a, _)| *a as i128)
        .sum();
    let latest_meta = confirmed.first().map(|(_, _, m)| m.clone()).unwrap_or(None);

    let observations = sqlx::query_as::<_, (String, i64, i64, Option<String>, Option<String>)>(
        "SELECT status, amount, confirmations, accepted_at, created_at FROM payment_observations \
         WHERE invoice_id = ? ORDER BY id DESC",
    )
    .bind(inv.id)
    .fetch_all(&state.db.pool)
    .await?;
    let observed_total: i128 = observations.iter().map(|(_, a, _, _, _)| *a as i128).sum();
    let final_obs: Vec<_> = observations
        .iter()
        .filter(|(s, _, c, _, _)| s == "settled" || *c >= required_confirmations)
        .collect();
    let final_observed_total: i128 = final_obs.iter().map(|(_, a, _, _, _)| *a as i128).sum();
    let max_confirmations = observations.iter().map(|(_, _, c, _, _)| *c).max().unwrap_or(0);
    let has_confirming = payments.iter().any(|(s, _, _)| s == "pending" || s == "submitted")
        || observations
            .iter()
            .any(|(s, _, c, _, _)| (s == "pending" || s == "matched") && *c < required_confirmations);
    let has_settleable = observations
        .iter()
        .any(|(s, _, c, _, _)| (s == "pending" || s == "matched") && *c >= required_confirmations);

    let payment_state = resolve_status(
        inv,
        invoice_total,
        applied_total,
        unapplied_receipt_total,
        &latest_meta,
        has_confirming,
        has_settleable,
    );

    let remaining = if applied_total < invoice_total { invoice_total - applied_total } else { 0 };
    let overpaid = if applied_total > invoice_total { applied_total - invoice_total } else { 0 };
    let last_observed_at = observations
        .iter()
        .find_map(|(_, _, _, acc, cr)| acc.clone().or_else(|| cr.clone()));

    Ok(json!({
        "totals": {
            "invoice": invoice_total.to_string(),
            "observed": observed_total.to_string(),
            "finalObserved": final_observed_total.to_string(),
            "credited": applied_total.to_string(),
            "remaining": remaining.to_string(),
            "overpaid": overpaid.to_string(),
            "unapplied": unapplied_receipt_total.to_string(),
        },
        "finality": {
            "confirmationsRequired": required_confirmations,
            "maxConfirmations": max_confirmations,
            "pendingObservationCount": observations.len() - final_obs.len(),
            "finalObservationCount": final_obs.len(),
        },
        "status": {
            "invoiceStatus": inv.status,
            "paymentState": payment_state,
            "lastObservedAt": last_observed_at,
        },
    }))
}

#[allow(clippy::too_many_arguments)]
fn resolve_status(
    inv: &InvoiceRow,
    invoice_total: i128,
    applied_total: i128,
    unapplied: i128,
    latest_meta: &Option<String>,
    has_confirming: bool,
    has_settleable: bool,
) -> &'static str {
    if unapplied > 0 || meta_bool(latest_meta, "appliedToInvoice") == Some(false) {
        return "unapplied_receipt";
    }
    if inv.status == "cancelled" {
        return "cancelled";
    }
    if inv.status == "expired" || is_expired_now(inv) {
        return "expired";
    }
    let settlement_state = meta_str(latest_meta, "settlementState");
    if settlement_state.as_deref() == Some("overpaid") || applied_total > invoice_total {
        return "overpaid";
    }
    if settlement_state.as_deref() == Some("underpaid") {
        return "underpaid";
    }
    if inv.status == "paid" || applied_total >= invoice_total {
        return "paid";
    }
    if applied_total > 0 {
        return "underpaid";
    }
    if has_settleable {
        return "ready_to_settle";
    }
    if has_confirming {
        return "confirming";
    }
    "awaiting_payment"
}

/// CheckoutStateService.fromPaymentStatus.
pub(crate) fn checkout_state(summary: &Value) -> Value {
    let state = summary["status"]["paymentState"].as_str().unwrap_or("");
    let (s, next, terminal) = match state {
        "awaiting_payment" => ("awaiting_payment", "open_kpr1_wallet", false),
        "confirming" | "ready_to_settle" => ("confirming_payment", "wait_for_kpr1_verification", false),
        "underpaid" => ("confirming_payment", "contact_merchant", false),
        "paid" | "overpaid" => ("paid", "show_receipt", true),
        "expired" => ("expired", "contact_merchant", true),
        "cancelled" => ("cancelled", "contact_merchant", true),
        "unapplied_receipt" => ("confirming_payment", "contact_merchant", false),
        _ => ("unavailable", "none", true),
    };
    json!({ "state": s, "nextAction": next, "isTerminal": terminal })
}

/// Payment status summary for an invoice id (load + derive). Used by exceptions.
pub(crate) async fn derive_payment_status_by_id(state: &AppState, id: i64) -> AppResult<Value> {
    let inv = load_by_id(state, id).await?;
    derive_payment_status(state, &inv).await
}

/// Load an invoice by id (no scoping) — used after a public link spawn.
pub(crate) async fn load_by_id(state: &AppState, id: i64) -> AppResult<InvoiceRow> {
    sqlx::query_as::<_, InvoiceRow>(&format!(
        "SELECT {INVOICE_COLS} FROM invoices WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(&state.db.pool)
    .await?
    .ok_or_else(|| AppError::commerce(404, "Invoice not found"))
}

/// Find an invoice by public_id (no scoping); None when absent.
pub(crate) async fn find_by_public_id(
    state: &AppState,
    public_id: &str,
) -> AppResult<Option<InvoiceRow>> {
    Ok(sqlx::query_as::<_, InvoiceRow>(&format!(
        "SELECT {INVOICE_COLS} FROM invoices WHERE public_id = ?"
    ))
    .bind(public_id)
    .fetch_optional(&state.db.pool)
    .await?)
}

fn kpr1_err(code: &str, message: &str) -> AppError {
    AppError::Kpr1 { code: code.to_string(), message: message.to_string() }
}

/// Port of Kpr1PaymentIntentService.fetchByInvoicePublicId. Returns the stored
/// signed canonical intent; transitions created->fetched.
pub(crate) async fn fetch_kpr1_intent(state: &AppState, public_id: &str) -> AppResult<Value> {
    let invoice = find_by_public_id(state, public_id).await?;
    let Some(invoice) = invoice else {
        return Err(kpr1_err("KPR1_INTENT_NOT_FOUND", "KPR-1 payment intent not found"));
    };
    let (_, intent) = load_relations(state, invoice.id).await?;
    let Some(intent) = intent else {
        return Err(kpr1_err("KPR1_INTENT_NOT_FOUND", "KPR-1 payment intent not found"));
    };

    if invoice.status != "open" {
        return Err(kpr1_err(
            "KPR1_INVOICE_NOT_OPEN",
            "KPR-1 payment intent is only available for open invoices",
        ));
    }
    // assertInvoiceStoreAcceptsPublicPayment: included default store always accepts.

    let expired = intent
        .expires_at
        .as_deref()
        .and_then(|e| chrono::DateTime::parse_from_rfc3339(e).ok())
        .map(|dt| dt <= chrono::Utc::now())
        .unwrap_or(false);
    if expired {
        sqlx::query("UPDATE kpr1_payment_intents SET status = 'expired' WHERE id = ?")
            .bind(intent.id)
            .execute(&state.db.pool)
            .await?;
        return Err(kpr1_err("KPR1_INTENT_EXPIRED", "KPR-1 payment intent has expired"));
    }

    if intent.status == "created" {
        let now = now_iso();
        sqlx::query("UPDATE kpr1_payment_intents SET status = 'fetched', fetched_at = ? WHERE id = ?")
            .bind(&now)
            .bind(intent.id)
            .execute(&state.db.pool)
            .await?;
    }

    Ok(serde_json::from_str(&intent.canonical_intent).unwrap_or(json!({})))
}

/// `GET /api/invoices`
pub async fn index(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Query(q): Query<InvoiceQuery>,
) -> AppResult<Json<Value>> {
    let store_id = resolve_request_store(&state, auth.user_id, q.store_id).await?;
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(10).max(1);
    let offset = (page - 1) * per_page;
    let payment_link_only = q.source.as_deref() == Some("payment_link");

    let filter = if payment_link_only {
        "user_id = ? AND store_id = ? AND payment_link_id IS NOT NULL"
    } else {
        "user_id = ? AND store_id = ?"
    };

    let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM invoices WHERE {filter}"))
        .bind(auth.user_id)
        .bind(store_id)
        .fetch_one(&state.db.pool)
        .await?;

    let invoices = sqlx::query_as::<_, InvoiceRow>(&format!(
        "SELECT {INVOICE_COLS} FROM invoices WHERE {filter} ORDER BY created_at DESC LIMIT ? OFFSET ?"
    ))
    .bind(auth.user_id)
    .bind(store_id)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&state.db.pool)
    .await?;

    let mut data = Vec::with_capacity(invoices.len());
    for inv in &invoices {
        let (items, intent) = load_relations(&state, inv.id).await?;
        data.push(serialize_invoice(inv, &items, intent.as_ref()));
    }

    Ok(Json(json!({
        "meta": paginator_meta(total, per_page, page),
        "data": data,
    })))
}

// --- store (create) ---

struct ItemInput {
    name: String,
    quantity: i64,
    unit_amount: i128,
}

struct CreateInput {
    external_id: Option<String>,
    metadata: Option<Value>,
    expires_at: Option<String>,
    payment_network: Option<String>,
    payment_asset: Option<String>,
    fee_delegation: Option<String>,
    payment_mode: Option<String>,
    store_id: Option<i64>,
    customer_country_code: Option<String>,
    items: Vec<ItemInput>,
}

fn vpush(errors: &mut Vec<ValidationFailure>, field: &str, rule: &str, message: &str) {
    errors.push(ValidationFailure {
        message: message.to_string(),
        rule: rule.to_string(),
        field: field.to_string(),
    });
}

fn is_atomic_amount(s: &str) -> bool {
    // ^(0|[1-9]\d*)$
    s == "0" || (!s.is_empty() && !s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit()))
}

fn validate_create(body: &Value) -> AppResult<CreateInput> {
    let mut errors = Vec::new();

    let opt_string = |key: &str| body.get(key).and_then(|v| v.as_str()).map(|s| s.trim().to_string());

    let fee_delegation = match body.get("feeDelegation") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if FEE_DELEGATIONS.contains(&s.as_str()) => Some(s.clone()),
        Some(_) => {
            vpush(&mut errors, "feeDelegation", "enum", "The selected feeDelegation is invalid");
            None
        }
    };
    let payment_mode = match body.get("paymentMode") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if PAYMENT_MODES.contains(&s.as_str()) => Some(s.clone()),
        Some(_) => {
            vpush(&mut errors, "paymentMode", "enum", "The selected paymentMode is invalid");
            None
        }
    };

    // items: array, minLength 1, each {name 1..255, quantity +int, unitAmount atomic}
    let mut items = Vec::new();
    match body.get("items") {
        None | Some(Value::Null) => {
            vpush(&mut errors, "items", "required", "The items field is required");
        }
        Some(Value::Array(arr)) if arr.is_empty() => {
            vpush(&mut errors, "items", "minLength", "The items field must have at least 1 items");
        }
        Some(Value::Array(arr)) => {
            for (i, item) in arr.iter().enumerate() {
                let name = item.get("name").and_then(|v| v.as_str()).map(|s| s.trim().to_string());
                let qty = item.get("quantity").and_then(|v| v.as_i64());
                let unit = item.get("unitAmount").and_then(|v| v.as_str()).map(|s| s.trim().to_string());

                let name_ok = match &name {
                    Some(n) if !n.is_empty() && n.chars().count() <= 255 => true,
                    _ => {
                        vpush(&mut errors, &format!("items.{i}.name"), "required", &format!("The items.{i}.name field is required"));
                        false
                    }
                };
                let qty_ok = match qty {
                    Some(q) if q > 0 => true,
                    _ => {
                        vpush(&mut errors, &format!("items.{i}.quantity"), "positive", &format!("The items.{i}.quantity field must be positive"));
                        false
                    }
                };
                let unit_ok = match &unit {
                    Some(u) if is_atomic_amount(u) => true,
                    _ => {
                        vpush(&mut errors, &format!("items.{i}.unitAmount"), "regex", &format!("The items.{i}.unitAmount field format is invalid"));
                        false
                    }
                };
                if name_ok && qty_ok && unit_ok {
                    items.push(ItemInput {
                        name: name.unwrap(),
                        quantity: qty.unwrap(),
                        unit_amount: unit.unwrap().parse().unwrap_or(0),
                    });
                }
            }
        }
        Some(_) => {
            vpush(&mut errors, "items", "array", "The items field must be an array");
        }
    }

    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }

    Ok(CreateInput {
        external_id: opt_string("externalId").filter(|s| !s.is_empty()),
        metadata: body.get("metadata").filter(|v| !v.is_null()).cloned(),
        expires_at: opt_string("expiresAt").filter(|s| !s.is_empty()),
        payment_network: opt_string("paymentNetwork").filter(|s| !s.is_empty()),
        payment_asset: opt_string("paymentAsset").filter(|s| !s.is_empty()),
        fee_delegation,
        payment_mode,
        store_id: body.get("storeId").and_then(|v| v.as_i64()),
        customer_country_code: opt_string("customerCountryCode")
            .filter(|s| !s.is_empty())
            .map(|s| s.to_uppercase()),
        items,
    })
}

use crate::store_context::assert_can_create_new_payments;

fn random_suffix() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// `POST /api/invoices`
pub async fn store(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let (invoice_id, store_id) = create_for_merchant(&state, auth.user_id, &body, None, None, None).await?;
    let inv = load_owned_invoice(&state, auth.user_id, store_id, invoice_id).await?;
    let (items, intent) = load_relations(&state, inv.id).await?;
    Ok(Json(serialize_invoice(&inv, &items, intent.as_ref())))
}

/// createForMerchant — shared by the invoices and commerce stores.
/// Returns (invoice_id, store_id); the caller serializes.
pub(crate) async fn create_for_merchant(
    state: &AppState,
    user_id: i64,
    body: &Value,
    payment_link_id: Option<i64>,
    subscription_id: Option<i64>,
    subscription_cycle_id: Option<i64>,
) -> AppResult<(i64, i64)> {
    let input = validate_create(body)?;

    let store_id = resolve_request_store(state, user_id, input.store_id).await?;
    assert_can_create_new_payments(state, store_id).await?;

    let network = input
        .payment_network
        .clone()
        .unwrap_or_else(|| state.config.kpr1.default_network.clone());
    let asset = input
        .payment_asset
        .clone()
        .unwrap_or_else(|| state.config.kpr1.default_asset.clone());
    let fee_delegation = input
        .fee_delegation
        .clone()
        .unwrap_or_else(|| "merchant_subsidized".to_string());

    // externalId uniqueness (user-scoped)
    if let Some(ext) = &input.external_id {
        let existing: Option<i64> =
            sqlx::query_scalar("SELECT id FROM invoices WHERE user_id = ? AND external_id = ?")
                .bind(user_id)
                .bind(ext)
                .fetch_optional(&state.db.pool)
                .await?;
        if existing.is_some() {
            return Err(AppError::commerce(422, "External id has already been used"));
        }
    }

    // expiresAt validation (parseOptionalDateTime)
    let expires_at = match &input.expires_at {
        None => None,
        Some(s) => {
            if chrono::DateTime::parse_from_rfc3339(s).is_err() {
                return Err(AppError::commerce(422, "expiresAt must be a valid ISO 8601 date-time"));
            }
            Some(s.clone())
        }
    };

    // amounts
    let subtotal: i128 = input.items.iter().map(|it| it.unit_amount * it.quantity as i128).sum();
    let service_fee: i128 = if fee_delegation == "customer_pays" {
        kpr1::customer_paid_amounts(subtotal, state.config.kpr1.platform_fee_bps, state.config.kpr1.platform_fee_flat_sompi)?.0
    } else {
        0
    };
    let total = subtotal + service_fee;

    let public_id = format!("inv_{}", random_suffix());
    let payment_reference = format!("payref_{}", random_suffix());
    let now = now_iso();
    let metadata_str = input.metadata.as_ref().map(|m| m.to_string());

    let result = sqlx::query(
        "INSERT INTO invoices \
         (user_id, store_id, public_id, external_id, payment_link_id, subscription_id, subscription_cycle_id, status, payment_address, payment_network, \
          payment_asset, payment_reference, subtotal_amount, total_amount, fee_delegation, payment_mode, \
          service_fee_amount, currency, pricing_country_code, metadata, expires_at, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(store_id)
    .bind(&public_id)
    .bind(&input.external_id)
    .bind(payment_link_id)
    .bind(subscription_id)
    .bind(subscription_cycle_id)
    .bind(format!("kpr1:pending:{public_id}"))
    .bind(&network)
    .bind(&asset)
    .bind(&payment_reference)
    .bind(subtotal as i64)
    .bind(total as i64)
    .bind(&fee_delegation)
    .bind(&input.payment_mode)
    .bind(service_fee as i64)
    .bind(&asset)
    .bind(&input.customer_country_code)
    .bind(&metadata_str)
    .bind(&expires_at)
    .bind(&now)
    .bind(&now)
    .execute(&state.db.pool)
    .await?;
    let invoice_id = result.last_insert_rowid();

    for it in &input.items {
        sqlx::query(
            "INSERT INTO invoice_items (invoice_id, name, quantity, unit_amount, total_amount, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(invoice_id)
        .bind(&it.name)
        .bind(it.quantity)
        .bind(it.unit_amount as i64)
        .bind((it.unit_amount * it.quantity as i128) as i64)
        .bind(&now)
        .bind(&now)
        .execute(&state.db.pool)
        .await?;
    }

    // Mint KPR-1 intent, then point payment_address at it.
    let intent_id = kpr1::create_for_invoice(
        state,
        &IntentInvoiceCtx {
            invoice_id,
            user_id,
            store_id: Some(store_id),
            public_id: public_id.clone(),
            total_amount: total as i64,
            payment_network: network.clone(),
            payment_asset: asset.clone(),
            payment_mode: input.payment_mode.clone(),
            expires_at: expires_at.clone(),
        },
    )
    .await?;

    sqlx::query("UPDATE invoices SET payment_address = ? WHERE id = ?")
        .bind(format!("kpr1:{intent_id}"))
        .bind(invoice_id)
        .execute(&state.db.pool)
        .await?;

    Ok((invoice_id, store_id))
}

/// `GET /api/invoices/:id`
pub async fn show(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<InvoiceQuery>,
) -> AppResult<Json<Value>> {
    let store_id = resolve_request_store(&state, auth.user_id, q.store_id).await?;
    let mut inv = load_owned_invoice(&state, auth.user_id, store_id, id).await?;
    expire_if_needed(&state, &mut inv).await?;
    let (items, intent) = load_relations(&state, inv.id).await?;
    Ok(Json(serialize_invoice(&inv, &items, intent.as_ref())))
}

/// `POST /api/invoices/:id/cancel`
pub async fn cancel(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<InvoiceQuery>,
) -> AppResult<Json<Value>> {
    let store_id = resolve_request_store(&state, auth.user_id, q.store_id).await?;
    let mut inv = load_owned_invoice(&state, auth.user_id, store_id, id).await?;
    expire_if_needed(&state, &mut inv).await?;

    if inv.status != "open" {
        return Err(AppError::commerce(422, "Only open invoices can be cancelled"));
    }

    let now = now_iso();
    sqlx::query("UPDATE invoices SET status = 'cancelled', cancelled_at = ?, updated_at = ? WHERE id = ?")
        .bind(&now)
        .bind(&now)
        .bind(inv.id)
        .execute(&state.db.pool)
        .await?;

    let inv = load_owned_invoice(&state, auth.user_id, store_id, id).await?;
    let (items, intent) = load_relations(&state, inv.id).await?;
    Ok(Json(serialize_invoice(&inv, &items, intent.as_ref())))
}
