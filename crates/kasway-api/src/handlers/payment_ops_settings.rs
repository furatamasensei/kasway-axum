//! `/api/payments/ops/{settings,capabilities,confirmation-policy,network-capabilities}`
//! — PaymentTenantSettingsController + PaymentConfirmationPolicyController +
//! PaymentNetworkCapabilitiesController.networkCapabilities. Merchant owner
//! always holds the payments.ops.* permissions.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::util::now_iso;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

const MODULES: &[&str] = &["adjustments", "exports", "webhooks", "notifications", "exceptions", "anomalies", "evidence_packs", "analytics"];
const NOTIF_CATEGORIES: &[&str] = &["payment_exception_created", "payment_exception_resolved", "payment_anomaly_detected", "webhook_delivery_failed", "webhook_endpoint_paused", "export_succeeded", "export_failed"];
const ADJUSTMENT_KINDS: &[&str] = &["manual_credit", "write_off", "refund_record", "correction"];
const POLICY_KEYS: &[&str] = &["version", "defaultConfirmations", "overrides", "riskBoostConfirmations"];
const PLATFORM_MIN_CONFIRMATIONS: i64 = 10;

#[derive(sqlx::FromRow)]
struct SettingsRow {
    enabled_payment_modules: String,
    allowed_networks: String,
    allowed_assets: String,
    default_export_retention_days: i64,
    webhook_retry_profile: String,
    exception_notification_categories: String,
    allowed_manual_adjustment_kinds: String,
    confirmation_policy: Option<String>,
}

fn default_exception_categories() -> Value {
    let mut m = serde_json::Map::new();
    for c in NOTIF_CATEGORIES { m.insert((*c).into(), json!(true)); }
    Value::Object(m)
}

fn settings_view(row: Option<&SettingsRow>) -> Value {
    match row {
        None => json!({
            "enabledPaymentModules": MODULES,
            "allowedNetworks": ["tn10"],
            "allowedAssets": ["KAS"],
            "defaultExportRetentionDays": 7,
            "webhookRetryProfile": "balanced",
            "exceptionNotificationCategories": default_exception_categories(),
            "allowedManualAdjustmentKinds": ADJUSTMENT_KINDS,
        }),
        Some(r) => json!({
            "enabledPaymentModules": parse_arr(&r.enabled_payment_modules),
            "allowedNetworks": parse_arr(&r.allowed_networks),
            "allowedAssets": parse_arr(&r.allowed_assets),
            "defaultExportRetentionDays": r.default_export_retention_days,
            "webhookRetryProfile": r.webhook_retry_profile,
            "exceptionNotificationCategories": normalize_categories(&r.exception_notification_categories),
            "allowedManualAdjustmentKinds": parse_arr(&r.allowed_manual_adjustment_kinds),
        }),
    }
}

fn parse_arr(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| json!([]))
}

fn normalize_categories(raw: &str) -> Value {
    let parsed: Value = serde_json::from_str(raw).unwrap_or_else(|_| json!({}));
    let mut out = serde_json::Map::new();
    for c in NOTIF_CATEGORIES {
        let v = parsed.get(*c).and_then(|x| x.as_bool()).unwrap_or(true);
        out.insert((*c).into(), json!(v));
    }
    Value::Object(out)
}

async fn load_settings(state: &AppState, user_id: i64) -> AppResult<Option<SettingsRow>> {
    Ok(sqlx::query_as::<_, SettingsRow>(
        "SELECT enabled_payment_modules, allowed_networks, allowed_assets, default_export_retention_days, \
         webhook_retry_profile, exception_notification_categories, allowed_manual_adjustment_kinds, confirmation_policy \
         FROM payment_tenant_settings WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db.pool)
    .await?)
}

// ---------------- confirmation policy ----------------

#[derive(Deserialize, Default)]
pub struct PolicyQuery {
    network: Option<String>,
    #[serde(rename = "assetId")]
    asset_id: Option<String>,
    currency: Option<String>,
    #[serde(rename = "invoiceAmount")]
    invoice_amount: Option<String>,
}

fn normalize_policy(raw: Option<&str>) -> Value {
    let parsed: Value = raw.and_then(|s| serde_json::from_str(s).ok()).unwrap_or_else(|| json!({}));
    let overrides: Vec<Value> = parsed.get("overrides").and_then(|v| v.as_array()).map(|a| {
        a.iter().filter_map(|o| {
            let rc = o.get("requiredConfirmations").and_then(|v| v.as_i64()).unwrap_or(0);
            if rc < 1 { return None; }
            Some(json!({
                "network": o.get("network").and_then(|v| v.as_str()),
                "assetId": o.get("assetId").and_then(|v| v.as_str()),
                "currency": o.get("currency").and_then(|v| v.as_str()),
                "minInvoiceAmount": o.get("minInvoiceAmount").and_then(|v| v.as_str()).unwrap_or("0"),
                "requiredConfirmations": rc,
                "reason": o.get("reason").and_then(|v| v.as_str()),
            }))
        }).collect()
    }).unwrap_or_default();
    let mut out = serde_json::Map::new();
    if let Some(v) = parsed.get("version").and_then(|v| v.as_str()) { out.insert("version".into(), json!(v)); }
    if let Some(d) = parsed.get("defaultConfirmations").and_then(|v| v.as_i64()) { if d >= 1 { out.insert("defaultConfirmations".into(), json!(d)); } }
    out.insert("overrides".into(), Value::Array(overrides));
    if let Some(r) = parsed.get("riskBoostConfirmations").and_then(|v| v.as_i64()) { if r >= 1 { out.insert("riskBoostConfirmations".into(), json!(r)); } }
    Value::Object(out)
}

fn resolve_policy(policy: &Value, network: &str, asset_id: &str, currency: &str, invoice_amount: i128) -> Value {
    let platform_min = PLATFORM_MIN_CONFIRMATIONS;
    let default_conf = policy.get("defaultConfirmations").and_then(|v| v.as_i64());
    let mut required = default_conf.unwrap_or(platform_min);
    let mut reason = "platform_default".to_string();
    let version = policy.get("version").and_then(|v| v.as_str()).unwrap_or("v1").to_string();
    if let Some(d) = default_conf {
        reason = if d == platform_min { "merchant_default".into() } else { "merchant_override".into() };
    }
    if let Some(overrides) = policy.get("overrides").and_then(|v| v.as_array()) {
        for o in overrides {
            let m_net = o.get("network").and_then(|v| v.as_str()).map(|n| n == network).unwrap_or(true);
            let m_asset = o.get("assetId").and_then(|v| v.as_str()).map(|a| a == asset_id).unwrap_or(true);
            let m_cur = o.get("currency").and_then(|v| v.as_str()).map(|c| c == currency).unwrap_or(true);
            let threshold: i128 = o.get("minInvoiceAmount").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0);
            let rc = o.get("requiredConfirmations").and_then(|v| v.as_i64()).unwrap_or(0);
            if m_net && m_asset && m_cur && invoice_amount >= threshold && rc > required {
                required = rc;
                reason = o.get("reason").and_then(|v| v.as_str()).unwrap_or("merchant_override").to_string();
            }
        }
    }
    let clamped = required < platform_min;
    let final_required = required.max(platform_min);
    json!({
        "requiredConfirmations": final_required,
        "policyId": format!("kasway-confirmation-policy:{version}"),
        "reasonKey": reason,
        "effectiveAt": now_iso(),
        "policyVersion": version,
        "platformMinimumConfirmations": platform_min,
        "clampedToPlatformMinimum": clamped,
    })
}

/// Required confirmations for one payment per the tenant's stored confirmation
/// policy (platform default when unset). Used by the chain observer to decide
/// when a matched observation may settle the invoice.
pub(crate) async fn required_confirmations_for(
    state: &AppState,
    user_id: i64,
    network: &str,
    asset_id: &str,
    currency: &str,
    invoice_amount: i128,
) -> Result<i64, sqlx::Error> {
    let raw: Option<Option<String>> = sqlx::query_scalar(
        "SELECT confirmation_policy FROM payment_tenant_settings WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db.pool)
    .await?;
    let policy = normalize_policy(raw.flatten().as_deref());
    let resolved = resolve_policy(&policy, network, asset_id, currency, invoice_amount);
    Ok(resolved
        .get("requiredConfirmations")
        .and_then(|v| v.as_i64())
        .unwrap_or(PLATFORM_MIN_CONFIRMATIONS))
}

/// `GET /api/payments/ops/confirmation-policy`
pub async fn confirmation_policy(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Query(q): Query<PolicyQuery>,
) -> AppResult<Json<Value>> {
    let row = load_settings(&state, auth.user_id).await?;
    let policy = normalize_policy(row.as_ref().and_then(|r| r.confirmation_policy.as_deref()));
    let network = q.network.clone().unwrap_or_else(|| "tn10".into());
    let asset_id = q.asset_id.clone().unwrap_or_else(|| "KAS".into());
    let currency = q.currency.clone().unwrap_or_else(|| "KAS".into());
    let invoice_amount = q.invoice_amount.clone().unwrap_or_else(|| "0".into());
    let amt: i128 = invoice_amount.parse().unwrap_or(0);
    let mut resolved = resolve_policy(&policy, &network, &asset_id, &currency, amt);
    let obj = resolved.as_object_mut().unwrap();
    obj.insert("currency".into(), json!(currency));
    obj.insert("network".into(), json!(network));
    obj.insert("assetId".into(), json!(asset_id));
    obj.insert("invoiceAmount".into(), json!(invoice_amount));
    obj.insert("configuredPolicy".into(), policy);
    obj.insert("serverTime".into(), json!(now_iso()));
    Ok(Json(resolved))
}

/// `PUT /api/payments/ops/confirmation-policy`
pub async fn update_confirmation_policy(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<(StatusCode, Json<Value>)> {
    let obj = body.as_object().cloned().unwrap_or_default();
    let unknown: Vec<&str> = obj.keys().filter(|k| !POLICY_KEYS.contains(&k.as_str())).map(|s| s.as_str()).collect();
    if !unknown.is_empty() {
        return Err(AppError::commerce(422, &format!("Unknown confirmation policy keys: {}", unknown.join(", "))));
    }
    // min confirmations check
    let bad_default = obj.get("defaultConfirmations").and_then(|v| v.as_i64()).map(|d| d < PLATFORM_MIN_CONFIRMATIONS).unwrap_or(false);
    let bad_override = obj.get("overrides").and_then(|v| v.as_array()).map(|a| a.iter().any(|o| o.get("requiredConfirmations").and_then(|v| v.as_i64()).unwrap_or(0) < PLATFORM_MIN_CONFIRMATIONS)).unwrap_or(false);
    if bad_default || bad_override {
        return Err(AppError::commerce(422, &format!("Confirmation policy minimum confirmations must be at least {PLATFORM_MIN_CONFIRMATIONS}")));
    }

    let current_row = load_settings(&state, auth.user_id).await?;
    let current = normalize_policy(current_row.as_ref().and_then(|r| r.confirmation_policy.as_deref()));
    let next = normalize_policy(Some(&body.to_string()));
    // merge: next fields override current
    let mut merged = current.as_object().cloned().unwrap_or_default();
    for key in ["version", "defaultConfirmations", "riskBoostConfirmations"] {
        if let Some(v) = next.get(key) { merged.insert(key.into(), v.clone()); }
    }
    if obj.get("overrides").is_some() { merged.insert("overrides".into(), next.get("overrides").cloned().unwrap_or(json!([]))); }
    let merged = Value::Object(merged);

    let now = now_iso();
    let current_view = settings_view(current_row.as_ref());
    sqlx::query(
        "INSERT INTO payment_tenant_settings (user_id, enabled_payment_modules, allowed_networks, allowed_assets, \
         default_export_retention_days, webhook_retry_profile, exception_notification_categories, allowed_manual_adjustment_kinds, confirmation_policy, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
         ON CONFLICT(user_id) DO UPDATE SET confirmation_policy = excluded.confirmation_policy, updated_at = excluded.updated_at",
    )
    .bind(auth.user_id)
    .bind(current_view["enabledPaymentModules"].to_string())
    .bind(current_view["allowedNetworks"].to_string())
    .bind(current_view["allowedAssets"].to_string())
    .bind(current_view["defaultExportRetentionDays"].as_i64().unwrap_or(7))
    .bind(current_view["webhookRetryProfile"].as_str().unwrap_or("balanced"))
    .bind(current_view["exceptionNotificationCategories"].to_string())
    .bind(current_view["allowedManualAdjustmentKinds"].to_string())
    .bind(merged.to_string())
    .bind(&now)
    .bind(&now)
    .execute(&state.db.pool)
    .await?;

    Ok((StatusCode::CREATED, Json(merged)))
}
