//! `/api/payments/ops/status` (merchant) + `/internal/payment-ops/status` (internal)
//! — PaymentLaunchController + PaymentLaunchService. Aggregated readiness checks.
//! Architecture-consistent deviations (no redis/queue runtime in the port):
//! the queue check reads the derived SLO queue report (not a redis ping), storage
//! is the local fs disk (probe succeeds), and TN10 is the disabled report.

use crate::auth::AuthMerchant;
use crate::error::AppResult;
use crate::handlers::{internal_observability, internal_slo, payments_networks};
use crate::state::AppState;
use crate::util::now_iso;
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

fn severity_from(status: &str) -> &'static str {
    match status { "pass" => "low", "warn" => "medium", _ => "high" }
}
fn slo_to_launch(s: &str) -> &'static str {
    match s { "ok" => "pass", "warn" => "warn", _ => "fail" }
}
fn max_status(statuses: &[&str]) -> &'static str {
    if statuses.contains(&"fail") { "fail" } else if statuses.contains(&"warn") { "warn" } else { "pass" }
}
fn chk(key: &str, status: &str, message_key: &str, metadata: Value) -> Value {
    json!({ "key": key, "status": status, "severity": severity_from(status), "messageKey": message_key, "metadata": metadata })
}
fn summarize(checks: &[Value]) -> Value {
    let pass = checks.iter().filter(|c| c["status"] == "pass").count();
    let warn = checks.iter().filter(|c| c["status"] == "warn").count();
    let fail = checks.iter().filter(|c| c["status"] == "fail").count();
    json!({ "pass": pass, "warn": warn, "fail": fail, "ready": fail == 0 })
}

// ---- shared checks ---------------------------------------------------------

async fn queue_check(state: &AppState, scope: &str) -> AppResult<Value> {
    let q = internal_slo::queues_value(state).await?;
    let empty = vec![];
    let queues = q["queues"].as_array().unwrap_or(&empty);
    let statuses: Vec<&str> = queues.iter().map(|x| slo_to_launch(x["status"].as_str().unwrap_or("ok"))).collect();
    let status = max_status(&statuses);
    let message_key = match status { "pass" => "payments.status.queue.ok", "warn" => "payments.status.queue.warn", _ => "payments.status.queue.fail" };
    let snap: Vec<Value> = queues.iter().map(|x| json!({
        "name": x["name"], "status": x["status"], "oldestAgeSeconds": x["oldestAgeSeconds"], "backlog": x["backlog"],
    })).collect();
    Ok(chk(&format!("{scope}.queue"), status, message_key, json!({ "checked": true, "queueCount": queues.len(), "queues": snap })))
}

async fn slo_check(state: &AppState, scope: &str) -> AppResult<Value> {
    let r = internal_slo::report_value(state).await?;
    let status = slo_to_launch(r["overallStatus"].as_str().unwrap_or("ok"));
    let message_key = match status { "pass" => "payments.status.slo.ok", "warn" => "payments.status.slo.warn", _ => "payments.status.slo.fail" };
    Ok(chk(&format!("{scope}.slo"), status, message_key, json!({
        "overallStatus": r["overallStatus"], "incidents": r["incidents"], "generatedAt": r["generatedAt"],
    })))
}

fn storage_check() -> Value {
    // drive.exists(probe) returns false without throwing → PASS (the local fs disk works)
    chk("system.storage", "pass", "payments.status.storage.ok", json!({ "disk": "fs", "probe": "payment-status/probe.txt" }))
}

fn tn10_check() -> Value {
    let report = internal_observability::tn10_disabled_report();
    // ready=false, status disabled → WARN
    chk("platform.tn10NodeStatus", "warn", "payments.status.platform.tn10.disabled", json!({
        "statusStatus": report["status"], "ready": report["ready"], "network": report["network"], "assetId": report["assetId"],
        "serverInfo": report["serverInfo"], "checks": report["checks"], "config": report["metadata"],
    }))
}

struct TenantCaps {
    modules: Vec<String>,
    retry_profile: String,
    exception_categories: Vec<String>,
    active_endpoints: i64,
    setup_exists: bool,
    setup_has_webhook_url: bool,
}

async fn tenant_caps(state: &AppState, user_id: i64) -> AppResult<TenantCaps> {
    let row = sqlx::query_as::<_, (Option<String>, Option<String>, Option<String>)>(
        "SELECT enabled_payment_modules, webhook_retry_profile, exception_notification_categories FROM payment_tenant_settings WHERE user_id = $1",
    ).bind(user_id).fetch_optional(&state.db.pool).await?;
    let (modules, retry_profile, exception_categories) = match row {
        Some((m, rp, ec)) => {
            let modules: Vec<String> = m.as_deref().and_then(|s| serde_json::from_str(s).ok()).unwrap_or_default();
            let cats: Vec<String> = ec.as_deref()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                .and_then(|v| v.as_object().map(|o| o.keys().cloned().collect()))
                .unwrap_or_default();
            (modules, rp.unwrap_or_else(|| "balanced".into()), cats)
        }
        None => (vec![], "balanced".into(), vec![]),
    };
    let active_endpoints: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM webhook_endpoints WHERE user_id = $1 AND is_active = 1 AND paused_at IS NULL",
    ).bind(user_id).fetch_one(&state.db.pool).await?;
    let setup = sqlx::query_as::<_, (Option<String>,)>("SELECT webhook_url FROM setups WHERE user_id = $1")
        .bind(user_id).fetch_optional(&state.db.pool).await?;
    Ok(TenantCaps {
        modules, retry_profile, exception_categories, active_endpoints,
        setup_exists: setup.is_some(),
        setup_has_webhook_url: setup.as_ref().map(|(u,)| u.as_deref().map(|s| !s.is_empty()).unwrap_or(false)).unwrap_or(false),
    })
}

// ---- handlers --------------------------------------------------------------

/// `GET /api/payments/ops/status` (merchant, payments.ops.read → owner allowed)
pub async fn status(auth: AuthMerchant, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let uid = auth.user_id;
    let caps = payments_networks::capabilities();
    let tc = tenant_caps(&state, uid).await?;

    // network assets
    let network_assets = chk(
        "merchant.networkAssets",
        if caps.is_empty() { "fail" } else { "pass" },
        if caps.is_empty() { "payments.status.networkAssets.missing" } else { "payments.status.networkAssets.ok" },
        json!({ "allowedNetworks": ["tn10"], "allowedAssets": ["KAS"], "visibleCapabilityCount": caps.len() }),
    );

    // wallet setup
    let setup = sqlx::query_as::<_, (Option<String>, Option<String>)>("SELECT kaspa_main_address, webhook_url FROM setups WHERE user_id = $1")
        .bind(uid).fetch_optional(&state.db.pool).await?;
    let wallet_setup = match &setup {
        None => chk("merchant.walletSetup", "fail", "payments.status.walletSetup.missingSetup", json!({ "setupExists": false })),
        Some((addr, webhook)) => {
            let has_addr = addr.as_deref().map(|a| !a.trim().is_empty()).unwrap_or(false);
            let st = if has_addr { "pass" } else { "warn" };
            chk("merchant.walletSetup", st,
                if has_addr { "payments.status.walletSetup.ok" } else { "payments.status.walletSetup.missingKaspaAddress" },
                json!({ "setupExists": true, "hasWalletAddress": has_addr, "setupHasWebhookUrl": webhook.as_deref().map(|w| !w.is_empty()).unwrap_or(false) }))
        }
    };

    // webhook health
    let wh_enabled = tc.active_endpoints > 0;
    let webhook_health = chk("merchant.webhookHealth", if wh_enabled { "pass" } else { "warn" },
        if wh_enabled { "payments.status.webhookHealth.ok" } else { "payments.status.webhookHealth.missing" },
        json!({ "setupExists": tc.setup_exists, "setupHasWebhookUrl": tc.setup_has_webhook_url, "hasActiveWebhookEndpoint": wh_enabled, "activeEndpointCount": tc.active_endpoints, "webhookRetryProfile": tc.retry_profile }));

    // retention policy (supportNotes ?? 1 > 0 — null treated valid, per Adonis)
    let ret = retention_policy(&state, uid).await?;
    let valid = ret.exports > 0 && ret.evidence > 0 && ret.notifications > 0 && ret.webhook_body > 0 && ret.support_notes.unwrap_or(1) > 0 && ret.anomaly > 0;
    let retention = chk("merchant.retentionPolicy", if valid { "pass" } else { "warn" },
        if valid { "payments.status.retentionPolicy.ok" } else { "payments.status.retentionPolicy.warn" },
        json!({ "exportsRetentionDays": ret.exports, "evidencePacksRetentionDays": ret.evidence, "notificationsRetentionDays": ret.notifications, "webhookResponseBodyRetentionDays": ret.webhook_body, "supportNotesRetentionDays": ret.support_notes, "anomalySignalsRetentionDays": ret.anomaly }));

    // notification preferences
    let notif_enabled = tc.modules.iter().any(|m| m == "notifications");
    let notifications = chk("merchant.notificationPreferences", if notif_enabled { "pass" } else { "warn" },
        if notif_enabled { "payments.status.notificationPreferences.ok" } else { "payments.status.notificationPreferences.disabled" },
        json!({ "moduleEnabled": notif_enabled, "configuredExceptionCategories": tc.exception_categories }));

    let api_scopes = chk("merchant.apiScopes", "pass", "payments.status.apiScope.sessionAuth",
        json!({ "authMode": "merchant", "requiredScopes": ["payments:read"] }));

    let checks = vec![
        network_assets, wallet_setup, webhook_health, retention, notifications,
        queue_check(&state, "merchant").await?, slo_check(&state, "merchant").await?, storage_check(), api_scopes,
    ];
    Ok(Json(json!({
        "scope": "merchant", "merchantId": uid, "generatedAt": now_iso(),
        "checks": checks, "summary": summarize(&checks),
    })))
}

/// `GET /internal/payment-ops/status` (internal token)
pub async fn internal_status(_token: crate::auth::InternalToken, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let caps = payments_networks::capabilities();
    let supported_networks: Vec<Value> = caps.iter().map(|c| c["network"].clone()).collect();
    let supported_asset_count: usize = caps.iter().map(|c| c["assets"].as_array().map(|a| a.len()).unwrap_or(0)).sum();
    let network_assets = chk("platform.networkAssets", "pass", "payments.status.platform.networkAssets.ok",
        json!({ "supportedNetworks": supported_networks, "supportedAssetCount": supported_asset_count }));

    // webhook aggregate
    let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhook_endpoints WHERE is_active = 1 AND paused_at IS NULL").fetch_one(&state.db.pool).await?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhook_endpoints").fetch_one(&state.db.pool).await?;
    let wh_status = if total == 0 { "pass" } else if active == 0 { "warn" } else { "pass" };
    let webhook_aggregate = chk("platform.webhookHealth", wh_status,
        if wh_status == "pass" { "payments.status.platform.webhookHealth.ok" } else { "payments.status.platform.webhookHealth.missing" },
        json!({ "activeEndpoints": active, "totalEndpoints": total }));

    // retention aggregate
    let rows = sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(
        "SELECT exports_retention_days, evidence_packs_retention_days, notifications_retention_days, webhook_response_body_retention_days, anomaly_signals_retention_days FROM payment_retention_policies",
    ).fetch_all(&state.db.pool).await?;
    let invalid = rows.iter().filter(|(e, ev, n, w, a)| *e <= 0 || *ev <= 0 || *n <= 0 || *w <= 0 || *a <= 0).count();
    let retention_aggregate = chk("platform.retentionPolicy", if invalid == 0 { "pass" } else { "warn" },
        if invalid == 0 { "payments.status.platform.retentionPolicy.ok" } else { "payments.status.platform.retentionPolicy.warn" },
        json!({ "configuredTenantPolicyCount": rows.len(), "invalidPolicyCount": invalid }));

    // notification aggregate
    let tenants = sqlx::query_as::<_, (Option<String>,)>("SELECT enabled_payment_modules FROM payment_tenant_settings").fetch_all(&state.db.pool).await?;
    let with_notif = tenants.iter().filter(|(m,)| m.as_deref().and_then(|s| serde_json::from_str::<Vec<String>>(s).ok()).map(|v| v.iter().any(|x| x == "notifications")).unwrap_or(false)).count();
    let notification_aggregate = chk("platform.notificationPreferences", "pass", "payments.status.platform.notificationPreferences.ok",
        json!({ "configuredTenantCount": tenants.len(), "tenantsWithConfiguredExceptionPreferences": with_notif }));

    let checks = vec![
        network_assets, storage_check(), queue_check(&state, "platform").await?, slo_check(&state, "platform").await?,
        webhook_aggregate, retention_aggregate, notification_aggregate, tn10_check(),
    ];
    Ok(Json(json!({
        "scope": "platform", "generatedAt": now_iso(),
        "checks": checks, "summary": summarize(&checks),
    })))
}

// retention policy with Adonis defaults (no row → defaults).
async fn retention_policy(state: &AppState, user_id: i64) -> AppResult<RetView> {
    let row = sqlx::query_as::<_, (i64, i64, i64, i64, Option<i64>, i64)>(
        "SELECT exports_retention_days, evidence_packs_retention_days, notifications_retention_days, webhook_response_body_retention_days, support_notes_retention_days, anomaly_signals_retention_days FROM payment_retention_policies WHERE user_id = $1",
    ).bind(user_id).fetch_optional(&state.db.pool).await?;
    Ok(match row {
        Some((e, ev, n, w, s, a)) => RetView { exports: e, evidence: ev, notifications: n, webhook_body: w, support_notes: s, anomaly: a },
        None => RetView { exports: 7, evidence: 7, notifications: 30, webhook_body: 30, support_notes: None, anomaly: 30 },
    })
}
struct RetView { exports: i64, evidence: i64, notifications: i64, webhook_body: i64, support_notes: Option<i64>, anomaly: i64 }
