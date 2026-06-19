//! `/internal/payment-ops/slo`, `/slo/queues`, `/slo/incidents` —
//! InternalPaymentOpsSloController + PaymentOpsSloService. DB-derived SLO
//! indicators / queue snapshots / incidents over the payment-ledger tables
//! (internal-token tier). Thresholds from config/payment_ops_slo.

use crate::auth::InternalToken;
use crate::error::AppResult;
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// ---- config (config/payment_ops_slo.ts) ------------------------------------

fn config() -> Value {
    json!({
        "indexer": { "warnAgeSeconds": 180, "criticalAgeSeconds": 600, "recoveryCooldownMinutes": 30 },
        "observationIngestion": { "warnAgeSeconds": 300, "criticalAgeSeconds": 900, "recoveryCooldownMinutes": 15 },
        "matchJob": { "warnAgeSeconds": 300, "criticalAgeSeconds": 900, "recoveryCooldownMinutes": 15 },
        "settlementJob": { "warnAgeSeconds": 600, "criticalAgeSeconds": 1800, "recoveryCooldownMinutes": 15 },
        "webhookFinalFailureRate": { "warnRate": 0.05, "criticalRate": 0.2, "minimumSamples": 20, "lookbackMinutes": 60, "recoveryCooldownMinutes": 15 },
        "asyncExportSuccessRate": { "warnRate": 0.95, "criticalRate": 0.8, "minimumSamples": 5, "lookbackHours": 24, "oldestQueuedWarnSeconds": 900, "oldestQueuedCriticalSeconds": 3600, "recoveryCooldownMinutes": 15 },
        "notificationJobs": { "warnFailures": 3, "criticalFailures": 12, "lookbackHours": 1, "recoveryCooldownMinutes": 15 }
    })
}

// ---- status helpers --------------------------------------------------------

fn rank(s: &str) -> i32 {
    match s { "critical" => 2, "warn" => 1, _ => 0 }
}
fn from_rank(r: i32) -> &'static str {
    match r { 2 => "critical", 1 => "warn", _ => "ok" }
}
fn max_status(statuses: &[&str]) -> &'static str {
    from_rank(statuses.iter().map(|s| rank(s)).max().unwrap_or(0))
}

fn age_status(age: Option<i64>, warn: i64, crit: i64) -> &'static str {
    match age {
        None => "ok",
        Some(a) if a >= crit => "critical",
        Some(a) if a >= warn => "warn",
        _ => "ok",
    }
}

fn rate_status(rate: Option<f64>, warn: f64, crit: f64, min: i64, total: i64) -> &'static str {
    match rate {
        _ if total < min => "ok",
        None => "ok",
        Some(r) if r >= crit => "critical",
        Some(r) if r >= warn => "warn",
        _ => "ok",
    }
}

fn iso(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string()
}

fn parse_dt(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc))
}

fn age_seconds(s: Option<&str>, now: DateTime<Utc>) -> Option<i64> {
    s.and_then(parse_dt).map(|dt| now.signed_duration_since(dt).num_seconds().max(0))
}

fn stable_incident_id(t: &str) -> String {
    format!("{:x}", Sha256::digest(t.as_bytes()))[..16].to_string()
}

// ---- indicators ------------------------------------------------------------

async fn indexer_freshness(state: &AppState, now: DateTime<Utc>) -> AppResult<Value> {
    let threshold = json!({ "warnSeconds": 180, "criticalSeconds": 600 });
    let row = sqlx::query_as::<_, (i64, String, String, String, Option<String>)>(
        "SELECT id, network, asset_id, source, updated_at FROM payment_indexer_checkpoints \
         WHERE network = 'tn10' AND asset_id = 'KAS' AND source = 'rusty-kaspa-node' ORDER BY updated_at DESC LIMIT 1",
    )
    .fetch_optional(&state.db.pool).await?;
    match row {
        None => Ok(json!({
            "status": "critical", "ageSeconds": Value::Null, "sampleCount": 0, "oldestItemAt": Value::Null,
            "threshold": threshold, "metadata": { "reason": "no_recent_checkpoint" }
        })),
        Some((id, network, asset_id, source, updated_at)) => {
            let age = age_seconds(updated_at.as_deref(), now);
            Ok(json!({
                "status": age_status(age, 180, 600), "ageSeconds": age, "sampleCount": 1,
                "oldestItemAt": updated_at, "threshold": threshold,
                "metadata": { "network": network, "assetId": asset_id, "source": source, "latestCheckpointId": id }
            }))
        }
    }
}

async fn observation_age_indicator(state: &AppState, statuses: &[&str], now: DateTime<Utc>, warn: i64, crit: i64) -> AppResult<Value> {
    let threshold = json!({ "warnSeconds": warn, "criticalSeconds": crit });
    let placeholders = statuses.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let count_sql = format!("SELECT COUNT(*) FROM payment_observations WHERE status IN ({placeholders})");
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql);
    for s in statuses { cq = cq.bind(*s); }
    let sample_count: i64 = cq.fetch_one(&state.db.pool).await?;
    if sample_count == 0 {
        return Ok(json!({ "status": "ok", "ageSeconds": Value::Null, "sampleCount": 0, "oldestItemAt": Value::Null, "threshold": threshold, "metadata": { "statuses": statuses } }));
    }
    let oldest_sql = format!(
        "SELECT accepted_at, created_at FROM payment_observations WHERE status IN ({placeholders}) ORDER BY COALESCE(accepted_at, created_at) ASC LIMIT 1"
    );
    let mut oq = sqlx::query_as::<_, (Option<String>, Option<String>)>(&oldest_sql);
    for s in statuses { oq = oq.bind(*s); }
    let (accepted_at, created_at) = oq.fetch_one(&state.db.pool).await?;
    let oldest = accepted_at.or(created_at);
    let age = age_seconds(oldest.as_deref(), now);
    Ok(json!({
        "status": age_status(age, warn, crit), "ageSeconds": age, "sampleCount": sample_count,
        "oldestItemAt": oldest, "threshold": threshold, "metadata": { "statuses": statuses }
    }))
}

async fn webhook_failure_rate(state: &AppState, now: DateTime<Utc>) -> AppResult<Value> {
    let threshold = json!({ "warnRate": 0.05, "criticalRate": 0.2, "minimumSamples": 20 });
    let from = iso(now - chrono::Duration::minutes(60));
    let to = iso(now);
    let rows = sqlx::query_as::<_, (String, i64)>(
        "SELECT status, COUNT(*) FROM webhook_deliveries WHERE created_at BETWEEN ? AND ? GROUP BY status",
    ).bind(&from).bind(&to).fetch_all(&state.db.pool).await?;
    let (mut succeeded, mut failed) = (0i64, 0i64);
    for (s, c) in rows { if s == "succeeded" { succeeded = c; } if s == "failed" { failed = c; } }
    let total = succeeded + failed;
    let rate = if total > 0 { Some(failed as f64 / total as f64) } else { None };
    Ok(json!({
        "status": rate_status(rate, 0.05, 0.2, 20, total), "rate": rate, "successCount": succeeded,
        "failureCount": failed, "totalCount": total, "threshold": threshold, "metadata": { "windowMinutes": 60 }
    }))
}

async fn async_export_rate(state: &AppState, now: DateTime<Utc>) -> AppResult<Value> {
    let threshold = json!({ "warnRate": 0.95, "criticalRate": 0.8, "minimumSamples": 5, "oldestQueuedWarnSeconds": 900, "oldestQueuedCriticalSeconds": 3600 });
    let from = iso(now - chrono::Duration::hours(24));
    let to = iso(now);
    let rows = sqlx::query_as::<_, (String, i64)>(
        "SELECT status, COUNT(*) FROM payment_operation_exports WHERE generated_at BETWEEN ? AND ? GROUP BY status",
    ).bind(&from).bind(&to).fetch_all(&state.db.pool).await?;
    let (mut succeeded, mut failed, mut queued, mut running, mut expired, mut other) = (0i64, 0, 0, 0, 0, 0);
    for (s, c) in rows {
        match s.as_str() {
            "succeeded" => succeeded += c, "failed" => failed += c, "queued" => queued += c,
            "running" => running += c, "expired" => expired += c, _ => other += c,
        }
    }
    let total = succeeded + failed;
    let success_rate = if total > 0 { Some(succeeded as f64 / total as f64) } else { None };
    let oldest_queued: Option<String> = sqlx::query_scalar(
        "SELECT generated_at FROM payment_operation_exports WHERE status = 'queued' ORDER BY generated_at ASC LIMIT 1",
    ).fetch_optional(&state.db.pool).await?.flatten();
    let oldest_age = age_seconds(oldest_queued.as_deref(), now);
    let async_failure_rate = success_rate.map(|r| 1.0 - r);
    let success_status = rate_status(async_failure_rate, 1.0 - 0.95, 1.0 - 0.8, 5, total);
    let queue_age_status = age_status(oldest_age, 900, 3600);
    Ok(json!({
        "status": max_status(&[success_status, queue_age_status]), "successRate": success_rate,
        "successCount": succeeded, "failureCount": failed, "totalCount": total,
        "oldestQueuedExportAgeSeconds": oldest_age, "oldestQueuedExportAt": oldest_queued, "threshold": threshold,
        "metadata": { "counts": { "succeeded": succeeded, "failed": failed, "queued": queued, "running": running, "expired": expired, "other": other }, "windowHours": 24 }
    }))
}

async fn notification_counts(state: &AppState, now: DateTime<Utc>) -> AppResult<Value> {
    let threshold = json!({ "warnFailures": 3, "criticalFailures": 12 });
    let from = iso(now - chrono::Duration::hours(1));
    let to = iso(now);
    let rows = sqlx::query_as::<_, (String, i64)>(
        "SELECT severity, COUNT(*) FROM payment_notifications WHERE created_at BETWEEN ? AND ? GROUP BY severity",
    ).bind(&from).bind(&to).fetch_all(&state.db.pool).await?;
    let (mut success, mut failure) = (0i64, 0i64);
    for (sev, c) in rows { if sev == "critical" { failure += c; } else { success += c; } }
    let status = if failure >= 12 { "critical" } else if failure >= 3 { "warn" } else { "ok" };
    Ok(json!({
        "status": status, "failureCount": failure, "successCount": success, "threshold": threshold,
        "metadata": { "windowHours": 1 }
    }))
}

// ---- incidents -------------------------------------------------------------

fn n(v: &Value, key: &str) -> Value { v.get(key).cloned().unwrap_or(Value::Null) }
fn age_or_zero(v: &Value) -> i64 { v["ageSeconds"].as_i64().unwrap_or(0) }

fn compose_incidents(ind: &Value, now: DateTime<Utc>) -> Vec<Value> {
    let now_iso = iso(now);
    let idx = &ind["indexerFreshness"];
    let net = idx["metadata"]["network"].as_str().unwrap_or("undefined");
    let obs = &ind["observationIngestionLag"];
    let mj = &ind["matchJobLag"];
    let sj = &ind["settlementJobLag"];
    let wh = &ind["webhookFinalFailureRate"];
    let ex = &ind["asyncExportSuccessRate"];
    let nt = &ind["notificationJobs"];
    let entries = vec![
        ("indexer_freshness", idx["status"].as_str().unwrap(),
         format!("Payment indexer lag is {}s for source {}.", age_or_zero(idx), net),
         json!({ "ageSeconds": n(idx, "ageSeconds"), "oldestItemAt": n(idx, "oldestItemAt"), "checkpointId": idx["metadata"]["latestCheckpointId"].clone() })),
        ("observation_ingestion_lag", obs["status"].as_str().unwrap(),
         format!("Observation ingestion lag is {}s with {} pending observations.", age_or_zero(obs), obs["sampleCount"].as_i64().unwrap_or(0)),
         json!({ "ageSeconds": n(obs, "ageSeconds"), "sampleCount": n(obs, "sampleCount"), "oldestItemAt": n(obs, "oldestItemAt") })),
        ("match_job_lag", mj["status"].as_str().unwrap(),
         format!("Match queue lag is {}s with {} pending observations.", age_or_zero(mj), mj["sampleCount"].as_i64().unwrap_or(0)),
         json!({ "ageSeconds": n(mj, "ageSeconds"), "sampleCount": n(mj, "sampleCount"), "oldestItemAt": n(mj, "oldestItemAt") })),
        ("settlement_job_lag", sj["status"].as_str().unwrap(),
         format!("Settlement lag is {}s with {} matched observations.", age_or_zero(sj), sj["sampleCount"].as_i64().unwrap_or(0)),
         json!({ "ageSeconds": n(sj, "ageSeconds"), "sampleCount": n(sj, "sampleCount"), "oldestItemAt": n(sj, "oldestItemAt") })),
        ("webhook_final_failure_rate", wh["status"].as_str().unwrap(),
         format!("Webhook final failure rate is {}% over {} final deliveries.", ((wh["rate"].as_f64().unwrap_or(0.0)) * 100.0).round() as i64, wh["totalCount"].as_i64().unwrap_or(0)),
         json!({ "rate": n(wh, "rate"), "successCount": n(wh, "successCount"), "failureCount": n(wh, "failureCount"), "totalCount": n(wh, "totalCount") })),
        ("async_export_health", ex["status"].as_str().unwrap(),
         format!("Async export success is {}% with {} evaluated exports.", ((ex["successRate"].as_f64().unwrap_or(0.0)) * 100.0).round() as i64, ex["totalCount"].as_i64().unwrap_or(0)),
         json!({ "successRate": n(ex, "successRate"), "oldestQueuedExportAgeSeconds": n(ex, "oldestQueuedExportAgeSeconds"), "oldestQueuedExportAt": n(ex, "oldestQueuedExportAt"), "successCount": n(ex, "successCount"), "failureCount": n(ex, "failureCount"), "totalCount": n(ex, "totalCount") })),
        ("notification_job_failures", nt["status"].as_str().unwrap(),
         format!("Notification job failures in the current window are {}.", nt["failureCount"].as_i64().unwrap_or(0)),
         json!({ "failureCount": n(nt, "failureCount"), "successCount": n(nt, "successCount") })),
    ];
    entries.into_iter().map(|(t, status, summary, metadata)| {
        let open = status != "ok";
        json!({
            "id": stable_incident_id(t), "type": t,
            "severity": if status == "critical" { "critical" } else { "warn" },
            "status": if open { "open" } else { "resolved" },
            "openedAt": if open { Value::String(now_iso.clone()) } else { Value::Null },
            "resolvedAt": if open { Value::Null } else { Value::String(now_iso.clone()) },
            "summary": summary, "metadata": metadata,
        })
    }).collect()
}

async fn build_indicators(state: &AppState, now: DateTime<Utc>) -> AppResult<Value> {
    Ok(json!({
        "indexerFreshness": indexer_freshness(state, now).await?,
        "observationIngestionLag": observation_age_indicator(state, &["pending"], now, 300, 900).await?,
        "matchJobLag": observation_age_indicator(state, &["pending"], now, 300, 900).await?,
        "settlementJobLag": observation_age_indicator(state, &["matched"], now, 600, 1800).await?,
        "webhookFinalFailureRate": webhook_failure_rate(state, now).await?,
        "asyncExportSuccessRate": async_export_rate(state, now).await?,
        "notificationJobs": notification_counts(state, now).await?,
    }))
}

/// `GET /internal/payment-ops/slo`
pub async fn slo(_token: InternalToken, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let now = Utc::now();
    let ind = build_indicators(&state, now).await?;
    let statuses: Vec<&str> = ["indexerFreshness", "observationIngestionLag", "matchJobLag", "settlementJobLag", "webhookFinalFailureRate", "asyncExportSuccessRate", "notificationJobs"]
        .iter().map(|k| ind[*k]["status"].as_str().unwrap()).collect();
    let overall = max_status(&statuses);
    let incidents = compose_incidents(&ind, now);
    let warn = incidents.iter().filter(|i| i["status"] == "open" && i["severity"] == "warn").count() as i64;
    let critical = incidents.iter().filter(|i| i["status"] == "open" && i["severity"] == "critical").count() as i64;
    Ok(Json(json!({
        "generatedAt": iso(now),
        "overallStatus": overall,
        "thresholds": config(),
        "incidents": { "critical": critical, "warn": warn, "open": warn + critical },
        "indicators": ind,
    })))
}

/// `GET /internal/payment-ops/slo/incidents`
pub async fn incidents(_token: InternalToken, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let now = Utc::now();
    let ind = build_indicators(&state, now).await?;
    let incidents = compose_incidents(&ind, now);
    let open = incidents.iter().filter(|i| i["status"] == "open").count() as i64;
    let resolved = incidents.iter().filter(|i| i["status"] == "resolved").count() as i64;
    Ok(Json(json!({
        "generatedAt": iso(now),
        "summary": { "total": incidents.len(), "open": open, "resolved": resolved },
        "incidents": incidents,
    })))
}

/// `GET /internal/payment-ops/slo/queues`
pub async fn queues(_token: InternalToken, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let now = Utc::now();
    let indexer = indexer_freshness(&state, now).await?;
    let match_lag = observation_age_indicator(&state, &["pending"], now, 300, 900).await?;
    let settle_lag = observation_age_indicator(&state, &["matched"], now, 600, 1800).await?;

    // webhook delivery queue (all-time backlog + oldest pending/delivering)
    let wh_rows = sqlx::query_as::<_, (String, i64)>("SELECT status, COUNT(*) FROM webhook_deliveries GROUP BY status").fetch_all(&state.db.pool).await?;
    let (mut wpending, mut wdelivering, mut wsucceeded, mut wfailed) = (0i64, 0, 0, 0);
    for (s, c) in wh_rows {
        match s.as_str() { "pending" => wpending = c, "delivering" => wdelivering = c, "succeeded" => wsucceeded = c, "failed" => wfailed = c, _ => {} }
    }
    let wh_oldest: Option<String> = sqlx::query_scalar(
        "SELECT created_at FROM webhook_deliveries WHERE status IN ('pending','delivering') ORDER BY created_at ASC LIMIT 1",
    ).fetch_optional(&state.db.pool).await?.flatten();
    let wh_oldest_age = age_seconds(wh_oldest.as_deref(), now);
    let wh_status = max_status(&[
        if wpending > 0 { "warn" } else { "ok" },
        if wdelivering > 0 { "warn" } else { "ok" },
        if (wfailed as f64) > 0.2 * 10.0 { "warn" } else { "ok" },
    ]);

    // export queue
    let ex_oldest: Option<String> = sqlx::query_scalar(
        "SELECT created_at FROM payment_operation_exports WHERE status IN ('queued','running') ORDER BY created_at ASC LIMIT 1",
    ).fetch_optional(&state.db.pool).await?.flatten();
    let ex_oldest_age = age_seconds(ex_oldest.as_deref(), now);
    let ex_age_status = age_status(ex_oldest_age, 900, 3600);
    let ex_rows = sqlx::query_as::<_, (String, i64)>("SELECT status, COUNT(*) FROM payment_operation_exports GROUP BY status").fetch_all(&state.db.pool).await?;
    let (mut equeued, mut erunning, mut esucceeded, mut efailed, mut eexpired, mut eother) = (0i64, 0, 0, 0, 0, 0);
    for (s, c) in ex_rows {
        match s.as_str() { "queued" => equeued = c, "running" => erunning = c, "succeeded" => esucceeded = c, "failed" => efailed = c, "expired" => eexpired = c, _ => eother += c }
    }
    let ex_totals = esucceeded + efailed;
    let ex_success_rate = if ex_totals > 0 { Some(esucceeded as f64 / ex_totals as f64) } else { None };
    let ex_failure_rate = ex_success_rate.map(|r| 1.0 - r);
    let ex_success_status = rate_status(ex_failure_rate, 1.0 - 0.95, 1.0 - 0.8, 5, ex_totals);
    let ex_status = max_status(&[ex_age_status, ex_success_status]);

    let notif = notification_counts(&state, now).await?;

    let reconcile_status = max_status(&[match_lag["status"].as_str().unwrap(), settle_lag["status"].as_str().unwrap()]);
    let reconcile_age = max_finite(match_lag["ageSeconds"].as_i64(), settle_lag["ageSeconds"].as_i64());
    let reconcile_oldest = if !match_lag["oldestItemAt"].is_null() { match_lag["oldestItemAt"].clone() } else { settle_lag["oldestItemAt"].clone() };

    let queues = json!([
        { "name": "payments_ingest", "status": indexer["status"], "backlog": { "checkpointLagSeconds": indexer["ageSeconds"].as_i64().unwrap_or(0) }, "oldestAgeSeconds": indexer["ageSeconds"], "oldestItemAt": indexer["oldestItemAt"], "threshold": { "warnSeconds": 180, "criticalSeconds": 600 }, "metadata": { "source": "payment_indexer_checkpoints", "checkpointSource": "rusty-kaspa-node" } },
        { "name": "payments_match", "status": match_lag["status"], "backlog": { "pendingCount": match_lag["sampleCount"], "pendingAgeSeconds": match_lag["ageSeconds"].as_i64().unwrap_or(0) }, "oldestAgeSeconds": match_lag["ageSeconds"], "oldestItemAt": match_lag["oldestItemAt"], "threshold": { "warnSeconds": 300, "criticalSeconds": 900 }, "metadata": { "statuses": ["pending"] } },
        { "name": "payments_settle_tn10", "status": settle_lag["status"], "backlog": { "matchedCount": settle_lag["sampleCount"], "matchedAgeSeconds": settle_lag["ageSeconds"].as_i64().unwrap_or(0) }, "oldestAgeSeconds": settle_lag["ageSeconds"], "oldestItemAt": settle_lag["oldestItemAt"], "threshold": { "warnSeconds": 600, "criticalSeconds": 1800 }, "metadata": { "statuses": ["matched"] } },
        { "name": "payments_reconcile", "status": reconcile_status, "backlog": { "pendingCount": match_lag["sampleCount"], "matchedCount": settle_lag["sampleCount"], "reconcileWorkload": match_lag["sampleCount"].as_i64().unwrap_or(0) + settle_lag["sampleCount"].as_i64().unwrap_or(0) }, "oldestAgeSeconds": reconcile_age, "oldestItemAt": reconcile_oldest, "threshold": { "warnSeconds": 300, "criticalSeconds": 1800 }, "metadata": { "source": "payment_observations_reconcile_projection" } },
        { "name": "notifications", "status": wh_status, "backlog": { "pendingDeliveries": wpending, "deliveringDeliveries": wdelivering, "failedDeliveries": wfailed, "succeededDeliveries": wsucceeded }, "oldestAgeSeconds": wh_oldest_age, "oldestItemAt": wh_oldest, "threshold": Value::Null, "metadata": { "source": "webhook_deliveries" } },
        { "name": "exports", "status": ex_status, "backlog": { "queued": equeued, "running": erunning, "succeeded": esucceeded, "failed": efailed, "expired": eexpired, "other": eother }, "oldestAgeSeconds": ex_oldest_age, "oldestItemAt": ex_oldest, "threshold": { "warnSeconds": 900, "criticalSeconds": 3600 }, "metadata": { "source": "payment_operation_exports", "successRate": ex_success_rate } },
        { "name": "payment_notifications", "status": notif["status"], "backlog": { "warningAndInfo": notif["successCount"], "critical": notif["failureCount"] }, "oldestAgeSeconds": Value::Null, "oldestItemAt": Value::Null, "threshold": { "warnFailures": 3, "criticalFailures": 12 }, "metadata": { "lookbackHours": 1 } }
    ]);
    Ok(Json(json!({ "generatedAt": iso(now), "queues": queues })))
}

fn max_finite(a: Option<i64>, b: Option<i64>) -> Value {
    match (a, b) {
        (None, x) => x.map(|v| json!(v)).unwrap_or(Value::Null),
        (x, None) => x.map(|v| json!(v)).unwrap_or(Value::Null),
        (Some(x), Some(y)) => json!(x.max(y)),
    }
}
