//! `/internal/payment-ops/{overview,merchants,merchants/:id,failures}` +
//! `/internal/payment-ops/tn10/status` — PaymentPlatformObservabilityService +
//! Tn10NodeStatusService (disabled path). DB-derived platform aggregates over the
//! payment-ledger tables (internal-token tier). The TN10 node status is the static
//! "disabled" report (KASPA_TN10_NODE_ENABLED unset); live RPC/WASM probes are external.

use crate::auth::InternalToken;
use crate::error::{AppError, AppResult};
use crate::handlers::payment_exceptions;
use crate::state::AppState;
use crate::util::paginator_meta;
use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Deserialize, Default)]
pub struct ObsQuery {
    from: Option<String>,
    to: Option<String>,
    #[serde(rename = "merchantId")]
    merchant_id: Option<i64>,
    severity: Option<String>,
    network: Option<String>,
    #[serde(rename = "assetId")]
    asset_id: Option<String>,
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
}

fn iso(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string()
}
fn parse_dt(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc))
}

/// (from, to) ISO window strings, validating filters → 422.
fn parse_window(q: &ObsQuery) -> AppResult<(String, String)> {
    let now = Utc::now();
    let from = match q.from.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => parse_dt(s).ok_or_else(|| AppError::commerce(422, "Payment platform observability date filters must be valid ISO date strings."))?,
        None => now - chrono::Duration::days(30),
    };
    let to = match q.to.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(s) => parse_dt(s).ok_or_else(|| AppError::commerce(422, "Payment platform observability date filters must be valid ISO date strings."))?,
        None => now,
    };
    if from > to {
        return Err(AppError::commerce(422, "Payment platform observability `from` date must be before or equal to `to` date."));
    }
    Ok((iso(from), iso(to)))
}

pub(crate) fn tn10_disabled_report() -> Value {
    json!({
        "status": "disabled", "ready": false, "network": "tn10", "assetId": "KAS",
        "generatedAt": iso(Utc::now()),
        "checks": [{ "key": "tn10.enabled", "status": "fail", "message": "TN10 status is disabled by default" }],
        "serverInfo": Value::Null,
        "metadata": { "enabled": false, "rpcUrl": Value::Null, "rpcEncoding": "json", "wasmSdkPath": Value::Null, "wasmSdkSha256": Value::Null, "expectedNetworkId": "testnet-10", "expectedServerVersion": "1.2.0-toc.2" }
    })
}

// ---- merchant id resolution + emails ---------------------------------------

async fn active_merchant_ids(state: &AppState, from: &str, to: &str, q: &ObsQuery) -> AppResult<Vec<i64>> {
    let mut sql = String::from("SELECT DISTINCT user_id FROM invoices WHERE created_at BETWEEN $1 AND $2");
    let mut binds: Vec<String> = vec![from.into(), to.into()];
    let mut n = 3;
    if let Some(m) = q.merchant_id { sql.push_str(&format!(" AND user_id = ${n}")); n += 1; binds.push(m.to_string()); }
    if let Some(net) = q.network.as_deref().filter(|s| !s.is_empty()) { sql.push_str(&format!(" AND payment_network = ${n}")); n += 1; binds.push(net.into()); }
    if let Some(a) = q.asset_id.as_deref().filter(|s| !s.is_empty()) { sql.push_str(&format!(" AND payment_asset = ${n}")); n += 1; binds.push(a.into()); }
    let _ = n;
    let mut query = sqlx::query_scalar::<_, i64>(&sql);
    for b in &binds { query = query.bind(b.clone()); }
    Ok(query.fetch_all(&state.db.pool).await?)
}

async fn merchant_emails(state: &AppState, ids: &[i64]) -> AppResult<HashMap<i64, String>> {
    if ids.is_empty() { return Ok(HashMap::new()); }
    let mut n = 1;
    let ph = ids.iter().map(|_| { let p = format!("${n}"); n += 1; p }).collect::<Vec<_>>().join(",");
    let sql = format!("SELECT id, email FROM users WHERE id IN ({ph})");
    let mut q = sqlx::query_as::<_, (i64, String)>(&sql);
    for id in ids { q = q.bind(*id); }
    Ok(q.fetch_all(&state.db.pool).await?.into_iter().collect())
}

/// Build `col IN ($start, $start+1, ...)` for `ids.len()` placeholders.
fn in_clause(col: &str, ids: &[i64], start: i32) -> String {
    let mut n = start;
    format!("{col} IN ({})", ids.iter().map(|_| { let p = format!("${n}"); n += 1; p }).collect::<Vec<_>>().join(","))
}

// ---- aggregates (filter-scoped) --------------------------------------------

async fn invoice_volume(state: &AppState, from: &str, to: &str, q: &ObsQuery) -> AppResult<Value> {
    let mut sql = String::from("SELECT status, COUNT(*), CAST(COALESCE(SUM(total_amount),0) AS BIGINT) FROM invoices WHERE created_at BETWEEN $1 AND $2");
    let mut binds: Vec<String> = vec![from.into(), to.into()];
    let mut n = 3;
    if let Some(m) = q.merchant_id { sql.push_str(&format!(" AND user_id = ${n}")); n += 1; binds.push(m.to_string()); }
    if let Some(net) = q.network.as_deref().filter(|s| !s.is_empty()) { sql.push_str(&format!(" AND payment_network = ${n}")); n += 1; binds.push(net.into()); }
    if let Some(a) = q.asset_id.as_deref().filter(|s| !s.is_empty()) { sql.push_str(&format!(" AND payment_asset = ${n}")); n += 1; binds.push(a.into()); }
    let _ = n;
    sql.push_str(" GROUP BY status");
    let mut query = sqlx::query_as::<_, (String, i64, i64)>(&sql);
    for b in &binds { query = query.bind(b.clone()); }
    let rows = query.fetch_all(&state.db.pool).await?;
    let mut by = json!({ "open": 0, "paid": 0, "expired": 0, "cancelled": 0 });
    let (mut total, mut amount) = (0i64, 0i128);
    for (status, count, amt) in rows {
        by[&status] = json!(by[&status].as_i64().unwrap_or(0) + count);
        total += count; amount += amt as i128;
    }
    Ok(json!({ "total": total, "totalAmount": amount.to_string(), "byStatus": by }))
}

async fn observation_volume(state: &AppState, from: &str, to: &str, q: &ObsQuery) -> AppResult<Value> {
    let mut sql = String::from(
        "SELECT po.status, COUNT(po.id), CAST(COALESCE(SUM(po.amount),0) AS BIGINT) FROM payment_observations po \
         JOIN invoices i ON i.id = po.invoice_id WHERE po.created_at BETWEEN $1 AND $2",
    );
    let mut binds: Vec<String> = vec![from.into(), to.into()];
    let mut n = 3;
    if let Some(m) = q.merchant_id { sql.push_str(&format!(" AND i.user_id = ${n}")); n += 1; binds.push(m.to_string()); }
    if let Some(net) = q.network.as_deref().filter(|s| !s.is_empty()) { sql.push_str(&format!(" AND po.network = ${n}")); n += 1; binds.push(net.into()); }
    if let Some(a) = q.asset_id.as_deref().filter(|s| !s.is_empty()) { sql.push_str(&format!(" AND po.asset_id = ${n}")); n += 1; binds.push(a.into()); }
    let _ = n;
    sql.push_str(" GROUP BY po.status");
    let mut query = sqlx::query_as::<_, (String, i64, i64)>(&sql);
    for b in &binds { query = query.bind(b.clone()); }
    let rows = query.fetch_all(&state.db.pool).await?;
    let mut by = json!({ "pending": 0, "matched": 0, "settled": 0, "ignored": 0 });
    let (mut total, mut amount) = (0i64, 0i128);
    for (status, count, amt) in rows {
        by[&status] = json!(by[&status].as_i64().unwrap_or(0) + count);
        total += count; amount += amt as i128;
    }
    Ok(json!({ "total": total, "totalAmount": amount.to_string(), "byStatus": by }))
}

async fn settlement_summary(state: &AppState, from: &str, to: &str, q: &ObsQuery) -> AppResult<Value> {
    let mut sql = String::from(
        "SELECT p.status, COUNT(*) FROM payments p JOIN invoices i ON i.id = p.invoice_id WHERE p.created_at BETWEEN $1 AND $2",
    );
    let mut binds: Vec<String> = vec![from.into(), to.into()];
    let mut n = 3;
    if let Some(m) = q.merchant_id { sql.push_str(&format!(" AND i.user_id = ${n}")); n += 1; binds.push(m.to_string()); }
    if let Some(net) = q.network.as_deref().filter(|s| !s.is_empty()) { sql.push_str(&format!(" AND i.payment_network = ${n}")); n += 1; binds.push(net.into()); }
    if let Some(a) = q.asset_id.as_deref().filter(|s| !s.is_empty()) { sql.push_str(&format!(" AND i.payment_asset = ${n}")); n += 1; binds.push(a.into()); }
    let _ = n;
    sql.push_str(" GROUP BY p.status");
    let mut query = sqlx::query_as::<_, (String, i64)>(&sql);
    for b in &binds { query = query.bind(b.clone()); }
    let rows = query.fetch_all(&state.db.pool).await?;
    let mut by = json!({ "pending": 0, "submitted": 0, "confirmed": 0, "failed": 0 });
    let mut total = 0i64;
    for (status, count) in rows { by[&status] = json!(by[&status].as_i64().unwrap_or(0) + count); total += count; }
    Ok(json!({ "total": total, "succeeded": by["confirmed"].as_i64().unwrap_or(0), "failed": by["failed"].as_i64().unwrap_or(0), "byStatus": by }))
}

async fn webhook_failure_summary(state: &AppState, from: &str, to: &str, ids: &[i64]) -> AppResult<Value> {
    if ids.is_empty() {
        return Ok(json!({ "total": 0, "failed": 0, "byStatus": { "failed": 0, "delivering": 0, "pending": 0, "other": 0, "succeeded": 0 } }));
    }
    let sql = format!(
        "SELECT d.status, COUNT(d.id) FROM webhook_deliveries d JOIN webhook_events e ON e.id = d.webhook_event_id \
         WHERE d.created_at BETWEEN $1 AND $2 AND d.status != 'succeeded' AND {} GROUP BY d.status",
        in_clause("e.user_id", ids, 3)
    );
    let mut q = sqlx::query_as::<_, (String, i64)>(&sql).bind(from).bind(to);
    for id in ids { q = q.bind(*id); }
    let rows = q.fetch_all(&state.db.pool).await?;
    let mut by = json!({ "failed": 0, "delivering": 0, "pending": 0, "other": 0, "succeeded": 0 });
    let mut total = 0i64;
    for (status, count) in rows {
        let key = if by.get(&status).is_some() { status } else { "other".into() };
        by[&key] = json!(by[&key].as_i64().unwrap_or(0) + count);
        total += count;
    }
    Ok(json!({ "total": total, "failed": by["failed"].as_i64().unwrap_or(0), "byStatus": by }))
}

async fn job_status_summary(state: &AppState, from: &str, to: &str, ids: &[i64], table: &str) -> AppResult<Value> {
    if ids.is_empty() {
        return Ok(json!({ "total": 0, "byStatus": { "queued": 0, "running": 0, "failed": 0, "expired": 0 } }));
    }
    let sql = format!(
        "SELECT status, COUNT(*) FROM {table} WHERE generated_at BETWEEN $1 AND $2 AND status != 'succeeded' AND {} GROUP BY status",
        in_clause("user_id", ids, 3)
    );
    let mut q = sqlx::query_as::<_, (String, i64)>(&sql).bind(from).bind(to);
    for id in ids { q = q.bind(*id); }
    let rows = q.fetch_all(&state.db.pool).await?;
    let mut by = json!({ "queued": 0, "running": 0, "failed": 0, "expired": 0 });
    let mut total = 0i64;
    for (status, count) in rows {
        by[&status] = json!(by[&status].as_i64().unwrap_or(0) + count);
        total += count;
    }
    Ok(json!({ "total": total, "byStatus": by }))
}

async fn notification_summary(state: &AppState, from: &str, to: &str, ids: &[i64]) -> AppResult<Value> {
    if ids.is_empty() {
        return Ok(json!({ "total": 0, "unread": 0, "bySeverity": { "info": 0, "warning": 0, "critical": 0 } }));
    }
    let sql = format!(
        "SELECT severity, read_at, COUNT(*) FROM payment_notifications WHERE created_at BETWEEN $1 AND $2 AND {} GROUP BY severity, read_at",
        in_clause("user_id", ids, 3)
    );
    let mut q = sqlx::query_as::<_, (String, Option<String>, i64)>(&sql).bind(from).bind(to);
    for id in ids { q = q.bind(*id); }
    let rows = q.fetch_all(&state.db.pool).await?;
    let mut by = json!({ "info": 0, "warning": 0, "critical": 0 });
    let (mut total, mut unread) = (0i64, 0i64);
    for (severity, read_at, count) in rows {
        total += count;
        if read_at.is_none() { unread += count; }
        by[&severity] = json!(by[&severity].as_i64().unwrap_or(0) + count);
    }
    Ok(json!({ "total": total, "unread": unread, "bySeverity": by }))
}

// ---- exceptions + failure rows ---------------------------------------------

async fn collect_exception_rows(state: &AppState, ids: &[i64], from: &str, to: &str, q: &ObsQuery) -> AppResult<Vec<Value>> {
    let emails = merchant_emails(state, ids).await?;
    let mut rows = Vec::new();
    for &mid in ids {
        let excs = payment_exceptions::derive_user_exceptions(state, mid, None, q.severity.as_deref(), None).await?;
        for e in excs {
            let sev = e["severity"].as_str().unwrap_or("");
            if let Some(f) = q.severity.as_deref() { if sev != f { continue; } }
            let net = e["network"].as_str();
            if let Some(f) = q.network.as_deref().filter(|s| !s.is_empty()) { if net != Some(f) { continue; } }
            let asset = e["assetId"].as_str();
            if let Some(f) = q.asset_id.as_deref().filter(|s| !s.is_empty()) { if asset != Some(f) { continue; } }
            let occurred = e["sourceTimestamps"]["occurredAt"].as_str().unwrap_or("");
            if occurred < from || occurred > to { continue; }
            rows.push(json!({
                "id": e["id"], "type": "exception", "severity": sev, "occurredAt": occurred,
                "merchant": { "id": mid, "email": emails.get(&mid).cloned().unwrap_or_default() },
                "network": e["network"], "assetId": e["assetId"],
                "resource": { "type": "payment_exception", "id": e["id"], "status": e["paymentState"],
                    "extra": { "exceptionType": e["type"], "invoiceId": e["invoice"]["id"], "publicId": e["invoice"]["publicId"] } },
                "payloadSafe": true, "notes": e["type"],
            }));
        }
    }
    Ok(rows)
}

async fn exception_summary(state: &AppState, ids: &[i64], from: &str, to: &str, q: &ObsQuery) -> AppResult<Value> {
    let rows = collect_exception_rows(state, ids, from, to, q).await?;
    let (mut high, mut medium, mut low) = (0i64, 0, 0);
    for r in &rows {
        match r["severity"].as_str().unwrap_or("") { "high" => high += 1, "medium" => medium += 1, "low" => low += 1, _ => {} }
    }
    Ok(json!({ "total": rows.len(), "bySeverity": { "high": high, "medium": medium, "low": low } }))
}

// ---- handlers --------------------------------------------------------------

/// `GET /internal/payment-ops/overview`
pub async fn overview(_token: InternalToken, State(state): State<AppState>, Query(q): Query<ObsQuery>) -> AppResult<Json<Value>> {
    let (from, to) = parse_window(&q)?;
    let ids = active_merchant_ids(&state, &from, &to, &q).await?;
    Ok(Json(json!({
        "range": { "from": from, "to": to },
        "activeMerchants": ids.len(),
        "invoiceVolume": invoice_volume(&state, &from, &to, &q).await?,
        "observationVolume": observation_volume(&state, &from, &to, &q).await?,
        "settlement": settlement_summary(&state, &from, &to, &q).await?,
        "exceptions": exception_summary(&state, &ids, &from, &to, &q).await?,
        "webhookFailures": webhook_failure_summary(&state, &from, &to, &ids).await?,
        "exportJobs": job_status_summary(&state, &from, &to, &ids, "payment_operation_exports").await?,
        "evidenceJobs": job_status_summary(&state, &from, &to, &ids, "payment_evidence_packs").await?,
        "notifications": notification_summary(&state, &from, &to, &ids).await?,
        "tn10NodeStatus": tn10_disabled_report(),
    })))
}

async fn merchant_totals(state: &AppState, mid: i64, from: &str, to: &str, base: &ObsQuery) -> AppResult<Value> {
    let q = ObsQuery { merchant_id: Some(mid), ..clone_filters(base) };
    let inv = invoice_volume(state, from, to, &q).await?;
    let obs = observation_volume(state, from, to, &q).await?;
    let settle = settlement_summary(state, from, to, &q).await?;
    let exc = exception_summary(state, &[mid], from, to, &q).await?;
    let wh = webhook_failure_summary(state, from, to, &[mid]).await?;
    let exp = job_status_summary(state, from, to, &[mid], "payment_operation_exports").await?;
    let ev = job_status_summary(state, from, to, &[mid], "payment_evidence_packs").await?;
    let notif = notification_summary(state, from, to, &[mid]).await?;
    Ok(json!({
        "invoiceVolume": { "total": inv["total"], "byStatus": inv["byStatus"] },
        "observationVolume": { "total": obs["total"], "byStatus": obs["byStatus"] },
        "settlement": settle,
        "exceptions": exc,
        "webhookFailures": { "total": wh["total"], "byStatus": wh["byStatus"] },
        "exportJobs": exp,
        "evidenceJobs": ev,
        "notifications": { "total": notif["total"], "unread": notif["unread"] },
    }))
}

fn clone_filters(q: &ObsQuery) -> ObsQuery {
    ObsQuery {
        from: q.from.clone(), to: q.to.clone(), merchant_id: q.merchant_id,
        severity: q.severity.clone(), network: q.network.clone(), asset_id: q.asset_id.clone(),
        page: q.page, per_page: q.per_page,
    }
}

/// `GET /internal/payment-ops/merchants`
pub async fn merchants(_token: InternalToken, State(state): State<AppState>, Query(q): Query<ObsQuery>) -> AppResult<Json<Value>> {
    let (from, to) = parse_window(&q)?;
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).clamp(1, 100);
    let mut ids = active_merchant_ids(&state, &from, &to, &q).await?;
    let total = ids.len() as i64;
    if ids.is_empty() {
        return Ok(Json(json!({ "meta": paginator_meta(0, per_page, page), "data": [] })));
    }
    ids.sort();
    let offset = ((page - 1) * per_page) as usize;
    let chunk: Vec<i64> = ids.into_iter().skip(offset).take(per_page as usize).collect();
    let emails = merchant_emails(&state, &chunk).await?;
    let mut data = Vec::with_capacity(chunk.len());
    for mid in &chunk {
        let totals = merchant_totals(&state, *mid, &from, &to, &q).await?;
        data.push(json!({ "merchant": { "id": mid, "email": emails.get(mid).cloned().unwrap_or_else(|| format!("merchant-{mid}")) }, "totals": totals }));
    }
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}

/// `GET /internal/payment-ops/merchants/:id`
pub async fn merchant(_token: InternalToken, State(state): State<AppState>, Path(id): Path<String>, Query(q): Query<ObsQuery>) -> AppResult<Json<Value>> {
    let mid = match id.parse::<i64>() { Ok(n) if n > 0 => n, _ => return Err(AppError::bad_request("Merchant id must be a positive integer.")) };
    let (from, to) = parse_window(&q)?;
    let target = ObsQuery { merchant_id: Some(mid), ..clone_filters(&q) };
    let ids = active_merchant_ids(&state, &from, &to, &target).await?;
    if !ids.contains(&mid) {
        return Err(AppError::commerce(404, "merchant not found"));
    }
    let email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id = $1").bind(mid).fetch_optional(&state.db.pool).await?;
    let email = email.ok_or_else(AppError::row_not_found)?;
    let totals = merchant_totals(&state, mid, &from, &to, &q).await?;
    Ok(Json(json!({ "range": { "from": from, "to": to }, "merchant": { "id": mid, "email": email }, "totals": totals })))
}

async fn collect_webhook_rows(state: &AppState, ids: &[i64], from: &str, to: &str) -> AppResult<Vec<Value>> {
    if ids.is_empty() { return Ok(vec![]); }
    let sql = format!(
        "SELECT d.id, d.status, d.attempt_count, d.error, d.created_at, d.webhook_event_id, e.user_id, e.event_type \
         FROM webhook_deliveries d JOIN webhook_events e ON e.id = d.webhook_event_id \
         WHERE d.created_at BETWEEN $1 AND $2 AND d.status != 'succeeded' AND {}",
        in_clause("e.user_id", ids, 3)
    );
    let mut q = sqlx::query_as::<_, (i64, String, i64, Option<String>, Option<String>, i64, i64, Option<String>)>(&sql).bind(from).bind(to);
    for id in ids { q = q.bind(*id); }
    let rows = q.fetch_all(&state.db.pool).await?;
    let emails = merchant_emails(state, ids).await?;
    Ok(rows.into_iter().map(|(did, status, attempts, error, occurred, event_id, uid, event_type)| {
        let severity = match status.as_str() { "failed" => "high", "delivering" => "medium", _ => "low" };
        json!({
            "id": format!("webhook_delivery:{did}"), "type": "webhook_delivery", "severity": severity, "occurredAt": occurred,
            "merchant": { "id": uid, "email": emails.get(&uid).cloned().unwrap_or_default() },
            "network": Value::Null, "assetId": Value::Null,
            "resource": { "type": "webhook_delivery", "id": did, "status": status,
                "extra": { "eventType": event_type.unwrap_or_default(), "eventId": event_id, "attemptCount": attempts, "hasDeliveryError": error.is_some() } },
            "payloadSafe": true,
        })
    }).collect())
}

async fn collect_job_rows(state: &AppState, ids: &[i64], from: &str, to: &str, kind: &str) -> AppResult<Vec<Value>> {
    if ids.is_empty() { return Ok(vec![]); }
    let table = if kind == "export_job" { "payment_operation_exports" } else { "payment_evidence_packs" };
    let extra_col = if kind == "export_job" { "kind, row_count" } else { "invoice_id" };
    let sql = format!(
        "SELECT id, user_id, status, error, generated_at, {extra_col} FROM {table} \
         WHERE status != 'succeeded' AND generated_at BETWEEN $1 AND $2 AND {}",
        in_clause("user_id", ids, 3)
    );
    let mut out = Vec::new();
    let emails = merchant_emails(state, ids).await?;
    if kind == "export_job" {
        let mut q = sqlx::query_as::<_, (i64, i64, String, Option<String>, Option<String>, String, i64)>(&sql).bind(from).bind(to);
        for id in ids { q = q.bind(*id); }
        for (eid, uid, status, error, occurred, ekind, row_count) in q.fetch_all(&state.db.pool).await? {
            let severity = match status.as_str() { "failed" | "expired" => "high", "running" => "medium", _ => "low" };
            out.push(json!({
                "id": format!("export_job:{eid}"), "type": "export_job", "severity": severity, "occurredAt": occurred,
                "merchant": { "id": uid, "email": emails.get(&uid).cloned().unwrap_or_default() },
                "network": Value::Null, "assetId": Value::Null,
                "resource": { "type": "payment_operation_export", "id": eid, "status": status, "extra": { "kind": ekind, "hasError": error.is_some(), "rowCount": row_count } },
                "payloadSafe": true, "notes": error,
            }));
        }
    } else {
        let mut q = sqlx::query_as::<_, (i64, i64, String, Option<String>, Option<String>, i64)>(&sql).bind(from).bind(to);
        for id in ids { q = q.bind(*id); }
        for (eid, uid, status, error, occurred, invoice_id) in q.fetch_all(&state.db.pool).await? {
            let severity = match status.as_str() { "failed" | "expired" => "high", "running" => "medium", _ => "low" };
            out.push(json!({
                "id": format!("evidence_pack:{eid}"), "type": "evidence_pack", "severity": severity, "occurredAt": occurred,
                "merchant": { "id": uid, "email": emails.get(&uid).cloned().unwrap_or_default() },
                "network": Value::Null, "assetId": Value::Null,
                "resource": { "type": "payment_evidence_pack", "id": eid, "status": status, "extra": { "invoiceId": invoice_id, "hasError": error.is_some() } },
                "payloadSafe": true, "notes": error,
            }));
        }
    }
    Ok(out)
}

/// `GET /internal/payment-ops/failures`
pub async fn failures(_token: InternalToken, State(state): State<AppState>, Query(q): Query<ObsQuery>) -> AppResult<Json<Value>> {
    let (from, to) = parse_window(&q)?;
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).clamp(1, 100);
    let ids = active_merchant_ids(&state, &from, &to, &q).await?;

    let mut rows: Vec<Value> = Vec::new();
    rows.extend(collect_exception_rows(&state, &ids, &from, &to, &q).await?);
    rows.extend(collect_webhook_rows(&state, &ids, &from, &to).await?);
    rows.extend(collect_job_rows(&state, &ids, &from, &to, "export_job").await?);
    rows.extend(collect_job_rows(&state, &ids, &from, &to, "evidence_pack").await?);

    rows.retain(|r| {
        if let Some(s) = q.severity.as_deref() { if r["severity"] != json!(s) { return false; } }
        if let Some(n) = q.network.as_deref().filter(|s| !s.is_empty()) { if r["network"] != json!(n) { return false; } }
        if let Some(a) = q.asset_id.as_deref().filter(|s| !s.is_empty()) { if r["assetId"] != json!(a) { return false; } }
        true
    });
    rows.sort_by(|l, r| r["occurredAt"].as_str().unwrap_or("").cmp(l["occurredAt"].as_str().unwrap_or("")));

    let total = rows.len() as i64;
    if total == 0 {
        return Ok(Json(json!({ "meta": paginator_meta(0, per_page, page), "data": [] })));
    }
    let start = ((page - 1) * per_page) as usize;
    let data: Vec<Value> = rows.into_iter().skip(start).take(per_page as usize).collect();
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}

/// `GET /internal/payment-ops/tn10/status`
pub async fn tn10_status(_token: InternalToken) -> Json<Value> {
    Json(tn10_disabled_report())
}
