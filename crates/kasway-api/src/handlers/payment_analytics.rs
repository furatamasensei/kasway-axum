//! `/api/payments/ops/analytics/{summary,timeseries,breakdown}` —
//! PaymentAnalyticsController + PaymentAnalyticsService. Merchant DB analytics over
//! invoices + observations + credits (+ exceptions/webhooks). The `payments` table
//! has no `confirmed_at` column, so — exactly as Adonis does when required columns
//! are absent — the payment aggregate is empty and state derives from credits +
//! observations + invoice status. Confirmation requirement uses the platform
//! minimum (10), matching invoices::derive_payment_status.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult};
use crate::handlers::payment_exceptions;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Datelike, Duration, TimeZone, Timelike, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const PLATFORM_MIN_CONFIRMATIONS: i64 = 10;
const PAYMENT_STATES: &[&str] = &[
    "awaiting_payment", "confirming", "ready_to_settle", "underpaid", "paid", "overpaid",
    "expired", "cancelled", "unapplied_receipt",
];

#[derive(Deserialize, Default)]
pub struct AnalyticsQuery {
    from: Option<String>,
    to: Option<String>,
    interval: Option<String>,
    network: Option<String>,
    #[serde(rename = "assetId")]
    asset_id: Option<String>,
    currency: Option<String>,
    status: Option<String>,
    #[serde(rename = "paymentState")]
    payment_state: Option<String>,
    dimension: Option<String>,
}

fn iso(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string()
}
fn parse_dt(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc))
}

struct Window {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    interval: String,
}

fn resolve_window(q: &AnalyticsQuery) -> AppResult<Window> {
    let now = Utc::now();
    let from = match q.from.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => parse_dt(s).ok_or_else(|| AppError::commerce(422, "Analytics date filters must be valid ISO date strings."))?,
        None => now - Duration::days(30),
    };
    let to = match q.to.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => parse_dt(s).ok_or_else(|| AppError::commerce(422, "Analytics date filters must be valid ISO date strings."))?,
        None => now,
    };
    let interval = match q.interval.as_deref() {
        Some(i @ ("hour" | "day" | "week" | "month")) => i.to_string(),
        _ => "day".to_string(),
    };
    if from > to {
        return Err(AppError::commerce(422, "Analytics `from` date must be before or equal to `to` date."));
    }
    Ok(Window { from, to, interval })
}

fn serialize_window(w: &Window) -> Value {
    json!({ "from": iso(w.from), "to": iso(w.to), "interval": w.interval })
}

fn validate_payment_state(q: &AnalyticsQuery) -> AppResult<()> {
    if let Some(ps) = q.payment_state.as_deref() {
        if !PAYMENT_STATES.contains(&ps) {
            return Err(AppError::validation_field("paymentState", "enum", "The selected paymentState is invalid"));
        }
    }
    Ok(())
}

// ---- invoice loading + derived state ---------------------------------------

#[derive(sqlx::FromRow)]
struct InvRow {
    id: i64,
    status: String,
    total_amount: i64,
    created_at: Option<String>,
    paid_at: Option<String>,
    expires_at: Option<String>,
    payment_network: Option<String>,
    payment_asset: Option<String>,
    currency: String,
}

struct Derived {
    total_amount: i128,
    currency: String,
    network: String,
    asset: String,
    created_at: Option<String>,
    paid_at: Option<String>,
    payment_state: String,
    first_observation_at: Option<String>,
    first_final_observation_at: Option<String>,
}

fn required_conf_from_metadata(meta: &Value) -> Option<i64> {
    let rc = meta.get("confirmationPolicy")?.get("requiredConfirmations")?;
    let n = match rc { Value::Number(n) => n.as_i64(), Value::String(s) => s.parse::<i64>().ok(), _ => None }?;
    if n > 0 { Some(n) } else { None }
}

async fn load_invoices(state: &AppState, user_id: i64, q: &AnalyticsQuery, w: &Window) -> AppResult<Vec<InvRow>> {
    let mut sql = String::from(
        "SELECT id, status, total_amount, created_at, paid_at, expires_at, payment_network, payment_asset, currency \
         FROM invoices WHERE user_id = ? AND created_at BETWEEN ? AND ?",
    );
    let mut binds: Vec<String> = vec![user_id.to_string(), iso(w.from), iso(w.to)];
    if let Some(n) = q.network.as_deref().filter(|s| !s.is_empty()) { sql.push_str(" AND payment_network = ?"); binds.push(n.into()); }
    if let Some(a) = q.asset_id.as_deref().filter(|s| !s.is_empty()) { sql.push_str(" AND payment_asset = ?"); binds.push(a.into()); }
    if let Some(c) = q.currency.as_deref().filter(|s| !s.is_empty()) { sql.push_str(" AND currency = ?"); binds.push(c.into()); }
    if let Some(s) = q.status.as_deref().filter(|s| !s.is_empty()) { sql.push_str(" AND status = ?"); binds.push(s.into()); }
    sql.push_str(" ORDER BY created_at ASC");
    let mut query = sqlx::query_as::<_, InvRow>(&sql);
    for b in &binds { query = query.bind(b.clone()); }
    Ok(query.fetch_all(&state.db.pool).await?)
}

async fn derive_invoices(state: &AppState, user_id: i64, q: &AnalyticsQuery, w: &Window) -> AppResult<Vec<Derived>> {
    let invoices = load_invoices(state, user_id, q, w).await?;
    let now = Utc::now();
    let mut out = Vec::with_capacity(invoices.len());
    for inv in &invoices {
        // observation aggregate
        let obs = sqlx::query_as::<_, (String, i64, i64, Option<String>, Option<String>, Option<String>)>(
            "SELECT status, amount, confirmations, accepted_at, created_at, metadata FROM payment_observations \
             WHERE invoice_id = ? ORDER BY id ASC",
        ).bind(inv.id).fetch_all(&state.db.pool).await?;
        let mut first_obs: Option<String> = None;
        let mut first_final: Option<String> = None;
        let (mut has_confirming, mut has_settleable) = (false, false);
        for (st, _amt, conf, accepted_at, created_at, metadata) in &obs {
            let req = match metadata.as_deref().and_then(|m| serde_json::from_str::<Value>(m).ok()) {
                Some(meta) => required_conf_from_metadata(&meta).map(|p| p.max(PLATFORM_MIN_CONFIRMATIONS)).unwrap_or(PLATFORM_MIN_CONFIRMATIONS),
                None => PLATFORM_MIN_CONFIRMATIONS,
            };
            let observed_at = accepted_at.clone().or_else(|| created_at.clone());
            if let Some(o) = &observed_at {
                if first_obs.as_ref().map(|f| o < f).unwrap_or(true) { first_obs = Some(o.clone()); }
            }
            let is_final = st == "settled" || *conf >= req;
            if is_final {
                if let Some(o) = &observed_at {
                    if first_final.as_ref().map(|f| o < f).unwrap_or(true) { first_final = Some(o.clone()); }
                }
            }
            let is_pending = st == "pending" || st == "matched";
            if is_pending && *conf < req { has_confirming = true; }
            if is_pending && *conf >= req { has_settleable = true; }
        }

        // credit total
        let credited: i64 = sqlx::query_scalar("SELECT CAST(COALESCE(SUM(amount),0) AS INTEGER) FROM payment_credits WHERE invoice_id = ?")
            .bind(inv.id).fetch_one(&state.db.pool).await?;
        let credited = credited as i128;
        let applied = if credited > 0 { credited } else { 0 };
        let total = inv.total_amount as i128;

        // resolvePaymentState (payments aggregate empty in our schema)
        let expired = inv.status == "open" && inv.expires_at.as_deref().and_then(parse_dt).map(|e| e <= now).unwrap_or(false);
        let state_str = if inv.status == "cancelled" { "cancelled" }
            else if inv.status == "expired" || expired { "expired" }
            else if applied > total { "overpaid" }
            else if credited == 0 && inv.status == "paid" { "paid" }
            else if applied >= total { "paid" }
            else if applied > 0 { "underpaid" }
            else if has_settleable { "ready_to_settle" }
            else if has_confirming { "confirming" }
            else { "awaiting_payment" };

        out.push(Derived {
            total_amount: total,
            currency: inv.currency.clone(),
            network: inv.payment_network.clone().unwrap_or_default(),
            asset: inv.payment_asset.clone().unwrap_or_default(),
            created_at: inv.created_at.clone(),
            paid_at: inv.paid_at.clone(),
            payment_state: state_str.to_string(),
            first_observation_at: first_obs,
            first_final_observation_at: first_final,
        });
    }
    // paymentState filter
    if let Some(ps) = q.payment_state.as_deref() {
        out.retain(|d| d.payment_state == ps);
    }
    Ok(out)
}

fn avg_seconds(pairs: &[(String, String)]) -> Value {
    let valid: Vec<i64> = pairs.iter().filter_map(|(f, t)| {
        let from = parse_dt(f)?; let to = parse_dt(t)?;
        let ms = to.timestamp_millis() - from.timestamp_millis();
        if ms >= 0 { Some(ms) } else { Some(0) }
    }).collect();
    if pairs.is_empty() { return Value::Null; }
    let total: i64 = valid.iter().sum();
    let avg = (total as f64) / (pairs.len() as f64) / 1000.0;
    json!((avg * 1000.0).round() / 1000.0)
}

// ---- exceptions ------------------------------------------------------------

async fn exception_rows(state: &AppState, user_id: i64, q: &AnalyticsQuery, w: &Window) -> AppResult<Vec<Value>> {
    let all = payment_exceptions::derive_user_exceptions(state, user_id, None, None, None).await?;
    let from = iso(w.from);
    let to = iso(w.to);
    let any_filter = [&q.currency, &q.status, &q.payment_state, &q.network, &q.asset_id]
        .iter().any(|f| f.as_deref().map(|s| !s.is_empty()).unwrap_or(false));

    // currency map (only needed when currency filter active)
    let mut currency_by_invoice: BTreeMap<i64, String> = BTreeMap::new();
    if q.currency.as_deref().map(|s| !s.is_empty()).unwrap_or(false) {
        let ids: Vec<i64> = all.iter().filter_map(|e| e["invoice"]["id"].as_i64()).collect();
        if !ids.is_empty() {
            let ph = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let sql = format!("SELECT id, currency FROM invoices WHERE user_id = ? AND id IN ({ph})");
            let mut query = sqlx::query_as::<_, (i64, String)>(&sql).bind(user_id);
            for id in &ids { query = query.bind(*id); }
            for (id, c) in query.fetch_all(&state.db.pool).await? { currency_by_invoice.insert(id, c); }
        }
    }

    Ok(all.into_iter().filter(|e| {
        let occurred = e["sourceTimestamps"]["occurredAt"].as_str().unwrap_or("");
        if occurred < from.as_str() || occurred > to.as_str() { return false; }
        if !any_filter { return true; }
        if let Some(n) = q.network.as_deref().filter(|s| !s.is_empty()) { if e["network"].as_str() != Some(n) { return false; } }
        if let Some(a) = q.asset_id.as_deref().filter(|s| !s.is_empty()) { if e["assetId"].as_str() != Some(a) { return false; } }
        if let Some(c) = q.currency.as_deref().filter(|s| !s.is_empty()) {
            let inv_cur = e["invoice"]["id"].as_i64().and_then(|id| currency_by_invoice.get(&id)).map(|s| s.as_str());
            if inv_cur != Some(c) { return false; }
        }
        if let Some(s) = q.status.as_deref().filter(|s| !s.is_empty()) { if e["invoice"]["status"].as_str() != Some(s) { return false; } }
        if let Some(ps) = q.payment_state.as_deref().filter(|s| !s.is_empty()) {
            if !PAYMENT_STATES.contains(&ps) || e["paymentState"].as_str() != Some(ps) { return false; }
        }
        true
    }).collect())
}

// ---- webhook ---------------------------------------------------------------

async fn webhook_summary(state: &AppState, user_id: i64, w: &Window) -> AppResult<Value> {
    let rows = sqlx::query_as::<_, (String, i64)>(
        "SELECT d.status, COUNT(*) FROM webhook_deliveries d LEFT JOIN webhook_events e ON e.id = d.webhook_event_id \
         WHERE d.delivered_at BETWEEN ? AND ? AND e.user_id = ? GROUP BY d.status",
    ).bind(iso(w.from)).bind(iso(w.to)).bind(user_id).fetch_all(&state.db.pool).await?;
    let (mut delivery, mut success, mut failure) = (0i64, 0i64, 0i64);
    for (status, count) in rows {
        delivery += count;
        let s = status.to_lowercase();
        if ["success", "succeeded", "delivered"].contains(&s.as_str()) { success += count; }
        else if ["failure", "failed"].contains(&s.as_str()) { failure += count; }
    }
    let rate = if delivery > 0 { json!(success as f64 / delivery as f64) } else { Value::Null };
    Ok(json!({ "deliveryCount": delivery, "successCount": success, "failureCount": failure, "successRate": rate }))
}

async fn webhook_breakdown(state: &AppState, user_id: i64, w: &Window) -> AppResult<Vec<(String, i64)>> {
    let rows = sqlx::query_as::<_, (String,)>(
        "SELECT d.status FROM webhook_deliveries d LEFT JOIN webhook_events e ON e.id = d.webhook_event_id \
         WHERE d.delivered_at BETWEEN ? AND ? AND e.user_id = ?",
    ).bind(iso(w.from)).bind(iso(w.to)).bind(user_id).fetch_all(&state.db.pool).await?;
    let mut grouped: BTreeMap<String, i64> = BTreeMap::new();
    for (status,) in rows {
        let key = match status.as_str() {
            "success" | "succeeded" | "delivered" => "success",
            "failure" | "failed" => "failure",
            _ => "other",
        };
        *grouped.entry(key.to_string()).or_insert(0) += 1;
    }
    if grouped.is_empty() { grouped.insert("none".into(), 0); }
    Ok(grouped.into_iter().collect())
}

// ---- bucket helpers --------------------------------------------------------

fn bucket_start(dt: DateTime<Utc>, interval: &str) -> DateTime<Utc> {
    match interval {
        "hour" => Utc.with_ymd_and_hms(dt.year(), dt.month(), dt.day(), dt.hour(), 0, 0).unwrap(),
        "week" => {
            let day = Utc.with_ymd_and_hms(dt.year(), dt.month(), dt.day(), 0, 0, 0).unwrap();
            day - Duration::days(dt.weekday().num_days_from_monday() as i64)
        }
        "month" => Utc.with_ymd_and_hms(dt.year(), dt.month(), 1, 0, 0, 0).unwrap(),
        _ => Utc.with_ymd_and_hms(dt.year(), dt.month(), dt.day(), 0, 0, 0).unwrap(),
    }
}

fn step(dt: DateTime<Utc>, interval: &str) -> DateTime<Utc> {
    match interval {
        "hour" => dt + Duration::hours(1),
        "week" => dt + Duration::days(7),
        "month" => {
            let (mut y, mut m) = (dt.year(), dt.month());
            if m == 12 { y += 1; m = 1; } else { m += 1; }
            Utc.with_ymd_and_hms(y, m, 1, 0, 0, 0).unwrap()
        }
        _ => dt + Duration::days(1),
    }
}

// ---- handlers --------------------------------------------------------------

/// `GET /api/payments/ops/analytics/summary`
pub async fn summary(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<AnalyticsQuery>) -> AppResult<Json<Value>> {
    validate_payment_state(&q)?;
    let w = resolve_window(&q)?;
    let invoices = derive_invoices(&state, auth.user_id, &q, &w).await?;

    let paid: Vec<&Derived> = invoices.iter().filter(|i| i.payment_state == "paid").collect();
    let underpaid = invoices.iter().filter(|i| i.payment_state == "underpaid").count();
    let overpaid = invoices.iter().filter(|i| i.payment_state == "overpaid").count();

    let to_first_obs: Vec<(String, String)> = invoices.iter()
        .filter_map(|i| i.first_observation_at.clone().and_then(|o| i.created_at.clone().map(|c| (c, o))))
        .collect();
    let final_to_paid: Vec<(String, String)> = invoices.iter()
        .filter(|i| i.payment_state == "paid" && i.first_final_observation_at.is_some() && i.paid_at.is_some())
        .map(|i| (i.first_final_observation_at.clone().unwrap(), i.paid_at.clone().unwrap()))
        .collect();

    let invoice_amount: i128 = invoices.iter().map(|i| i.total_amount).sum();
    let paid_amount: i128 = paid.iter().map(|i| i.total_amount).sum();

    // exception severity summary
    let excs = exception_rows(&state, auth.user_id, &q, &w).await?;
    let (mut high, mut medium, mut low) = (0i64, 0, 0);
    for e in &excs { match e["severity"].as_str().unwrap_or("") { "high" => high += 1, "medium" => medium += 1, "low" => low += 1, _ => {} } }

    Ok(Json(json!({
        "range": serialize_window(&w),
        "invoiceCount": invoices.len(),
        "invoiceAmount": invoice_amount.to_string(),
        "paidCount": paid.len(),
        "paidAmount": paid_amount.to_string(),
        "underpaidCount": underpaid,
        "overpaidCount": overpaid,
        "exceptionCountsBySeverity": { "high": high, "medium": medium, "low": low },
        "averageTimeToFirstObservationSeconds": avg_seconds(&to_first_obs),
        "averageTimeFromFinalObservationToPaidSeconds": avg_seconds(&final_to_paid),
        "webhookSummary": webhook_summary(&state, auth.user_id, &w).await?,
    })))
}

/// `GET /api/payments/ops/analytics/timeseries`
pub async fn timeseries(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<AnalyticsQuery>) -> AppResult<Json<Value>> {
    validate_payment_state(&q)?;
    let w = resolve_window(&q)?;
    let invoices = derive_invoices(&state, auth.user_id, &q, &w).await?;

    // empty buckets in order
    #[derive(Default)]
    struct Bucket { ic: i64, ia: i128, pc: i64, pa: i128, uc: i64, ua: i128, oc: i64, oa: i128 }
    let mut order: Vec<String> = Vec::new();
    let mut buckets: BTreeMap<String, Bucket> = BTreeMap::new();
    let mut cursor = bucket_start(w.from, &w.interval);
    let end = bucket_start(w.to, &w.interval);
    while cursor <= end {
        let key = iso(cursor);
        order.push(key.clone());
        buckets.insert(key, Bucket::default());
        cursor = step(cursor, &w.interval);
    }

    for inv in &invoices {
        let Some(created) = inv.created_at.as_deref().and_then(parse_dt) else { continue };
        let key = iso(bucket_start(created, &w.interval));
        if let Some(b) = buckets.get_mut(&key) {
            b.ic += 1; b.ia += inv.total_amount;
            match inv.payment_state.as_str() {
                "paid" => { b.pc += 1; b.pa += inv.total_amount; }
                "underpaid" => { b.uc += 1; b.ua += inv.total_amount; }
                "overpaid" => { b.oc += 1; b.oa += inv.total_amount; }
                _ => {}
            }
        }
    }

    let rows: Vec<Value> = order.iter().map(|k| {
        let b = &buckets[k];
        json!({
            "bucket": k, "invoiceCount": b.ic, "invoiceAmount": b.ia.to_string(),
            "paidCount": b.pc, "paidAmount": b.pa.to_string(),
            "underpaidCount": b.uc, "underpaidAmount": b.ua.to_string(),
            "overpaidCount": b.oc, "overpaidAmount": b.oa.to_string(),
        })
    }).collect();

    Ok(Json(json!({ "range": serialize_window(&w), "interval": w.interval, "buckets": rows })))
}

fn empty_breakdown_row(key: &str, count: usize) -> Value {
    json!({
        "key": key, "invoiceCount": count, "invoiceAmount": "0", "paidCount": 0, "paidAmount": "0",
        "underpaidCount": 0, "underpaidAmount": "0", "overpaidCount": 0, "overpaidAmount": "0",
    })
}

fn sort_breakdown(mut rows: Vec<Value>) -> Vec<Value> {
    rows.sort_by(|a, b| {
        let ca = a["invoiceCount"].as_i64().unwrap_or(0);
        let cb = b["invoiceCount"].as_i64().unwrap_or(0);
        cb.cmp(&ca).then_with(|| a["key"].as_str().unwrap_or("").cmp(b["key"].as_str().unwrap_or("")))
    });
    rows
}

/// `GET /api/payments/ops/analytics/breakdown`
pub async fn breakdown(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<AnalyticsQuery>) -> AppResult<Json<Value>> {
    validate_payment_state(&q)?;
    let dimension = match q.dimension.as_deref() {
        Some(d @ ("paymentState" | "network" | "asset" | "currency" | "exceptionType" | "webhookStatus")) => d.to_string(),
        _ => return Err(AppError::validation_field("dimension", "enum", "The selected dimension is invalid")),
    };
    let w = resolve_window(&q)?;

    if dimension == "webhookStatus" {
        let rows: Vec<Value> = webhook_breakdown(&state, auth.user_id, &w).await?
            .into_iter().map(|(k, c)| empty_breakdown_row(&k, c as usize)).collect();
        return Ok(Json(json!({ "range": serialize_window(&w), "dimension": dimension, "rows": rows })));
    }

    if dimension == "exceptionType" {
        let excs = exception_rows(&state, auth.user_id, &q, &w).await?;
        let mut grouped: BTreeMap<String, usize> = BTreeMap::new();
        for e in &excs { *grouped.entry(e["type"].as_str().unwrap_or("").to_string()).or_insert(0) += 1; }
        let rows: Vec<Value> = grouped.into_iter().map(|(k, c)| empty_breakdown_row(&k, c)).collect();
        return Ok(Json(json!({ "range": serialize_window(&w), "dimension": dimension, "rows": sort_breakdown(rows) })));
    }

    let invoices = derive_invoices(&state, auth.user_id, &q, &w).await?;
    let mut grouped: BTreeMap<String, Vec<&Derived>> = BTreeMap::new();
    for inv in &invoices {
        let key = match dimension.as_str() {
            "paymentState" => inv.payment_state.clone(),
            "network" => inv.network.clone(),
            "asset" => inv.asset.clone(),
            _ => inv.currency.clone(),
        };
        grouped.entry(key).or_default().push(inv);
    }
    let rows: Vec<Value> = grouped.into_iter().map(|(key, values)| {
        let paid: Vec<&&Derived> = values.iter().filter(|i| i.payment_state == "paid").collect();
        let underpaid: Vec<&&Derived> = values.iter().filter(|i| i.payment_state == "underpaid").collect();
        let overpaid: Vec<&&Derived> = values.iter().filter(|i| i.payment_state == "overpaid").collect();
        let sum = |v: &[&&Derived]| -> String { v.iter().map(|i| i.total_amount).sum::<i128>().to_string() };
        json!({
            "key": key,
            "invoiceCount": values.len(),
            "invoiceAmount": values.iter().map(|i| i.total_amount).sum::<i128>().to_string(),
            "paidCount": paid.len(), "paidAmount": sum(&paid),
            "underpaidCount": underpaid.len(), "underpaidAmount": sum(&underpaid),
            "overpaidCount": overpaid.len(), "overpaidAmount": sum(&overpaid),
        })
    }).collect();

    Ok(Json(json!({ "range": serialize_window(&w), "dimension": dimension, "rows": sort_breakdown(rows) })))
}
