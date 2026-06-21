//! `/api/metrics/*` — MetricsController + MetricsService (port).
//! Time buckets use Postgres `to_char` over the ISO timestamp text columns; the
//! response shapes mirror Adonis. Time-window bounds compare against ISO
//! timestamp strings.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Map, Value};

#[derive(Deserialize, Default)]
pub struct MetricsQuery {
    from: Option<String>,
    to: Option<String>,
    interval: Option<String>,
    #[serde(rename = "storeId")]
    store_id: Option<i64>,
}

struct Window {
    from: String,
    to: String,
    interval: String,
}

fn parse_dt(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&chrono::Utc));
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Some(d.and_hms_opt(0, 0, 0).unwrap().and_utc());
    }
    None
}

fn fmt_iso(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string()
}

fn resolve_window(q: &MetricsQuery) -> AppResult<Window> {
    let now = chrono::Utc::now();
    let from = match &q.from {
        Some(s) => parse_dt(s).ok_or_else(|| AppError::commerce(422, "Metrics date filters must be valid ISO dates."))?,
        None => now - chrono::Duration::days(30),
    };
    let to = match &q.to {
        Some(s) => parse_dt(s).ok_or_else(|| AppError::commerce(422, "Metrics date filters must be valid ISO dates."))?,
        None => now,
    };
    if from > to {
        return Err(AppError::commerce(422, "Metrics `from` date must be before or equal to `to` date."));
    }
    let interval = match q.interval.as_deref() {
        Some(i @ ("day" | "week" | "month")) => i.to_string(),
        Some(_) => return Err(AppError::commerce(422, "Metrics interval is invalid.")),
        None => "day".to_string(),
    };
    Ok(Window { from: fmt_iso(from), to: fmt_iso(to), interval })
}

fn serialize_window(w: &Window) -> Value {
    json!({ "from": w.from, "to": w.to, "interval": w.interval })
}

fn seed_counts(statuses: &[&str]) -> Map<String, Value> {
    let mut m = Map::new();
    for s in statuses {
        m.insert((*s).into(), json!(0));
    }
    m
}

/// Builds the optional `store_id` filter and the placeholder numbers for the
/// `from`/`to` window bounds, given that `$1` is always the `user_id` bind and
/// the optional store filter (when present) takes `$2`.
fn store_window_params(store_id: Option<i64>, store_col: &str) -> (String, u8, u8) {
    if store_id.is_some() {
        (format!(" AND {store_col} = $2"), 3, 4)
    } else {
        (String::new(), 2, 3)
    }
}

async fn invoice_counts(state: &AppState, user_id: i64, w: &Window, store_id: Option<i64>) -> AppResult<Value> {
    let mut counts = seed_counts(&["open", "paid", "expired", "cancelled"]);
    let (store_clause, from_n, to_n) = store_window_params(store_id, "store_id");
    let sql = format!(
        "SELECT status, COUNT(*) c FROM invoices WHERE user_id = $1{store_clause} AND created_at BETWEEN ${from_n} AND ${to_n} GROUP BY status"
    );
    let mut q = sqlx::query_as::<_, (String, i64)>(&sql).bind(user_id);
    if let Some(s) = store_id { q = q.bind(s); }
    let rows = q.bind(&w.from).bind(&w.to).fetch_all(&state.db.pool).await?;
    for (status, c) in rows { counts.insert(status, json!(c)); }
    Ok(Value::Object(counts))
}

async fn payment_counts(state: &AppState, user_id: i64, w: &Window, store_id: Option<i64>) -> AppResult<Value> {
    let mut counts = seed_counts(&["pending", "submitted", "confirmed", "failed"]);
    let (store_clause, from_n, to_n) = store_window_params(store_id, "i.store_id");
    let sql = format!(
        "SELECT p.status, COUNT(*) c FROM payments p JOIN invoices i ON i.id = p.invoice_id \
         WHERE i.user_id = $1{store_clause} AND p.created_at BETWEEN ${from_n} AND ${to_n} GROUP BY p.status"
    );
    let mut q = sqlx::query_as::<_, (String, i64)>(&sql).bind(user_id);
    if let Some(s) = store_id { q = q.bind(s); }
    let rows = q.bind(&w.from).bind(&w.to).fetch_all(&state.db.pool).await?;
    for (status, c) in rows { counts.insert(status, json!(c)); }
    Ok(Value::Object(counts))
}

async fn observation_summary(state: &AppState, user_id: i64, w: &Window, store_id: Option<i64>) -> AppResult<Value> {
    let mut counts = seed_counts(&["pending", "matched", "settled", "ignored"]);
    let (store_clause, from_n, to_n) = store_window_params(store_id, "i.store_id");
    let sql = format!(
        "SELECT po.status, COUNT(*) c, COALESCE(SUM(po.amount),0) t FROM payment_observations po \
         JOIN invoices i ON i.id = po.invoice_id WHERE i.user_id = $1{store_clause} \
         AND COALESCE(po.accepted_at, po.created_at) BETWEEN ${from_n} AND ${to_n} GROUP BY po.status"
    );
    let mut q = sqlx::query_as::<_, (String, i64, i64)>(&sql).bind(user_id);
    if let Some(s) = store_id { q = q.bind(s); }
    let rows = q.bind(&w.from).bind(&w.to).fetch_all(&state.db.pool).await?;
    let (mut total_count, mut total_amount) = (0i64, 0i64);
    for (status, c, t) in rows {
        counts.insert(status, json!(c));
        total_count += c;
        total_amount += t;
    }
    Ok(json!({ "totalCount": total_count, "totalAmount": total_amount, "counts": Value::Object(counts) }))
}

fn empty_credit_summary() -> Value {
    json!({ "totalCount": 0, "totalAmount": 0, "invoiceCount": 0 })
}

async fn webhook_counts(state: &AppState, user_id: i64, w: &Window) -> AppResult<Value> {
    let mut counts = seed_counts(&["success", "failure"]);
    let rows = sqlx::query_as::<_, (String, i64)>(
        "SELECT d.status, COUNT(*) c FROM webhook_deliveries d \
         JOIN webhook_events e ON e.id = d.webhook_event_id WHERE e.user_id = $1 \
         AND d.delivered_at BETWEEN $2 AND $3 GROUP BY d.status",
    )
    .bind(user_id)
    .bind(&w.from)
    .bind(&w.to)
    .fetch_all(&state.db.pool)
    .await?;
    let mut success = 0i64;
    let mut failure = 0i64;
    for (status, c) in rows {
        match status.as_str() {
            "success" | "succeeded" | "delivered" => success += c,
            "failure" | "failed" => failure += c,
            _ => {}
        }
    }
    counts.insert("success".into(), json!(success));
    counts.insert("failure".into(), json!(failure));
    Ok(Value::Object(counts))
}

async fn revenue_data(state: &AppState, user_id: i64, w: &Window, store_id: Option<i64>) -> AppResult<Value> {
    let (store_clause, from_n, to_n) = store_window_params(store_id, "store_id");
    let totals_sql = format!(
        "SELECT CAST(COALESCE(SUM(total_amount),0) AS DOUBLE PRECISION) total, CAST(COALESCE(AVG(total_amount),0) AS DOUBLE PRECISION) average \
         FROM invoices WHERE user_id = $1{store_clause} AND status = 'paid' AND paid_at BETWEEN ${from_n} AND ${to_n}"
    );
    let mut tq = sqlx::query_as::<_, (f64, f64)>(&totals_sql).bind(user_id);
    if let Some(s) = store_id { tq = tq.bind(s); }
    let (total, average) = tq.bind(&w.from).bind(&w.to).fetch_one(&state.db.pool).await?;

    let bucket_fmt = match w.interval.as_str() {
        "month" => "YYYY-MM",
        "week" => "IYYY-IW",
        _ => "YYYY-MM-DD",
    };
    let (store_clause, from_n, to_n) = store_window_params(store_id, "store_id");
    let series_sql = format!(
        "SELECT to_char((paid_at)::timestamptz, '{bucket_fmt}') bucket, CAST(COALESCE(SUM(total_amount),0) AS DOUBLE PRECISION) total, COUNT(*) c \
         FROM invoices WHERE user_id = $1{store_clause} AND status = 'paid' AND paid_at BETWEEN ${from_n} AND ${to_n} \
         GROUP BY bucket ORDER BY bucket ASC"
    );
    let mut sq = sqlx::query_as::<_, (Option<String>, f64, i64)>(&series_sql).bind(user_id);
    if let Some(s) = store_id { sq = sq.bind(s); }
    let series = sq.bind(&w.from).bind(&w.to).fetch_all(&state.db.pool).await?;
    let series: Vec<Value> = series
        .into_iter()
        .map(|(bucket, total, c)| json!({ "bucket": bucket, "totalPaidInvoiceVolume": total, "paidInvoiceCount": c }))
        .collect();

    Ok(json!({
        "range": serialize_window(w),
        "totalPaidInvoiceVolume": total,
        "averagePaidInvoiceValue": average,
        "series": series,
    }))
}

// --- handlers ---

pub async fn overview(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<MetricsQuery>) -> AppResult<Json<Value>> {
    let w = resolve_window(&q)?;
    let revenue = revenue_data(&state, auth.user_id, &w, q.store_id).await?;
    Ok(Json(json!({
        "range": serialize_window(&w),
        "totalPaidInvoiceVolume": revenue["totalPaidInvoiceVolume"],
        "averagePaidInvoiceValue": revenue["averagePaidInvoiceValue"],
        "invoiceCounts": invoice_counts(&state, auth.user_id, &w, q.store_id).await?,
        "paymentCounts": payment_counts(&state, auth.user_id, &w, q.store_id).await?,
        "paymentObservationSummary": observation_summary(&state, auth.user_id, &w, q.store_id).await?,
        "paymentCreditSummary": empty_credit_summary(),
        "webhookDeliveryCounts": webhook_counts(&state, auth.user_id, &w).await?,
    })))
}

pub async fn revenue(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<MetricsQuery>) -> AppResult<Json<Value>> {
    let w = resolve_window(&q)?;
    Ok(Json(revenue_data(&state, auth.user_id, &w, q.store_id).await?))
}

pub async fn payments(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<MetricsQuery>) -> AppResult<Json<Value>> {
    let w = resolve_window(&q)?;
    Ok(Json(json!({
        "range": serialize_window(&w),
        "counts": payment_counts(&state, auth.user_id, &w, q.store_id).await?,
        "paymentObservationSummary": observation_summary(&state, auth.user_id, &w, q.store_id).await?,
        "paymentCreditSummary": empty_credit_summary(),
    })))
}

pub async fn payment_observations(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<MetricsQuery>) -> AppResult<Json<Value>> {
    let w = resolve_window(&q)?;
    Ok(Json(json!({
        "range": serialize_window(&w),
        "summary": observation_summary(&state, auth.user_id, &w, q.store_id).await?,
    })))
}

pub async fn payment_credits(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<MetricsQuery>) -> AppResult<Json<Value>> {
    let w = resolve_window(&q)?;
    Ok(Json(json!({ "range": serialize_window(&w), "summary": empty_credit_summary() })))
}

pub async fn webhooks(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<MetricsQuery>) -> AppResult<Json<Value>> {
    let w = resolve_window(&q)?;
    Ok(Json(json!({ "range": serialize_window(&w), "counts": webhook_counts(&state, auth.user_id, &w).await? })))
}
