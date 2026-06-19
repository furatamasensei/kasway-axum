//! `/api/webhook-endpoints`, `/api/webhook-events`, `/api/webhook-deliveries`.
//! WebhookEndpointsController / WebhookEventsController /
//! WebhookDeliveryControlsController + their services.
//!
//! Merchant-guarded (owner always has `payments.ops.manage_webhooks`). Actual
//! HTTP delivery (DeliverWebhookJob) + notifications are deferred — delivery
//! rows are created `pending`. URL registration enforces the SSRF policy
//! (synchronous checks; DNS resolution is deferred).

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::state::AppState;
use crate::store_context::resolve_request_store;
use crate::util::{now_iso, paginator_meta};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};

const WEBHOOK_EVENT_TYPES: &[&str] = &[
    "invoice.created",
    "invoice.cancelled",
    "invoice.expired",
    "payment.confirmed",
    "invoice.paid",
    "subscription.created",
    "subscription.updated",
    "subscription.paused",
    "subscription.resumed",
    "subscription.cancelled",
    "subscription.invoice.created",
    "subscription.invoice.paid",
    "subscription.past_due",
];

// ---------- rows + serialization ----------

#[derive(sqlx::FromRow)]
struct EndpointRow {
    id: i64,
    user_id: i64,
    store_id: Option<i64>,
    url: String,
    events: String,
    is_active: bool,
    paused_at: Option<String>,
    secret_rotated_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const ENDPOINT_COLS: &str = "id, user_id, store_id, url, events, is_active, paused_at, \
    secret_rotated_at, created_at, updated_at";

fn serialize_endpoint(e: &EndpointRow, deliveries: Option<&[DeliveryRow]>) -> Value {
    let mut obj = json!({
        "id": e.id,
        "userId": e.user_id,
        "storeId": e.store_id,
        "url": e.url,
        "events": serde_json::from_str::<Value>(&e.events).unwrap_or(json!([])),
        "isActive": e.is_active,
        "pausedAt": e.paused_at,
        "secretRotatedAt": e.secret_rotated_at,
        "createdAt": e.created_at,
        "updatedAt": e.updated_at,
    });
    if let (Value::Object(map), Some(ds)) = (&mut obj, deliveries) {
        map.insert("deliveries".into(), Value::Array(ds.iter().map(|d| serialize_delivery(d, None, None)).collect()));
    }
    obj
}

#[derive(sqlx::FromRow)]
struct EventRow {
    id: i64,
    user_id: i64,
    store_id: Option<i64>,
    event_type: String,
    resource_type: String,
    resource_id: String,
    payload: String,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const EVENT_COLS: &str = "id, user_id, store_id, event_type, resource_type, resource_id, payload, created_at, updated_at";

fn serialize_event(e: &EventRow, deliveries: Option<&[(DeliveryRow, Option<EndpointRow>)]>) -> Value {
    let mut obj = json!({
        "id": e.id,
        "userId": e.user_id,
        "storeId": e.store_id,
        "eventType": e.event_type,
        "resourceType": e.resource_type,
        "resourceId": e.resource_id,
        "payload": serde_json::from_str::<Value>(&e.payload).unwrap_or(json!({})),
        "createdAt": e.created_at,
        "updatedAt": e.updated_at,
    });
    if let (Value::Object(map), Some(ds)) = (&mut obj, deliveries) {
        map.insert(
            "deliveries".into(),
            Value::Array(ds.iter().map(|(d, ep)| serialize_delivery(d, ep.as_ref(), None)).collect()),
        );
    }
    obj
}

#[derive(sqlx::FromRow)]
struct DeliveryRow {
    id: i64,
    webhook_event_id: i64,
    webhook_endpoint_id: i64,
    status: String,
    attempt_count: i64,
    response_status: Option<i64>,
    response_body: Option<String>,
    error: Option<String>,
    is_replay: bool,
    last_attempted_at: Option<String>,
    next_attempt_at: Option<String>,
    delivered_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const DELIVERY_COLS: &str = "id, webhook_event_id, webhook_endpoint_id, status, attempt_count, \
    response_status, response_body, error, is_replay, last_attempted_at, next_attempt_at, \
    delivered_at, created_at, updated_at";

fn serialize_delivery(d: &DeliveryRow, endpoint: Option<&EndpointRow>, event: Option<&EventRow>) -> Value {
    let mut obj = json!({
        "id": d.id,
        "webhookEventId": d.webhook_event_id,
        "webhookEndpointId": d.webhook_endpoint_id,
        "status": d.status,
        "attemptCount": d.attempt_count,
        "responseStatus": d.response_status,
        "responseBody": d.response_body,
        "error": d.error,
        "isReplay": d.is_replay,
        "lastAttemptedAt": d.last_attempted_at,
        "nextAttemptAt": d.next_attempt_at,
        "deliveredAt": d.delivered_at,
        "createdAt": d.created_at,
        "updatedAt": d.updated_at,
    });
    if let Value::Object(map) = &mut obj {
        if let Some(ep) = endpoint {
            map.insert("endpoint".into(), serialize_endpoint(ep, None));
        }
        if let Some(ev) = event {
            map.insert("event".into(), serialize_event(ev, None));
        }
    }
    obj
}

// ---------- helpers ----------

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn q_store_id(q: &WebhookQuery) -> Option<i64> {
    q.store_id
}

#[derive(Deserialize, Default)]
pub struct WebhookQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
    #[serde(rename = "storeId")]
    store_id: Option<i64>,
    status: Option<String>,
    #[serde(rename = "webhookEventId")]
    webhook_event_id: Option<i64>,
    #[serde(rename = "webhookEndpointId")]
    webhook_endpoint_id: Option<i64>,
    #[serde(rename = "eventType")]
    event_type: Option<String>,
    #[serde(rename = "isReplay")]
    is_replay: Option<bool>,
}

/// findEndpoint: user-scoped (+ optional storeId). 404 when absent/cross-user.
async fn find_endpoint(state: &AppState, user_id: i64, id: i64, store_id: Option<i64>) -> AppResult<EndpointRow> {
    let mut sql = format!("SELECT {ENDPOINT_COLS} FROM webhook_endpoints WHERE user_id = ? AND id = ?");
    if store_id.is_some() {
        sql.push_str(" AND store_id = ?");
    }
    let mut q = sqlx::query_as::<_, EndpointRow>(&sql).bind(user_id).bind(id);
    if let Some(sid) = store_id {
        q = q.bind(sid);
    }
    q.fetch_optional(&state.db.pool).await?.ok_or_else(AppError::row_not_found)
}

/// findOrFail by id (global) — pause/resume/rotate use this then ownership 403.
async fn find_endpoint_global(state: &AppState, id: i64) -> AppResult<EndpointRow> {
    sqlx::query_as::<_, EndpointRow>(&format!("SELECT {ENDPOINT_COLS} FROM webhook_endpoints WHERE id = ?"))
        .bind(id)
        .fetch_optional(&state.db.pool)
        .await?
        .ok_or_else(AppError::row_not_found)
}

// ---------- URL policy (SSRF) ----------

fn validate_webhook_url(raw: &str, allow_loopback: bool) -> Result<(), (&'static str, &'static str)> {
    let parsed = url::Url::parse(raw).map_err(|_| ("invalid_url", "Webhook URL is not a valid URL"))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(("embedded_credentials", "Webhook URL must not contain embedded credentials"));
    }
    let host = parsed.host_str().unwrap_or("").trim_matches(|c| c == '[' || c == ']').to_lowercase();
    let is_loopback = matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1");

    if parsed.scheme() != "https" {
        let http_ok = parsed.scheme() == "http" && allow_loopback && is_loopback;
        if !http_ok {
            return Err(("forbidden_protocol", "Webhook URL must use https (plain http is only allowed towards localhost in development)"));
        }
    }
    if allow_loopback && is_loopback {
        return Ok(());
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_forbidden_ip(&ip) {
            return Err(("forbidden_address", "Webhook URL must not target a private, loopback, link-local, or reserved address"));
        }
    }
    Ok(())
}

fn is_forbidden_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
                || v4.is_broadcast() || v4.is_documentation()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

fn allow_loopback(state: &AppState) -> bool {
    state.config.node_env != "production"
}

// ---------- endpoints CRUD ----------

/// `GET /api/webhook-endpoints`
pub async fn endpoints_index(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Query(q): Query<WebhookQuery>,
) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(10).max(1);
    let offset = (page - 1) * per_page;

    let (filter, bind_store) = match q.store_id {
        Some(_) => (" AND store_id = ?", true),
        None => ("", false),
    };

    let count_sql = format!("SELECT COUNT(*) FROM webhook_endpoints WHERE user_id = ?{filter}");
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql).bind(auth.user_id);
    if bind_store { cq = cq.bind(q.store_id.unwrap()); }
    let total = cq.fetch_one(&state.db.pool).await?;

    let list_sql = format!(
        "SELECT {ENDPOINT_COLS} FROM webhook_endpoints WHERE user_id = ?{filter} ORDER BY created_at DESC LIMIT ? OFFSET ?"
    );
    let mut lq = sqlx::query_as::<_, EndpointRow>(&list_sql).bind(auth.user_id);
    if bind_store { lq = lq.bind(q.store_id.unwrap()); }
    let rows = lq.bind(per_page).bind(offset).fetch_all(&state.db.pool).await?;

    let data: Vec<Value> = rows.iter().map(|e| serialize_endpoint(e, None)).collect();
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}

/// `POST /api/webhook-endpoints`
pub async fn endpoints_store(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<(StatusCode, Json<Value>)> {
    let (url_, events, is_active, store_id_in) = validate_store_endpoint(&body)?;

    if let Err((code, reason)) = validate_webhook_url(&url_, allow_loopback(&state)) {
        return Err(AppError::Validation(vec![ValidationFailure {
            message: reason.into(),
            rule: code.into(),
            field: "url".into(),
        }]));
    }

    let store_id = resolve_request_store(&state, auth.user_id, store_id_in).await?;
    let signing_secret = format!("whsec_{}", random_hex(32));
    let now = now_iso();
    // dedup events preserving order
    let mut seen = std::collections::HashSet::new();
    let events: Vec<String> = events.into_iter().filter(|e| seen.insert(e.clone())).collect();
    let events_json = serde_json::to_string(&events).unwrap();

    let result = sqlx::query(
        "INSERT INTO webhook_endpoints (user_id, store_id, url, events, signing_secret, is_active, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(auth.user_id)
    .bind(store_id)
    .bind(&url_)
    .bind(&events_json)
    .bind(&signing_secret)
    .bind(is_active as i64)
    .bind(&now)
    .bind(&now)
    .execute(&state.db.pool)
    .await?;
    let id = result.last_insert_rowid();

    let e = find_endpoint(&state, auth.user_id, id, None).await?;
    let mut v = serialize_endpoint(&e, None);
    v["signingSecret"] = Value::String(signing_secret);
    Ok((StatusCode::CREATED, Json(v)))
}

/// `GET /api/webhook-endpoints/:id`
pub async fn endpoints_show(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<WebhookQuery>,
) -> AppResult<Json<Value>> {
    let e = find_endpoint(&state, auth.user_id, id, q_store_id(&q)).await?;
    let deliveries = sqlx::query_as::<_, DeliveryRow>(&format!(
        "SELECT {DELIVERY_COLS} FROM webhook_deliveries WHERE webhook_endpoint_id = ? ORDER BY created_at DESC LIMIT 20"
    ))
    .bind(e.id)
    .fetch_all(&state.db.pool)
    .await?;
    Ok(Json(serialize_endpoint(&e, Some(&deliveries))))
}

/// `PUT /api/webhook-endpoints/:id`
pub async fn endpoints_update(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<WebhookQuery>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let e = find_endpoint(&state, auth.user_id, id, q_store_id(&q)).await?;
    let now = now_iso();

    if let Some(url_v) = body.get("url") {
        let url_ = url_v.as_str().unwrap_or("");
        if let Err((code, reason)) = validate_webhook_url(url_, allow_loopback(&state)) {
            return Err(AppError::Validation(vec![ValidationFailure {
                message: reason.into(),
                rule: code.into(),
                field: "url".into(),
            }]));
        }
        sqlx::query("UPDATE webhook_endpoints SET url = ?, updated_at = ? WHERE id = ?")
            .bind(url_).bind(&now).bind(e.id).execute(&state.db.pool).await?;
    }
    if let Some(events_v) = body.get("events") {
        let events = parse_events(events_v)?;
        let mut seen = std::collections::HashSet::new();
        let events: Vec<String> = events.into_iter().filter(|x| seen.insert(x.clone())).collect();
        sqlx::query("UPDATE webhook_endpoints SET events = ?, updated_at = ? WHERE id = ?")
            .bind(serde_json::to_string(&events).unwrap()).bind(&now).bind(e.id).execute(&state.db.pool).await?;
    }
    if let Some(active) = body.get("isActive").and_then(|v| v.as_bool()) {
        sqlx::query("UPDATE webhook_endpoints SET is_active = ?, updated_at = ? WHERE id = ?")
            .bind(active as i64).bind(&now).bind(e.id).execute(&state.db.pool).await?;
    }

    let e = find_endpoint(&state, auth.user_id, id, None).await?;
    Ok(Json(serialize_endpoint(&e, None)))
}

/// `DELETE /api/webhook-endpoints/:id`
pub async fn endpoints_destroy(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<WebhookQuery>,
) -> AppResult<StatusCode> {
    let e = find_endpoint(&state, auth.user_id, id, q_store_id(&q)).await?;
    sqlx::query("DELETE FROM webhook_endpoints WHERE id = ?").bind(e.id).execute(&state.db.pool).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/webhook-endpoints/:id/test-send`
pub async fn endpoints_test_send(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<WebhookQuery>,
    Json(body): Json<Value>,
) -> AppResult<(StatusCode, Json<Value>)> {
    let e = find_endpoint(&state, auth.user_id, id, q_store_id(&q)).await?;
    let event_type = match body.get("eventType").and_then(|v| v.as_str()) {
        Some(t) if WEBHOOK_EVENT_TYPES.contains(&t) => t.to_string(),
        _ => {
            return Err(AppError::Validation(vec![ValidationFailure {
                message: "The selected eventType is invalid".into(),
                rule: "enum".into(),
                field: "eventType".into(),
            }]))
        }
    };

    let events: Vec<String> = serde_json::from_str(&e.events).unwrap_or_default();
    let subscribed = e.is_active && e.paused_at.is_none() && events.contains(&event_type);
    if !subscribed {
        return Err(AppError::Validation(vec![ValidationFailure {
            message: format!("Endpoint is not subscribed to {event_type}"),
            rule: "subscription".into(),
            field: "eventType".into(),
        }]));
    }

    let resource_type = body.get("resourceType").and_then(|v| v.as_str()).unwrap_or("webhook_endpoint").to_string();
    let resource_id = match body.get("resourceId") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => e.id.to_string(),
    };
    let payload = body.get("payload").cloned().unwrap_or_else(|| json!({ "test": true, "webhookEndpointId": e.id }));
    let now = now_iso();

    let ev = sqlx::query(
        "INSERT INTO webhook_events (user_id, store_id, event_type, resource_type, resource_id, payload, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(e.user_id).bind(e.store_id).bind(&event_type).bind(&resource_type).bind(&resource_id)
    .bind(payload.to_string()).bind(&now).bind(&now)
    .execute(&state.db.pool).await?;
    let event_id = ev.last_insert_rowid();

    let delivery_id = create_delivery(&state, event_id, e.id, false, &now).await?;

    Ok((StatusCode::ACCEPTED, Json(json!({
        "eventId": event_id,
        "deliveryId": delivery_id,
        "eventType": event_type,
    }))))
}

async fn create_delivery(state: &AppState, event_id: i64, endpoint_id: i64, is_replay: bool, now: &str) -> AppResult<i64> {
    let r = sqlx::query(
        "INSERT INTO webhook_deliveries (webhook_event_id, webhook_endpoint_id, status, attempt_count, is_replay, created_at, updated_at) \
         VALUES (?, ?, 'pending', 0, ?, ?, ?)",
    )
    .bind(event_id).bind(endpoint_id).bind(is_replay as i64).bind(now).bind(now)
    .execute(&state.db.pool).await?;
    // DeliverWebhookJob.dispatch -> deferred no-op
    Ok(r.last_insert_rowid())
}

// ---------- delivery controls (pause/resume/rotate) ----------

/// `POST /api/webhook-endpoints/:id/pause`
pub async fn endpoints_pause(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    let e = find_endpoint_global(&state, id).await?;
    if e.user_id != auth.user_id {
        return Err(AppError::Forbidden);
    }
    if e.paused_at.is_none() {
        sqlx::query("UPDATE webhook_endpoints SET paused_at = ?, updated_at = ? WHERE id = ?")
            .bind(now_iso()).bind(now_iso()).bind(e.id).execute(&state.db.pool).await?;
        // notification emit -> deferred no-op
    }
    let e = find_endpoint_global(&state, id).await?;
    Ok(Json(serialize_endpoint(&e, None)))
}

/// `POST /api/webhook-endpoints/:id/resume`
pub async fn endpoints_resume(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    let e = find_endpoint_global(&state, id).await?;
    if e.user_id != auth.user_id {
        return Err(AppError::Forbidden);
    }
    if e.paused_at.is_some() {
        sqlx::query("UPDATE webhook_endpoints SET paused_at = NULL, updated_at = ? WHERE id = ?")
            .bind(now_iso()).bind(e.id).execute(&state.db.pool).await?;
    }
    let e = find_endpoint_global(&state, id).await?;
    Ok(Json(serialize_endpoint(&e, None)))
}

/// `POST /api/webhook-endpoints/:id/rotate-secret`
pub async fn endpoints_rotate_secret(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    let e = find_endpoint_global(&state, id).await?;
    if e.user_id != auth.user_id {
        return Err(AppError::Forbidden);
    }
    let secret = format!("whsec_{}", random_hex(32));
    let now = now_iso();
    sqlx::query("UPDATE webhook_endpoints SET signing_secret = ?, secret_rotated_at = ?, updated_at = ? WHERE id = ?")
        .bind(&secret).bind(&now).bind(&now).bind(e.id).execute(&state.db.pool).await?;
    let e = find_endpoint_global(&state, id).await?;
    let mut v = serialize_endpoint(&e, None);
    v["signingSecret"] = Value::String(secret);
    Ok(Json(v))
}

// ---------- deliveries ----------

/// `GET /api/webhook-deliveries`
pub async fn deliveries_index(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Query(q): Query<WebhookQuery>,
) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(10).max(1);
    let offset = (page - 1) * per_page;

    // base: deliveries whose endpoint belongs to merchant (+ filters)
    let mut where_sql = String::from(
        "FROM webhook_deliveries d JOIN webhook_endpoints e ON e.id = d.webhook_endpoint_id WHERE e.user_id = ?",
    );
    if q.store_id.is_some() { where_sql.push_str(" AND e.store_id = ?"); }
    if q.webhook_event_id.is_some() { where_sql.push_str(" AND d.webhook_event_id = ?"); }
    if q.webhook_endpoint_id.is_some() { where_sql.push_str(" AND d.webhook_endpoint_id = ?"); }
    if q.status.is_some() { where_sql.push_str(" AND d.status = ?"); }
    if q.is_replay.is_some() { where_sql.push_str(" AND d.is_replay = ?"); }
    if q.event_type.is_some() {
        where_sql.push_str(" AND EXISTS (SELECT 1 FROM webhook_events ev WHERE ev.id = d.webhook_event_id AND ev.event_type = ?)");
    }

    let count_sql = format!("SELECT COUNT(*) {where_sql}");
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql).bind(auth.user_id);
    if let Some(s) = q.store_id { cq = cq.bind(s); }
    if let Some(v) = q.webhook_event_id { cq = cq.bind(v); }
    if let Some(v) = q.webhook_endpoint_id { cq = cq.bind(v); }
    if let Some(v) = &q.status { cq = cq.bind(v.clone()); }
    if let Some(v) = q.is_replay { cq = cq.bind(v as i64); }
    if let Some(v) = &q.event_type { cq = cq.bind(v.clone()); }
    let total: i64 = cq.fetch_one(&state.db.pool).await?;

    // fetch delivery ids (then load rows + relations)
    let id_sql = format!("SELECT d.id {where_sql} ORDER BY d.created_at DESC LIMIT ? OFFSET ?");
    let mut id_query = sqlx::query_scalar::<_, i64>(&id_sql);
    id_query = id_query.bind(auth.user_id);
    if let Some(s) = q.store_id { id_query = id_query.bind(s); }
    if let Some(v) = q.webhook_event_id { id_query = id_query.bind(v); }
    if let Some(v) = q.webhook_endpoint_id { id_query = id_query.bind(v); }
    if let Some(v) = &q.status { id_query = id_query.bind(v.clone()); }
    if let Some(v) = q.is_replay { id_query = id_query.bind(v as i64); }
    if let Some(v) = &q.event_type { id_query = id_query.bind(v.clone()); }
    let ids: Vec<i64> = id_query.bind(per_page).bind(offset).fetch_all(&state.db.pool).await?;

    let mut data = Vec::with_capacity(ids.len());
    for did in ids {
        data.push(load_delivery_full(&state, did).await?);
    }
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}

async fn load_delivery_full(state: &AppState, id: i64) -> AppResult<Value> {
    let d = sqlx::query_as::<_, DeliveryRow>(&format!("SELECT {DELIVERY_COLS} FROM webhook_deliveries WHERE id = ?"))
        .bind(id)
        .fetch_one(&state.db.pool)
        .await?;
    let endpoint = sqlx::query_as::<_, EndpointRow>(&format!("SELECT {ENDPOINT_COLS} FROM webhook_endpoints WHERE id = ?"))
        .bind(d.webhook_endpoint_id)
        .fetch_optional(&state.db.pool)
        .await?;
    let event = sqlx::query_as::<_, EventRow>(&format!("SELECT {EVENT_COLS} FROM webhook_events WHERE id = ?"))
        .bind(d.webhook_event_id)
        .fetch_optional(&state.db.pool)
        .await?;
    Ok(serialize_delivery(&d, endpoint.as_ref(), event.as_ref()))
}

/// getDeliveryForMerchant: delivery whose endpoint belongs to merchant.
async fn delivery_for_merchant(state: &AppState, user_id: i64, id: i64, store_id: Option<i64>) -> AppResult<DeliveryRow> {
    let mut sql = format!(
        "SELECT {DELIVERY_COLS} FROM webhook_deliveries d WHERE d.id = ? AND EXISTS \
         (SELECT 1 FROM webhook_endpoints e WHERE e.id = d.webhook_endpoint_id AND e.user_id = ?"
    );
    if store_id.is_some() { sql.push_str(" AND e.store_id = ?"); }
    sql.push(')');
    let mut q = sqlx::query_as::<_, DeliveryRow>(&sql).bind(id).bind(user_id);
    if let Some(s) = store_id { q = q.bind(s); }
    q.fetch_optional(&state.db.pool).await?.ok_or(AppError::NotFound("Not found"))
}

/// `GET /api/webhook-deliveries/:id`
pub async fn deliveries_show(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<WebhookQuery>,
) -> AppResult<Json<Value>> {
    let d = delivery_for_merchant(&state, auth.user_id, id, q_store_id(&q)).await?;
    Ok(Json(load_delivery_full(&state, d.id).await?))
}

/// `POST /api/webhook-deliveries/:id/replay`
pub async fn deliveries_replay(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<WebhookQuery>,
) -> AppResult<(StatusCode, Json<Value>)> {
    let d = delivery_for_merchant(&state, auth.user_id, id, q_store_id(&q)).await?;
    let now = now_iso();
    let replay_id = create_delivery(&state, d.webhook_event_id, d.webhook_endpoint_id, true, &now).await?;
    Ok((StatusCode::ACCEPTED, Json(load_delivery_full(&state, replay_id).await?)))
}

// ---------- events ----------

/// `GET /api/webhook-events`
pub async fn events_index(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Query(q): Query<WebhookQuery>,
) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(10).max(1);
    let offset = (page - 1) * per_page;

    let (filter, bind_store) = match q.store_id {
        Some(_) => (" AND store_id = ?", true),
        None => ("", false),
    };
    let count_sql = format!("SELECT COUNT(*) FROM webhook_events WHERE user_id = ?{filter}");
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql).bind(auth.user_id);
    if bind_store { cq = cq.bind(q.store_id.unwrap()); }
    let total = cq.fetch_one(&state.db.pool).await?;

    let list_sql = format!(
        "SELECT {EVENT_COLS} FROM webhook_events WHERE user_id = ?{filter} ORDER BY created_at DESC LIMIT ? OFFSET ?"
    );
    let mut lq = sqlx::query_as::<_, EventRow>(&list_sql).bind(auth.user_id);
    if bind_store { lq = lq.bind(q.store_id.unwrap()); }
    let rows = lq.bind(per_page).bind(offset).fetch_all(&state.db.pool).await?;

    let mut data = Vec::with_capacity(rows.len());
    for ev in &rows {
        let ds = load_event_deliveries(&state, ev.id).await?;
        data.push(serialize_event(ev, Some(&ds)));
    }
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}

async fn load_event_deliveries(state: &AppState, event_id: i64) -> AppResult<Vec<(DeliveryRow, Option<EndpointRow>)>> {
    let ds = sqlx::query_as::<_, DeliveryRow>(&format!(
        "SELECT {DELIVERY_COLS} FROM webhook_deliveries WHERE webhook_event_id = ? ORDER BY created_at DESC"
    ))
    .bind(event_id)
    .fetch_all(&state.db.pool)
    .await?;
    let mut out = Vec::with_capacity(ds.len());
    for d in ds {
        let ep = sqlx::query_as::<_, EndpointRow>(&format!("SELECT {ENDPOINT_COLS} FROM webhook_endpoints WHERE id = ?"))
            .bind(d.webhook_endpoint_id)
            .fetch_optional(&state.db.pool)
            .await?;
        out.push((d, ep));
    }
    Ok(out)
}

async fn load_event_owned(state: &AppState, user_id: i64, id: i64, store_id: Option<i64>) -> AppResult<EventRow> {
    // query by id (+ optional store), then ownership 403
    let mut sql = format!("SELECT {EVENT_COLS} FROM webhook_events WHERE id = ?");
    if store_id.is_some() { sql.push_str(" AND store_id = ?"); }
    let mut q = sqlx::query_as::<_, EventRow>(&sql).bind(id);
    if let Some(s) = store_id { q = q.bind(s); }
    let ev = q.fetch_optional(&state.db.pool).await?.ok_or_else(AppError::row_not_found)?;
    if ev.user_id != user_id {
        return Err(AppError::Forbidden);
    }
    Ok(ev)
}

/// `GET /api/webhook-events/:id`
pub async fn events_show(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<WebhookQuery>,
) -> AppResult<Json<Value>> {
    let ev = load_event_owned(&state, auth.user_id, id, q_store_id(&q)).await?;
    let ds = load_event_deliveries(&state, ev.id).await?;
    Ok(Json(serialize_event(&ev, Some(&ds))))
}

/// `POST /api/webhook-events/:id/replay`
pub async fn events_replay(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<WebhookQuery>,
) -> AppResult<(StatusCode, Json<Value>)> {
    let ev = load_event_owned(&state, auth.user_id, id, q_store_id(&q)).await?;

    // createDeliveries(event, isReplay=true): active, non-paused, subscribed endpoints matching store
    let mut sql = format!(
        "SELECT {ENDPOINT_COLS} FROM webhook_endpoints WHERE user_id = ? AND is_active = 1 AND paused_at IS NULL"
    );
    if ev.store_id.is_some() { sql.push_str(" AND store_id = ?"); } else { sql.push_str(" AND store_id IS NULL"); }
    let mut q2 = sqlx::query_as::<_, EndpointRow>(&sql).bind(ev.user_id);
    if let Some(s) = ev.store_id { q2 = q2.bind(s); }
    let endpoints = q2.fetch_all(&state.db.pool).await?;

    let now = now_iso();
    for ep in &endpoints {
        let events: Vec<String> = serde_json::from_str(&ep.events).unwrap_or_default();
        if events.contains(&ev.event_type) {
            create_delivery(&state, ev.id, ep.id, true, &now).await?;
        }
    }

    let ds = load_event_deliveries(&state, ev.id).await?;
    Ok((StatusCode::ACCEPTED, Json(serialize_event(&ev, Some(&ds)))))
}

// ---------- validation ----------

fn parse_events(v: &Value) -> AppResult<Vec<String>> {
    let arr = v.as_array().ok_or_else(|| AppError::Validation(vec![ValidationFailure {
        message: "The events field must be an array".into(),
        rule: "array".into(),
        field: "events".into(),
    }]))?;
    if arr.is_empty() {
        return Err(AppError::Validation(vec![ValidationFailure {
            message: "The events field must have at least 1 items".into(),
            rule: "minLength".into(),
            field: "events".into(),
        }]));
    }
    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        match item.as_str() {
            Some(s) if WEBHOOK_EVENT_TYPES.contains(&s) => out.push(s.to_string()),
            _ => return Err(AppError::Validation(vec![ValidationFailure {
                message: format!("The selected events.{i} is invalid"),
                rule: "enum".into(),
                field: format!("events.{i}"),
            }])),
        }
    }
    Ok(out)
}

#[allow(clippy::type_complexity)]
fn validate_store_endpoint(body: &Value) -> AppResult<(String, Vec<String>, bool, Option<i64>)> {
    let mut errors = Vec::new();
    let url_ = match body.get("url").and_then(|v| v.as_str()) {
        Some(u) if url::Url::parse(u).is_ok() => Some(u.to_string()),
        _ => { errors.push(ValidationFailure { message: "The url field must be a valid URL".into(), rule: "url".into(), field: "url".into() }); None }
    };
    let events = match body.get("events") {
        Some(v) => match parse_events(v) {
            Ok(e) => Some(e),
            Err(AppError::Validation(mut errs)) => { errors.append(&mut errs); None }
            Err(e) => return Err(e),
        },
        None => { errors.push(ValidationFailure { message: "The events field is required".into(), rule: "required".into(), field: "events".into() }); None }
    };
    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }
    Ok((
        url_.unwrap(),
        events.unwrap(),
        body.get("isActive").and_then(|v| v.as_bool()).unwrap_or(true),
        body.get("storeId").and_then(|v| v.as_i64()),
    ))
}
