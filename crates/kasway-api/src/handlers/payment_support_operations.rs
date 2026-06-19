//! `/api/support/payments/*` — SupportPaymentOperationsController (internal-token
//! tier). DB-portable read/notes surface. Audit-event recording is a no-op side
//! effect (not in the response contract). `exceptions` (cross-merchant exception
//! engine) and `replayWebhookDelivery` (external redelivery job) are deferred.

use crate::auth::InternalToken;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::handlers::{invoices, payment_exceptions, payment_operations};
use crate::state::AppState;
use crate::util::{now_iso, paginator_meta};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Map, Value};

// ---- sensitive-data masking (mirrors maskSensitiveMetadata) ----------------

fn is_sensitive_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        "secret", "token", "wallet", "private", "seed", "material", "password",
        "passphrase", "hash", "fingerprint", "authorization", "signature", "encrypted",
        "apikey", "api_key", "api-key", "api key",
    ];
    NEEDLES.iter().any(|n| k.contains(n))
}

fn mask_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, val)| {
                    if is_sensitive_key(k) {
                        (k.clone(), json!("[redacted]"))
                    } else {
                        (k.clone(), mask_value(val))
                    }
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(mask_value).collect()),
        other => other.clone(),
    }
}

// ---- invoice serialization (support shape) ---------------------------------

async fn merchant_email(state: &AppState, user_id: i64) -> AppResult<Option<String>> {
    Ok(sqlx::query_scalar("SELECT email FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(&state.db.pool)
        .await?)
}

fn serialize_note(
    id: i64,
    user_id: i64,
    invoice_id: i64,
    actor_type: &str,
    actor_id: Option<&str>,
    note: &str,
    metadata: &Value,
    created_at: &Option<String>,
    updated_at: &Option<String>,
) -> Value {
    json!({
        "id": id,
        "userId": user_id,
        "invoiceId": invoice_id,
        "actorType": actor_type,
        "actorId": actor_id,
        "note": note,
        "metadata": mask_value(metadata),
        "createdAt": created_at,
        "updatedAt": updated_at,
    })
}

async fn fetch_notes(state: &AppState, invoice_id: i64) -> AppResult<Vec<Value>> {
    let rows = sqlx::query_as::<_, (i64, i64, i64, String, Option<String>, String, String, Option<String>, Option<String>)>(
        "SELECT id, user_id, invoice_id, actor_type, actor_id, note, metadata, created_at, updated_at \
         FROM payment_support_notes WHERE invoice_id = ? ORDER BY created_at DESC LIMIT 50",
    )
    .bind(invoice_id)
    .fetch_all(&state.db.pool)
    .await?;
    Ok(rows
        .iter()
        .map(|(id, uid, iid, at, aid, note, meta, c, u)| {
            let m: Value = serde_json::from_str(meta).unwrap_or(json!({}));
            serialize_note(*id, *uid, *iid, at, aid.as_deref(), note, &m, c, u)
        })
        .collect())
}

async fn serialize_support_invoice(
    state: &AppState,
    inv: &invoices::InvoiceRow,
    include_notes: bool,
) -> AppResult<Value> {
    let (items, intent) = invoices::load_relations(state, inv.id()).await?;
    let mut base = invoices::serialize_invoice(inv, &items, intent.as_ref());
    let status = invoices::derive_payment_status(state, inv).await?;
    let user_id = base.get("userId").and_then(|v| v.as_i64()).unwrap_or(0);
    let email = merchant_email(state, user_id).await?;

    if let Value::Object(obj) = &mut base {
        let masked = mask_value(&obj.get("metadata").cloned().unwrap_or(json!({})));
        obj.insert("metadata".into(), masked);
        obj.insert("paymentStatus".into(), status);
        obj.insert("supportMerchant".into(), json!({ "id": user_id, "email": email }));
        if include_notes {
            let notes = fetch_notes(state, inv.id()).await?;
            obj.insert("supportNotesCount".into(), json!(notes.len()));
            obj.insert("supportNotes".into(), Value::Array(notes));
        } else {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_support_notes WHERE invoice_id = ?")
                .bind(inv.id())
                .fetch_one(&state.db.pool)
                .await?;
            obj.insert("supportNotesCount".into(), json!(count));
        }
    }
    Ok(base)
}

/// findInvoice: id-or-publicId, cross-merchant, 404 'Invoice not found'.
async fn find_invoice(state: &AppState, ident: &str) -> AppResult<invoices::InvoiceRow> {
    let norm = ident.trim();
    if let Ok(n) = norm.parse::<i64>() {
        if n > 0 {
            if let Ok(inv) = invoices::load_by_id(state, n).await {
                return Ok(inv);
            }
        }
    }
    invoices::load_by_public_id(state, norm)
        .await
        .map_err(|_| AppError::commerce(404, "Invoice not found"))
}

// ---- handlers --------------------------------------------------------------

enum Bind {
    Str(String),
    Int(i64),
}

#[derive(Deserialize, Default)]
pub struct SearchQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
    #[serde(rename = "invoiceId")]
    invoice_id: Option<i64>,
    #[serde(rename = "publicId")]
    public_id: Option<String>,
    #[serde(rename = "externalId")]
    external_id: Option<String>,
    #[serde(rename = "paymentAddress")]
    payment_address: Option<String>,
    #[serde(rename = "merchantId")]
    merchant_id: Option<i64>,
    #[serde(rename = "merchantEmail")]
    merchant_email: Option<String>,
    status: Option<String>,
}

/// `GET /api/support/payments/search`
pub async fn search(
    _token: InternalToken,
    State(state): State<AppState>,
    Query(q): Query<SearchQuery>,
) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).clamp(1, 100);

    let mut where_sql = String::from(" WHERE 1=1");
    let mut binds: Vec<Bind> = Vec::new();
    if let Some(v) = q.invoice_id {
        where_sql.push_str(" AND id = ?");
        binds.push(Bind::Int(v));
    }
    if let Some(v) = q.public_id.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        where_sql.push_str(" AND public_id = ?");
        binds.push(Bind::Str(v.to_string()));
    }
    if let Some(v) = q.external_id.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        where_sql.push_str(" AND external_id = ?");
        binds.push(Bind::Str(v.to_string()));
    }
    if let Some(v) = q.payment_address.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        where_sql.push_str(" AND payment_address = ?");
        binds.push(Bind::Str(v.to_string()));
    }
    if let Some(v) = q.merchant_id {
        where_sql.push_str(" AND user_id = ?");
        binds.push(Bind::Int(v));
    }
    if let Some(v) = q.merchant_email.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        where_sql.push_str(" AND user_id IN (SELECT id FROM users WHERE LOWER(email) = ?)");
        binds.push(Bind::Str(v.to_lowercase()));
    }
    if let Some(v) = q.status.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        where_sql.push_str(" AND status = ?");
        binds.push(Bind::Str(v.to_string()));
    }

    let count_sql = format!("SELECT COUNT(*) FROM invoices{where_sql}");
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql);
    for b in &binds {
        cq = match b {
            Bind::Str(s) => cq.bind(s.clone()),
            Bind::Int(i) => cq.bind(*i),
        };
    }
    let total: i64 = cq.fetch_one(&state.db.pool).await?;

    let list_sql = format!(
        "SELECT id FROM invoices{where_sql} ORDER BY created_at DESC, id DESC LIMIT {per_page} OFFSET {}",
        (page - 1) * per_page
    );
    let mut lq = sqlx::query_scalar::<_, i64>(&list_sql);
    for b in &binds {
        lq = match b {
            Bind::Str(s) => lq.bind(s.clone()),
            Bind::Int(i) => lq.bind(*i),
        };
    }
    let ids: Vec<i64> = lq.fetch_all(&state.db.pool).await?;

    let mut data = Vec::with_capacity(ids.len());
    for id in ids {
        let inv = invoices::load_by_id(&state, id).await?;
        data.push(serialize_support_invoice(&state, &inv, false).await?);
    }
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}

#[derive(Deserialize, Default)]
pub struct ExceptionsQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
    #[serde(rename = "type")]
    exc_type: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    #[serde(rename = "invoiceId")]
    invoice_id: Option<i64>,
    #[serde(rename = "publicId")]
    public_id: Option<String>,
    #[serde(rename = "externalId")]
    external_id: Option<String>,
    #[serde(rename = "paymentAddress")]
    payment_address: Option<String>,
    #[serde(rename = "merchantId")]
    merchant_id: Option<i64>,
    #[serde(rename = "merchantEmail")]
    merchant_email: Option<String>,
    sort: Option<String>,
    direction: Option<String>,
}

/// resolveExceptionMerchantIds: which merchants to scan for exceptions.
async fn resolve_exception_merchant_ids(state: &AppState, q: &ExceptionsQuery) -> AppResult<Vec<i64>> {
    if let Some(id) = q.merchant_id {
        return Ok(vec![id]);
    }
    if let Some(email) = q.merchant_email.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let id: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE LOWER(email) = ?")
            .bind(email.to_lowercase())
            .fetch_optional(&state.db.pool)
            .await?;
        return Ok(id.into_iter().collect());
    }
    // distinct merchants whose invoices match the invoice-identifier filters
    let mut sql = String::from("SELECT DISTINCT user_id FROM invoices WHERE 1=1");
    let mut binds: Vec<Bind> = Vec::new();
    if let Some(v) = q.invoice_id {
        sql.push_str(" AND id = ?");
        binds.push(Bind::Int(v));
    }
    if let Some(v) = q.public_id.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        sql.push_str(" AND public_id = ?");
        binds.push(Bind::Str(v.to_string()));
    }
    if let Some(v) = q.external_id.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        sql.push_str(" AND external_id = ?");
        binds.push(Bind::Str(v.to_string()));
    }
    if let Some(v) = q.payment_address.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        sql.push_str(" AND payment_address = ?");
        binds.push(Bind::Str(v.to_string()));
    }
    let mut query = sqlx::query_scalar::<_, i64>(&sql);
    for b in &binds {
        query = match b {
            Bind::Str(s) => query.bind(s.clone()),
            Bind::Int(i) => query.bind(*i),
        };
    }
    Ok(query.fetch_all(&state.db.pool).await?)
}

fn occurred_millis(row: &Value) -> i64 {
    row["sourceTimestamps"]["occurredAt"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.timestamp_millis())
        .unwrap_or(0)
}

fn severity_rank(row: &Value) -> i64 {
    match row["severity"].as_str().unwrap_or("") {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// `GET /api/support/payments/exceptions`
pub async fn exceptions(
    _token: InternalToken,
    State(state): State<AppState>,
    Query(q): Query<ExceptionsQuery>,
) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).clamp(1, 100);

    let merchant_ids = resolve_exception_merchant_ids(&state, &q).await?;
    if merchant_ids.is_empty() {
        return Ok(Json(json!({ "meta": paginator_meta(0, per_page, page), "data": [] })));
    }

    let mut rows: Vec<Value> = Vec::new();
    for mid in merchant_ids {
        let email = merchant_email(&state, mid).await?;
        let mut excs = payment_exceptions::derive_user_exceptions(
            &state,
            mid,
            q.exc_type.as_deref(),
            q.severity.as_deref(),
            q.status.as_deref(),
        )
        .await?;
        for e in &mut excs {
            if let Value::Object(o) = e {
                o.insert("merchant".into(), json!({ "id": mid, "email": email }));
            }
        }
        rows.extend(excs);
    }

    // sortExceptions (replicates Adonis comparator formula)
    let direction: i64 = if q.direction.as_deref() == Some("asc") { 1 } else { -1 };
    let by_severity = q.sort.as_deref() == Some("severity");
    rows.sort_by(|l, r| {
        if by_severity {
            let diff = (severity_rank(l) - severity_rank(r)) * direction;
            if diff != 0 {
                return diff.cmp(&0);
            }
        }
        let occ = (occurred_millis(r) - occurred_millis(l)) * direction;
        occ.cmp(&0)
    });

    let total = rows.len() as i64;
    let start = ((page - 1) * per_page) as usize;
    let data: Vec<Value> = rows.into_iter().skip(start).take(per_page as usize).collect();
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}

/// `GET /api/support/payments/invoices/:id`
pub async fn invoice_detail(
    _token: InternalToken,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let inv = find_invoice(&state, &id).await?;
    Ok(Json(serialize_support_invoice(&state, &inv, true).await?))
}

/// `GET /api/support/payments/invoices/:id/timeline`
pub async fn invoice_timeline(
    _token: InternalToken,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let inv = find_invoice(&state, &id).await?;
    let events = payment_operations::timeline_events(&state, inv.id()).await?.unwrap_or_default();
    let masked: Vec<Value> = events.iter().map(mask_value).collect();
    Ok(Json(json!({ "data": masked })))
}

/// `GET /api/support/payments/webhook-deliveries/:id`
pub async fn get_webhook_delivery(
    _token: InternalToken,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    let d = sqlx::query_as::<_, (i64, i64, i64, String, i64, Option<i64>, Option<String>, Option<String>, bool, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>)>(
        "SELECT id, webhook_event_id, webhook_endpoint_id, status, attempt_count, response_status, \
         response_body, error, is_replay, last_attempted_at, next_attempt_at, delivered_at, created_at, updated_at \
         FROM webhook_deliveries WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.db.pool)
    .await?;
    let (did, event_id, endpoint_id, status, attempt_count, response_status, response_body, error, is_replay, last_attempted_at, next_attempt_at, delivered_at, created_at, updated_at) =
        d.ok_or_else(|| AppError::commerce(404, "Webhook delivery not found"))?;

    // event (required: 404 if absent)
    let event = sqlx::query_as::<_, (i64, i64, String, String, String, String, Option<String>, Option<String>)>(
        "SELECT id, user_id, event_type, resource_type, resource_id, payload, created_at, updated_at \
         FROM webhook_events WHERE id = ?",
    )
    .bind(event_id)
    .fetch_optional(&state.db.pool)
    .await?
    .ok_or_else(|| AppError::commerce(404, "Webhook delivery not found"))?;
    let (ev_id, ev_user, ev_type, ev_rtype, ev_rid, ev_payload, ev_created, ev_updated) = event;

    // endpoint (optional)
    let endpoint = sqlx::query_as::<_, (i64, i64, Option<i64>, String, String, bool, Option<String>, Option<String>, Option<String>, Option<String>)>(
        "SELECT id, user_id, store_id, url, events, is_active, paused_at, secret_rotated_at, created_at, updated_at \
         FROM webhook_endpoints WHERE id = ?",
    )
    .bind(endpoint_id)
    .fetch_optional(&state.db.pool)
    .await?;
    let endpoint_json = endpoint.map(|(eid, euser, estore, url, events, active, paused, rotated, ec, eu)| {
        json!({
            "id": eid, "userId": euser, "storeId": estore, "url": url,
            "events": serde_json::from_str::<Value>(&events).unwrap_or(json!([])),
            "isActive": active, "pausedAt": paused, "secretRotatedAt": rotated,
            "createdAt": ec, "updatedAt": eu, "signingSecret": "[redacted]",
        })
    });

    let body_len = response_body.as_ref().map(|s| s.len()).unwrap_or(0);
    let payload: Value = serde_json::from_str(&ev_payload).unwrap_or(json!({}));

    Ok(Json(json!({
        "id": did,
        "webhookEventId": event_id,
        "webhookEndpointId": endpoint_id,
        "status": status,
        "attemptCount": attempt_count,
        "responseStatus": response_status,
        "error": error,
        "isReplay": is_replay,
        "lastAttemptedAt": last_attempted_at,
        "nextAttemptAt": next_attempt_at,
        "deliveredAt": delivered_at,
        "createdAt": created_at,
        "updatedAt": updated_at,
        "endpoint": endpoint_json,
        "responseBody": Value::Null,
        "responseBodyLength": body_len,
        "responseBodyTruncated": body_len > 400,
        "responseBodyPreview": Value::Null,
        "merchantId": ev_user,
        "event": {
            "id": ev_id, "userId": ev_user, "eventType": ev_type, "resourceType": ev_rtype,
            "resourceId": ev_rid, "payload": mask_value(&payload), "createdAt": ev_created, "updatedAt": ev_updated,
        },
    })))
}

fn support_actor_id(headers: &HeaderMap) -> Option<String> {
    for h in ["x-support-actor-id", "x-support-operator-id", "x-operator-id"] {
        if let Some(v) = headers.get(h).and_then(|v| v.to_str().ok()).filter(|s| !s.is_empty()) {
            return Some(v.to_string());
        }
    }
    None
}

#[derive(Deserialize)]
pub struct NoteBody {
    note: Option<String>,
    metadata: Option<Value>,
}

/// `POST /api/support/payments/invoices/:id/notes`
pub async fn add_invoice_note(
    _token: InternalToken,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<NoteBody>,
) -> AppResult<Response> {
    let note = body.note.as_deref().map(str::trim).unwrap_or("");
    if note.is_empty() || note.len() > 2000 {
        return Err(AppError::Validation(vec![ValidationFailure {
            message: if note.is_empty() { "The note field must be defined".into() } else { "The note field must not exceed 2000 characters".into() },
            rule: if note.is_empty() { "required".into() } else { "maxLength".into() },
            field: "note".into(),
        }]));
    }
    let inv = find_invoice(&state, &id).await?;
    let user_id: i64 = sqlx::query_scalar("SELECT user_id FROM invoices WHERE id = ?")
        .bind(inv.id())
        .fetch_one(&state.db.pool)
        .await?;
    let actor_id = support_actor_id(&headers);
    let metadata = mask_value(&body.metadata.unwrap_or(json!({})));
    let now = now_iso();
    let new_id = sqlx::query(
        "INSERT INTO payment_support_notes (user_id, invoice_id, actor_type, actor_id, note, metadata, created_at, updated_at) \
         VALUES (?, ?, 'support', ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(inv.id())
    .bind(&actor_id)
    .bind(note)
    .bind(metadata.to_string())
    .bind(&now)
    .bind(&now)
    .execute(&state.db.pool)
    .await?
    .last_insert_rowid();

    let value = serialize_note(new_id, user_id, inv.id(), "support", actor_id.as_deref(), note, &metadata, &Some(now.clone()), &Some(now));
    Ok((StatusCode::CREATED, Json(value)).into_response())
}

/// `POST /api/support/payments/invoices/:id/evidence-packs/regenerate`
pub async fn regenerate_evidence_pack(
    _token: InternalToken,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let inv = find_invoice(&state, &id).await?;
    let user_id: i64 = sqlx::query_scalar("SELECT user_id FROM invoices WHERE id = ?")
        .bind(inv.id())
        .fetch_one(&state.db.pool)
        .await?;
    let now = now_iso();
    let new_id = sqlx::query(
        "INSERT INTO payment_evidence_packs \
         (user_id, invoice_id, status, checksum, generated_by_user_id, generated_at, created_at, updated_at) \
         VALUES (?, ?, 'queued', '', ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(inv.id())
    .bind(user_id)
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .execute(&state.db.pool)
    .await?
    .last_insert_rowid();

    Ok((StatusCode::ACCEPTED, Json(json!({
        "id": new_id,
        "userId": user_id,
        "invoiceId": inv.id(),
        "status": "queued",
        "checksum": "",
        "storageDisk": Value::Null,
        "storagePath": Value::Null,
        "byteSize": Value::Null,
        "generatedByUserId": user_id,
        "generatedAt": now.clone(),
        "expiresAt": Value::Null,
        "error": Value::Null,
        "createdAt": now.clone(),
        "updatedAt": now,
    }))).into_response())
}
