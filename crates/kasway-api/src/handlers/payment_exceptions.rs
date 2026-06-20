//! `/api/payments/ops/exceptions*` — PaymentOperationsExceptionsController.
//! index derives exceptions (invoice-backed: underpaid/overpaid + settlement
//! receipts) and filters out resolved ones; resolution read + resolve + dismiss
//! persist into payment_exception_resolutions. link-observation / ignore-observation
//! are deferred (they mutate observation rows whose extended columns aren't modeled yet).

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult};
use crate::handlers::invoices;
use crate::state::AppState;
use crate::util::now_iso;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize, Default)]
pub struct ExcQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
    #[serde(rename = "type")]
    exc_type: Option<String>,
    severity: Option<String>,
    status: Option<String>,
}

#[derive(sqlx::FromRow)]
struct InvRow {
    id: i64,
    public_id: String,
    external_id: Option<String>,
    status: String,
    payment_network: Option<String>,
    payment_asset: Option<String>,
    payment_address: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

fn exc_row(exc_type: &str, severity: &str, inv: &InvRow, summary: &Value) -> Value {
    let totals = &summary["totals"];
    let last_observed = summary["status"]["lastObservedAt"].clone();
    let occurred = if last_observed.is_string() { last_observed.clone() } else { json!(inv.updated_at) };
    json!({
        "id": format!("{exc_type}:invoice:{}", inv.id),
        "type": exc_type,
        "severity": severity,
        "invoice": { "id": inv.id, "publicId": inv.public_id, "externalId": inv.external_id, "status": inv.status },
        "amounts": {
            "invoice": totals["invoice"], "observed": totals["observed"], "credited": totals["credited"],
            "remaining": totals["remaining"], "overpaid": totals["overpaid"],
        },
        "sourceTimestamps": { "invoiceCreatedAt": inv.created_at, "lastObservedAt": last_observed, "occurredAt": occurred },
        "paymentState": summary["status"]["paymentState"],
        "network": inv.payment_network,
        "assetId": inv.payment_asset,
        "paymentAddress": inv.payment_address,
    })
}

/// Derive the active (non-resolved/dismissed) exception list for one merchant,
/// applying the type/severity/status filters. Shared by the merchant exceptions
/// index and the support cross-merchant exception listing.
/// Returns rows in invoice-created-desc order (callers re-sort as needed).
pub(crate) async fn derive_user_exceptions(
    state: &AppState,
    user_id: i64,
    exc_type: Option<&str>,
    severity: Option<&str>,
    status: Option<&str>,
) -> AppResult<Vec<Value>> {
    let invoices_rows = sqlx::query_as::<_, InvRow>(
        "SELECT id, public_id, external_id, status, payment_network, payment_asset, payment_address, created_at, updated_at \
         FROM invoices WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(&state.db.pool)
    .await?;

    let mut rows: Vec<Value> = Vec::new();
    for inv in &invoices_rows {
        let summary = invoices::derive_payment_status_by_id(state, inv.id).await?;
        match summary["status"]["paymentState"].as_str() {
            Some("underpaid") => rows.push(exc_row("underpaid", "medium", inv, &summary)),
            Some("overpaid") => rows.push(exc_row("overpaid", "medium", inv, &summary)),
            _ => {}
        }
    }

    // filter out resolved/dismissed
    let keys: Vec<String> = rows.iter().map(|r| r["id"].as_str().unwrap().to_string()).collect();
    let mut closed = std::collections::HashSet::new();
    if !keys.is_empty() {
        let placeholders = keys.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!("SELECT DISTINCT exception_key FROM payment_exception_resolutions WHERE user_id = ? AND status IN ('resolved','dismissed') AND exception_key IN ({placeholders})");
        let mut qx = sqlx::query_scalar::<_, String>(&sql).bind(user_id);
        for k in &keys { qx = qx.bind(k.clone()); }
        for k in qx.fetch_all(&state.db.pool).await? { closed.insert(k); }
    }
    let mut active: Vec<Value> = rows.into_iter().filter(|r| !closed.contains(r["id"].as_str().unwrap())).collect();

    // filters
    if let Some(t) = exc_type { active.retain(|r| r["type"] == json!(t)); }
    if let Some(s) = severity { active.retain(|r| r["severity"] == json!(s)); }
    if let Some(s) = status { active.retain(|r| r["invoice"]["status"] == json!(s)); }

    Ok(active)
}

/// `GET /api/payments/ops/exceptions`
pub async fn index(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<ExcQuery>) -> AppResult<Json<Value>> {
    let active = derive_user_exceptions(
        &state,
        auth.user_id,
        q.exc_type.as_deref(),
        q.severity.as_deref(),
        q.status.as_deref(),
    )
    .await?;

    // paginate (manual, matching Adonis derived paginator)
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).max(1);
    let total = active.len() as i64;
    let first = ((page - 1) * per_page) as usize;
    let data: Vec<Value> = active.into_iter().skip(first).take(per_page as usize).collect();
    let last_page = std::cmp::max((total as f64 / per_page as f64).ceil() as i64, 1);

    Ok(Json(json!({
        "meta": {
            "total": total, "perPage": per_page, "currentPage": page, "lastPage": last_page, "firstPage": 1,
            "firstPageUrl": "/?page=1", "lastPageUrl": format!("/?page={last_page}"),
            "nextPageUrl": if page < last_page { Value::String(format!("/?page={}", page + 1)) } else { Value::Null },
            "previousPageUrl": if page > 1 { Value::String(format!("/?page={}", page - 1)) } else { Value::Null },
        },
        "data": data,
    })))
}

#[derive(sqlx::FromRow)]
struct ResolutionRow {
    id: i64,
    user_id: i64,
    exception_type: String,
    exception_key: String,
    invoice_id: Option<i64>,
    payment_observation_id: Option<i64>,
    action: String,
    status: String,
    note: Option<String>,
    metadata: String,
    resolved_by_user_id: Option<i64>,
    resolved_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const RES_COLS: &str = "id, user_id, exception_type, exception_key, invoice_id, payment_observation_id, \
    action, status, note, metadata, resolved_by_user_id, resolved_at, created_at, updated_at";

fn serialize_resolution(r: &ResolutionRow) -> Value {
    json!({
        "id": r.id,
        "userId": r.user_id,
        "exceptionType": r.exception_type,
        "exceptionKey": r.exception_key,
        "invoiceId": r.invoice_id,
        "paymentObservationId": r.payment_observation_id,
        "action": r.action,
        "status": r.status,
        "note": r.note,
        "metadata": serde_json::from_str::<Value>(&r.metadata).unwrap_or(json!({})),
        "resolvedByUserId": r.resolved_by_user_id,
        "resolvedAt": r.resolved_at,
        "createdAt": r.created_at,
        "updatedAt": r.updated_at,
    })
}

fn invoice_id_from_key(key: &str) -> Option<i64> {
    let parts: Vec<&str> = key.split(':').collect();
    parts.iter().position(|p| *p == "invoice").and_then(|i| parts.get(i + 1)).and_then(|s| s.parse().ok())
}

/// `GET /api/payments/ops/exceptions/:id/resolution`
pub async fn resolution(auth: AuthMerchant, State(state): State<AppState>, Path(key): Path<String>) -> AppResult<Json<Value>> {
    let row: Option<ResolutionRow> = sqlx::query_as::<_, ResolutionRow>(&format!(
        "SELECT {RES_COLS} FROM payment_exception_resolutions WHERE user_id = ? AND exception_key = ? ORDER BY created_at DESC, id DESC LIMIT 1"
    ))
    .bind(auth.user_id).bind(&key).fetch_optional(&state.db.pool).await?;
    let row = row.ok_or_else(|| AppError::commerce(404, "Payment exception resolution not found"))?;
    Ok(Json(serialize_resolution(&row)))
}

async fn create_resolution(state: &AppState, user_id: i64, key: &str, action: &str, status: &str, body: &Value) -> AppResult<Json<Value>> {
    let note = body.get("note").and_then(|v| v.as_str());
    if status == "dismissed" && note.map(|s| s.trim().is_empty()).unwrap_or(true) {
        return Err(AppError::validation_field("note", "required", "The note field is required"));
    }
    let metadata = body.get("metadata").filter(|v| v.is_object()).cloned().unwrap_or(json!({}));
    let exc_type = key.split(':').next().unwrap_or("unknown");
    let invoice_id = invoice_id_from_key(key);
    let now = now_iso();
    let r = sqlx::query(
        "INSERT INTO payment_exception_resolutions (user_id, exception_type, exception_key, invoice_id, action, status, note, metadata, resolved_by_user_id, resolved_at, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id).bind(exc_type).bind(key).bind(invoice_id).bind(action).bind(status).bind(note).bind(metadata.to_string()).bind(user_id).bind(&now).bind(&now).bind(&now)
    .execute(&state.db.pool).await?;
    // notifications.emit -> deferred no-op
    let row = sqlx::query_as::<_, ResolutionRow>(&format!("SELECT {RES_COLS} FROM payment_exception_resolutions WHERE id = ?")).bind(r.last_insert_rowid()).fetch_one(&state.db.pool).await?;
    Ok(Json(serialize_resolution(&row)))
}

/// `POST /api/payments/ops/exceptions/:id/resolve`
pub async fn resolve(auth: AuthMerchant, State(state): State<AppState>, Path(key): Path<String>, Json(body): Json<Value>) -> AppResult<(StatusCode, Json<Value>)> {
    Ok((StatusCode::CREATED, create_resolution(&state, auth.user_id, &key, "mark_reviewed", "resolved", &body).await?))
}

/// `POST /api/payments/ops/exceptions/:id/dismiss`
pub async fn dismiss(auth: AuthMerchant, State(state): State<AppState>, Path(key): Path<String>, Json(body): Json<Value>) -> AppResult<(StatusCode, Json<Value>)> {
    Ok((StatusCode::CREATED, create_resolution(&state, auth.user_id, &key, "dismiss", "dismissed", &body).await?))
}

// ---- link / ignore observation (#154 / #155) -------------------------------

fn observation_id_from_key(key: &str) -> Option<i64> {
    let marker = ":observation:";
    let idx = key.find(marker)?;
    let rest = &key[idx + marker.len()..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

#[derive(sqlx::FromRow)]
struct ObsRow {
    id: i64,
    invoice_id: Option<i64>,
    status: String,
    network: Option<String>,
    asset_id: Option<String>,
    payment_address: Option<String>,
    metadata: Option<String>,
}

const OBS_COLS: &str = "id, invoice_id, status, network, asset_id, payment_address, metadata";

fn obs_kpr1_meta(o: &ObsRow) -> Value {
    let m: Value = o.metadata.as_deref().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(json!({}));
    match m.get("kpr1") { Some(k) if k.is_object() => k.clone(), _ => m }
}

async fn observation_for_merchant(state: &AppState, user_id: i64, id: i64) -> AppResult<ObsRow> {
    let obs = sqlx::query_as::<_, ObsRow>(&format!("SELECT {OBS_COLS} FROM payment_observations WHERE id = ?"))
        .bind(id).fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::commerce(404, "Payment observation not found"))?;
    // belongs-to-merchant: via invoice_id, kpr1 intentId, or payment route match
    let mut belongs = false;
    if let Some(inv_id) = obs.invoice_id {
        let found: Option<i64> = sqlx::query_scalar("SELECT id FROM invoices WHERE id = ? AND user_id = ?")
            .bind(inv_id).bind(user_id).fetch_optional(&state.db.pool).await?;
        belongs = found.is_some();
    }
    if !belongs {
        if let Some(intent_id) = obs_kpr1_meta(&obs)["intentId"].as_str() {
            let found: Option<i64> = sqlx::query_scalar("SELECT id FROM kpr1_payment_intents WHERE intent_id = ? AND user_id = ?")
                .bind(intent_id).bind(user_id).fetch_optional(&state.db.pool).await?;
            belongs = found.is_some();
        }
    }
    if !belongs {
        let found: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM invoices WHERE user_id = ? AND payment_address = ? AND payment_network = ? AND payment_asset = ?",
        ).bind(user_id).bind(&obs.payment_address).bind(&obs.network).bind(&obs.asset_id).fetch_optional(&state.db.pool).await?;
        belongs = found.is_some();
    }
    if !belongs {
        return Err(AppError::commerce(404, "Payment observation not found"));
    }
    Ok(obs)
}

async fn assert_exception_belongs(state: &AppState, user_id: i64, key: &str) -> AppResult<()> {
    let excs = derive_user_exceptions(state, user_id, None, None, None).await?;
    if excs.iter().any(|e| e["id"].as_str() == Some(key)) {
        Ok(())
    } else {
        Err(AppError::commerce(404, "Payment exception not found"))
    }
}

#[allow(clippy::too_many_arguments)]
async fn insert_resolution(state: &AppState, user_id: i64, key: &str, action: &str, status: &str, note: Option<&str>, metadata: &Value, invoice_id: Option<i64>, observation_id: Option<i64>) -> AppResult<Value> {
    let exc_type = key.split(':').next().unwrap_or("unknown");
    let now = now_iso();
    let r = sqlx::query(
        "INSERT INTO payment_exception_resolutions (user_id, exception_type, exception_key, invoice_id, payment_observation_id, action, status, note, metadata, resolved_by_user_id, resolved_at, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id).bind(exc_type).bind(key).bind(invoice_id).bind(observation_id).bind(action).bind(status)
    .bind(note).bind(metadata.to_string()).bind(user_id).bind(&now).bind(&now).bind(&now)
    .execute(&state.db.pool).await?;
    let row = sqlx::query_as::<_, ResolutionRow>(&format!("SELECT {RES_COLS} FROM payment_exception_resolutions WHERE id = ?"))
        .bind(r.last_insert_rowid()).fetch_one(&state.db.pool).await?;
    Ok(serialize_resolution(&row))
}

/// `POST /api/payments/ops/exceptions/:id/ignore-observation`
pub async fn ignore_observation(auth: AuthMerchant, State(state): State<AppState>, Path(key): Path<String>, Json(body): Json<Value>) -> AppResult<(StatusCode, Json<Value>)> {
    let obs_id = observation_id_from_key(&key)
        .ok_or_else(|| AppError::commerce(422, "Exception does not reference an observation"))?;
    let obs = observation_for_merchant(&state, auth.user_id, obs_id).await?;
    if !matches!(obs.status.as_str(), "pending" | "ignored") {
        return Err(AppError::commerce(422, "Only pending or ignored observations can be ignored"));
    }
    let mut meta: Value = obs.metadata.as_deref().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(json!({}));
    if let Value::Object(m) = &mut meta {
        m.insert("ignoredByResolution".into(), json!(true));
        m.insert("ignoredAt".into(), json!(now_iso()));
    }
    sqlx::query("UPDATE payment_observations SET status = 'ignored', metadata = ?, updated_at = ? WHERE id = ?")
        .bind(meta.to_string()).bind(now_iso()).bind(obs.id).execute(&state.db.pool).await?;
    let note = body.get("note").and_then(|v| v.as_str());
    let metadata = body.get("metadata").filter(|v| v.is_object()).cloned().unwrap_or(json!({}));
    let res = insert_resolution(&state, auth.user_id, &key, "ignore_observation", "resolved", note, &metadata, None, Some(obs.id)).await?;
    Ok((StatusCode::CREATED, Json(res)))
}

/// `POST /api/payments/ops/exceptions/:id/link-observation`
pub async fn link_observation(auth: AuthMerchant, State(state): State<AppState>, Path(key): Path<String>, Json(body): Json<Value>) -> AppResult<(StatusCode, Json<Value>)> {
    let invoice_id = body.get("invoiceId").and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::validation_field("invoiceId", "required", "The invoiceId field must be defined"))?;
    let obs_id = body.get("paymentObservationId").and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::validation_field("paymentObservationId", "required", "The paymentObservationId field must be defined"))?;

    assert_exception_belongs(&state, auth.user_id, &key).await?;

    let invoice = sqlx::query_as::<_, (i64, String, Option<String>, Option<String>)>(
        "SELECT id, payment_address, payment_network, payment_asset FROM invoices WHERE user_id = ? AND id = ?",
    ).bind(auth.user_id).bind(invoice_id).fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::commerce(404, "Invoice not found"))?;
    let (inv_id, inv_addr, inv_net, inv_asset) = invoice;
    let obs = observation_for_merchant(&state, auth.user_id, obs_id).await?;

    if let Some(linked) = obs.invoice_id { if linked != inv_id {
        return Err(AppError::commerce(422, "Observation is already linked to another invoice"));
    }}
    if obs.network != inv_net || obs.asset_id != inv_asset {
        return Err(AppError::commerce(422, "Observation does not match the invoice payment route"));
    }
    if !inv_addr.starts_with("kpr1:") {
        return Err(AppError::commerce(422, "Only KPR-1 covenant invoices can be linked to observations"));
    }
    if let Some(oaddr) = &obs.payment_address {
        if oaddr.starts_with("kpr1:") && *oaddr != inv_addr {
            return Err(AppError::commerce(422, "Observation does not match the invoice payment route"));
        }
    }
    let intent = sqlx::query_as::<_, (String, String)>(
        "SELECT intent_id, script_hash FROM kpr1_payment_intents WHERE invoice_id = ? AND user_id = ?",
    ).bind(inv_id).bind(auth.user_id).fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::commerce(422, "KPR-1 payment intent is required before linking observations"))?;
    let (intent_id, script_hash) = intent;
    let km = obs_kpr1_meta(&obs);
    if let Some(oid) = km["intentId"].as_str() { if oid != intent_id {
        return Err(AppError::commerce(422, "Observation does not match the invoice payment route"));
    }}
    if let Some(osh) = km["scriptHash"].as_str() { if osh != script_hash {
        return Err(AppError::commerce(422, "Observation does not match the invoice payment route"));
    }}

    let mut meta: Value = obs.metadata.as_deref().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(json!({}));
    if let Value::Object(m) = &mut meta {
        m.insert("linkedByResolution".into(), json!(true));
        m.insert("linkedAt".into(), json!(now_iso()));
    }
    let now = now_iso();
    // matchedAt = existing ?? now
    sqlx::query("UPDATE payment_observations SET invoice_id = ?, status = 'matched', matched_at = COALESCE(matched_at, ?), metadata = ?, updated_at = ? WHERE id = ?")
        .bind(inv_id).bind(&now).bind(meta.to_string()).bind(&now).bind(obs.id).execute(&state.db.pool).await?;
    // settleObservationById — settlement is derive-on-read in the port (no-op here)

    let note = body.get("note").and_then(|v| v.as_str());
    let metadata = body.get("metadata").filter(|v| v.is_object()).cloned().unwrap_or(json!({}));
    let res = insert_resolution(&state, auth.user_id, &key, "link_observation", "resolved", note, &metadata, Some(inv_id), Some(obs.id)).await?;
    Ok((StatusCode::CREATED, Json(res)))
}
