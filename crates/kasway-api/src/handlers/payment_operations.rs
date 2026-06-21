//! `/api/payments/ops/{invoices,invoices/:id,observations,credits}`
//! — PaymentOperationsController. Read surface over the payment ledger.
//! `timeline` (PaymentTimelineService) is ported separately.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult};
use crate::handlers::invoices;
use crate::state::AppState;
use crate::util::paginator_meta;
use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize, Default)]
pub struct OpsQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
    status: Option<String>,
    network: Option<String>,
    #[serde(rename = "assetId")]
    asset_id: Option<String>,
    #[serde(rename = "invoiceId")]
    invoice_id: Option<i64>,
    #[serde(rename = "publicId")]
    public_id: Option<String>,
    #[serde(rename = "externalId")]
    external_id: Option<String>,
    #[serde(rename = "storeId")]
    store_id: Option<i64>,
}

/// `GET /api/payments/ops/invoices`
pub async fn invoices_index(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Query(q): Query<OpsQuery>,
) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).max(1);

    let mut n = 1;
    let mut filter = format!("user_id = ${n}"); n += 1;
    if q.status.is_some() { filter.push_str(&format!(" AND status = ${n}")); n += 1; }
    if q.network.is_some() { filter.push_str(&format!(" AND payment_network = ${n}")); n += 1; }
    if q.asset_id.is_some() { filter.push_str(&format!(" AND payment_asset = ${n}")); n += 1; }
    if q.invoice_id.is_some() { filter.push_str(&format!(" AND id = ${n}")); n += 1; }
    if q.public_id.is_some() { filter.push_str(&format!(" AND public_id = ${n}")); n += 1; }
    if q.external_id.is_some() { filter.push_str(&format!(" AND external_id = ${n}")); n += 1; }
    if q.store_id.is_some() { filter.push_str(&format!(" AND store_id = ${n}")); n += 1; }
    let _ = n;

    let count_sql = format!("SELECT COUNT(*) FROM invoices WHERE {filter}");
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql).bind(auth.user_id);
    if let Some(v) = &q.status { cq = cq.bind(v.clone()); }
    if let Some(v) = &q.network { cq = cq.bind(v.clone()); }
    if let Some(v) = &q.asset_id { cq = cq.bind(v.clone()); }
    if let Some(v) = q.invoice_id { cq = cq.bind(v); }
    if let Some(v) = &q.public_id { cq = cq.bind(v.clone()); }
    if let Some(v) = &q.external_id { cq = cq.bind(v.clone()); }
    if let Some(v) = q.store_id { cq = cq.bind(v); }
    let total: i64 = cq.fetch_one(&state.db.pool).await?;

    let id_sql = format!("SELECT id FROM invoices WHERE {filter} ORDER BY created_at DESC LIMIT {per_page} OFFSET {}", (page - 1) * per_page);
    let mut iq = sqlx::query_scalar::<_, i64>(&id_sql).bind(auth.user_id);
    if let Some(v) = &q.status { iq = iq.bind(v.clone()); }
    if let Some(v) = &q.network { iq = iq.bind(v.clone()); }
    if let Some(v) = &q.asset_id { iq = iq.bind(v.clone()); }
    if let Some(v) = q.invoice_id { iq = iq.bind(v); }
    if let Some(v) = &q.public_id { iq = iq.bind(v.clone()); }
    if let Some(v) = &q.external_id { iq = iq.bind(v.clone()); }
    if let Some(v) = q.store_id { iq = iq.bind(v); }
    let ids: Vec<i64> = iq.fetch_all(&state.db.pool).await?;

    let mut data = Vec::with_capacity(ids.len());
    for id in ids {
        let inv = invoices::load_by_id(&state, id).await?;
        let (items, intent) = invoices::load_relations(&state, inv.id()).await?;
        let mut v = invoices::serialize_invoice(&inv, &items, intent.as_ref());
        let status = invoices::derive_payment_status(&state, &inv).await?;
        if let Value::Object(m) = &mut v { m.insert("paymentStatus".into(), status); }
        data.push(v);
    }
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}

/// `GET /api/payments/ops/invoices/:id`
pub async fn invoice_detail(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    let invoice_id: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM invoices WHERE user_id = $1 AND (CAST(id AS TEXT) = $2 OR public_id = $3)",
    )
    .bind(auth.user_id).bind(&id).bind(&id)
    .fetch_optional(&state.db.pool).await?;
    let invoice_id = invoice_id.ok_or_else(|| AppError::commerce(404, "Invoice not found"))?;

    let inv = invoices::load_by_id(&state, invoice_id).await?;
    let (items, intent) = invoices::load_relations(&state, inv.id()).await?;
    let mut v = invoices::serialize_invoice(&inv, &items, intent.as_ref());
    let status = invoices::derive_payment_status(&state, &inv).await?;

    // adjustmentSummary
    let rows = sqlx::query_as::<_, (String, i64)>("SELECT direction, amount FROM payment_adjustments WHERE invoice_id = $1")
        .bind(invoice_id).fetch_all(&state.db.pool).await?;
    let (mut credit, mut debit) = (0i128, 0i128);
    for (dir, amt) in &rows {
        if dir == "credit" { credit += *amt as i128; } else { debit += *amt as i128; }
    }
    let adjustment_summary = json!({
        "count": rows.len(),
        "credit": credit.to_string(),
        "debit": debit.to_string(),
        "net": (credit - debit).to_string(),
    });

    if let Value::Object(m) = &mut v {
        m.insert("paymentStatus".into(), status);
        m.insert("adjustmentSummary".into(), adjustment_summary);
    }
    Ok(Json(v))
}

#[derive(sqlx::FromRow)]
struct TlInvoice {
    id: i64,
    public_id: String,
    external_id: Option<String>,
    status: String,
    currency: String,
    total_amount: i64,
    metadata: Option<String>,
    created_at: Option<String>,
    paid_at: Option<String>,
    expires_at: Option<String>,
    cancelled_at: Option<String>,
}

/// `GET /api/payments/ops/invoices/:id/timeline`
pub async fn timeline(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    // user-scoped existence check (404), then build the shared event list
    let inv_id: i64 = sqlx::query_scalar(
        "SELECT id FROM invoices WHERE user_id = $1 AND (CAST(id AS TEXT) = $2 OR public_id = $3)",
    )
    .bind(auth.user_id).bind(&id).bind(&id)
    .fetch_optional(&state.db.pool).await?
    .ok_or_else(|| AppError::commerce(404, "Invoice not found"))?;
    let data = timeline_events(&state, inv_id).await?.unwrap_or_default();
    Ok(Json(json!({ "data": data })))
}

/// Build the timeline event list for an invoice by id (no ownership scope).
/// Returns `None` when the invoice does not exist. Shared by the merchant and
/// support timeline endpoints (PaymentTimelineService.getInvoiceTimeline*).
pub(crate) async fn timeline_events(state: &AppState, invoice_id: i64) -> AppResult<Option<Vec<Value>>> {
    let inv: Option<TlInvoice> = sqlx::query_as::<_, TlInvoice>(
        "SELECT id, public_id, external_id, status, currency, total_amount, metadata, created_at, \
         paid_at, expires_at, cancelled_at FROM invoices WHERE id = $1",
    )
    .bind(invoice_id)
    .fetch_optional(&state.db.pool).await?;
    let inv = match inv { Some(i) => i, None => return Ok(None) };

    let inv_ref = json!({ "id": inv.id, "publicId": inv.public_id, "externalId": inv.external_id, "status": inv.status });
    let meta = match &inv.metadata { Some(s) => serde_json::from_str(s).unwrap_or(json!({})), None => json!({}) };
    let amount = inv.total_amount.to_string();
    // (occurredAt, priority, sortId, value)
    let mut entries: Vec<(String, i64, i64, Value)> = Vec::new();
    let mut push = |entries: &mut Vec<(String, i64, i64, Value)>, occurred: &str, prio: i64, sort_id: i64, v: Value| {
        entries.push((occurred.to_string(), prio, sort_id, v));
    };

    let created = inv.created_at.clone().unwrap_or_default();
    push(&mut entries, &created, 10, inv.id, json!({
        "id": format!("invoice:{}:created", inv.id), "type": "invoice.created", "source": "invoice",
        "occurredAt": inv.created_at, "invoice": inv_ref, "summary": "Invoice created", "amount": amount, "currency": inv.currency, "metadata": meta,
    }));
    if let Some(p) = &inv.paid_at {
        push(&mut entries, p, 10, inv.id, json!({ "id": format!("invoice:{}:paid", inv.id), "type": "invoice.paid", "source": "invoice", "occurredAt": p, "invoice": inv_ref, "summary": "Invoice paid", "amount": amount, "currency": inv.currency, "metadata": meta }));
    }
    if inv.status == "expired" {
        if let Some(e) = &inv.expires_at {
            push(&mut entries, e, 10, inv.id, json!({ "id": format!("invoice:{}:expired", inv.id), "type": "invoice.expired", "source": "invoice", "occurredAt": e, "invoice": inv_ref, "summary": "Invoice expired", "amount": amount, "currency": inv.currency, "metadata": meta }));
        }
    }
    if let Some(c) = &inv.cancelled_at {
        push(&mut entries, c, 10, inv.id, json!({ "id": format!("invoice:{}:cancelled", inv.id), "type": "invoice.cancelled", "source": "invoice", "occurredAt": c, "invoice": inv_ref, "summary": "Invoice cancelled", "amount": amount, "currency": inv.currency, "metadata": meta }));
    }

    // adjustments (full table available)
    let adjustments = sqlx::query_as::<_, (i64, String, String, i64, String, Option<String>, String, Option<String>)>(
        "SELECT id, kind, direction, amount, currency, external_reference, reason, created_at FROM payment_adjustments WHERE invoice_id = $1 ORDER BY id ASC",
    ).bind(inv.id).fetch_all(&state.db.pool).await?;
    for (aid, kind, direction, amt, currency, ext, reason, c) in adjustments {
        let occurred = c.clone().unwrap_or_default();
        push(&mut entries, &occurred, 45, aid, json!({
            "id": format!("payment_adjustment:{aid}:created"), "type": format!("payment_adjustment.{kind}"), "source": "payment_adjustment",
            "occurredAt": c, "invoice": inv_ref, "summary": format!("Payment adjustment {kind}"), "amount": amt.to_string(), "currency": currency, "metadata": {},
            "adjustment": { "id": aid, "kind": kind, "direction": direction, "externalReference": ext, "reason": reason },
        }));
    }

    // credits (minimal table)
    let credits = sqlx::query_as::<_, (i64, i64, Option<String>)>("SELECT id, amount, created_at FROM payment_credits WHERE invoice_id = $1 ORDER BY id ASC").bind(inv.id).fetch_all(&state.db.pool).await?;
    for (cid, amt, c) in credits {
        let occurred = c.clone().unwrap_or_default();
        push(&mut entries, &occurred, 40, cid, json!({
            "id": format!("payment_credit:{cid}:credited"), "type": "payment_credit.credited", "source": "payment_credit",
            "occurredAt": c, "invoice": inv_ref, "summary": "Payment credit applied", "amount": amt.to_string(), "metadata": {}, "credit": { "id": cid },
        }));
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    Ok(Some(entries.into_iter().map(|(_, _, _, v)| v).collect()))
}

/// `GET /api/payments/ops/observations`
pub async fn observations(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Query(q): Query<OpsQuery>,
) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).max(1);
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_observations po JOIN invoices i ON i.id = po.invoice_id WHERE i.user_id = $1",
    ).bind(auth.user_id).fetch_one(&state.db.pool).await?;
    let rows = sqlx::query_as::<_, (i64, Option<i64>, String, i64, i64, Option<String>)>(
        "SELECT po.id, po.invoice_id, po.status, po.amount, po.confirmations, po.created_at \
         FROM payment_observations po JOIN invoices i ON i.id = po.invoice_id WHERE i.user_id = $1 \
         ORDER BY po.id DESC LIMIT $2 OFFSET $3",
    ).bind(auth.user_id).bind(per_page).bind((page - 1) * per_page).fetch_all(&state.db.pool).await?;
    let data: Vec<Value> = rows.into_iter().map(|(id, inv, status, amount, conf, created)| json!({
        "id": id, "invoiceId": inv, "status": status, "amount": amount.to_string(), "confirmations": conf, "createdAt": created,
    })).collect();
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}

/// `GET /api/payments/ops/credits`
pub async fn credits(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Query(q): Query<OpsQuery>,
) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).max(1);
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_credits pc JOIN invoices i ON i.id = pc.invoice_id WHERE i.user_id = $1",
    ).bind(auth.user_id).fetch_one(&state.db.pool).await?;
    let rows = sqlx::query_as::<_, (i64, Option<i64>, i64, Option<String>)>(
        "SELECT pc.id, pc.invoice_id, pc.amount, pc.created_at FROM payment_credits pc \
         JOIN invoices i ON i.id = pc.invoice_id WHERE i.user_id = $1 ORDER BY pc.id DESC LIMIT $2 OFFSET $3",
    ).bind(auth.user_id).bind(per_page).bind((page - 1) * per_page).fetch_all(&state.db.pool).await?;
    let data: Vec<Value> = rows.into_iter().map(|(id, inv, amount, created)| json!({
        "id": id, "invoiceId": inv, "amount": amount.to_string(), "createdAt": created,
    })).collect();
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}
