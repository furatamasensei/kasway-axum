//! `/api/checkout/invoices/*` — CheckoutInvoicesController (public, no auth).
//! show / kpr1Intent / submitKpr1Payment. The wallet submission persists the
//! intent (status→submitted) from a txId; the optional signed-transaction relay
//! and chain observation need the Kaspa node/WASM (no gateway in the port → relay
//! fails, observation is none — faithful to a node-less deployment).

use crate::error::{AppError, AppResult};
use crate::handlers::{invoices, payment_links};
use crate::state::AppState;
use crate::store_context::assert_can_create_new_payments;
use crate::util::now_iso;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

fn kpr1_err(code: &str, message: &str, metadata: Option<Value>) -> Response {
    let mut body = json!({ "message": message, "code": code });
    if let Some(Value::Object(m)) = metadata {
        for (k, v) in m { body[k] = v; }
    }
    (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
}

/// `POST /api/checkout/invoices/:publicId/kpr1-payments`
pub async fn submit_kpr1_payment(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Response> {
    let invoice = sqlx::query_as::<_, (i64, Option<i64>, String)>(
        "SELECT id, store_id, status FROM invoices WHERE public_id = ?",
    ).bind(&public_id).fetch_optional(&state.db.pool).await?;
    let Some((inv_id, store_id, inv_status)) = invoice else {
        return Ok(kpr1_err("KPR1_INTENT_NOT_FOUND", "KPR-1 payment intent not found", None));
    };
    let intent = sqlx::query_as::<_, (i64, String, Option<String>, Option<String>, Option<String>)>(
        "SELECT id, status, tx_id, expires_at, metadata FROM kpr1_payment_intents WHERE invoice_id = ?",
    ).bind(inv_id).fetch_optional(&state.db.pool).await?;
    let Some((intent_id, status, current_tx, expires_at, metadata)) = intent else {
        return Ok(kpr1_err("KPR1_INTENT_NOT_FOUND", "KPR-1 payment intent not found", None));
    };

    if inv_status != "open" {
        return Ok(kpr1_err("KPR1_INVOICE_NOT_OPEN", "KPR-1 payments can only be submitted for open invoices", None));
    }
    if let Some(sid) = store_id {
        if assert_can_create_new_payments(&state, sid).await.is_err() {
            return Ok(kpr1_err("KPR1_STORE_ENTITLEMENT_REQUIRED", "KPR-1 payments require an active store entitlement", None));
        }
    }
    if let Some(exp) = expires_at.as_deref().and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()) {
        if exp.with_timezone(&chrono::Utc) <= chrono::Utc::now() {
            sqlx::query("UPDATE kpr1_payment_intents SET status = 'expired' WHERE id = ?").bind(intent_id).execute(&state.db.pool).await?;
            return Ok(kpr1_err("KPR1_INTENT_EXPIRED", "KPR-1 payment intent has expired", None));
        }
    }
    if !matches!(status.as_str(), "created" | "fetched" | "submitted") {
        return Ok(kpr1_err("KPR1_INTENT_NOT_ACCEPTING_PAYMENTS",
            &format!("KPR-1 payment intent is not accepting wallet submissions in status {status}"),
            Some(json!({ "status": status }))));
    }

    let expected_tx_id = body.get("txId").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let has_signed = body.get("signedTransaction").map(|v| !v.is_null()).unwrap_or(false);
    if expected_tx_id.is_none() && !has_signed {
        return Ok(kpr1_err("KPR1_PAYMENT_PROOF_REQUIRED", "KPR-1 wallet submission requires either a tx id or a signed transaction payload", None));
    }
    if let Some(cur) = &current_tx {
        if has_signed || expected_tx_id.as_ref().map(|t| t != cur).unwrap_or(false) {
            return Ok(kpr1_err("KPR1_TX_ID_ALREADY_SUBMITTED", "KPR-1 payment intent already has a submitted tx id", Some(json!({ "currentTxId": cur }))));
        }
    }
    if has_signed {
        return Ok(kpr1_err("KPR1_SIGNED_TRANSACTION_RELAY_FAILED", "KPR-1 signed transaction could not be relayed",
            Some(json!({ "reason": "Kaspa node relay gateway is not configured" }))));
    }
    let Some(tx_id) = expected_tx_id else {
        return Ok(kpr1_err("KPR1_TX_ID_REQUIRED", "KPR-1 wallet tx id is required", None));
    };

    let mut meta: Value = metadata.as_deref().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(json!({}));
    if let Value::Object(m) = &mut meta {
        m.insert("walletSubmission".into(), body.get("metadata").cloned().unwrap_or(json!({})));
    }
    let now = now_iso();
    sqlx::query("UPDATE kpr1_payment_intents SET status = 'submitted', tx_id = ?, submitted_at = COALESCE(submitted_at, ?), metadata = ?, updated_at = ? WHERE id = ?")
        .bind(&tx_id).bind(&now).bind(meta.to_string()).bind(&now).bind(intent_id)
        .execute(&state.db.pool).await?;

    let (_i, updated) = invoices::load_relations(&state, inv_id).await?;
    let updated = updated.ok_or_else(|| AppError::commerce(500, "intent vanished"))?;
    let mut out = invoices::serialize_intent(&updated);
    out["settlement"] = json!({
        "relayed": false, "observed": false, "observationId": Value::Null,
        "settled": false, "invoiceStatus": inv_status, "intentStatus": "submitted",
    });
    Ok((StatusCode::OK, Json(out)).into_response())
}

/// `GET /api/checkout/invoices/:publicId`
pub async fn show(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
) -> AppResult<Json<Value>> {
    let mut inv = invoices::load_by_public_id(&state, &public_id).await?;
    invoices::expire_if_needed(&state, &mut inv).await?;
    let (items, intent) = invoices::load_relations(&state, inv.id()).await?;

    let summary = invoices::derive_payment_status(&state, &inv).await?;
    let checkout_state = invoices::checkout_state(&summary);

    let mut contract = invoices::serialize_kpr1_contract(&inv, &items, intent.as_ref());
    if let Value::Object(map) = &mut contract {
        map.insert("paymentStatus".into(), summary);
        map.insert("checkoutState".into(), checkout_state);
    }
    Ok(Json(contract))
}

/// `GET /api/checkout/invoices/:publicId/kpr1-intent`
pub async fn kpr1_intent(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
) -> AppResult<Json<Value>> {
    let canonical_intent = invoices::fetch_kpr1_intent(&state, &public_id).await?;
    Ok(Json(canonical_intent))
}

/// `GET /api/checkout/links/:publicId` — public link landing summary.
pub async fn link_show(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
) -> AppResult<Json<Value>> {
    Ok(Json(payment_links::public_summary(&state, &public_id).await?))
}

/// `POST /api/checkout/links/:publicId/invoices` — spawn a fresh invoice.
pub async fn link_create_invoice(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
) -> AppResult<Json<Value>> {
    let (invoice_id, _store_id) = payment_links::spawn_invoice_for_checkout(&state, &public_id).await?;
    let inv = invoices::load_by_id(&state, invoice_id).await?;
    let (items, intent) = invoices::load_relations(&state, inv.id()).await?;
    Ok(Json(invoices::serialize_kpr1_contract(&inv, &items, intent.as_ref())))
}
