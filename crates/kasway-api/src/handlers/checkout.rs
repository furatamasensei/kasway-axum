//! `/api/checkout/invoices/*` — CheckoutInvoicesController (public, no auth).
//! show / kpr1Intent / submitKpr1Payment. The wallet submission persists the
//! intent (status→submitted) from a txId; the optional signed-transaction relay
//! and chain observation need the Kaspa node/WASM (no gateway in the port → relay
//! fails, observation is none — faithful to a node-less deployment).

use crate::error::{AppError, AppResult};
use crate::handlers::{invoices, payment_links};
use crate::state::AppState;
use crate::store_context::assert_can_create_new_payments;
use crate::util::to_iso;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

/// `body[key]` as a trimmed, non-empty string.
pub(crate) fn body_str<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    body.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn kpr1_err(code: &str, message: &str, metadata: Option<Value>) -> Response {
    let mut body = json!({ "message": message, "code": code });
    if let Some(Value::Object(m)) = metadata {
        for (k, v) in m { body[k] = v; }
    }
    // Every KPR-1 refusal passes through here, so one line here covers them all.
    // The access log only shows "422" — useless when a user reports "my payment
    // failed"; the machine code is the thing that says WHY.
    tracing::warn!("kpr1 refused: {code} — {message}");
    (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
}

/// `POST /api/checkout/invoices/:publicId/kpr1-payments`
pub async fn submit_kpr1_payment(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Response> {
    // The request-arrival timestamp is the payment deadline authority. Database
    // work or scheduler order after this point must not invalidate a timely tx.
    let received_at = chrono::Utc::now();
    let received_at_iso = to_iso(received_at);
    let invoice = sqlx::query_as::<_, (i64, Option<i64>, String)>(
        "SELECT id, store_id, status FROM invoices WHERE public_id = $1",
    ).bind(&public_id).fetch_optional(&state.db.pool).await?;
    let Some((inv_id, store_id, inv_status)) = invoice else {
        return Ok(kpr1_err("KPR1_INTENT_NOT_FOUND", "KPR-1 payment intent not found", None));
    };
    let intent = sqlx::query_as::<_, (i64, String, Option<String>, Option<String>, Option<String>)>(
        "SELECT id, status, tx_id, expires_at, metadata FROM kpr1_payment_intents WHERE invoice_id = $1",
    ).bind(inv_id).fetch_optional(&state.db.pool).await?;
    let Some((intent_id, status, current_tx, expires_at, metadata)) = intent else {
        return Ok(kpr1_err("KPR1_INTENT_NOT_FOUND", "KPR-1 payment intent not found", None));
    };

    let arrived_in_time = expires_at
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|deadline| received_at <= deadline)
        .unwrap_or(true);
    if inv_status != "open" && !(inv_status == "expired" && arrived_in_time) {
        return Ok(kpr1_err("KPR1_INVOICE_NOT_OPEN", "KPR-1 payments can only be submitted for open invoices", None));
    }
    if let Some(sid) = store_id {
        if assert_can_create_new_payments(&state, sid).await.is_err() {
            return Ok(kpr1_err("KPR1_STORE_ENTITLEMENT_REQUIRED", "KPR-1 payments require an active store entitlement", None));
        }
    }
    if !arrived_in_time {
        let _ = invoices::expire_invoice(&state, inv_id).await?;
        return Ok(kpr1_err("KPR1_INTENT_EXPIRED", "KPR-1 payment intent has expired", None));
    }
    if !matches!(status.as_str(), "created" | "fetched" | "submitted")
        && !(status == "expired" && arrived_in_time) {
        return Ok(kpr1_err("KPR1_INTENT_NOT_ACCEPTING_PAYMENTS",
            &format!("KPR-1 payment intent is not accepting wallet submissions in status {status}"),
            Some(json!({ "status": status }))));
    }

    let expected_tx_id = body_str(&body, "txId").map(str::to_string);
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
    let now = received_at_iso;
    // Atomic claim of the tx id: only write when it is still unset (or already the
    // same tx — idempotent re-submit) and the intent is still accepting payments.
    // This closes the race where two concurrent submissions both pass the earlier
    // SELECT-then-check and clobber each other.
    let res = sqlx::query(
        "UPDATE kpr1_payment_intents SET status = 'submitted', tx_id = $1, submitted_at = COALESCE(submitted_at, $2), metadata = $3, updated_at = $4 \
         WHERE id = $5 AND (status IN ('created', 'fetched', 'submitted') \
         OR (status = 'expired' AND expires_at IS NOT NULL AND $2 <= expires_at)) \
         AND (tx_id IS NULL OR tx_id = $1)")
        .bind(&tx_id).bind(&now).bind(meta.to_string()).bind(&now).bind(intent_id)
        .execute(&state.db.pool).await?;
    if res.rows_affected() == 0 {
        // A concurrent submission already claimed a different tx id (or the intent
        // left the accepting states). Report the tx id now on record.
        let existing: Option<String> = sqlx::query_scalar("SELECT tx_id FROM kpr1_payment_intents WHERE id = $1")
            .bind(intent_id).fetch_optional(&state.db.pool).await?.flatten();
        return Ok(kpr1_err(
            "KPR1_TX_ID_ALREADY_SUBMITTED",
            "KPR-1 payment intent already has a submitted tx id",
            existing.map(|cur| json!({ "currentTxId": cur })),
        ));
    }

    // If the expiry worker crossed this request, restore the payable state. The
    // intent timestamp above remains the auditable proof it arrived on time.
    sqlx::query("UPDATE invoices SET status = 'open', updated_at = $1 WHERE id = $2 AND status = 'expired' AND expires_at >= $1")
        .bind(&now).bind(inv_id).execute(&state.db.pool).await?;
    sqlx::query("UPDATE subscription_cycles SET status = 'invoiced', past_due_at = NULL, updated_at = $1 WHERE invoice_id = $2 AND status = 'past_due'")
        .bind(&now).bind(inv_id).execute(&state.db.pool).await?;

    let (_i, updated) = invoices::load_relations(&state, inv_id).await?;
    let updated = updated.ok_or_else(|| AppError::commerce(500, "intent vanished"))?;
    let mut out = invoices::serialize_intent(&updated);
    out["settlement"] = json!({
        "relayed": false, "observed": false, "observationId": Value::Null,
        "settled": false, "invoiceStatus": "open", "intentStatus": "submitted",
    });
    Ok((StatusCode::OK, Json(out)).into_response())
}

/// `POST /api/checkout/invoices/:publicId/kpr1-finalize`
///
/// The payer supplies their refund address; we derive and persist the covenant
/// P2SH address the payer must fund. Covenant is the only settlement path.
pub async fn finalize_kpr1_covenant(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Response> {
    let Some(refund_address) = body_str(&body, "refundAddress") else {
        return Ok(kpr1_err(
            "KPR1_REFUND_ADDRESS_REQUIRED",
            "A customer refund address is required to finalize the covenant",
            None,
        ));
    };
    let out = crate::kpr1::finalize_covenant_for_invoice(&state, &public_id, refund_address).await?;
    Ok((StatusCode::OK, Json(out)).into_response())
}

/// `POST /api/checkout/invoices/:publicId/kpr1-release/prepare`
///
/// Step 1 of customer-confirmed release: returns the covenant sighash the
/// customer signs (with their refund key) to authorize paying the merchant.
pub async fn prepare_kpr1_release(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
) -> AppResult<Json<Value>> {
    let out = crate::covenant_keeper::customer_release_prepare(&state, &public_id).await?;
    Ok(Json(out))
}

/// `POST /api/checkout/invoices/:publicId/kpr1-release`
///
/// Step 2: the customer submits their signature; the server attaches it,
/// broadcasts the release, and marks the invoice paid.
pub async fn submit_kpr1_release(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Response> {
    let Some(signature) = body_str(&body, "signature") else {
        return Ok(kpr1_err(
            "KPR1_RELEASE_SIGNATURE_REQUIRED",
            "A customer signature is required to release funds to the merchant",
            None,
        ));
    };
    let out = crate::covenant_keeper::customer_release_submit(&state, &public_id, signature).await?;
    Ok((StatusCode::OK, Json(out)).into_response())
}

/// `POST /api/checkout/invoices/:publicId/kpr1-refund/prepare`
///
/// Merchant-initiated refund, step 1. The merchant refunds the customer the full
/// gross; they authorize the covenant spend AND pay the gas, so this returns BOTH
/// sighashes for the merchant to sign. The customer can never trigger this — only
/// a valid merchant signature spends the covenant on the refund branch.
pub async fn prepare_kpr1_refund(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
) -> AppResult<Json<Value>> {
    let out = crate::covenant_keeper::merchant_refund_prepare(&state, &public_id).await?;
    Ok(Json(out))
}

/// `POST /api/checkout/invoices/:publicId/kpr1-refund`
///
/// Merchant-initiated refund, step 2. Body: `{ covenantSignature, feeSignature }`
/// (both signed by the merchant key). The server attaches them, broadcasts, and
/// marks the invoice refunded.
pub async fn submit_kpr1_refund(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Response> {
    let covenant_sig = body_str(&body, "covenantSignature");
    let fee_sig = body_str(&body, "feeSignature");
    let (Some(covenant_sig), Some(fee_sig)) = (covenant_sig, fee_sig) else {
        return Ok(kpr1_err(
            "KPR1_REFUND_SIGNATURES_REQUIRED",
            "A merchant covenant signature and fee signature are both required to refund",
            None,
        ));
    };
    let out = crate::covenant_keeper::merchant_refund_submit(&state, &public_id, covenant_sig, fee_sig).await?;
    Ok((StatusCode::OK, Json(out)).into_response())
}

/// Parse `{ split: [{address, amount}], feePayer }` shared by the settle endpoints.
fn parse_settle_body(body: &Value) -> Result<(Vec<(String, u64)>, crate::covenant_keeper::FeePayer), Response> {
    let split = body.get("split").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|o| {
                let addr = o.get("address").and_then(|v| v.as_str())?.trim().to_string();
                let amount = o.get("amount").and_then(|v| v.as_u64())?;
                Some((addr, amount))
            })
            .collect::<Vec<_>>()
    });
    let Some(split) = split.filter(|s| !s.is_empty()) else {
        return Err(kpr1_err("KPR1_SETTLE_SPLIT_REQUIRED", "A non-empty settlement split [{address, amount}] is required", None));
    };
    let fee_payer = match body.get("feePayer").and_then(|v| v.as_str()) {
        Some("merchant") => crate::covenant_keeper::FeePayer::Merchant,
        Some("customer") | None => crate::covenant_keeper::FeePayer::Customer,
        Some(other) => {
            return Err(kpr1_err("KPR1_SETTLE_FEEPAYER_INVALID", &format!("feePayer must be 'customer' or 'merchant' (got '{other}')"), None));
        }
    };
    Ok((split, fee_payer))
}

/// `POST /api/checkout/invoices/:publicId/kpr1-settle/prepare`
///
/// Tier 1 bilateral mutual settlement, step 1. Both parties agree an arbitrary
/// split of the gross. Body: `{ split: [{address, amount}], feePayer }`. Returns
/// the covenant sighash BOTH sign and the fee sighash the fee payer signs.
pub async fn prepare_kpr1_settle(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Response> {
    let (split, fee_payer) = match parse_settle_body(&body) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let out = crate::covenant_keeper::mutual_settle_prepare(&state, &public_id, &split, fee_payer).await?;
    Ok((StatusCode::OK, Json(out)).into_response())
}

/// `POST /api/checkout/invoices/:publicId/kpr1-settle`
///
/// Tier 1 mutual settlement, step 2. Body: `{ split, feePayer, customerSignature,
/// merchantSignature, feeSignature }`. Broadcasts the co-signed split.
pub async fn submit_kpr1_settle(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Response> {
    let (split, fee_payer) = match parse_settle_body(&body) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    let customer_sig = body_str(&body, "customerSignature");
    let merchant_sig = body_str(&body, "merchantSignature");
    let fee_sig = body_str(&body, "feeSignature");
    let (Some(customer_sig), Some(merchant_sig), Some(fee_sig)) = (customer_sig, merchant_sig, fee_sig) else {
        return Ok(kpr1_err(
            "KPR1_SETTLE_SIGNATURES_REQUIRED",
            "customerSignature, merchantSignature and feeSignature are all required to settle",
            None,
        ));
    };
    let out = crate::covenant_keeper::mutual_settle_submit(&state, &public_id, &split, fee_payer, customer_sig, merchant_sig, fee_sig).await?;
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
