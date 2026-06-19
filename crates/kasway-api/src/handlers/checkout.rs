//! `/api/checkout/invoices/*` — CheckoutInvoicesController (public, no auth).
//!
//! `show` and `kpr1Intent` are ported here. `submitKpr1Payment` is deferred:
//! it relays a signed transaction to the chain and runs settlement (external
//! chain/relay surface) — see ENDPOINTS.md.

use crate::error::AppResult;
use crate::handlers::{invoices, payment_links};
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::Json;
use serde_json::Value;

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
