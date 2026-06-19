//! `/api/commerce/invoices` — CommerceInvoicesController (store, show).
//! Both return `serializeKpr1PaymentContract()` (serialize with paymentAddress
//! always dropped). Reuses the shared `invoices::create_for_merchant`.

use crate::auth::AuthMerchant;
use crate::error::AppResult;
use crate::handlers::invoices;
use crate::state::AppState;
use crate::store_context::resolve_request_store;
use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize, Default)]
pub struct StoreIdQuery {
    #[serde(rename = "storeId")]
    store_id: Option<i64>,
}

/// `POST /api/commerce/invoices`
pub async fn store(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let (invoice_id, store_id) = invoices::create_for_merchant(&state, auth.user_id, &body, None, None, None).await?;
    let inv = invoices::load_owned_invoice(&state, auth.user_id, store_id, invoice_id).await?;
    let (items, intent) = invoices::load_relations(&state, inv.id()).await?;
    Ok(Json(invoices::serialize_kpr1_contract(&inv, &items, intent.as_ref())))
}

/// `GET /api/commerce/invoices/:publicId`
pub async fn show(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    Query(q): Query<StoreIdQuery>,
) -> AppResult<Json<Value>> {
    let store_id = resolve_request_store(&state, auth.user_id, q.store_id).await?;
    let mut inv = invoices::load_owned_by_public_id(&state, auth.user_id, store_id, &public_id).await?;
    invoices::expire_if_needed(&state, &mut inv).await?;
    let (items, intent) = invoices::load_relations(&state, inv.id()).await?;
    Ok(Json(invoices::serialize_kpr1_contract(&inv, &items, intent.as_ref())))
}
