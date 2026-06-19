//! Public `/api/payments/networks*` — PaymentNetworkCapabilitiesController.
//! Returns the static `paymentNetworkCapabilities` data (no auth).

use crate::error::{AppError, AppResult};
use axum::extract::Path;
use axum::Json;
use serde_json::{json, Value};

pub(crate) fn capabilities() -> Vec<Value> {
    vec![json!({
        "network": "tn10",
        "confirmationPolicy": "chain_observation",
        "addressDerivationSupported": false,
        "observationSource": "kaspa_indexer",
        "settlementSupportLevel": "full",
        "assets": [{
            "assetId": "KAS",
            "confirmationPolicy": "chain_observation",
            "addressDerivationSupported": false,
            "settlementSupportLevel": "full",
        }],
    })]
}

/// `GET /api/payments/networks`
pub async fn networks() -> Json<Value> {
    Json(Value::Array(capabilities()))
}

/// `GET /api/payments/networks/:network/assets`
pub async fn network_assets(Path(network): Path<String>) -> AppResult<Json<Value>> {
    capabilities()
        .into_iter()
        .find(|c| c["network"] == network)
        .map(Json)
        .ok_or_else(|| AppError::commerce(404, &format!("Unknown payment network: {network}")))
}
