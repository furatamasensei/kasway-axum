//! `/internal/payment-indexer/*` — InternalPaymentIndexerController.
//! Guarded by `internalApiToken()`.

use crate::auth::InternalToken;
use crate::error::AppResult;
use crate::state::AppState;
use crate::util::json_or_null;
use axum::extract::State;
use axum::Json;
use serde::Serialize;
use serde_json::{json, Value};

#[derive(sqlx::FromRow)]
struct CheckpointRow {
    id: i64,
    network: String,
    asset_id: String,
    source: String,
    checkpoint: Option<String>,
    metadata: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckpointDto {
    id: i64,
    network: String,
    asset_id: String,
    source: String,
    checkpoint: Option<String>,
    metadata: Value,
    created_at: Option<String>,
    updated_at: Option<String>,
}

impl From<CheckpointRow> for CheckpointDto {
    fn from(r: CheckpointRow) -> Self {
        // metadata is jsonb in Postgres; Lucid hands back the parsed object.
        let metadata = json_or_null(&r.metadata);
        CheckpointDto {
            id: r.id,
            network: r.network,
            asset_id: r.asset_id,
            source: r.source,
            checkpoint: r.checkpoint,
            metadata,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// `GET /internal/payment-indexer/healthz`
pub async fn healthz(
    _token: InternalToken,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    let row = sqlx::query_as::<_, CheckpointRow>(
        "SELECT id, network, asset_id, source, checkpoint, metadata, created_at, updated_at \
         FROM payment_indexer_checkpoints \
         WHERE network = 'tn10' AND asset_id = 'KAS' AND source = 'rusty-kaspa-node' \
         ORDER BY updated_at DESC LIMIT 1",
    )
    .fetch_optional(&state.db.pool)
    .await?;

    let checkpoint = row.map(|r| serde_json::to_value(CheckpointDto::from(r)).unwrap());

    Ok(Json(json!({
        "status": "ok",
        "network": "tn10",
        "assetId": "KAS",
        "source": "rusty-kaspa-node",
        "checkpoint": checkpoint,
    })))
}

/// `GET /internal/payment-indexer/checkpoints`
pub async fn checkpoints(
    _token: InternalToken,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    let rows = sqlx::query_as::<_, CheckpointRow>(
        "SELECT id, network, asset_id, source, checkpoint, metadata, created_at, updated_at \
         FROM payment_indexer_checkpoints WHERE network = 'tn10' ORDER BY updated_at DESC",
    )
    .fetch_all(&state.db.pool)
    .await?;

    let data: Vec<Value> = rows
        .into_iter()
        .map(|r| serde_json::to_value(CheckpointDto::from(r)).unwrap())
        .collect();

    Ok(Json(json!({ "data": data })))
}
