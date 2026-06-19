//! Health endpoints.
//! `GET /internal/healthz` -> `{ "status": "ok" }` (see start/routes.ts).

use axum::Json;
use serde_json::{json, Value};

pub async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}
