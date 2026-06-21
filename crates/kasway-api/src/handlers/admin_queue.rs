//! `/admin/queue/*` — QueueDash dashboard mount (start/routes admin queue group).
//! The adminQueueDashboard middleware gates the third-party UI: in production it
//! returns 404 `{message:'Not found'}` unless ADMIN_QUEUE_ENABLED is set (and then
//! requires the internal token). The shipped config never sets ADMIN_QUEUE_ENABLED,
//! and the dashboard UI itself is a third-party Node bundle with no app source, so
//! the port serves the disabled gate response.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// `ANY /admin/queue` and `/admin/queue/*` — disabled-gate response.
pub async fn gate() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({ "message": "Not found" }))).into_response()
}
