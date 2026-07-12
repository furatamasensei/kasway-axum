//! `/openapi.json` — public, static. The OpenAPI spec is generated verbatim from
//! the Adonis `#openapi/spec` (dumped to JSON and embedded), so bytes match the
//! source contract. Human-facing documentation lives on the kasway-v2 landing site.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

const OPENAPI_JSON: &str = include_str!("assets/openapi.json");

/// `GET /openapi.json`
pub async fn openapi() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("application/json")),
            (header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=300")),
        ],
        OPENAPI_JSON,
    )
        .into_response()
}
