//! `/openapi.json` and `/docs` — public, static. The OpenAPI spec and the docs
//! HTML are generated verbatim from the Adonis `#openapi/spec` and `#openapi/docs`
//! (dumped to JSON/HTML and embedded), so bytes match the source contract.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

const OPENAPI_JSON: &str = include_str!("assets/openapi.json");
const DOCS_HTML: &str = include_str!("assets/docs.html");

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

/// `GET /docs`
pub async fn docs() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"))],
        DOCS_HTML,
    )
        .into_response()
}
