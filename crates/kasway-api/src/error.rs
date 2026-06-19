//! Error type mapped to AdonisJS HTTP response contracts.
//!
//! Adonis conventions we reproduce (validated against `kasway-v2-api`):
//! - `response.unauthorized({ message })`  -> 401 `{ "message": ... }`
//! - `response.forbidden()`                -> 403 (empty body) or `{ "message": ... }`
//! - `response.notFound()` / findOrFail    -> 404 `{ "message": "Row not found" }`
//! - VineJS validation failure             -> 422 `{ "errors": [ { message, rule, field } ] }`
//! - `response.serviceUnavailable({ ... })`-> 503 `{ "message": ... }`
//! - uncaught                              -> 500 `{ "message": ... }`

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("bad request")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized(&'static str),
    /// Forbidden with no body, matching bare `response.forbidden()`.
    #[error("forbidden")]
    Forbidden,
    #[error("forbidden")]
    ForbiddenWithMessage(String),
    #[error("not found")]
    NotFound(&'static str),
    #[error("service unavailable")]
    ServiceUnavailable(&'static str),
    #[error("validation failed")]
    Validation(Vec<ValidationFailure>),
    /// CommerceError / StoreContextError: arbitrary status + `{ message }`.
    /// (Non-development `toResponseBody` always returns just the message.)
    #[error("commerce error")]
    Commerce { status: u16, message: String },
    /// Kpr1PaymentIntentError surfaced directly (checkout): 422 `{ message, code }`.
    #[error("kpr1 error")]
    Kpr1 { code: String, message: String },
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error("internal error")]
    Internal(String),
}

#[derive(Debug, Serialize)]
pub struct ValidationFailure {
    pub message: String,
    pub rule: String,
    pub field: String,
}

#[derive(Serialize)]
struct MessageBody {
    message: String,
}

#[derive(Serialize)]
struct ErrorsBody {
    errors: Vec<ValidationFailure>,
}

impl AppError {
    /// Convenience for the very common Lucid `findOrFail` 404.
    pub fn row_not_found() -> Self {
        AppError::NotFound("Row not found")
    }

    /// Single-field VineJS-shaped 422.
    pub fn validation_field(field: &str, rule: &str, message: &str) -> Self {
        AppError::Validation(vec![ValidationFailure {
            message: message.to_string(),
            rule: rule.to_string(),
            field: field.to_string(),
        }])
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        AppError::BadRequest(msg.into())
    }

    /// CommerceError(status, message).
    pub fn commerce(status: u16, msg: impl Into<String>) -> Self {
        AppError::Commerce { status, message: msg.into() }
    }

    /// 401 `{ message: "Invalid credentials" }` (AuthController.login).
    pub fn bad_credentials() -> Self {
        AppError::Unauthorized("Invalid credentials")
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, Json(MessageBody { message: msg })).into_response()
            }
            AppError::Unauthorized(msg) => {
                (StatusCode::UNAUTHORIZED, Json(MessageBody { message: msg.into() })).into_response()
            }
            AppError::Forbidden => StatusCode::FORBIDDEN.into_response(),
            AppError::ForbiddenWithMessage(msg) => {
                (StatusCode::FORBIDDEN, Json(MessageBody { message: msg })).into_response()
            }
            AppError::NotFound(msg) => {
                (StatusCode::NOT_FOUND, Json(MessageBody { message: msg.into() })).into_response()
            }
            AppError::ServiceUnavailable(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(MessageBody { message: msg.into() }),
            )
                .into_response(),
            AppError::Commerce { status, message } => {
                let code = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                (code, Json(MessageBody { message })).into_response()
            }
            AppError::Kpr1 { code, message } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "message": message, "code": code })),
            )
                .into_response(),
            AppError::Validation(failures) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorsBody { errors: failures }),
            )
                .into_response(),
            AppError::Database(err) => {
                tracing::error!(error = ?err, "database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(MessageBody { message: "Internal server error".into() }),
                )
                    .into_response()
            }
            AppError::Internal(msg) => {
                tracing::error!(error = %msg, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(MessageBody { message: "Internal server error".into() }),
                )
                    .into_response()
            }
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;
