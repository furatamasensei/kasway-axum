//! Auth extractors mirroring the AdonisJS middleware in `app/middleware/`.
//!
//! Phase 1 implements the `internalApiToken()` tier. The merchant (Bearer
//! access token) and API-key tiers follow as their endpoints are ported.

use crate::auth_token;
use crate::error::AppError;
use crate::state::AppState;
use crate::util::constant_time_eq;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;

/// Authenticated merchant (User), resolved from a Bearer access token.
/// Mirrors `auth_middleware.ts` default-guard (`merchant`) path.
pub struct AuthMerchant {
    pub user_id: i64,
    pub token_id: i64,
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthMerchant {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts).ok_or(AppError::Unauthorized("Unauthorized access"))?;
        match auth_token::verify(&state.db.pool, &auth_token::MERCHANT, &token).await? {
            Some(v) => Ok(AuthMerchant {
                user_id: v.tokenable_id,
                token_id: v.token_id,
            }),
            None => Err(AppError::Unauthorized("Unauthorized access")),
        }
    }
}

/// Extract the `Authorization: Bearer <token>` value.
pub fn bearer_token(parts: &Parts) -> Option<String> {
    let auth = parts.headers.get("authorization")?.to_str().ok()?;
    auth.strip_prefix("Bearer ").map(|t| t.trim().to_string())
}

/// Guards `internalApiToken()` routes. See `internal_api_token_middleware.ts`.
pub struct InternalToken;

#[axum::async_trait]
impl FromRequestParts<AppState> for InternalToken {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(configured) = state.config.internal_api_token.as_deref() else {
            return Err(AppError::ServiceUnavailable(
                "Internal API token is not configured",
            ));
        };

        let provided = extract_token(parts);
        match provided {
            Some(token) if constant_time_eq(token.as_bytes(), configured.as_bytes()) => {
                Ok(InternalToken)
            }
            _ => Err(AppError::Unauthorized("Unauthorized access")),
        }
    }
}

/// `Authorization: Bearer <t>` takes precedence, else `x-internal-api-token`.
fn extract_token(parts: &Parts) -> Option<String> {
    bearer_token(parts).or_else(|| {
        parts
            .headers
            .get("x-internal-api-token")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_string())
    })
}
