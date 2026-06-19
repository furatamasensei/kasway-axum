//! `/api/auth/*` — AuthController (login, register, profile, logout).
//! Google OAuth (redirect/callback) is deferred (external dependency).

use crate::auth::AuthMerchant;
use crate::auth_token;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::password::{hash_password, verify_password};
use crate::state::AppState;
use crate::util::now_iso;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct UserDto {
    id: i64,
    full_name: Option<String>,
    email: String,
    avatar_url: Option<String>,
    onboarded: bool,
    created_at: Option<String>,
    updated_at: Option<String>,
}

/// `POST /api/auth/login`
pub async fn login(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    // captcha first (matches controller order)
    let captcha_token = body.get("token").and_then(|v| v.as_str());
    if !state.config.captcha_ok(captcha_token) {
        return Err(AppError::bad_request("Captcha validation failed"));
    }

    // loginValidator: email (string,email), password (string)
    let mut errors = Vec::new();
    let email = validate_email(&body, "email", &mut errors);
    let password = validate_required_string(&body, "password", &mut errors);
    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }
    let email = email.unwrap();
    let password = password.unwrap();

    // merchant (User) path
    if let Some((id, stored)) = sqlx::query_as::<_, (i64, String)>(
        "SELECT id, password FROM users WHERE email = ?",
    )
    .bind(&email)
    .fetch_optional(&state.db.pool)
    .await?
    {
        if !verify_password(&password, &stored) {
            return Err(AppError::bad_credentials());
        }
        let token = auth_token::mint(&state.db.pool, &auth_token::MERCHANT, id).await?;
        let onboarded: bool =
            sqlx::query_scalar("SELECT onboarded FROM users WHERE id = ?")
                .bind(id)
                .fetch_one(&state.db.pool)
                .await?;
        return Ok(Json(json!({
            "token": token,
            "role": "merchant",
            "onboarded": onboarded,
        })));
    }

    // team-member (client) path
    let member = sqlx::query_as::<_, (i64, Option<String>, String)>(
        "SELECT id, password, role FROM team_members WHERE email = ?",
    )
    .bind(&email)
    .fetch_optional(&state.db.pool)
    .await?;

    let Some((id, stored, role)) = member else {
        return Err(AppError::bad_credentials());
    };
    let ok = stored
        .as_deref()
        .map(|h| verify_password(&password, h))
        .unwrap_or(false);
    if !ok {
        return Err(AppError::bad_credentials());
    }
    let token = auth_token::mint(&state.db.pool, &auth_token::CLIENT, id).await?;
    Ok(Json(json!({
        "token": token,
        "role": role,
        "onboarded": true,
    })))
}

/// `POST /api/auth/register`
pub async fn register(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<(StatusCode, Json<Value>)> {
    let captcha_token = body.get("token").and_then(|v| v.as_str());
    if !state.config.captcha_ok(captcha_token) {
        return Err(AppError::bad_request("Captcha validation failed"));
    }

    // registerValidator: fullName (required), email (email + unique users/team_members), password (required)
    let mut errors = Vec::new();
    let full_name = validate_required_string(&body, "fullName", &mut errors);
    let email = validate_email(&body, "email", &mut errors);
    let password = validate_required_string(&body, "password", &mut errors);

    // unique email check only if the email passed format validation
    if let Some(email) = email.as_ref() {
        let taken: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE \
             UNION SELECT 1 FROM team_members WHERE email = ? COLLATE NOCASE LIMIT 1",
        )
        .bind(email)
        .bind(email)
        .fetch_optional(&state.db.pool)
        .await?;
        if taken.is_some() {
            errors.push(ValidationFailure {
                message: "The email has already been taken".into(),
                rule: "database.unique".into(),
                field: "email".into(),
            });
        }
    }

    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }

    let now = now_iso();
    let result = sqlx::query(
        "INSERT INTO users (full_name, email, password, onboarded, created_at, updated_at) \
         VALUES (?, ?, ?, 0, ?, ?)",
    )
    .bind(full_name.unwrap())
    .bind(email.unwrap())
    .bind(hash_password(&password.unwrap()))
    .bind(&now)
    .bind(&now)
    .execute(&state.db.pool)
    .await?;

    let id = result.last_insert_rowid();
    let token = auth_token::mint(&state.db.pool, &auth_token::MERCHANT, id).await?;

    Ok((
        StatusCode::OK,
        Json(json!({ "success": true, "token": token })),
    ))
}

/// `GET /api/auth/profile` (auth: merchant)
pub async fn profile(
    auth: AuthMerchant,
    State(state): State<AppState>,
) -> AppResult<Json<UserDto>> {
    let user = sqlx::query_as::<_, UserDto>(
        "SELECT id, full_name, email, avatar_url, onboarded, created_at, updated_at \
         FROM users WHERE id = ?",
    )
    .bind(auth.user_id)
    .fetch_optional(&state.db.pool)
    .await?
    .ok_or(AppError::Unauthorized("Unauthorized access"))?;

    Ok(Json(user))
}

/// `POST /api/auth/logout` (auth: merchant)
pub async fn logout(
    auth: AuthMerchant,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    auth_token::delete(&state.db.pool, &auth_token::MERCHANT, auth.token_id).await?;
    Ok(Json(json!({ "success": true })))
}

// --- VineJS-shaped validation helpers ---

fn validate_required_string(
    body: &Value,
    field: &str,
    errors: &mut Vec<ValidationFailure>,
) -> Option<String> {
    match body.get(field) {
        None | Some(Value::Null) => {
            errors.push(ValidationFailure {
                message: format!("The {field} field is required"),
                rule: "required".into(),
                field: field.into(),
            });
            None
        }
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => {
            errors.push(ValidationFailure {
                message: format!("The {field} field must be a string"),
                rule: "string".into(),
                field: field.into(),
            });
            None
        }
    }
}

fn validate_email(
    body: &Value,
    field: &str,
    errors: &mut Vec<ValidationFailure>,
) -> Option<String> {
    let value = validate_required_string(body, field, errors)?;
    if is_email(&value) {
        Some(value)
    } else {
        errors.push(ValidationFailure {
            message: format!("The {field} field must be a valid email address"),
            rule: "email".into(),
            field: field.into(),
        });
        None
    }
}

fn is_email(value: &str) -> bool {
    let mut parts = value.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !value.contains(char::is_whitespace)
}
