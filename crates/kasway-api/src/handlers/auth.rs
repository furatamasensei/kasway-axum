//! `/api/auth/*` — AuthController (login, register, profile, logout) + Google
//! OAuth (redirect/callback) via the standard OAuth2 code flow. Google endpoint
//! URLs are config-overridable (state::GoogleConfig) so the token/userinfo
//! exchange is testable against a local mock.

use crate::auth::AuthMerchant;
use crate::auth_token;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::password::{hash_password, verify_password};
use crate::state::AppState;
use crate::util::now_iso;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use url::Url;

/// Serializes an integer-backed boolean flag (Postgres stores booleans as
/// 0/1 BIGINT) as a JSON boolean to preserve the API contract.
fn ser_int_as_bool<S: serde::Serializer>(v: &i64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_bool(*v != 0)
}

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct UserDto {
    id: i64,
    full_name: Option<String>,
    email: String,
    avatar_url: Option<String>,
    #[serde(serialize_with = "ser_int_as_bool")]
    onboarded: i64,
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
    if !state.config.captcha_ok(captcha_token, None).await {
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
        "SELECT id, password FROM users WHERE LOWER(email) = LOWER($1)",
    )
    .bind(&email)
    .fetch_optional(&state.db.pool)
    .await?
    {
        if !verify_password(&password, &stored) {
            return Err(AppError::bad_credentials());
        }
        let token = auth_token::mint(&state.db.pool, &auth_token::MERCHANT, id).await?;
        let onboarded: i64 =
            sqlx::query_scalar("SELECT onboarded FROM users WHERE id = $1")
                .bind(id)
                .fetch_one(&state.db.pool)
                .await?;
        return Ok(Json(json!({
            "token": token,
            "role": "merchant",
            "onboarded": onboarded != 0,
        })));
    }

    Err(AppError::bad_credentials())
}

/// `POST /api/auth/register`
pub async fn register(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<(StatusCode, Json<Value>)> {
    let captcha_token = body.get("token").and_then(|v| v.as_str());
    if !state.config.captcha_ok(captcha_token, None).await {
        return Err(AppError::bad_request("Captcha validation failed"));
    }

    // registerValidator: fullName (required), email (email + unique users), password (required)
    let mut errors = Vec::new();
    let full_name = validate_required_string(&body, "fullName", &mut errors);
    let email = validate_email(&body, "email", &mut errors);
    let password = validate_required_string(&body, "password", &mut errors);

    // unique email check only if the email passed format validation
    if let Some(email) = email.as_ref() {
        let taken: Option<i64> = sqlx::query_scalar(
            "SELECT CAST(1 AS BIGINT) FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1",
        )
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
    let id: i64 = sqlx::query_scalar::<_, i64>(
        "INSERT INTO users (full_name, email, password, onboarded, created_at, updated_at) \
         VALUES ($1, $2, $3, 0, $4, $5) RETURNING id",
    )
    .bind(full_name.unwrap())
    .bind(email.unwrap())
    .bind(hash_password(&password.unwrap()))
    .bind(&now)
    .bind(&now)
    .fetch_one(&state.db.pool)
    .await?;

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
         FROM users WHERE id = $1",
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

// ---- Google OAuth (redirect / callback) ------------------------------------

/// Max age (seconds) of a stateless OAuth `state` token before it is rejected.
const OAUTH_STATE_MAX_AGE_SECS: i64 = 600;

/// Secret used to sign the stateless OAuth `state` token. Prefers the internal
/// API token, falling back to the Google client secret so a value is always
/// available in an OAuth-configured deployment.
fn oauth_state_secret(state: &AppState) -> String {
    state
        .config
        .internal_api_token
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| state.config.google.client_secret.clone())
}

fn oauth_state_sig(secret: &str, ts: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("hmac accepts any key length");
    mac.update(ts.as_bytes());
    mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect()
}

/// Build a stateless, tamper-proof OAuth `state`: `<unix_ts>.<hex HMAC-SHA256>`.
/// Round-tripped by Google and validated in the callback to defeat login CSRF.
fn make_oauth_state(secret: &str) -> String {
    let ts = chrono::Utc::now().timestamp().to_string();
    let sig = oauth_state_sig(secret, &ts);
    format!("{ts}.{sig}")
}

/// Validate a stateless OAuth `state`: signature must match (constant-time) and
/// the token must not be older than `OAUTH_STATE_MAX_AGE_SECS`.
fn verify_oauth_state(secret: &str, token: &str) -> bool {
    let Some((ts, sig)) = token.split_once('.') else {
        return false;
    };
    let expected = oauth_state_sig(secret, ts);
    if !crate::util::constant_time_eq(sig.as_bytes(), expected.as_bytes()) {
        return false;
    }
    let Ok(ts_val) = ts.parse::<i64>() else {
        return false;
    };
    let age = chrono::Utc::now().timestamp() - ts_val;
    (0..=OAUTH_STATE_MAX_AGE_SECS).contains(&age)
}

/// `GET /api/auth/google/redirect` — returns the Google authorize URL (stateless).
pub async fn redirect_google(State(state): State<AppState>) -> AppResult<String> {
    let g = &state.config.google;
    let redirect_uri = format!("{}/auth/google/callback", g.app_url);
    let csrf_state = make_oauth_state(&oauth_state_secret(&state));
    let url = Url::parse_with_params(
        &g.authorize_url,
        &[
            ("response_type", "code"),
            ("client_id", g.client_id.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("scope", "openid email profile"),
            ("state", csrf_state.as_str()),
        ],
    )
    .map_err(|_| AppError::commerce(500, "Invalid Google authorize URL"))?;
    Ok(url.to_string())
}

#[derive(Deserialize)]
pub struct GoogleCallbackQuery {
    code: Option<String>,
    error: Option<String>,
    state: Option<String>,
}

#[derive(Deserialize)]
struct GoogleToken {
    access_token: String,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    email: Option<String>,
    name: Option<String>,
    picture: Option<String>,
}

/// `GET /auth/google/callback` — exchanges the code, upserts the user, mints a
/// merchant token, and redirects to the frontend callback.
pub async fn callback_google(
    State(state): State<AppState>,
    Query(q): Query<GoogleCallbackQuery>,
) -> AppResult<Response> {
    if q.error.as_deref() == Some("access_denied") {
        return Ok("You have cancelled the login process".into_response());
    }
    if let Some(err) = q.error.filter(|e| !e.is_empty()) {
        return Ok(err.into_response());
    }
    let Some(code) = q.code.filter(|c| !c.is_empty()) else {
        return Ok("We are unable to verify the request. Please try again".into_response());
    };

    // CSRF: require a valid, unexpired stateless `state` round-tripped by Google.
    let secret = oauth_state_secret(&state);
    let state_ok = q
        .state
        .as_deref()
        .map(|s| verify_oauth_state(&secret, s))
        .unwrap_or(false);
    if !state_ok {
        return Err(AppError::Unauthorized("Invalid or missing OAuth state"));
    }

    let g = &state.config.google;
    let redirect_uri = format!("{}/auth/google/callback", g.app_url);
    let client = reqwest::Client::new();

    let token: GoogleToken = client
        .post(&g.token_url)
        .form(&[
            ("code", code.as_str()),
            ("client_id", g.client_id.as_str()),
            ("client_secret", g.client_secret.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .map_err(|_| AppError::commerce(502, "Google token exchange failed"))?
        .json()
        .await
        .map_err(|_| AppError::commerce(502, "Google token exchange failed"))?;

    let info: GoogleUserInfo = client
        .get(&g.userinfo_url)
        .bearer_auth(&token.access_token)
        .send()
        .await
        .map_err(|_| AppError::commerce(502, "Google user info failed"))?
        .json()
        .await
        .map_err(|_| AppError::commerce(502, "Google user info failed"))?;

    let email = info.email.filter(|e| !e.is_empty()).ok_or_else(|| AppError::commerce(502, "Google account has no email"))?;

    // firstOrCreate by email
    let existing: Option<(i64, i64)> = sqlx::query_as("SELECT id, onboarded FROM users WHERE LOWER(email) = LOWER($1)")
        .bind(&email)
        .fetch_optional(&state.db.pool)
        .await?;
    let (user_id, onboarded) = match existing {
        Some((id, ob)) => (id, ob),
        None => {
            let random_pw: String = (0..16).map(|_| rand::thread_rng().gen_range(b'a'..=b'z') as char).collect();
            let now = now_iso();
            let id = sqlx::query_scalar::<_, i64>(
                "INSERT INTO users (full_name, email, password, avatar_url, onboarded, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, 0, $5, $6) RETURNING id",
            )
            .bind(info.name)
            .bind(&email)
            .bind(hash_password(&random_pw))
            .bind(info.picture)
            .bind(&now)
            .bind(&now)
            .fetch_one(&state.db.pool)
            .await?;
            (id, 0i64)
        }
    };

    let token_value = auth_token::mint(&state.db.pool, &auth_token::MERCHANT, user_id).await?;
    let location = format!(
        "{}/auth/callback?token={}&onboarded={}",
        g.frontend_url, token_value, onboarded != 0
    );
    Ok((StatusCode::FOUND, [(header::LOCATION, location)]).into_response())
}
