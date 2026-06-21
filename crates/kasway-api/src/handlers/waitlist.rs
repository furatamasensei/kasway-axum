//! `POST /api/waitlist/join` — public waitlist signup. Spam protection layers,
//! mirroring the bug_reports handler: Cloudflare Turnstile via the shared
//! `captcha_ok`, a per-IP-hash rate limit (max 3/hour), and duplicate-email
//! protection (UNIQUE constraint + graceful 409). The raw IP is never stored —
//! only a salted SHA-256 hash, exactly as bug_reports does.

use crate::error::{AppError, AppResult, ValidationFailure};
use crate::state::AppState;
use crate::util::now_iso;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const APP_KEY_DEFAULT: &str = "kasway-local-waitlist-salt";
const RATE_LIMIT_MAX: i64 = 3;

fn vfail(field: &str, rule: &str, msg: &str) -> AppError {
    AppError::Validation(vec![ValidationFailure { message: msg.into(), rule: rule.into(), field: field.into() }])
}

fn opt_str(body: &Value, field: &str, max: usize) -> Option<String> {
    body.get(field).and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).map(|s| s.chars().take(max).collect())
}

/// `POST /api/waitlist/join`
pub async fn join_waitlist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Response> {
    // --- validation (email format) ---
    let email_raw = body.get("email").and_then(|v| v.as_str()).map(|s| s.trim()).unwrap_or("");
    if email_raw.is_empty() {
        return Err(vfail("email", "required", "The email field must be defined"));
    }
    let valid_email = {
        let mut parts = email_raw.splitn(2, '@');
        match (parts.next(), parts.next()) {
            (Some(local), Some(domain)) => {
                !local.is_empty()
                    && domain.contains('.')
                    && !domain.starts_with('.')
                    && !domain.ends_with('.')
                    && !domain.contains(' ')
            }
            _ => false,
        }
    };
    if !valid_email || email_raw.chars().count() > 320 {
        return Err(vfail("email", "email", "The email field must be a valid email address"));
    }
    let email = email_raw.to_lowercase();

    let token = opt_str(&body, "turnstile_token", 4096);
    let source = opt_str(&body, "source", 64);

    // client IP (best-effort: x-forwarded-for else loopback) — never store raw IP.
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "127.0.0.1".into());

    // --- (a) captcha (Turnstile) ---
    if !state.config.captcha_ok(token.as_deref(), Some(&ip)).await {
        return Err(AppError::commerce(400, "Captcha validation failed"));
    }

    let ip_hash = format!("{:x}", Sha256::digest(format!("{APP_KEY_DEFAULT}:{ip}").as_bytes()));
    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.chars().take(512).collect::<String>());

    // --- (c) rate limit: max 3 signups per hour per IP hash. created_at is a
    // fixed-width ISO8601 string, so lexicographic >= is a valid time comparison.
    let cutoff = (Utc::now() - Duration::hours(1)).format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string();
    let recent: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM waitlist_entries WHERE ip_hash = $1 AND created_at >= $2",
    )
    .bind(&ip_hash)
    .bind(&cutoff)
    .fetch_one(&state.db.pool)
    .await?;
    if recent >= RATE_LIMIT_MAX {
        return Err(AppError::commerce(429, "Too many signups from this network. Please try again later."));
    }

    // --- (b) duplicate email: pre-check for a clean 409, with ON CONFLICT below
    // closing the check-then-insert race.
    let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM waitlist_entries WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.db.pool)
        .await?;
    if exists.is_some() {
        return Err(AppError::commerce(409, "This email is already on the waitlist."));
    }

    let now = now_iso();
    let res = sqlx::query(
        "INSERT INTO waitlist_entries (email, ip_hash, user_agent, turnstile_token, source, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (email) DO NOTHING",
    )
    .bind(&email)
    .bind(&ip_hash)
    .bind(user_agent)
    .bind(token)
    .bind(source)
    .bind(&now)
    .execute(&state.db.pool)
    .await?;

    // Concurrent insert won the race for the same email.
    if res.rows_affected() == 0 {
        return Err(AppError::commerce(409, "This email is already on the waitlist."));
    }

    Ok((StatusCode::CREATED, Json(json!({ "status": "joined", "message": "You're on the waitlist! We'll be in touch." }))).into_response())
}
