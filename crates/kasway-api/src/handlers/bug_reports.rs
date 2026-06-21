//! `POST /api/bug-reports` — BugReportsController + BugReportService. Public
//! (optional merchant auth for reporterUserId). Captcha via the shared
//! `captcha_ok` (Turnstile bypass when no secret & not production). Attachments +
//! tracker forwarding stubbed (manual_export_stub), matching the Adonis v1 service.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::state::AppState;
use crate::util::now_iso;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const CATEGORIES: &[&str] = &["api", "checkout", "dashboard", "docs", "explorer", "wallet", "webhooks", "payments", "security", "other"];
const IMPACTS: &[&str] = &["low", "medium", "high", "critical"];
const APP_KEY_DEFAULT: &str = "kasway-local-bug-report-salt";

fn vfail(field: &str, rule: &str, msg: &str) -> AppError {
    AppError::Validation(vec![ValidationFailure { message: msg.into(), rule: rule.into(), field: field.into() }])
}

fn req_str(body: &Value, field: &str, min: usize, max: usize) -> AppResult<String> {
    let s = body.get(field).and_then(|v| v.as_str()).map(|s| s.trim().to_string());
    match s {
        Some(s) if s.chars().count() >= min && s.chars().count() <= max => Ok(s),
        Some(s) if s.chars().count() < min => Err(vfail(field, "minLength", &format!("The {field} field must have at least {min} characters"))),
        Some(_) => Err(vfail(field, "maxLength", &format!("The {field} field must not exceed {max} characters"))),
        None => Err(vfail(field, "required", &format!("The {field} field must be defined"))),
    }
}

fn opt_str(body: &Value, field: &str, max: usize) -> Option<String> {
    body.get(field).and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).map(|s| s.chars().take(max).collect())
}

fn has_attachment(body: &Value, field: &str) -> bool {
    match body.get(field) {
        None | Some(Value::Null) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(_) => true,
    }
}

fn random_public_id() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    format!("bug_{}", b.iter().map(|x| format!("{:02x}", x)).collect::<String>())
}

/// `POST /api/bug-reports`
pub async fn store(
    State(state): State<AppState>,
    reporter: Option<AuthMerchant>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> AppResult<Response> {
    // --- validation (createBugReportValidator) ---
    let token = req_str(&body, "token", 1, 4096)?;
    let summary = req_str(&body, "summary", 8, 200)?;
    let description = req_str(&body, "description", 20, 5000)?;
    let category = body.get("category").and_then(|v| v.as_str()).unwrap_or("");
    if !CATEGORIES.contains(&category) {
        return Err(vfail("category", "enum", "The selected category is invalid"));
    }
    let impact = match body.get("impact").and_then(|v| v.as_str()) {
        Some(i) if IMPACTS.contains(&i) => i.to_string(),
        Some(_) => return Err(vfail("impact", "enum", "The selected impact is invalid")),
        None => "medium".to_string(),
    };
    if let Some(email) = body.get("contactEmail").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) {
        if !email.contains('@') {
            return Err(vfail("contactEmail", "email", "The contactEmail field must be a valid email address"));
        }
    }

    // client IP (best-effort: x-forwarded-for else loopback)
    let ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).and_then(|s| s.split(',').next()).map(|s| s.trim().to_string()).unwrap_or_else(|| "127.0.0.1".into());

    // --- captcha ---
    if !state.config.captcha_ok(Some(&token), Some(&ip)).await {
        return Err(AppError::commerce(400, "Captcha validation failed"));
    }

    let attachments_provided = ["attachments", "attachment", "files"].iter().any(|f| has_attachment(&body, f));
    let website = opt_str(&body, "website", 255);
    let status = if website.is_some() { "spam" } else { "new" };

    let ip_hash = format!("{:x}", Sha256::digest(format!("{APP_KEY_DEFAULT}:{ip}").as_bytes()));
    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.chars().take(512).collect::<String>());
    let reporter_user_id = reporter.map(|r| r.user_id);

    // default store of reporter
    let store_id: Option<i64> = match reporter_user_id {
        Some(uid) => sqlx::query_scalar("SELECT id FROM stores WHERE user_id = $1 AND is_default = 1")
            .bind(uid).fetch_optional(&state.db.pool).await?,
        None => None,
    };

    let safe_metadata = json!({ "attachments": "rejected_in_v1", "trackerForwarding": "manual_export_stub" });
    let now = now_iso();
    let public_id = random_public_id();

    sqlx::query(
        "INSERT INTO bug_reports \
         (public_id, status, category, impact, summary, description, steps_to_reproduce, expected_behavior, \
          actual_behavior, contact_email, contact_name, page_url, browser, os, invoice_id, payment_id, \
          transaction_id, reporter_user_id, store_id, ip_hash, user_agent, captcha_provider, captcha_success, \
          safe_metadata, tracker_provider, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, 'turnstile', 1, $22, 'manual_export_stub', $23, $24)",
    )
    .bind(&public_id).bind(status).bind(category).bind(&impact).bind(&summary).bind(&description)
    .bind(opt_str(&body, "stepsToReproduce", 4000)).bind(opt_str(&body, "expectedBehavior", 2000))
    .bind(opt_str(&body, "actualBehavior", 2000)).bind(opt_str(&body, "contactEmail", 255))
    .bind(opt_str(&body, "contactName", 120)).bind(opt_str(&body, "pageUrl", 2048))
    .bind(opt_str(&body, "browser", 255)).bind(opt_str(&body, "os", 255))
    .bind(opt_str(&body, "invoiceId", 128)).bind(opt_str(&body, "paymentId", 128))
    .bind(opt_str(&body, "transactionId", 128)).bind(reporter_user_id).bind(store_id)
    .bind(&ip_hash).bind(user_agent).bind(safe_metadata.to_string()).bind(&now).bind(&now)
    .execute(&state.db.pool).await?;

    let base = "Bug report received. Kasway support will triage it without exposing private tracker details.";
    let message = if attachments_provided {
        format!("{base} Note: file attachments aren't supported yet, so they were not included — please paste any relevant details into the description.")
    } else {
        base.to_string()
    };

    Ok((StatusCode::CREATED, Json(json!({ "publicId": public_id, "status": status, "message": message }))).into_response())
}
