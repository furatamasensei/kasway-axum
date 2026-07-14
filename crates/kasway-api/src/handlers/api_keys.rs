//! `/api/api-keys` — ApiKeysController + ApiKeyService + ApiKeyPolicy.
//!
//! Keys are `ksw_{prefix}_{secret}`; only `sha256(key)` is stored. `keyHash`
//! is hidden from serialization. Bouncer `create` is always allowed; show/
//! revoke/rotate require ownership (else 403) after a `findOrFail` (404).

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::state::AppState;
use crate::util::{encode_hex, now_iso, paginator_meta, ser_json_arr, sha256_hex};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const KEY_PREFIX: &str = "ksw";

const API_KEY_SCOPES: &[&str] = &[
    "commerce:invoices:read",
    "commerce:invoices:write",
    "commerce:subscriptions:read",
    "commerce:subscriptions:write",
    "payments:read",
    "payments:write",
    "webhooks:manage",
    "metrics:read",
    "mcp:read",
    "mcp:stores:read",
    "mcp:invoices:read",
    "mcp:kpr1:read",
    "mcp:webhooks:read",
    "mcp:subscriptions:read",
];

/// Serialized like Lucid (camelCase); `keyHash` is never selected, so it cannot leak.
#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct ApiKeyRow {
    id: i64,
    user_id: i64,
    name: String,
    prefix: String,
    #[serde(serialize_with = "ser_json_arr")]
    scopes: String,
    last_used_at: Option<String>,
    expires_at: Option<String>,
    revoked_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const SELECT_COLS: &str = "id, user_id, name, prefix, scopes, last_used_at, expires_at, \
                           revoked_at, created_at, updated_at";

fn serialize_row(row: &ApiKeyRow) -> Value {
    serde_json::to_value(row).unwrap_or(Value::Null)
}

fn generate_key_material() -> (String, String, String) {
    let mut prefix_bytes = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut prefix_bytes);
    let prefix = encode_hex(&prefix_bytes);

    let mut secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    let secret = URL_SAFE_NO_PAD.encode(secret_bytes);

    let key = format!("{KEY_PREFIX}_{prefix}_{secret}");
    let key_hash = sha256_hex(key.as_bytes());
    (prefix, key, key_hash)
}

async fn fetch_owned(
    state: &AppState,
    id: i64,
    user_id: i64,
) -> AppResult<ApiKeyRow> {
    let row = sqlx::query_as::<_, ApiKeyRow>(&format!(
        "SELECT {SELECT_COLS} FROM api_keys WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.db.pool)
    .await?
    .ok_or_else(AppError::row_not_found)?; // findOrFail -> 404

    if row.user_id != user_id {
        return Err(AppError::Forbidden); // ApiKeyPolicy denies
    }
    Ok(row)
}

#[derive(Deserialize)]
pub struct PageParams {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
}

/// `GET /api/api-keys`
pub async fn index(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Query(params): Query<PageParams>,
) -> AppResult<Json<Value>> {
    let page = params.page.unwrap_or(1).clamp(1, 100_000);
    let per_page = params.per_page.unwrap_or(10).clamp(1, 100);
    let offset = (page - 1) * per_page;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_keys WHERE user_id = $1")
        .bind(auth.user_id)
        .fetch_one(&state.db.pool)
        .await?;

    let rows = sqlx::query_as::<_, ApiKeyRow>(&format!(
        "SELECT {SELECT_COLS} FROM api_keys WHERE user_id = $1 \
         ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3"
    ))
    .bind(auth.user_id)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&state.db.pool)
    .await?;

    let data: Vec<Value> = rows.iter().map(serialize_row).collect();

    Ok(Json(json!({
        "meta": paginator_meta(total, per_page, page),
        "data": data,
    })))
}

/// `POST /api/api-keys`
pub async fn store(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<(StatusCode, Json<Value>)> {
    let (name, scopes, expires_at) = validate_create(&body)?;

    let (prefix, key, key_hash) = generate_key_material();
    let now = now_iso();
    let scopes_json = serde_json::to_string(&scopes).unwrap();

    let id: i64 = sqlx::query_scalar::<_, i64>(
        "INSERT INTO api_keys \
         (user_id, name, prefix, key_hash, scopes, last_used_at, expires_at, revoked_at, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, NULL, $6, NULL, $7, $8) RETURNING id",
    )
    .bind(auth.user_id)
    .bind(&name)
    .bind(&prefix)
    .bind(&key_hash)
    .bind(&scopes_json)
    .bind(&expires_at)
    .bind(&now)
    .bind(&now)
    .fetch_one(&state.db.pool)
    .await?;
    let row = fetch_owned(&state, id, auth.user_id).await?;
    let mut value = serialize_row(&row);
    value["key"] = Value::String(key);

    Ok((StatusCode::CREATED, Json(value)))
}

/// `GET /api/api-keys/:id`
pub async fn show(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    let row = fetch_owned(&state, id, auth.user_id).await?;
    Ok(Json(serialize_row(&row)))
}

/// `POST /api/api-keys/:id/revoke`
pub async fn revoke(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    fetch_owned(&state, id, auth.user_id).await?;
    let now = now_iso();
    sqlx::query("UPDATE api_keys SET revoked_at = $1, updated_at = $2 WHERE id = $3")
        .bind(&now)
        .bind(&now)
        .bind(id)
        .execute(&state.db.pool)
        .await?;
    let row = fetch_owned(&state, id, auth.user_id).await?;
    Ok(Json(serialize_row(&row)))
}

/// `POST /api/api-keys/:id/rotate`
pub async fn rotate(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    fetch_owned(&state, id, auth.user_id).await?;

    let (prefix, key, key_hash) = generate_key_material();
    let now = now_iso();
    sqlx::query(
        "UPDATE api_keys SET prefix = $1, key_hash = $2, last_used_at = NULL, revoked_at = NULL, \
         updated_at = $3 WHERE id = $4",
    )
    .bind(&prefix)
    .bind(&key_hash)
    .bind(&now)
    .bind(id)
    .execute(&state.db.pool)
    .await?;

    let row = fetch_owned(&state, id, auth.user_id).await?;
    let mut value = serialize_row(&row);
    value["key"] = Value::String(key);
    Ok(Json(value))
}

// --- validation (createApiKeyValidator) ---

fn validate_create(body: &Value) -> AppResult<(String, Vec<String>, Option<String>)> {
    let mut errors: Vec<ValidationFailure> = Vec::new();

    // name: string, trim, minLength 1, maxLength 120
    let name = match body.get("name") {
        None | Some(Value::Null) => {
            push(&mut errors, "name", "required", "The name field is required");
            None
        }
        Some(Value::String(s)) => {
            let trimmed = s.trim().to_string();
            if trimmed.is_empty() {
                push(&mut errors, "name", "minLength", "The name field must have at least 1 characters");
                None
            } else if trimmed.chars().count() > 120 {
                push(&mut errors, "name", "maxLength", "The name field must not be greater than 120 characters");
                None
            } else {
                Some(trimmed)
            }
        }
        Some(_) => {
            push(&mut errors, "name", "string", "The name field must be a string");
            None
        }
    };

    // scopes: array, minLength 1, each enum, distinct
    let scopes = validate_scopes(body, &mut errors);

    // expiresAt: iso8601 date, after today, nullable, optional
    let expires_at = match body.get("expiresAt") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => match validate_future_date(s) {
            Ok(v) => Some(v),
            Err((rule, msg)) => {
                push(&mut errors, "expiresAt", rule, &msg);
                None
            }
        },
        Some(_) => {
            push(&mut errors, "expiresAt", "date", "The expiresAt field must be a datetime value");
            None
        }
    };

    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }
    Ok((name.unwrap(), scopes.unwrap(), expires_at))
}

fn validate_scopes(body: &Value, errors: &mut Vec<ValidationFailure>) -> Option<Vec<String>> {
    match body.get("scopes") {
        None | Some(Value::Null) => {
            push(errors, "scopes", "required", "The scopes field is required");
            None
        }
        Some(Value::Array(items)) => {
            if items.is_empty() {
                push(errors, "scopes", "minLength", "The scopes field must have at least 1 items");
                return None;
            }
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                match item.as_str() {
                    Some(s) if API_KEY_SCOPES.contains(&s) => out.push(s.to_string()),
                    _ => {
                        push(
                            errors,
                            &format!("scopes.{i}"),
                            "enum",
                            &format!("The selected scopes.{i} is invalid"),
                        );
                        return None;
                    }
                }
            }
            // distinct
            let mut seen = std::collections::HashSet::new();
            for s in &out {
                if !seen.insert(s.clone()) {
                    push(errors, "scopes", "distinct", "The scopes field has duplicate values");
                    return None;
                }
            }
            Some(out)
        }
        Some(_) => {
            push(errors, "scopes", "array", "The scopes field must be an array");
            None
        }
    }
}

fn validate_future_date(s: &str) -> Result<String, (&'static str, String)> {
    let parsed = chrono::DateTime::parse_from_rfc3339(s)
        .map_err(|_| ("date", "The expiresAt field must be a datetime value".to_string()))?;
    if parsed.naive_utc().date() <= chrono::Utc::now().date_naive() {
        return Err(("after", "The expiresAt field must be a date after today".to_string()));
    }
    Ok(s.to_string())
}

fn push(errors: &mut Vec<ValidationFailure>, field: &str, rule: &str, message: &str) {
    errors.push(ValidationFailure::new(field, rule, message));
}
