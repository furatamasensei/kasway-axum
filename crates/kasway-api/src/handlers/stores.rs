//! `/api/stores` — StoresController + StoreService.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::state::AppState;
use crate::store_context::{assert_can_create_new_payments, ensure_default_store};
use crate::util::now_iso;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use rand::RngCore;
use serde_json::{json, Value};

#[derive(sqlx::FromRow)]
pub(crate) struct StoreRow {
    id: i64,
    user_id: i64,
    public_id: String,
    name: String,
    slug: Option<String>,
    status: String,
    is_included: bool,
    is_default: bool,
    metadata: Option<String>,
    disabled_at: Option<String>,
    archived_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const STORE_COLS: &str = "id, user_id, public_id, name, slug, status, is_included, is_default, \
    metadata, disabled_at, archived_at, created_at, updated_at";

fn serialize_store(s: &StoreRow) -> Value {
    let metadata = match &s.metadata {
        None => Value::Null,
        Some(m) => serde_json::from_str(m).unwrap_or(Value::Null),
    };
    json!({
        "id": s.id,
        "userId": s.user_id,
        "publicId": s.public_id,
        "name": s.name,
        "slug": s.slug,
        "status": s.status,
        "isIncluded": s.is_included,
        "isDefault": s.is_default,
        "metadata": metadata,
        "disabledAt": s.disabled_at,
        "archivedAt": s.archived_at,
        "createdAt": s.created_at,
        "updatedAt": s.updated_at,
    })
}

async fn load_owned_store(state: &AppState, user_id: i64, id: i64) -> AppResult<StoreRow> {
    sqlx::query_as::<_, StoreRow>(&format!(
        "SELECT {STORE_COLS} FROM stores WHERE user_id = $1 AND id = $2"
    ))
    .bind(user_id)
    .bind(id)
    .fetch_optional(&state.db.pool)
    .await?
    .ok_or_else(|| AppError::commerce(404, "Store not found"))
}

async fn ensure_slug_available(
    state: &AppState,
    user_id: i64,
    slug: &Option<String>,
    except_id: Option<i64>,
) -> AppResult<()> {
    let Some(slug) = slug else { return Ok(()) };
    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM stores WHERE user_id = $1 AND slug = $2 AND id != $3",
    )
    .bind(user_id)
    .bind(slug)
    .bind(except_id.unwrap_or(0))
    .fetch_optional(&state.db.pool)
    .await?;
    if existing.is_some() {
        return Err(AppError::commerce(422, "Store slug has already been used"));
    }
    Ok(())
}

/// `GET /api/stores`
pub async fn index(auth: AuthMerchant, State(state): State<AppState>) -> AppResult<Json<Value>> {
    ensure_default_store(&state, auth.user_id).await?;
    let stores = sqlx::query_as::<_, StoreRow>(&format!(
        "SELECT {STORE_COLS} FROM stores WHERE user_id = $1 ORDER BY is_default DESC, id ASC"
    ))
    .bind(auth.user_id)
    .fetch_all(&state.db.pool)
    .await?;
    Ok(Json(Value::Array(stores.iter().map(serialize_store).collect())))
}

/// `POST /api/stores`
pub async fn store(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<(StatusCode, Json<Value>)> {
    let (name, slug, metadata) = validate_store(&body, true)?;
    ensure_default_store(&state, auth.user_id).await?;
    ensure_slug_available(&state, auth.user_id, &slug, None).await?;

    // metadata merged with { entitlementRequired: true }
    let mut meta = metadata.unwrap_or_else(|| json!({}));
    if let Value::Object(map) = &mut meta {
        map.insert("entitlementRequired".into(), json!(true));
    }
    let now = now_iso();
    let public_id = format!("store_{}", random_hex(12));

    let id: i64 = sqlx::query_scalar::<_, i64>(
        "INSERT INTO stores \
         (user_id, public_id, name, slug, status, is_included, is_default, metadata, disabled_at, archived_at, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 'disabled', 0, 0, $5, $6, NULL, $7, $8) RETURNING id",
    )
    .bind(auth.user_id)
    .bind(&public_id)
    .bind(name.unwrap())
    .bind(&slug)
    .bind(meta.to_string())
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .fetch_one(&state.db.pool)
    .await?;
    // NOTE: markPaidStorePendingEntitlement (pending entitlement) is a side
    // effect not surfaced in the response; deferred to the entitlements slice.

    let s = load_owned_store(&state, auth.user_id, id).await?;
    Ok((StatusCode::CREATED, Json(serialize_store(&s))))
}

/// `GET /api/stores/:id`
pub async fn show(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    ensure_default_store(&state, auth.user_id).await?;
    let s = load_owned_store(&state, auth.user_id, id).await?;
    Ok(Json(serialize_store(&s)))
}

/// `PUT /api/stores/:id`
pub async fn update(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let (name, slug, metadata) = validate_store(&body, false)?;
    ensure_default_store(&state, auth.user_id).await?;
    let s = load_owned_store(&state, auth.user_id, id).await?;

    // slug uniqueness only when changed
    if body.get("slug").is_some() && slug != s.slug {
        ensure_slug_available(&state, auth.user_id, &slug, Some(s.id)).await?;
    }

    let now = now_iso();
    if let Some(name) = name {
        sqlx::query("UPDATE stores SET name = $1, updated_at = $2 WHERE id = $3")
            .bind(name).bind(&now).bind(s.id).execute(&state.db.pool).await?;
    }
    if body.get("slug").is_some() {
        sqlx::query("UPDATE stores SET slug = $1, updated_at = $2 WHERE id = $3")
            .bind(&slug).bind(&now).bind(s.id).execute(&state.db.pool).await?;
    }
    if body.get("metadata").is_some() {
        let meta_str = metadata.map(|m| m.to_string());
        sqlx::query("UPDATE stores SET metadata = $1, updated_at = $2 WHERE id = $3")
            .bind(&meta_str).bind(&now).bind(s.id).execute(&state.db.pool).await?;
    }

    let s = load_owned_store(&state, auth.user_id, id).await?;
    Ok(Json(serialize_store(&s)))
}

/// `POST /api/stores/:id/default`
pub async fn set_default(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    ensure_default_store(&state, auth.user_id).await?;
    let s = load_owned_store(&state, auth.user_id, id).await?;
    assert_can_create_new_payments(&state, s.id).await?;

    // clear other defaults first to respect the partial-unique index
    sqlx::query("UPDATE stores SET is_default = 0 WHERE user_id = $1")
        .bind(auth.user_id)
        .execute(&state.db.pool)
        .await?;
    sqlx::query("UPDATE stores SET is_default = 1, updated_at = $1 WHERE id = $2")
        .bind(now_iso())
        .bind(s.id)
        .execute(&state.db.pool)
        .await?;

    let s = load_owned_store(&state, auth.user_id, id).await?;
    Ok(Json(serialize_store(&s)))
}

// --- validation (create/updateStoreValidator) ---

fn is_valid_slug(s: &str) -> bool {
    // ^[a-z0-9][a-z0-9-]*$, 1..80
    !s.is_empty()
        && s.len() <= 80
        && s.chars().next().map(|c| c.is_ascii_lowercase() || c.is_ascii_digit()).unwrap_or(false)
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Returns (name, slug, metadata). `name_required` toggles create vs update.
#[allow(clippy::type_complexity)]
fn validate_store(
    body: &Value,
    name_required: bool,
) -> AppResult<(Option<String>, Option<String>, Option<Value>)> {
    let mut errors = Vec::new();

    let name = match body.get("name") {
        Some(Value::String(s)) if !s.trim().is_empty() && s.trim().chars().count() <= 255 => {
            Some(s.trim().to_string())
        }
        None if !name_required => None,
        _ => {
            errors.push(ValidationFailure {
                message: "The name field is required".into(),
                rule: "required".into(),
                field: "name".into(),
            });
            None
        }
    };

    let slug = match body.get("slug") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if is_valid_slug(s.trim()) => Some(s.trim().to_string()),
        Some(_) => {
            errors.push(ValidationFailure {
                message: "The slug field format is invalid".into(),
                rule: "regex".into(),
                field: "slug".into(),
            });
            None
        }
    };

    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }

    let metadata = body.get("metadata").filter(|v| !v.is_null()).cloned();
    Ok((name, slug, metadata))
}

fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
