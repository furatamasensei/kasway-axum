//! `/api/payments/ops/notification-preferences` + `/api/payments/ops/notifications`
//! — PaymentNotificationsController + PaymentNotificationService.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::state::AppState;
use crate::util::{now_iso, paginator_meta};
use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

const CATEGORIES: &[&str] = &["payment_exception_created", "payment_exception_resolved", "payment_anomaly_detected", "webhook_delivery_failed", "webhook_endpoint_paused", "export_succeeded", "export_failed"];
const CHANNELS: &[&str] = &["email", "in_app"];

#[derive(Deserialize, Default)]
pub struct PageQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct PrefRow {
    id: i64,
    user_id: i64,
    category: String,
    channels: String,
    enabled: bool,
    created_at: Option<String>,
    updated_at: Option<String>,
}

fn serialize_pref(p: &PrefRow) -> Value {
    json!({
        "id": p.id,
        "userId": p.user_id,
        "category": p.category,
        "channels": serde_json::from_str::<Value>(&p.channels).unwrap_or(json!([])),
        "enabled": p.enabled,
        "createdAt": p.created_at,
        "updatedAt": p.updated_at,
    })
}

async fn ensure_defaults(state: &AppState, user_id: i64) -> AppResult<()> {
    let now = now_iso();
    for c in CATEGORIES {
        sqlx::query(
            "INSERT INTO payment_notification_preferences (user_id, category, channels, enabled, created_at, updated_at) \
             VALUES ($1, $2, '[\"email\",\"in_app\"]', 1, $3, $4) ON CONFLICT(user_id, category) DO NOTHING",
        )
        .bind(user_id).bind(c).bind(&now).bind(&now)
        .execute(&state.db.pool).await?;
    }
    Ok(())
}

async fn list_prefs(state: &AppState, user_id: i64) -> AppResult<Vec<Value>> {
    let rows = sqlx::query_as::<_, PrefRow>(
        "SELECT id, user_id, category, channels, enabled, created_at, updated_at FROM payment_notification_preferences WHERE user_id = $1 ORDER BY category ASC",
    )
    .bind(user_id)
    .fetch_all(&state.db.pool)
    .await?;
    Ok(rows.iter().map(serialize_pref).collect())
}

/// `GET /api/payments/ops/notification-preferences`
pub async fn preferences(auth: AuthMerchant, State(state): State<AppState>) -> AppResult<Json<Value>> {
    ensure_defaults(&state, auth.user_id).await?;
    Ok(Json(Value::Array(list_prefs(&state, auth.user_id).await?)))
}

/// `PUT /api/payments/ops/notification-preferences`
pub async fn update_preferences(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let prefs = body.get("preferences").and_then(|v| v.as_array())
        .filter(|a| !a.is_empty())
        .ok_or_else(|| AppError::validation_field("preferences", "minLength", "The preferences field must have at least 1 items"))?
        .clone();

    let now = now_iso();
    for (i, p) in prefs.iter().enumerate() {
        let category = p.get("category").and_then(|v| v.as_str()).filter(|s| CATEGORIES.contains(s))
            .ok_or_else(|| AppError::validation_field(&format!("preferences.{i}.category"), "enum", "The selected category is invalid"))?;
        let channels = p.get("channels").and_then(|v| v.as_array())
            .ok_or_else(|| AppError::validation_field(&format!("preferences.{i}.channels"), "array", "The channels field must be an array"))?;
        let mut seen = std::collections::HashSet::new();
        let mut chans = Vec::new();
        for c in channels {
            let cs = c.as_str().filter(|s| CHANNELS.contains(s))
                .ok_or_else(|| AppError::validation_field(&format!("preferences.{i}.channels"), "enum", "The selected channels is invalid"))?;
            if seen.insert(cs.to_string()) { chans.push(cs.to_string()); }
        }
        let enabled = p.get("enabled").and_then(|v| v.as_bool())
            .ok_or_else(|| AppError::validation_field(&format!("preferences.{i}.enabled"), "boolean", "The enabled field must be a boolean"))?;

        sqlx::query(
            "INSERT INTO payment_notification_preferences (user_id, category, channels, enabled, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT(user_id, category) DO UPDATE SET channels = excluded.channels, enabled = excluded.enabled, updated_at = excluded.updated_at",
        )
        .bind(auth.user_id).bind(category).bind(serde_json::to_string(&chans).unwrap()).bind(enabled as i64).bind(&now).bind(&now)
        .execute(&state.db.pool).await?;
    }
    Ok(Json(Value::Array(list_prefs(&state, auth.user_id).await?)))
}

#[derive(sqlx::FromRow)]
struct NotifRow {
    id: i64,
    user_id: i64,
    category: String,
    severity: String,
    title_key: String,
    body_key: String,
    resource_type: String,
    resource_id: String,
    read_at: Option<String>,
    metadata: String,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const NOTIF_COLS: &str = "id, user_id, category, severity, title_key, body_key, resource_type, resource_id, read_at, metadata, created_at, updated_at";

fn serialize_notif(n: &NotifRow) -> Value {
    json!({
        "id": n.id,
        "userId": n.user_id,
        "category": n.category,
        "severity": n.severity,
        "titleKey": n.title_key,
        "bodyKey": n.body_key,
        "resourceType": n.resource_type,
        "resourceId": n.resource_id,
        "readAt": n.read_at,
        "metadata": serde_json::from_str::<Value>(&n.metadata).unwrap_or(json!({})),
        "createdAt": n.created_at,
        "updatedAt": n.updated_at,
    })
}

/// `GET /api/payments/ops/notifications`
pub async fn index(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<PageQuery>) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).max(1);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_notifications WHERE user_id = $1").bind(auth.user_id).fetch_one(&state.db.pool).await?;
    let rows = sqlx::query_as::<_, NotifRow>(&format!("SELECT {NOTIF_COLS} FROM payment_notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"))
        .bind(auth.user_id).bind(per_page).bind((page - 1) * per_page).fetch_all(&state.db.pool).await?;
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": rows.iter().map(serialize_notif).collect::<Vec<_>>() })))
}

/// `POST /api/payments/ops/notifications/:id/read`
pub async fn read(auth: AuthMerchant, State(state): State<AppState>, Path(id): Path<i64>) -> AppResult<Json<Value>> {
    let notif: Option<NotifRow> = sqlx::query_as::<_, NotifRow>(&format!("SELECT {NOTIF_COLS} FROM payment_notifications WHERE user_id = $1 AND id = $2"))
        .bind(auth.user_id).bind(id).fetch_optional(&state.db.pool).await?;
    let notif = notif.ok_or_else(|| AppError::commerce(404, "Payment notification not found"))?;
    sqlx::query("UPDATE payment_notifications SET read_at = $1, updated_at = $2 WHERE id = $3").bind(now_iso()).bind(now_iso()).bind(notif.id).execute(&state.db.pool).await?;
    let notif = sqlx::query_as::<_, NotifRow>(&format!("SELECT {NOTIF_COLS} FROM payment_notifications WHERE id = $1")).bind(notif.id).fetch_one(&state.db.pool).await?;
    Ok(Json(serialize_notif(&notif)))
}

/// Test/seed helper exposed for integration tests is unnecessary; rows are seeded via SQL.
#[allow(dead_code)]
fn _unused() {
    let _ = ValidationFailure { message: String::new(), rule: String::new(), field: String::new() };
}
