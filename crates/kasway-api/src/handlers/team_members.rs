//! `/api/team-members/*` — TeamMembersController.
//! Merchant-guarded management routes + client-guarded self routes
//! (set-online/offline, update-profile, logout). Mail + transmit broadcasts
//! are deferred (no-op).

use crate::auth::{AuthClient, AuthMerchant};
use crate::auth_token;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::handlers::teams::{serialize_member, TeamMemberRow, MEMBER_COLS};
use crate::state::AppState;
use crate::util::now_iso;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Value};

const PAYMENT_OPERATION_PERMISSIONS: &[&str] = &[
    "payments.ops.read",
    "payments.ops.export",
    "payments.ops.adjust",
    "payments.ops.resolve_exceptions",
    "payments.ops.manage_webhooks",
    "payments.ops.manage_notifications",
    "payments.ops.manage_settings",
];

async fn load_member(state: &AppState, id: i64) -> AppResult<TeamMemberRow> {
    sqlx::query_as::<_, TeamMemberRow>(&format!("SELECT {MEMBER_COLS} FROM team_members WHERE id = ?"))
        .bind(id)
        .fetch_optional(&state.db.pool)
        .await?
        .ok_or_else(AppError::row_not_found)
}

/// findOrFail + ownership (teamMember.userId === merchant.id).
async fn load_owned(state: &AppState, user_id: i64, id: i64) -> AppResult<TeamMemberRow> {
    let m = load_member(state, id).await?;
    if m.user_id != user_id {
        return Err(AppError::Forbidden);
    }
    Ok(m)
}

// --- merchant-guarded ---

/// `DELETE /api/team-members/:id`
pub async fn destroy(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    let m = load_owned(&state, auth.user_id, id).await?;
    sqlx::query("DELETE FROM team_members WHERE id = ?").bind(m.id).execute(&state.db.pool).await?;
    Ok(Json(json!({ "success": true })))
}

/// `GET /api/team-members/:id/payment-permissions`
pub async fn payment_permissions(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    let m = load_owned(&state, auth.user_id, id).await?;
    let perms: Value = serde_json::from_str(&m.payment_permissions).unwrap_or(json!([]));
    Ok(Json(json!({ "permissions": perms })))
}

/// `PUT /api/team-members/:id/payment-permissions`
pub async fn update_payment_permissions(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let m = load_owned(&state, auth.user_id, id).await?;

    let raw = match body.get("permissions") {
        Some(Value::Array(a)) => a.clone(),
        _ => {
            return Err(AppError::Validation(vec![ValidationFailure {
                message: "The permissions field must be an array".into(),
                rule: "array".into(),
                field: "permissions".into(),
            }]))
        }
    };
    let mut errors = Vec::new();
    let mut perms = Vec::new();
    for (i, p) in raw.iter().enumerate() {
        match p.as_str() {
            Some(s) if PAYMENT_OPERATION_PERMISSIONS.contains(&s) => perms.push(s.to_string()),
            _ => errors.push(ValidationFailure {
                message: format!("The selected permissions.{i} is invalid"),
                rule: "enum".into(),
                field: format!("permissions.{i}"),
            }),
        }
    }
    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }
    // normalize: unique + filter valid, preserve order
    let mut seen = std::collections::HashSet::new();
    let normalized: Vec<String> = perms.into_iter().filter(|p| seen.insert(p.clone())).collect();
    let json_str = serde_json::to_string(&normalized).unwrap();

    sqlx::query("UPDATE team_members SET payment_permissions = ?, updated_at = ? WHERE id = ?")
        .bind(&json_str)
        .bind(now_iso())
        .bind(m.id)
        .execute(&state.db.pool)
        .await?;

    Ok(Json(json!({ "permissions": normalized })))
}

async fn set_member_status(
    state: &AppState,
    user_id: i64,
    id: i64,
    status: &str,
) -> AppResult<Json<Value>> {
    let m = load_owned(state, user_id, id).await?;
    sqlx::query("UPDATE team_members SET status = ?, updated_at = ? WHERE id = ?")
        .bind(status)
        .bind(now_iso())
        .bind(m.id)
        .execute(&state.db.pool)
        .await?;
    let m = load_member(state, id).await?;
    Ok(Json(serialize_member(&m)))
}

/// `POST /api/team-members/:id/activate`
pub async fn activate(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    set_member_status(&state, auth.user_id, id, "active").await
}

/// `POST /api/team-members/:id/deactivate`
pub async fn deactivate(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    set_member_status(&state, auth.user_id, id, "inactive").await
}

/// `POST /api/team-members/:id/promote`
pub async fn promote(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    let m = load_owned(&state, auth.user_id, id).await?;

    // current manager (firstOrFail -> 404 when none)
    let current_manager: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM team_members WHERE team_id = ? AND role = 'manager' LIMIT 1",
    )
    .bind(m.team_id)
    .fetch_optional(&state.db.pool)
    .await?;
    let Some(manager_id) = current_manager else {
        return Err(AppError::row_not_found());
    };

    let now = now_iso();
    sqlx::query("UPDATE team_members SET role = 'staff', updated_at = ? WHERE id = ?")
        .bind(&now).bind(manager_id).execute(&state.db.pool).await?;
    sqlx::query("UPDATE team_members SET role = 'manager', updated_at = ? WHERE id = ?")
        .bind(&now).bind(m.id).execute(&state.db.pool).await?;

    let m = load_member(&state, id).await?;
    Ok(Json(serialize_member(&m)))
}

/// `POST /api/team-members/:id/resend-invite`
pub async fn resend_invite(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    load_owned(&state, auth.user_id, id).await?;
    // SendInviteEmail dispatch -> deferred no-op
    Ok(Json(json!({ "success": true })))
}

// --- client-guarded (team member self) ---

/// `POST /api/team-members/set-online`
pub async fn set_online(
    auth: AuthClient,
    State(state): State<AppState>,
) -> AppResult<impl IntoResponse> {
    sqlx::query("UPDATE team_members SET is_online = 1, updated_at = ? WHERE id = ?")
        .bind(now_iso())
        .bind(auth.member_id)
        .execute(&state.db.pool)
        .await?;
    // transmit.broadcast -> deferred no-op
    Ok(StatusCode::OK)
}

/// `POST /api/team-members/set-offline`
pub async fn set_offline(
    auth: AuthClient,
    State(state): State<AppState>,
) -> AppResult<impl IntoResponse> {
    sqlx::query("UPDATE team_members SET is_online = 0, updated_at = ? WHERE id = ?")
        .bind(now_iso())
        .bind(auth.member_id)
        .execute(&state.db.pool)
        .await?;
    Ok(StatusCode::OK)
}

/// `PUT /api/team-members/update-profile`
pub async fn update_profile(
    auth: AuthClient,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let now = now_iso();
    if let Some(name) = body.get("name").and_then(|v| v.as_str()) {
        sqlx::query("UPDATE team_members SET name = ?, updated_at = ? WHERE id = ?")
            .bind(name).bind(&now).bind(auth.member_id).execute(&state.db.pool).await?;
    }
    if let Some(avatar) = body.get("avatarUrl").and_then(|v| v.as_str()) {
        sqlx::query("UPDATE team_members SET avatar_url = ?, updated_at = ? WHERE id = ?")
            .bind(avatar).bind(&now).bind(auth.member_id).execute(&state.db.pool).await?;
    }
    let m = load_member(&state, auth.member_id).await?;
    Ok(Json(serialize_member(&m)))
}

/// `POST /api/team-members/logout`
pub async fn logout(
    auth: AuthClient,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    auth_token::delete(&state.db.pool, &auth_token::CLIENT, auth.token_id).await?;
    Ok(Json(json!({ "success": true })))
}
