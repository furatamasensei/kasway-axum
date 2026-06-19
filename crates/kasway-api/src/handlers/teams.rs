//! `/api/teams` — TeamsController. Email dispatch (invite / account mails) is a
//! deferred side effect (no-op here).

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::state::AppState;
use crate::util::{now_iso, paginator_meta};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(sqlx::FromRow)]
pub(crate) struct TeamRow {
    pub id: i64,
    pub user_id: i64,
    pub currency_id: Option<i64>,
    pub name: String,
    pub is_active: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

const TEAM_COLS: &str = "id, user_id, currency_id, name, is_active, created_at, updated_at";

#[derive(sqlx::FromRow)]
pub(crate) struct TeamMemberRow {
    pub id: i64,
    pub team_id: i64,
    pub user_id: i64,
    pub name: String,
    pub email: String,
    pub avatar_url: Option<String>,
    pub status: String,
    pub invitation_sent_at: Option<String>,
    pub joined_at: Option<String>,
    pub left_at: Option<String>,
    pub is_online: bool,
    pub role: String,
    pub payment_permissions: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

pub(crate) const MEMBER_COLS: &str = "id, team_id, user_id, name, email, avatar_url, status, \
    invitation_sent_at, joined_at, left_at, is_online, role, payment_permissions, created_at, updated_at";

pub(crate) fn serialize_member(m: &TeamMemberRow) -> Value {
    json!({
        "id": m.id,
        "teamId": m.team_id,
        "userId": m.user_id,
        "name": m.name,
        "email": m.email,
        "avatarUrl": m.avatar_url,
        "invitationSentAt": m.invitation_sent_at,
        "joinedAt": m.joined_at,
        "leftAt": m.left_at,
        "isOnline": m.is_online,
        "role": m.role,
        "status": m.status,
        "paymentPermissions": serde_json::from_str::<Value>(&m.payment_permissions).unwrap_or(json!([])),
        "createdAt": m.created_at,
        "updatedAt": m.updated_at,
    })
}

fn serialize_currency(c: &crate::handlers::currencies::Currency) -> Value {
    serde_json::to_value(c).unwrap()
}

fn serialize_team(team: &TeamRow, currency: Option<&Value>, members: Option<&[TeamMemberRow]>) -> Value {
    let mut obj = json!({
        "id": team.id,
        "userId": team.user_id,
        "currencyId": team.currency_id,
        "name": team.name,
        "isActive": team.is_active,
        "createdAt": team.created_at,
        "updatedAt": team.updated_at,
    });
    if let Value::Object(map) = &mut obj {
        if let Some(cur) = currency {
            map.insert("currency".into(), cur.clone());
        }
        if let Some(members) = members {
            map.insert(
                "teamMembers".into(),
                Value::Array(members.iter().map(serialize_member).collect()),
            );
        }
    }
    obj
}

async fn load_team(state: &AppState, id: i64) -> AppResult<TeamRow> {
    sqlx::query_as::<_, TeamRow>(&format!("SELECT {TEAM_COLS} FROM teams WHERE id = ?"))
        .bind(id)
        .fetch_optional(&state.db.pool)
        .await?
        .ok_or_else(AppError::row_not_found)
}

/// members ordered manager-first then id asc.
async fn load_members(state: &AppState, team_id: i64) -> AppResult<Vec<TeamMemberRow>> {
    Ok(sqlx::query_as::<_, TeamMemberRow>(&format!(
        "SELECT {MEMBER_COLS} FROM team_members WHERE team_id = ? \
         ORDER BY CASE WHEN role = 'manager' THEN 0 ELSE 1 END, id ASC"
    ))
    .bind(team_id)
    .fetch_all(&state.db.pool)
    .await?)
}

#[derive(Deserialize, Default)]
pub struct TeamQuery {
    page: Option<i64>,
    limit: Option<i64>,
}

/// `GET /api/teams`
pub async fn index(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Query(q): Query<TeamQuery>,
) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(10).max(1);
    let offset = (page - 1) * limit;

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM teams WHERE user_id = ?")
        .bind(auth.user_id)
        .fetch_one(&state.db.pool)
        .await?;

    let teams = sqlx::query_as::<_, TeamRow>(&format!(
        "SELECT {TEAM_COLS} FROM teams WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?"
    ))
    .bind(auth.user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db.pool)
    .await?;

    let mut data = Vec::with_capacity(teams.len());
    for team in &teams {
        let currency = match team.currency_id {
            Some(cid) => sqlx::query_as::<_, crate::handlers::currencies::Currency>(
                "SELECT id, type, code, name, symbol, country, locale, created_at, updated_at FROM currencies WHERE id = ?",
            )
            .bind(cid)
            .fetch_optional(&state.db.pool)
            .await?
            .map(|c| serialize_currency(&c)),
            None => None,
        };
        let members = load_members(&state, team.id).await?;
        data.push(serialize_team(team, currency.as_ref(), Some(&members)));
    }

    Ok(Json(json!({ "meta": paginator_meta(total, limit, page), "data": data })))
}

/// `POST /api/teams`
pub async fn store(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let input = validate_store_team(&state, auth.user_id, &body).await?;
    let now = now_iso();

    let result = sqlx::query(
        "INSERT INTO teams (user_id, currency_id, name, is_active, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(auth.user_id)
    .bind(input.currency_id)
    .bind(&input.name)
    .bind(input.is_active as i64)
    .bind(&now)
    .bind(&now)
    .execute(&state.db.pool)
    .await?;
    let team_id = result.last_insert_rowid();

    for m in &input.members {
        sqlx::query(
            "INSERT INTO team_members (user_id, team_id, name, email, role, status, is_online, invitation_sent_at, payment_permissions, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, 'invited', 0, ?, '[]', ?, ?)",
        )
        .bind(auth.user_id)
        .bind(team_id)
        .bind(&m.name)
        .bind(&m.email)
        .bind(&m.role)
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .execute(&state.db.pool)
        .await?;
        // SendInviteEmail dispatch -> deferred no-op
    }

    let team = load_team(&state, team_id).await?;
    Ok(Json(serialize_team(&team, None, None)))
}

/// `GET /api/teams/:id`
pub async fn show(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    let team = load_team(&state, id).await?;
    if team.user_id != auth.user_id {
        return Err(AppError::Forbidden);
    }
    let members = load_members(&state, team.id).await?;
    Ok(Json(serialize_team(&team, None, Some(&members))))
}

/// `PUT /api/teams/:id`
pub async fn update(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let team = load_team(&state, id).await?;
    if team.user_id != auth.user_id {
        return Err(AppError::Forbidden);
    }
    let input = validate_update_team(&state, auth.user_id, id, &body).await?;
    let now = now_iso();

    if let Some(name) = &input.name {
        sqlx::query("UPDATE teams SET name = ?, updated_at = ? WHERE id = ?")
            .bind(name).bind(&now).bind(team.id).execute(&state.db.pool).await?;
    }
    if let Some(cid) = input.currency_id {
        sqlx::query("UPDATE teams SET currency_id = ?, updated_at = ? WHERE id = ?")
            .bind(cid).bind(&now).bind(team.id).execute(&state.db.pool).await?;
    }

    // member sync by email (remove/add/update)
    if let Some(members) = &input.members {
        let existing = load_members(&state, team.id).await?;
        let input_emails: Vec<&str> = members.iter().map(|m| m.email.as_str()).collect();

        for ex in &existing {
            if !input_emails.contains(&ex.email.as_str()) {
                sqlx::query("DELETE FROM team_members WHERE id = ?").bind(ex.id).execute(&state.db.pool).await?;
            }
        }
        for m in members {
            if let Some(ex) = existing.iter().find(|e| e.email == m.email) {
                sqlx::query("UPDATE team_members SET name = ?, role = ?, updated_at = ? WHERE id = ?")
                    .bind(&m.name).bind(&m.role).bind(&now).bind(ex.id).execute(&state.db.pool).await?;
            } else {
                sqlx::query(
                    "INSERT INTO team_members (user_id, team_id, name, email, role, status, is_online, invitation_sent_at, payment_permissions, created_at, updated_at) \
                     VALUES (?, ?, ?, ?, ?, 'invited', 0, ?, '[]', ?, ?)",
                )
                .bind(auth.user_id).bind(team.id).bind(&m.name).bind(&m.email).bind(&m.role)
                .bind(&now).bind(&now).bind(&now).execute(&state.db.pool).await?;
            }
        }
    }

    let team = load_team(&state, id).await?;
    let members = load_members(&state, team.id).await?;
    Ok(Json(serialize_team(&team, None, Some(&members))))
}

/// `DELETE /api/teams/:id`
pub async fn destroy(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<impl IntoResponse> {
    let team = load_team(&state, id).await?;
    if team.user_id != auth.user_id {
        return Err(AppError::Forbidden);
    }
    // team_members cascade via FK
    sqlx::query("DELETE FROM teams WHERE id = ?").bind(team.id).execute(&state.db.pool).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/teams/:id/add-member`
pub async fn add_member(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let team = load_team(&state, id).await?;
    if team.user_id != auth.user_id {
        return Err(AppError::Forbidden);
    }
    let m = validate_member(&state, &body, None).await?;
    let now = now_iso();
    let result = sqlx::query(
        "INSERT INTO team_members (user_id, team_id, name, email, role, status, is_online, invitation_sent_at, payment_permissions, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, 'invited', 0, ?, '[]', ?, ?)",
    )
    .bind(team.user_id)
    .bind(team.id)
    .bind(&m.name)
    .bind(&m.email)
    .bind(&m.role)
    .bind(&now)
    .bind(&now)
    .bind(&now)
    .execute(&state.db.pool)
    .await?;
    let member_id = result.last_insert_rowid();

    let member = sqlx::query_as::<_, TeamMemberRow>(&format!(
        "SELECT {MEMBER_COLS} FROM team_members WHERE id = ?"
    ))
    .bind(member_id)
    .fetch_one(&state.db.pool)
    .await?;
    Ok(Json(serialize_member(&member)))
}

// --- validation ---

struct MemberInput {
    name: String,
    email: String,
    role: String,
}

struct StoreTeamInput {
    name: String,
    currency_id: i64,
    is_active: bool,
    members: Vec<MemberInput>,
}

struct UpdateTeamInput {
    name: Option<String>,
    currency_id: Option<i64>,
    members: Option<Vec<MemberInput>>,
}

fn vpush(errors: &mut Vec<ValidationFailure>, field: &str, rule: &str, message: &str) {
    errors.push(ValidationFailure {
        message: message.to_string(),
        rule: rule.to_string(),
        field: field.to_string(),
    });
}

async fn currency_exists(state: &AppState, id: i64) -> AppResult<bool> {
    let found: Option<i64> = sqlx::query_scalar("SELECT id FROM currencies WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db.pool)
        .await?;
    Ok(found.is_some())
}

fn parse_member(item: &Value, idx: usize, errors: &mut Vec<ValidationFailure>) -> Option<MemberInput> {
    let name = item.get("name").and_then(|v| v.as_str()).map(|s| s.trim().to_string());
    let email = item.get("email").and_then(|v| v.as_str()).map(|s| s.trim().to_string());
    let role = item.get("role").and_then(|v| v.as_str()).map(|s| s.to_string());
    let mut ok = true;
    let name = match name {
        Some(n) if n.chars().count() >= 2 && n.chars().count() <= 100 => n,
        _ => { vpush(errors, &format!("teamMembers.{idx}.name"), "minLength", "The teamMembers name must be at least 2 characters"); ok = false; String::new() }
    };
    let email = match email {
        Some(e) if e.contains('@') => e,
        _ => { vpush(errors, &format!("teamMembers.{idx}.email"), "email", "The teamMembers email must be a valid email address"); ok = false; String::new() }
    };
    let role = match role.as_deref() {
        Some("manager") | Some("staff") => role.unwrap(),
        _ => { vpush(errors, &format!("teamMembers.{idx}.role"), "enum", "The selected role is invalid"); ok = false; String::new() }
    };
    if ok { Some(MemberInput { name, email, role }) } else { None }
}

async fn validate_store_team(state: &AppState, user_id: i64, body: &Value) -> AppResult<StoreTeamInput> {
    let mut errors = Vec::new();

    let name = match body.get("name").and_then(|v| v.as_str()) {
        Some(n) if n.trim().chars().count() >= 3 && n.trim().chars().count() <= 100 => Some(n.trim().to_string()),
        _ => { vpush(&mut errors, "name", "minLength", "The name field must have at least 3 characters"); None }
    };
    if let Some(n) = &name {
        let dup: Option<i64> = sqlx::query_scalar("SELECT id FROM teams WHERE user_id = ? AND name = ? COLLATE NOCASE")
            .bind(user_id).bind(n).fetch_optional(&state.db.pool).await?;
        if dup.is_some() {
            vpush(&mut errors, "name", "database.unique", "The name has already been taken");
        }
    }

    let currency_id = body.get("currencyId").and_then(|v| v.as_i64());
    match currency_id {
        Some(cid) if currency_exists(state, cid).await? => {}
        _ => vpush(&mut errors, "currencyId", "database.exists", "The selected currencyId is invalid"),
    }

    let mut members = Vec::new();
    match body.get("teamMembers") {
        Some(Value::Array(arr)) if !arr.is_empty() => {
            for (i, item) in arr.iter().enumerate() {
                if let Some(m) = parse_member(item, i, &mut errors) {
                    members.push(m);
                }
            }
        }
        _ => vpush(&mut errors, "teamMembers", "minLength", "The teamMembers field must have at least 1 items"),
    }

    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }
    Ok(StoreTeamInput {
        name: name.unwrap(),
        currency_id: currency_id.unwrap(),
        is_active: body.get("isActive").and_then(|v| v.as_bool()).unwrap_or(true),
        members,
    })
}

async fn validate_update_team(state: &AppState, user_id: i64, team_id: i64, body: &Value) -> AppResult<UpdateTeamInput> {
    let mut errors = Vec::new();

    let name = match body.get("name") {
        None | Some(Value::Null) => None,
        Some(Value::String(n)) if n.trim().chars().count() >= 3 && n.trim().chars().count() <= 100 => Some(n.trim().to_string()),
        _ => { vpush(&mut errors, "name", "minLength", "The name field must have at least 3 characters"); None }
    };
    if let Some(n) = &name {
        let dup: Option<i64> = sqlx::query_scalar("SELECT id FROM teams WHERE user_id = ? AND name = ? AND id != ?")
            .bind(user_id).bind(n).bind(team_id).fetch_optional(&state.db.pool).await?;
        if dup.is_some() {
            vpush(&mut errors, "name", "database.unique", "The name has already been taken");
        }
    }

    let currency_id = body.get("currencyId").and_then(|v| v.as_i64());
    if let Some(cid) = currency_id {
        if !currency_exists(state, cid).await? {
            vpush(&mut errors, "currencyId", "database.exists", "The selected currencyId is invalid");
        }
    }

    let members = match body.get("teamMembers") {
        None | Some(Value::Null) => None,
        Some(Value::Array(arr)) if !arr.is_empty() => {
            let mut out = Vec::new();
            for (i, item) in arr.iter().enumerate() {
                if let Some(m) = parse_member(item, i, &mut errors) {
                    out.push(m);
                }
            }
            Some(out)
        }
        _ => { vpush(&mut errors, "teamMembers", "minLength", "The teamMembers field must have at least 1 items"); None }
    };

    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }
    Ok(UpdateTeamInput { name, currency_id, members })
}

/// addNewMemberValidator
async fn validate_member(state: &AppState, body: &Value, _exclude: Option<i64>) -> AppResult<MemberInput> {
    let mut errors = Vec::new();
    let m = parse_member(body, 0, &mut errors);
    // remap field names from teamMembers.0.X -> X
    for e in errors.iter_mut() {
        e.field = e.field.replace("teamMembers.0.", "");
    }
    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }
    let m = m.unwrap();
    let dup: Option<i64> = sqlx::query_scalar("SELECT id FROM team_members WHERE email = ? COLLATE NOCASE")
        .bind(&m.email).fetch_optional(&state.db.pool).await?;
    if dup.is_some() {
        return Err(AppError::Validation(vec![ValidationFailure {
            message: "The email has already been taken".into(),
            rule: "database.unique".into(),
            field: "email".into(),
        }]));
    }
    Ok(m)
}
