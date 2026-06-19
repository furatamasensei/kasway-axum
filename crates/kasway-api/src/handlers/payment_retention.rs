//! `/api/payments/ops/retention-policy` + `/retention-runs`
//! — PaymentRetentionPoliciesController + PaymentRetentionPolicyService.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::util::{now_iso, paginator_meta};
use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize, Default)]
pub struct PageQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct PolicyRow {
    exports_retention_days: i64,
    evidence_packs_retention_days: i64,
    notifications_retention_days: i64,
    webhook_response_body_retention_days: i64,
    support_notes_retention_days: Option<i64>,
    anomaly_signals_retention_days: i64,
}

const POLICY_COLS: &str = "exports_retention_days, evidence_packs_retention_days, notifications_retention_days, \
    webhook_response_body_retention_days, support_notes_retention_days, anomaly_signals_retention_days";

fn default_snapshot() -> Value {
    json!({
        "exportsRetentionDays": 7,
        "evidencePacksRetentionDays": 7,
        "notificationsRetentionDays": 30,
        "webhookResponseBodyRetentionDays": 30,
        "supportNotesRetentionDays": Value::Null,
        "anomalySignalsRetentionDays": 30,
    })
}

fn snapshot(p: &PolicyRow) -> Value {
    json!({
        "exportsRetentionDays": p.exports_retention_days,
        "evidencePacksRetentionDays": p.evidence_packs_retention_days,
        "notificationsRetentionDays": p.notifications_retention_days,
        "webhookResponseBodyRetentionDays": p.webhook_response_body_retention_days,
        "supportNotesRetentionDays": p.support_notes_retention_days,
        "anomalySignalsRetentionDays": p.anomaly_signals_retention_days,
    })
}

async fn load_policy(state: &AppState, user_id: i64) -> AppResult<Option<PolicyRow>> {
    Ok(sqlx::query_as::<_, PolicyRow>(&format!("SELECT {POLICY_COLS} FROM payment_retention_policies WHERE user_id = ?"))
        .bind(user_id).fetch_optional(&state.db.pool).await?)
}

/// `GET /api/payments/ops/retention-policy`
pub async fn policy(auth: AuthMerchant, State(state): State<AppState>) -> AppResult<Json<Value>> {
    Ok(Json(match load_policy(&state, auth.user_id).await? {
        Some(p) => snapshot(&p),
        None => default_snapshot(),
    }))
}

const FIELD_MAP: &[(&str, &str)] = &[
    ("exportsRetentionDays", "exports_retention_days"),
    ("evidencePacksRetentionDays", "evidence_packs_retention_days"),
    ("notificationsRetentionDays", "notifications_retention_days"),
    ("webhookResponseBodyRetentionDays", "webhook_response_body_retention_days"),
    ("supportNotesRetentionDays", "support_notes_retention_days"),
    ("anomalySignalsRetentionDays", "anomaly_signals_retention_days"),
];

/// `PUT /api/payments/ops/retention-policy`
pub async fn update_policy(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    // validation: each provided field is an int >= 1 (supportNotes nullable)
    for (json_key, _) in FIELD_MAP {
        if let Some(v) = body.get(*json_key) {
            if v.is_null() && *json_key == "supportNotesRetentionDays" {
                continue;
            }
            match v.as_i64() {
                Some(n) if n >= 1 => {}
                _ => return Err(AppError::validation_field(json_key, "min", &format!("The {json_key} field must be at least 1"))),
            }
        }
    }

    // current snapshot (default if none) then merge provided
    let current = match load_policy(&state, auth.user_id).await? {
        Some(p) => snapshot(&p),
        None => default_snapshot(),
    };
    let mut merged = current.as_object().cloned().unwrap();
    for (json_key, _) in FIELD_MAP {
        if let Some(v) = body.get(*json_key) {
            merged.insert((*json_key).into(), v.clone());
        }
    }
    let m = Value::Object(merged.clone());
    let now = now_iso();
    let support = m["supportNotesRetentionDays"].as_i64();

    sqlx::query(
        "INSERT INTO payment_retention_policies (user_id, exports_retention_days, evidence_packs_retention_days, \
         notifications_retention_days, webhook_response_body_retention_days, support_notes_retention_days, \
         anomaly_signals_retention_days, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(user_id) DO UPDATE SET exports_retention_days = excluded.exports_retention_days, \
         evidence_packs_retention_days = excluded.evidence_packs_retention_days, \
         notifications_retention_days = excluded.notifications_retention_days, \
         webhook_response_body_retention_days = excluded.webhook_response_body_retention_days, \
         support_notes_retention_days = excluded.support_notes_retention_days, \
         anomaly_signals_retention_days = excluded.anomaly_signals_retention_days, updated_at = excluded.updated_at",
    )
    .bind(auth.user_id)
    .bind(m["exportsRetentionDays"].as_i64().unwrap_or(7))
    .bind(m["evidencePacksRetentionDays"].as_i64().unwrap_or(7))
    .bind(m["notificationsRetentionDays"].as_i64().unwrap_or(30))
    .bind(m["webhookResponseBodyRetentionDays"].as_i64().unwrap_or(30))
    .bind(support)
    .bind(m["anomalySignalsRetentionDays"].as_i64().unwrap_or(30))
    .bind(&now)
    .bind(&now)
    .execute(&state.db.pool)
    .await?;

    Ok(Json(m))
}

#[derive(sqlx::FromRow)]
struct RunRow {
    id: i64,
    status: String,
    started_at: String,
    finished_at: Option<String>,
    exports_expired_count: i64,
    evidence_packs_expired_count: i64,
    notifications_deleted_count: i64,
    webhook_response_bodies_redacted_count: i64,
    support_notes_deleted_count: i64,
    anomaly_signals_deleted_count: i64,
    errors: String,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const RUN_COLS: &str = "id, status, started_at, finished_at, exports_expired_count, evidence_packs_expired_count, \
    notifications_deleted_count, webhook_response_bodies_redacted_count, support_notes_deleted_count, \
    anomaly_signals_deleted_count, errors, created_at, updated_at";

/// `GET /api/payments/ops/retention-runs`
pub async fn retention_runs(_auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<PageQuery>) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).max(1);
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_retention_runs").fetch_one(&state.db.pool).await?;
    let rows = sqlx::query_as::<_, RunRow>(&format!("SELECT {RUN_COLS} FROM payment_retention_runs ORDER BY created_at DESC LIMIT ? OFFSET ?"))
        .bind(per_page).bind((page - 1) * per_page).fetch_all(&state.db.pool).await?;
    let data: Vec<Value> = rows.iter().map(|r| json!({
        "id": r.id,
        "status": r.status,
        "startedAt": r.started_at,
        "finishedAt": r.finished_at,
        "exportsExpiredCount": r.exports_expired_count,
        "evidencePacksExpiredCount": r.evidence_packs_expired_count,
        "notificationsDeletedCount": r.notifications_deleted_count,
        "webhookResponseBodiesRedactedCount": r.webhook_response_bodies_redacted_count,
        "supportNotesDeletedCount": r.support_notes_deleted_count,
        "anomalySignalsDeletedCount": r.anomaly_signals_deleted_count,
        "errorCount": serde_json::from_str::<Value>(&r.errors).ok().and_then(|v| v.as_array().map(|a| a.len())).unwrap_or(0),
        "createdAt": r.created_at,
        "updatedAt": r.updated_at,
    })).collect();
    Ok(Json(json!({ "meta": paginator_meta(total, per_page, page), "data": data })))
}
