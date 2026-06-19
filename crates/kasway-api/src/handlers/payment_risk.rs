//! `/api/payments/ops/risk/*` — PaymentRiskController + PaymentRiskRuleService.
//! catalog/rule-hits(index/show)/review(acknowledge/dismiss/note)/report.
//! `evaluate` (the passive detection engine) is deferred — background scan over
//! invoices/wallet submissions/fingerprints.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::util::{now_iso, paginator_meta};
use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

const EVALUATOR_VERSION: &str = "passive-risk-v1";

fn catalog_value() -> Value {
    json!([
        { "key": "kpr1_high_value_invoice", "version": "v1", "description": "KPR-1 invoice amount meets the passive review threshold.", "severity": "review", "owner": "payment_operations", "thresholdSummary": "invoice total >= 10000000000 sompi", "passiveOnly": true, "rolloutStatus": "active" },
        { "key": "kpr1_repeated_failed_wallet_submission", "version": "v1", "description": "Multiple failed KPR-1 wallet submissions are present for the same invoice.", "severity": "review", "owner": "payment_operations", "thresholdSummary": "failed KPR-1 wallet submissions for one invoice >= 2", "passiveOnly": true, "rolloutStatus": "active" },
        { "key": "kpr1_payout_address_recent_change", "version": "v1", "description": "Current merchant payout address differs from an active KPR-1 intent output.", "severity": "high", "owner": "payment_operations", "thresholdSummary": "setup updated within 24 hours after intent creation", "passiveOnly": true, "rolloutStatus": "active" },
        { "key": "kpr1_repeated_client_fingerprint", "version": "v1", "description": "The same wallet client fingerprint appears across several KPR-1 submissions.", "severity": "info", "owner": "payment_operations", "thresholdSummary": "same redacted client fingerprint count >= 3", "passiveOnly": true, "rolloutStatus": "active" },
    ])
}

#[derive(Deserialize, Default)]
pub struct RiskQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
    #[serde(rename = "ruleKey")]
    rule_key: Option<String>,
    status: Option<String>,
    severity: Option<String>,
    #[serde(rename = "resourceType")]
    resource_type: Option<String>,
}

#[derive(sqlx::FromRow)]
struct HitRow {
    id: i64,
    user_id: i64,
    rule_key: String,
    rule_version: String,
    severity: String,
    status: String,
    outcome: String,
    resource_type: String,
    resource_id: String,
    reason: String,
    input_snapshot: String,
    thresholds: String,
    dedupe_key: String,
    evaluator_version: String,
    detected_at: String,
    window_start: String,
    window_end: String,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const HIT_COLS: &str = "id, user_id, rule_key, rule_version, severity, status, outcome, resource_type, \
    resource_id, reason, input_snapshot, thresholds, dedupe_key, evaluator_version, detected_at, \
    window_start, window_end, created_at, updated_at";

async fn review_events(state: &AppState, hit_id: i64) -> AppResult<Vec<Value>> {
    let rows = sqlx::query_as::<_, (i64, i64, i64, Option<i64>, String, String, String, Option<String>, Option<String>, String, Option<String>, Option<String>)>(
        "SELECT id, risk_rule_hit_id, user_id, reviewer_user_id, action, previous_status, next_status, reason, note, metadata, created_at, updated_at \
         FROM payment_risk_review_events WHERE risk_rule_hit_id = ? ORDER BY created_at ASC",
    ).bind(hit_id).fetch_all(&state.db.pool).await?;
    Ok(rows.into_iter().map(|(id, hit, uid, rev, action, prev, next, reason, note, meta, c, u)| json!({
        "id": id, "riskRuleHitId": hit, "userId": uid, "reviewerUserId": rev, "action": action,
        "previousStatus": prev, "nextStatus": next, "reason": reason, "note": note,
        "metadata": serde_json::from_str::<Value>(&meta).unwrap_or(json!({})), "createdAt": c, "updatedAt": u,
    })).collect())
}

async fn serialize_hit(state: &AppState, h: &HitRow) -> AppResult<Value> {
    Ok(json!({
        "id": h.id,
        "userId": h.user_id,
        "ruleKey": h.rule_key,
        "ruleVersion": h.rule_version,
        "severity": h.severity,
        "status": h.status,
        "outcome": h.outcome,
        "resourceType": h.resource_type,
        "resourceId": h.resource_id,
        "reason": h.reason,
        "inputSnapshot": serde_json::from_str::<Value>(&h.input_snapshot).unwrap_or(json!({})),
        "thresholds": serde_json::from_str::<Value>(&h.thresholds).unwrap_or(json!({})),
        "dedupeKey": h.dedupe_key,
        "evaluatorVersion": h.evaluator_version,
        "detectedAt": h.detected_at,
        "windowStart": h.window_start,
        "windowEnd": h.window_end,
        "createdAt": h.created_at,
        "updatedAt": h.updated_at,
        "reviewEvents": review_events(state, h.id).await?,
    }))
}

async fn load_hit(state: &AppState, user_id: i64, id: i64) -> AppResult<HitRow> {
    sqlx::query_as::<_, HitRow>(&format!("SELECT {HIT_COLS} FROM payment_risk_rule_hits WHERE user_id = ? AND id = ?"))
        .bind(user_id).bind(id).fetch_optional(&state.db.pool).await?
        .ok_or_else(|| AppError::commerce(404, "Payment risk rule hit not found"))
}

/// `GET /api/payments/ops/risk/catalog`
pub async fn catalog(_auth: AuthMerchant) -> Json<Value> {
    Json(json!({ "passiveOnly": true, "evaluatorVersion": EVALUATOR_VERSION, "rules": catalog_value() }))
}

/// `GET /api/payments/ops/risk/rule-hits`
pub async fn index(auth: AuthMerchant, State(state): State<AppState>, Query(q): Query<RiskQuery>) -> AppResult<Json<Value>> {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(25).max(1);
    let mut filter = String::from("user_id = ?");
    if q.rule_key.is_some() { filter.push_str(" AND rule_key = ?"); }
    if q.status.is_some() { filter.push_str(" AND status = ?"); }
    if q.severity.is_some() { filter.push_str(" AND severity = ?"); }
    if q.resource_type.is_some() { filter.push_str(" AND resource_type = ?"); }

    let count_sql = format!("SELECT COUNT(*) FROM payment_risk_rule_hits WHERE {filter}");
    let mut cq = sqlx::query_scalar::<_, i64>(&count_sql).bind(auth.user_id);
    if let Some(v) = &q.rule_key { cq = cq.bind(v.clone()); }
    if let Some(v) = &q.status { cq = cq.bind(v.clone()); }
    if let Some(v) = &q.severity { cq = cq.bind(v.clone()); }
    if let Some(v) = &q.resource_type { cq = cq.bind(v.clone()); }
    let total = cq.fetch_one(&state.db.pool).await?;

    let list_sql = format!("SELECT {HIT_COLS} FROM payment_risk_rule_hits WHERE {filter} ORDER BY detected_at DESC LIMIT {per_page} OFFSET {}", (page - 1) * per_page);
    let mut lq = sqlx::query_as::<_, HitRow>(&list_sql).bind(auth.user_id);
    if let Some(v) = &q.rule_key { lq = lq.bind(v.clone()); }
    if let Some(v) = &q.status { lq = lq.bind(v.clone()); }
    if let Some(v) = &q.severity { lq = lq.bind(v.clone()); }
    if let Some(v) = &q.resource_type { lq = lq.bind(v.clone()); }
    let rows = lq.fetch_all(&state.db.pool).await?;
    let mut data = Vec::new();
    for h in &rows { data.push(serialize_hit(&state, h).await?); }
    Ok(Json(json!({ "passiveOnly": true, "meta": paginator_meta(total, per_page, page), "data": data })))
}

/// `GET /api/payments/ops/risk/rule-hits/:id`
pub async fn show(auth: AuthMerchant, State(state): State<AppState>, Path(id): Path<i64>) -> AppResult<Json<Value>> {
    let h = load_hit(&state, auth.user_id, id).await?;
    Ok(Json(serialize_hit(&state, &h).await?))
}

async fn review(auth_id: i64, state: &AppState, id: i64, action: &str, body: &Value) -> AppResult<Json<Value>> {
    let hit = load_hit(state, auth_id, id).await?;
    let next = match action {
        "acknowledge" => "acknowledged",
        "dismiss" => "dismissed",
        _ => hit.status.as_str(),
    }.to_string();
    let reason = body.get("reason").and_then(|v| v.as_str());
    let note = body.get("note").and_then(|v| v.as_str());
    let metadata = body.get("metadata").filter(|v| v.is_object()).cloned().unwrap_or(json!({}));
    let now = now_iso();
    sqlx::query("UPDATE payment_risk_rule_hits SET status = ?, updated_at = ? WHERE id = ?").bind(&next).bind(&now).bind(hit.id).execute(&state.db.pool).await?;
    sqlx::query(
        "INSERT INTO payment_risk_review_events (risk_rule_hit_id, user_id, reviewer_user_id, action, previous_status, next_status, reason, note, metadata, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(hit.id).bind(hit.user_id).bind(auth_id).bind(action).bind(&hit.status).bind(&next).bind(reason).bind(note).bind(metadata.to_string()).bind(&now).bind(&now)
    .execute(&state.db.pool).await?;
    let hit = load_hit(state, auth_id, id).await?;
    Ok(Json(serialize_hit(state, &hit).await?))
}

pub async fn acknowledge(auth: AuthMerchant, State(state): State<AppState>, Path(id): Path<i64>, Json(body): Json<Value>) -> AppResult<Json<Value>> {
    review(auth.user_id, &state, id, "acknowledge", &body).await
}
pub async fn dismiss(auth: AuthMerchant, State(state): State<AppState>, Path(id): Path<i64>, Json(body): Json<Value>) -> AppResult<Json<Value>> {
    review(auth.user_id, &state, id, "dismiss", &body).await
}
pub async fn note(auth: AuthMerchant, State(state): State<AppState>, Path(id): Path<i64>, Json(body): Json<Value>) -> AppResult<Json<Value>> {
    review(auth.user_id, &state, id, "note", &body).await
}

/// `GET /api/payments/ops/risk/report`
pub async fn report(auth: AuthMerchant, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let hits = sqlx::query_as::<_, HitRow>(&format!("SELECT {HIT_COLS} FROM payment_risk_rule_hits WHERE user_id = ? ORDER BY detected_at DESC"))
        .bind(auth.user_id).fetch_all(&state.db.pool).await?;

    let count_by = |f: &dyn Fn(&HitRow) -> String| -> Value {
        let mut m = serde_json::Map::new();
        for h in &hits {
            let k = f(h);
            let n = m.get(&k).and_then(|v| v.as_i64()).unwrap_or(0) + 1;
            m.insert(k, json!(n));
        }
        Value::Object(m)
    };
    let by_rule = count_by(&|h| h.rule_key.clone());
    let by_severity = count_by(&|h| h.severity.clone());
    let by_status = count_by(&|h| h.status.clone());

    let mut recent_high = Vec::new();
    for h in hits.iter().filter(|h| h.severity == "high").take(10) {
        recent_high.push(serialize_hit(&state, h).await?);
    }

    // topAffectedResources
    let mut counts: std::collections::HashMap<String, (String, String, i64)> = std::collections::HashMap::new();
    for h in &hits {
        let key = format!("{}:{}", h.resource_type, h.resource_id);
        let e = counts.entry(key).or_insert((h.resource_type.clone(), h.resource_id.clone(), 0));
        e.2 += 1;
    }
    let mut top: Vec<(String, String, i64)> = counts.into_values().collect();
    top.sort_by(|a, b| b.2.cmp(&a.2));
    let top_affected: Vec<Value> = top.into_iter().take(10).map(|(rt, ri, c)| json!({ "resourceType": rt, "resourceId": ri, "count": c })).collect();

    let rules: Vec<Value> = catalog_value().as_array().unwrap().iter().map(|r| {
        let key = r["key"].as_str().unwrap();
        let mut obj = r.clone();
        obj["recentHitCount"] = json!(by_rule.get(key).and_then(|v| v.as_i64()).unwrap_or(0));
        obj
    }).collect();

    Ok(Json(json!({
        "passiveOnly": true,
        "activeEnforcement": false,
        "evaluatorVersion": EVALUATOR_VERSION,
        "totals": { "total": hits.len(), "byRule": by_rule, "bySeverity": by_severity, "byStatus": by_status },
        "rules": rules,
        "topAffectedResources": top_affected,
        "recentHighSeverity": recent_high,
        "stopConditionsForActiveEnforcement": [
            "legal_finance_support_signoff_missing",
            "operator_review_process_missing",
            "rule_noise_rate_unmeasured",
            "merchant_communication_not_approved",
        ],
    })))
}
