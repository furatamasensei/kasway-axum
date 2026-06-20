//! `/api/payments/ops/risk/*` — PaymentRiskController + PaymentRiskRuleService.
//! catalog/rule-hits(index/show)/review(acknowledge/dismiss/note)/report.
//! `evaluate` is the passive detection engine: a DB scan over invoices / failed
//! wallet submissions / payout-address changes / repeated client fingerprints.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::util::{now_iso, paginator_meta, sha256_hex};
use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::{Duration, Utc};
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

// ---- evaluate (#161 passive detection engine) ------------------------------

const HIGH_VALUE_INVOICE_THRESHOLD: i64 = 10_000_000_000;
const FAILED_WALLET_SUBMISSION_THRESHOLD: i64 = 2;
const CLIENT_FINGERPRINT_THRESHOLD: usize = 3;
const PAYOUT_CHANGE_WINDOW_HOURS: i64 = 24;
const RULE_VERSION: &str = "v1";

fn iso(dt: chrono::DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string()
}
fn parse_dt(s: &str) -> Option<chrono::DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc))
}
fn mask_address(v: &str) -> String {
    if v.chars().count() <= 16 {
        format!("{}...", v.chars().take(6).collect::<String>())
    } else {
        let chars: Vec<char> = v.chars().collect();
        let last6: String = chars[chars.len() - 6..].iter().collect();
        format!("{}...{}", chars[..10].iter().collect::<String>(), last6)
    }
}

struct PendingHit {
    rule_key: &'static str,
    severity: String,
    resource_type: &'static str,
    resource_id: String,
    reason: &'static str,
    input_snapshot: Value,
    thresholds: Value,
    window_start: String,
    window_end: String,
}

async fn record_hit(state: &AppState, h: &PendingHit, now_iso_str: &str) -> AppResult<HitRow> {
    let dedupe = sha256_hex(format!(
        "{EVALUATOR_VERSION}:{}:{}:{}:{}:{}:{}",
        // userId is embedded by caller via input_snapshot? No — match Adonis: include userId
        h.input_snapshot["__userId"].as_i64().unwrap_or(0),
        h.rule_key, h.resource_type, h.resource_id, h.window_start, h.window_end
    ).as_bytes());
    if let Some(existing) = sqlx::query_as::<_, HitRow>(&format!("SELECT {HIT_COLS} FROM payment_risk_rule_hits WHERE dedupe_key = ?"))
        .bind(&dedupe).fetch_optional(&state.db.pool).await?
    {
        return Ok(existing);
    }
    let user_id = h.input_snapshot["__userId"].as_i64().unwrap_or(0);
    let mut snapshot = h.input_snapshot.clone();
    if let Value::Object(o) = &mut snapshot { o.remove("__userId"); }
    let id = sqlx::query(
        "INSERT INTO payment_risk_rule_hits (user_id, rule_key, rule_version, severity, status, outcome, \
         resource_type, resource_id, reason, input_snapshot, thresholds, dedupe_key, evaluator_version, \
         detected_at, window_start, window_end, created_at, updated_at) \
         VALUES (?, ?, ?, ?, 'open', 'observed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id).bind(h.rule_key).bind(RULE_VERSION).bind(&h.severity).bind(h.resource_type)
    .bind(&h.resource_id).bind(h.reason).bind(snapshot.to_string()).bind(h.thresholds.to_string())
    .bind(&dedupe).bind(EVALUATOR_VERSION).bind(now_iso_str).bind(&h.window_start).bind(&h.window_end)
    .bind(now_iso_str).bind(now_iso_str)
    .execute(&state.db.pool).await?.last_insert_rowid();
    sqlx::query_as::<_, HitRow>(&format!("SELECT {HIT_COLS} FROM payment_risk_rule_hits WHERE id = ?"))
        .bind(id).fetch_one(&state.db.pool).await.map_err(Into::into)
}

/// `POST /api/payments/ops/risk/evaluate`
pub async fn evaluate(auth: AuthMerchant, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let uid = auth.user_id;
    let now = Utc::now();
    let now_str = iso(now);
    let week_start = iso(now - Duration::days(7));
    let day_start = iso(now - Duration::hours(24));
    let week_end = now_str.clone();
    let day_end = now_str.clone();
    let mut pending: Vec<PendingHit> = Vec::new();

    // 1. high-value invoices (with a KPR-1 intent) in the past week
    let hi = sqlx::query_as::<_, (i64, String, String, i64, Option<String>)>(
        "SELECT i.id, i.public_id, i.status, i.total_amount, i.payment_network FROM invoices i \
         JOIN kpr1_payment_intents k ON k.invoice_id = i.id \
         WHERE i.user_id = ? AND i.created_at BETWEEN ? AND ? AND i.total_amount >= ?",
    ).bind(uid).bind(&week_start).bind(&week_end).bind(HIGH_VALUE_INVOICE_THRESHOLD)
    .fetch_all(&state.db.pool).await?;
    for (id, public_id, status, total, network) in hi {
        pending.push(PendingHit {
            rule_key: "kpr1_high_value_invoice", severity: "review".into(), resource_type: "invoice",
            resource_id: id.to_string(), reason: "invoice_amount_exceeds_passive_review_threshold",
            input_snapshot: json!({ "__userId": uid, "invoiceId": id, "publicId": public_id, "status": status, "totalAmount": total.to_string(), "paymentNetwork": network }),
            thresholds: json!({ "amountSompi": HIGH_VALUE_INVOICE_THRESHOLD.to_string() }),
            window_start: week_start.clone(), window_end: week_end.clone(),
        });
    }

    // 2. repeated failed wallet submissions per KPR-1 invoice (week)
    let failed = sqlx::query_as::<_, (i64, String, i64)>(
        "SELECT i.id, i.public_id, COUNT(*) AS c FROM payments p JOIN invoices i ON i.id = p.invoice_id \
         WHERE i.user_id = ? AND p.status = 'failed' AND i.payment_address LIKE 'kpr1:%' \
         AND p.updated_at BETWEEN ? AND ? GROUP BY i.id, i.public_id HAVING COUNT(*) >= ?",
    ).bind(uid).bind(&week_start).bind(&week_end).bind(FAILED_WALLET_SUBMISSION_THRESHOLD)
    .fetch_all(&state.db.pool).await?;
    for (id, public_id, count) in failed {
        pending.push(PendingHit {
            rule_key: "kpr1_repeated_failed_wallet_submission",
            severity: if count >= 5 { "high".into() } else { "review".into() },
            resource_type: "invoice", resource_id: id.to_string(),
            reason: "failed_kpr1_wallet_submissions_for_same_invoice",
            input_snapshot: json!({ "__userId": uid, "invoiceId": id, "publicId": public_id, "failedSubmissionCount": count }),
            thresholds: json!({ "failedSubmissionCount": FAILED_WALLET_SUBMISSION_THRESHOLD }),
            window_start: week_start.clone(), window_end: week_end.clone(),
        });
    }

    // 3. payout address recent change
    let setup = sqlx::query_as::<_, (Option<String>, Option<String>)>(
        "SELECT kaspa_main_address, updated_at FROM setups WHERE user_id = ?",
    ).bind(uid).fetch_optional(&state.db.pool).await?;
    if let Some((Some(addr), setup_updated)) = setup {
        let current = addr.trim().to_string();
        if !current.is_empty() {
            if let Some(setup_upd) = setup_updated.as_deref().and_then(parse_dt) {
                let intents = sqlx::query_as::<_, (i64, i64, String, String, Option<String>)>(
                    "SELECT id, invoice_id, status, merchant_address, created_at FROM kpr1_payment_intents \
                     WHERE user_id = ? AND status IN ('submitted','observed','verified','settled') AND created_at BETWEEN ? AND ?",
                ).bind(uid).bind(&week_start).bind(&week_end).fetch_all(&state.db.pool).await?;
                for (id, invoice_id, status, merchant_addr, created) in intents {
                    let Some(created_dt) = created.as_deref().and_then(parse_dt) else { continue };
                    let changed_after = setup_upd > created_dt;
                    let recent = (setup_upd - created_dt).num_hours() <= PAYOUT_CHANGE_WINDOW_HOURS;
                    if changed_after && recent && current.to_lowercase() != merchant_addr.to_lowercase() {
                        pending.push(PendingHit {
                            rule_key: "kpr1_payout_address_recent_change", severity: "high".into(),
                            resource_type: "kpr1_payment_intent", resource_id: id.to_string(),
                            reason: "merchant_payout_address_changed_after_intent_creation",
                            input_snapshot: json!({ "__userId": uid, "intentId": id, "invoiceId": invoice_id, "intentStatus": status,
                                "originalMerchantAddress": mask_address(&merchant_addr), "currentMerchantAddress": mask_address(&current),
                                "setupUpdatedAt": setup_updated, "intentCreatedAt": created }),
                            thresholds: json!({ "changedWithinHours": PAYOUT_CHANGE_WINDOW_HOURS }),
                            window_start: week_start.clone(), window_end: week_end.clone(),
                        });
                    }
                }
            }
        }
    }

    // 4. repeated client fingerprints (day)
    let fp_intents = sqlx::query_as::<_, (i64, Option<String>)>(
        "SELECT id, metadata FROM kpr1_payment_intents WHERE user_id = ? AND updated_at BETWEEN ? AND ?",
    ).bind(uid).bind(&day_start).bind(&day_end).fetch_all(&state.db.pool).await?;
    let mut by_fp: std::collections::BTreeMap<String, Vec<i64>> = std::collections::BTreeMap::new();
    for (id, metadata) in fp_intents {
        let meta: Value = metadata.as_deref().and_then(|m| serde_json::from_str(m).ok()).unwrap_or(json!({}));
        let fp = meta["walletSubmission"]["clientFingerprint"].as_str().map(|s| s.trim()).filter(|s| !s.is_empty());
        if let Some(fp) = fp {
            by_fp.entry(sha256_hex(fp.as_bytes())).or_default().push(id);
        }
    }
    for (fp_hash, ids) in by_fp {
        if ids.len() < CLIENT_FINGERPRINT_THRESHOLD { continue; }
        pending.push(PendingHit {
            rule_key: "kpr1_repeated_client_fingerprint", severity: "info".into(),
            resource_type: "kpr1_client_fingerprint", resource_id: fp_hash.clone(),
            reason: "same_client_fingerprint_seen_across_multiple_kpr1_submissions",
            input_snapshot: json!({ "__userId": uid, "fingerprintHash": fp_hash, "submissionCount": ids.len(), "intentIds": ids.iter().take(10).collect::<Vec<_>>() }),
            thresholds: json!({ "submissionCount": CLIENT_FINGERPRINT_THRESHOLD }),
            window_start: day_start.clone(), window_end: day_end.clone(),
        });
    }

    let mut records = Vec::new();
    for h in &pending {
        let row = record_hit(&state, h, &now_str).await?;
        records.push(serialize_hit(&state, &row).await?);
    }
    Ok(Json(json!({ "passiveOnly": true, "data": records })))
}
