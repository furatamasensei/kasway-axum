//! Permissionless evaluator marketplace and signed encrypted dispute protocol.
//!
//! Backend is deliberately a verifier/indexer. It stores public profile terms,
//! canonical commitments, signatures, ciphertext, and chain references; it has
//! no participant private keys and never receives case plaintext.
//!
//! Every signed payload carries the v1 envelope (`domain`, `protocolVersion`,
//! `network`, `action`, `nonce`, `expiresAt`); `(signer, nonce)` is consumed
//! exactly once so a captured payload cannot be replayed.

use crate::error::{AppError, AppResult};
use crate::kpr1::canonicalize;
use crate::state::AppState;
use crate::util::{decode_hex, decode_hex32, encode_hex, now_iso, to_iso};
use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row, Transaction};

const PROTOCOL_VERSION: &str = "1";
const MAX_LIST_LIMIT: i64 = 100;
const MAX_CIPHERTEXT_BYTES: usize = 256 * 1024;
const MAX_TAGS: usize = 8;
const MAX_CASE_ID_LEN: usize = 128;
const NONCE_REPLAY_CODE: &str = "ARBITRATION_NONCE_REPLAY";

const PROFILE_DOMAIN: &str = "kasway/evaluator-profile/v1";
const QUOTE_DOMAIN: &str = "kasway/evaluator-quote/v1";
const ENGAGEMENT_DOMAIN: &str = "kasway/evaluator-engagement/v1";
const CASE_OPEN_DOMAIN: &str = "kasway/dispute-open/v1";
const MESSAGE_DOMAIN: &str = "kasway/case-message/v1";
const DECISION_COMMIT_DOMAIN: &str = "kasway/evaluator-decision-commit/v1";
const DECISION_REVEAL_DOMAIN: &str = "kasway/evaluator-decision-reveal/v1";
const FEEDBACK_DOMAIN: &str = "kasway/evaluator-feedback/v1";

const MESSAGE_ACTIONS: &[&str] = &["negotiation", "evidence", "question", "response", "statement"];

/// Fee a profile advertises for the `maxFeeSompi` filter and `sort=fee`.
const FEE_EXPR: &str = "(CASE p.fee_kind WHEN 'fixed' THEN p.fee_value ELSE p.minimum_fee_sompi END)";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub category: Option<String>,
    pub language: Option<String>,
    pub max_fee_sompi: Option<i64>,
    pub sort: Option<String>,
    pub order: Option<String>,
}

#[derive(Clone, Copy)]
enum ActionRule {
    Exact(&'static str),
    OneOf(&'static [&'static str]),
}

fn obj<'a>(value: &'a Value, field: &str) -> AppResult<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| AppError::unprocessable(format!("{field} must be an object")))
}

fn str_field<'a>(value: &'a Value, field: &str) -> AppResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::unprocessable(format!("{field} is required")))
}

fn i64_field(value: &Value, field: &str) -> AppResult<i64> {
    value
        .get(field)
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
        .ok_or_else(|| AppError::unprocessable(format!("{field} must be an integer")))
}

/// `None` when the field is absent or null; an error when present but not an integer.
fn opt_i64_field(value: &Value, field: &str) -> AppResult<Option<i64>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => i64_field(value, field).map(Some),
    }
}

fn string_array(value: &Value, field: &str, max: usize) -> AppResult<Vec<String>> {
    let array = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::unprocessable(format!("{field} must be an array")))?;
    if array.len() > max {
        return Err(AppError::unprocessable(format!(
            "{field} may contain at most {max} entries"
        )));
    }
    let mut out = Vec::with_capacity(array.len());
    for item in array {
        let s = item
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::unprocessable(format!("{field} entries must be non-empty strings"))
            })?;
        if s.len() > 64 {
            return Err(AppError::unprocessable(format!(
                "{field} entries may not exceed 64 characters"
            )));
        }
        if !out.iter().any(|existing| existing == s) {
            out.push(s.to_string());
        }
    }
    Ok(out)
}

fn canonical_hash(value: &Value) -> [u8; 32] {
    Sha256::digest(canonicalize(value).as_bytes()).into()
}

fn canonical_hash_hex(value: &Value) -> String {
    encode_hex(&canonical_hash(value))
}

fn validate_hex(value: &str, bytes: usize, field: &str) -> AppResult<()> {
    if decode_hex(value).is_none_or(|v| v.len() != bytes) {
        return Err(AppError::unprocessable(format!(
            "{field} must be {}-byte hex",
            bytes
        )));
    }
    Ok(())
}

fn validate_key(value: &str, field: &str) -> AppResult<[u8; 32]> {
    decode_hex32(value).ok_or_else(|| {
        AppError::unprocessable(format!("{field} must be a 32-byte x-only public key"))
    })
}

fn validate_time(value: &str, field: &str) -> AppResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|v| v.with_timezone(&Utc))
        .map_err(|_| AppError::unprocessable(format!("{field} must be an RFC3339 timestamp")))
}

/// A signed RFC3339 field normalized to UTC [`to_iso`] form, so stored
/// timestamps compare as TEXT and cast in SQL (chrono accepts offsets up to
/// ±23:59; Postgres rejects anything past ±15:59). Never use for values that
/// are later compared for equality against the signed terms.
fn iso_field(value: &Value, field: &str) -> AppResult<String> {
    Ok(to_iso(validate_time(str_field(value, field)?, field)?))
}

/// Verify the signed envelope (domain, version, network, action, nonce,
/// expiry) and the BIP-340 signature. Returns `(payload hash hex, nonce)`; the
/// caller must still `consume_nonce` for the signer.
fn verify_payload(
    payload: &Value,
    signature_hex: &str,
    signer_key: &str,
    domain: &str,
    action: ActionRule,
) -> AppResult<(String, String)> {
    obj(payload, "payload")?;
    if str_field(payload, "domain")? != domain {
        return Err(AppError::unprocessable(format!(
            "payload domain must be {domain}"
        )));
    }
    if str_field(payload, "protocolVersion")? != PROTOCOL_VERSION {
        return Err(AppError::unprocessable(
            "unsupported arbitration protocolVersion",
        ));
    }
    let network = str_field(payload, "network")?;
    if !matches!(network, "tn10" | "mainnet") {
        return Err(AppError::unprocessable("network must be tn10 or mainnet"));
    }
    let actual = str_field(payload, "action")?;
    let allowed = match action {
        ActionRule::Exact(expected) => actual == expected,
        ActionRule::OneOf(list) => list.contains(&actual),
    };
    if !allowed {
        let expected = match action {
            ActionRule::Exact(expected) => expected.to_string(),
            ActionRule::OneOf(list) => format!("one of {}", list.join(", ")),
        };
        return Err(AppError::unprocessable(format!("action must be {expected}")));
    }
    let nonce = str_field(payload, "nonce")?;
    validate_hex(nonce, 32, "nonce")?;
    if validate_time(str_field(payload, "expiresAt")?, "expiresAt")? <= Utc::now() {
        return Err(AppError::unprocessable("expiresAt must be in the future"));
    }
    let key = validate_key(signer_key, "signerKey")?;
    let sig = decode_hex(signature_hex)
        .filter(|v| v.len() == 64)
        .ok_or_else(|| {
            AppError::unprocessable("signature must be a 64-byte BIP-340 signature encoded as hex")
        })?;
    let digest = canonical_hash(payload);
    if !kasway_covenant::verify_schnorr_digest(&key, &digest, &sig) {
        return Err(AppError::commerce(401, "Invalid BIP-340 payload signature"));
    }
    Ok((encode_hex(&digest), nonce.to_ascii_lowercase()))
}

/// Record `(signer, nonce)`; a second use is a replay (409).
async fn consume_nonce<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    signer_key: &str,
    nonce: &str,
) -> AppResult<()> {
    let inserted = sqlx::query(
        "INSERT INTO arbitration_nonces (signer_key, nonce, created_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(signer_key.to_ascii_lowercase())
    .bind(nonce)
    .bind(now_iso())
    .execute(executor)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(AppError::coded(409, NONCE_REPLAY_CODE, "nonce already used by this signer"));
    }
    Ok(())
}

fn signed_parts(body: &Value) -> AppResult<(&Value, &str)> {
    let payload = body
        .get("payload")
        .ok_or_else(|| AppError::unprocessable("payload is required"))?;
    let signature = str_field(body, "signature")?;
    Ok((payload, signature))
}

fn deterministic_id(prefix: &str, key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    format!("{prefix}_{}", &encode_hex(&digest)[..32])
}

fn profile_json(row: &PgRow) -> Value {
    let categories: Value =
        serde_json::from_str(row.get::<&str, _>("categories")).unwrap_or_else(|_| json!([]));
    let languages: Value =
        serde_json::from_str(row.get::<&str, _>("languages")).unwrap_or_else(|_| json!([]));
    json!({
        "profileId": row.get::<String, _>("profile_id"),
        "identityKey": row.get::<String, _>("identity_key"),
        "messagingKey": row.get::<String, _>("messaging_key"),
        "pseudonym": row.get::<String, _>("pseudonym"),
        "categories": categories,
        "languages": languages,
        "policyHash": row.get::<String, _>("policy_hash"),
        "fee": {
            "kind": row.get::<String, _>("fee_kind"),
            "value": row.get::<i64, _>("fee_value").to_string(),
            "minimumSompi": row.get::<i64, _>("minimum_fee_sompi").to_string(),
            "maximumSompi": row.try_get::<i64, _>("maximum_fee_sompi").ok().map(|v| v.to_string()),
        },
        "responseSlaSeconds": row.get::<i64, _>("response_sla_seconds"),
        "decisionSlaSeconds": row.get::<i64, _>("decision_sla_seconds"),
        "bondReference": row.try_get::<String, _>("bond_reference").ok(),
        "profileVersion": row.get::<i64, _>("profile_version"),
        "expiresAt": row.get::<String, _>("expires_at"),
        "payloadHash": row.get::<String, _>("payload_hash"),
        "signature": row.get::<String, _>("signature"),
        "status": row.get::<String, _>("status"),
        "createdAt": row.get::<String, _>("created_at"),
        "updatedAt": row.get::<String, _>("updated_at"),
    })
}

// ---------------------------------------------------------------------------
// Reputation: settled-case aggregates per profile, computed in SQL so the
// listing can filter and sort on them.
// ---------------------------------------------------------------------------

const REPUTATION_CTE: &str = "WITH settled AS ( \
    SELECT d.case_id, e.profile_id, d.decision_outcome, d.opened_at::timestamptz AS opened_at, \
           d.settled_at::timestamptz AS settled_at, d.decision_due_at::timestamptz AS due_at, \
           (SELECT MIN(COALESCE(m.received_at, m.created_at)::timestamptz) FROM dispute_messages m WHERE m.case_id=d.case_id AND m.participant_role='evaluator') AS first_evaluator_at \
    FROM dispute_cases d JOIN evaluator_engagements e ON e.engagement_id=d.engagement_id WHERE d.state='settled' \
  ), fb AS ( \
    SELECT profile_id, COUNT(*) AS ratings, \
           AVG(score) FILTER (WHERE author_role='customer')::FLOAT8 AS customer_average, \
           AVG(score) FILTER (WHERE author_role='seller')::FLOAT8 AS seller_average \
    FROM evaluator_feedback GROUP BY profile_id \
  ), rep AS ( \
    SELECT s.profile_id, COUNT(*) AS verified_cases, \
           COALESCE(MAX(fb.ratings), 0) AS ratings, MAX(fb.customer_average) AS customer_average, MAX(fb.seller_average) AS seller_average, \
           percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (s.first_evaluator_at - s.opened_at))::FLOAT8) AS median_response_seconds, \
           percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (s.settled_at - s.opened_at))::FLOAT8) AS median_resolution_seconds, \
           AVG(CASE WHEN s.settled_at <= s.due_at THEN 1.0 ELSE 0.0 END)::FLOAT8 AS sla_completion_rate, \
           COUNT(*) FILTER (WHERE s.decision_outcome='release') AS release_count, \
           COUNT(*) FILTER (WHERE s.decision_outcome='refund') AS refund_count \
    FROM settled s LEFT JOIN fb ON fb.profile_id=s.profile_id GROUP BY s.profile_id \
  )";

const REPUTATION_COLUMNS: &str = "COALESCE(r.verified_cases, 0) AS verified_cases, COALESCE(r.ratings, 0) AS ratings, \
    r.customer_average, r.seller_average, r.median_response_seconds, r.median_resolution_seconds, r.sla_completion_rate, \
    COALESCE(r.release_count, 0) AS release_count, COALESCE(r.refund_count, 0) AS refund_count";

fn reputation_json(row: &PgRow) -> Value {
    json!({
        "verifiedCases": row.get::<i64, _>("verified_cases"),
        "ratings": row.get::<i64, _>("ratings"),
        "customerAverage": row.get::<Option<f64>, _>("customer_average"),
        "sellerAverage": row.get::<Option<f64>, _>("seller_average"),
        "medianResponseSeconds": row.get::<Option<f64>, _>("median_response_seconds"),
        "medianResolutionSeconds": row.get::<Option<f64>, _>("median_resolution_seconds"),
        "slaCompletionRate": row.get::<Option<f64>, _>("sla_completion_rate"),
        "outcomes": {
            "release": row.get::<i64, _>("release_count"),
            "refund": row.get::<i64, _>("refund_count"),
        },
    })
}

async fn reputation_value(state: &AppState, profile_id: &str) -> AppResult<Value> {
    let sql = format!(
        "{REPUTATION_CTE} SELECT {REPUTATION_COLUMNS} FROM (SELECT $1::text AS profile_id) p LEFT JOIN rep r ON r.profile_id=p.profile_id",
    );
    let row = sqlx::query(&sql).bind(profile_id).fetch_one(&state.db.pool).await?;
    Ok(reputation_json(&row))
}

pub async fn evaluator_index(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> AppResult<Json<Value>> {
    let limit = query.limit.unwrap_or(50).clamp(1, MAX_LIST_LIMIT);
    let offset = query.offset.unwrap_or(0).max(0);
    let (sort_expr, default_order, nulls_last) = match query.sort.as_deref().unwrap_or("newest") {
        "newest" => ("p.created_at", "DESC", false),
        "fee" => (FEE_EXPR, "ASC", false),
        "cases" => ("COALESCE(r.verified_cases, 0)", "DESC", false),
        "resolution_time" => ("r.median_resolution_seconds", "ASC", true),
        "rating" => ("COALESCE(r.customer_average, 0) + COALESCE(r.seller_average, 0)", "DESC", false),
        _ => {
            return Err(AppError::unprocessable(
                "sort must be one of newest, fee, cases, resolution_time, rating",
            ))
        }
    };
    let order = match query.order.as_deref() {
        None => default_order,
        Some("asc") => "ASC",
        Some("desc") => "DESC",
        Some(_) => return Err(AppError::unprocessable("order must be asc or desc")),
    };
    let nulls = if nulls_last { " NULLS LAST" } else { "" };
    let sql = format!(
        "{REPUTATION_CTE} SELECT p.*, {REPUTATION_COLUMNS} \
         FROM evaluator_profiles p LEFT JOIN rep r ON r.profile_id=p.profile_id \
         WHERE p.status='active' AND p.expires_at > $1 \
           AND ($2::text IS NULL OR p.categories::jsonb ? $2) \
           AND ($3::text IS NULL OR p.languages::jsonb ? $3) \
           AND ($4::bigint IS NULL OR {FEE_EXPR} <= $4) \
         ORDER BY {sort_expr} {order}{nulls}, p.created_at DESC LIMIT $5 OFFSET $6",
    );
    let rows = sqlx::query(&sql)
        .bind(now_iso())
        .bind(query.category.as_deref().map(str::trim).filter(|s| !s.is_empty()))
        .bind(query.language.as_deref().map(str::trim).filter(|s| !s.is_empty()))
        .bind(query.max_fee_sompi)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db.pool)
        .await?;
    let data: Vec<Value> = rows
        .iter()
        .map(|row| {
            let mut profile = profile_json(row);
            profile["reputation"] = reputation_json(row);
            profile
        })
        .collect();
    Ok(Json(
        json!({ "data": data, "meta": { "limit": limit, "offset": offset, "count": data.len() } }),
    ))
}

pub async fn evaluator_show(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
) -> AppResult<Json<Value>> {
    let row = sqlx::query("SELECT * FROM evaluator_profiles WHERE profile_id = $1")
        .bind(profile_id)
        .fetch_optional(&state.db.pool)
        .await?
        .ok_or_else(AppError::row_not_found)?;
    let reputation = reputation_value(&state, row.get::<&str, _>("profile_id")).await?;
    let mut result = profile_json(&row);
    result["reputation"] = reputation;
    Ok(Json(result))
}

pub async fn evaluator_store(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let (payload, signature) = signed_parts(&body)?;
    let identity_key = str_field(payload, "identityKey")?;
    let (payload_hash, nonce) = verify_payload(
        payload, signature, identity_key, PROFILE_DOMAIN, ActionRule::Exact("publish_profile"),
    )?;
    let expected_id = deterministic_id("eval", identity_key);
    if str_field(payload, "profileId")? != expected_id {
        return Err(AppError::unprocessable(format!(
            "profileId must be {expected_id}"
        )));
    }
    validate_key(str_field(payload, "messagingKey")?, "messagingKey")?;
    validate_hex(str_field(payload, "policyHash")?, 32, "policyHash")?;
    let pseudonym = str_field(payload, "pseudonym")?;
    if pseudonym.len() > 80 {
        return Err(AppError::unprocessable(
            "pseudonym may not exceed 80 characters",
        ));
    }
    let categories = string_array(payload, "categories", 16)?;
    let languages = string_array(payload, "languages", 16)?;
    let fee = payload
        .get("fee")
        .ok_or_else(|| AppError::unprocessable("fee is required"))?;
    obj(fee, "fee")?;
    let fee_kind = str_field(fee, "kind")?;
    if !matches!(fee_kind, "fixed" | "bps") {
        return Err(AppError::unprocessable("fee.kind must be fixed or bps"));
    }
    let fee_value = i64_field(fee, "value")?;
    let min_fee = i64_field(fee, "minimumSompi")?;
    let max_fee = opt_i64_field(fee, "maximumSompi")?;
    if fee_value < 0
        || min_fee < 0
        || max_fee.is_some_and(|v| v < min_fee)
        || (fee_kind == "bps" && fee_value > 10_000)
    {
        return Err(AppError::unprocessable("invalid evaluator fee bounds"));
    }
    let response_sla = i64_field(payload, "responseSlaSeconds")?;
    let decision_sla = i64_field(payload, "decisionSlaSeconds")?;
    if response_sla <= 0 || decision_sla <= 0 {
        return Err(AppError::unprocessable("SLA values must be positive"));
    }
    let version = i64_field(payload, "profileVersion")?;
    if version <= 0 {
        return Err(AppError::unprocessable("profileVersion must be positive"));
    }
    let expires_at = iso_field(payload, "expiresAt")?;
    let now = now_iso();
    let mut tx = state.db.pool.begin().await?;
    consume_nonce(&mut *tx, identity_key, &nonce).await?;
    sqlx::query(
        "INSERT INTO evaluator_profiles (profile_id, identity_key, messaging_key, pseudonym, categories, languages, policy_hash, fee_kind, fee_value, minimum_fee_sompi, maximum_fee_sompi, response_sla_seconds, decision_sla_seconds, bond_reference, profile_version, expires_at, payload_hash, signature, status, created_at, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'active',$19,$20) \
         ON CONFLICT (profile_id) DO UPDATE SET messaging_key=EXCLUDED.messaging_key, pseudonym=EXCLUDED.pseudonym, categories=EXCLUDED.categories, languages=EXCLUDED.languages, policy_hash=EXCLUDED.policy_hash, fee_kind=EXCLUDED.fee_kind, fee_value=EXCLUDED.fee_value, minimum_fee_sompi=EXCLUDED.minimum_fee_sompi, maximum_fee_sompi=EXCLUDED.maximum_fee_sompi, response_sla_seconds=EXCLUDED.response_sla_seconds, decision_sla_seconds=EXCLUDED.decision_sla_seconds, bond_reference=EXCLUDED.bond_reference, profile_version=EXCLUDED.profile_version, expires_at=EXCLUDED.expires_at, payload_hash=EXCLUDED.payload_hash, signature=EXCLUDED.signature, status='active', updated_at=EXCLUDED.updated_at \
         WHERE evaluator_profiles.identity_key=EXCLUDED.identity_key AND evaluator_profiles.profile_version < EXCLUDED.profile_version",
    )
    .bind(&expected_id).bind(identity_key).bind(str_field(payload, "messagingKey")?).bind(pseudonym)
    .bind(serde_json::to_string(&categories).unwrap()).bind(serde_json::to_string(&languages).unwrap())
    .bind(str_field(payload, "policyHash")?).bind(fee_kind).bind(fee_value).bind(min_fee).bind(max_fee)
    .bind(response_sla).bind(decision_sla).bind(payload.get("bondReference").and_then(Value::as_str))
    .bind(version).bind(expires_at).bind(payload_hash).bind(signature).bind(&now).bind(&now)
    .execute(&mut *tx).await?;
    tx.commit().await?;
    evaluator_show(State(state), Path(expected_id)).await
}

/// Validate the shared fee fields (`feeSompi`, `feePayer`, `feeBps?`,
/// `feeCapSompi?`) and return `(feeSompi, feeBps, feeCapSompi)`.
fn fee_fields(value: &Value) -> AppResult<(i64, Option<i64>, Option<i64>)> {
    let fee_sompi = i64_field(value, "feeSompi")?;
    if fee_sompi <= 0 {
        return Err(AppError::unprocessable("feeSompi must be positive"));
    }
    if str_field(value, "feePayer")? != "customer" {
        return Err(AppError::unprocessable(
            "protocol v1 requires feePayer customer",
        ));
    }
    let fee_bps = opt_i64_field(value, "feeBps")?;
    if fee_bps.is_some_and(|b| !(0..=10_000).contains(&b)) {
        return Err(AppError::unprocessable("feeBps must be between 0 and 10000"));
    }
    let fee_cap = opt_i64_field(value, "feeCapSompi")?;
    if fee_cap.is_some_and(|c| c <= 0) {
        return Err(AppError::unprocessable("feeCapSompi must be positive"));
    }
    Ok((fee_sompi, fee_bps, fee_cap))
}

pub async fn quote_store(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let (payload, signature) = signed_parts(&body)?;
    let evaluator_key = str_field(payload, "evaluatorKey")?;
    let (payload_hash, nonce) = verify_payload(
        payload, signature, evaluator_key, QUOTE_DOMAIN, ActionRule::Exact("issue_quote"),
    )?;
    let quote_id = str_field(payload, "quoteId")?;
    let profile_id = str_field(payload, "profileId")?;
    let invoice_id = str_field(payload, "invoiceId")?;
    let customer_key = str_field(payload, "customerKey")?;
    validate_key(customer_key, "customerKey")?;
    validate_hex(
        str_field(payload, "caseKeyCommitment")?,
        32,
        "caseKeyCommitment",
    )?;
    validate_hex(str_field(payload, "policyHash")?, 32, "policyHash")?;
    validate_hex(
        str_field(payload, "evidenceFormatHash")?,
        32,
        "evidenceFormatHash",
    )?;
    let (fee_sompi, fee_bps, fee_cap) = fee_fields(payload)?;
    let allowed = string_array(payload, "allowedOutcomes", 2)?;
    if allowed.is_empty()
        || allowed
            .iter()
            .any(|v| !matches!(v.as_str(), "release" | "refund"))
    {
        return Err(AppError::unprocessable(
            "allowedOutcomes must contain release and/or refund",
        ));
    }
    let decision_sla = i64_field(payload, "decisionSlaSeconds")?;
    let dispute_deadline = str_field(payload, "disputeDeadline")?;
    let expires_at = iso_field(payload, "expiresAt")?;
    if decision_sla <= 0 {
        return Err(AppError::unprocessable("quote SLA is invalid"));
    }
    validate_time(dispute_deadline, "disputeDeadline")?;
    let reward_address = str_field(payload, "rewardAddress")?;
    kasway_covenant::schnorr_pubkey_from_address(reward_address).map_err(|_| {
        AppError::unprocessable("rewardAddress must be a case-specific Schnorr P2PK Kaspa address")
    })?;
    if let Some(key) = payload.get("backupEvaluatorKey").and_then(Value::as_str) {
        validate_key(key, "backupEvaluatorKey")?;
    }
    let profile = sqlx::query("SELECT identity_key, policy_hash, status, minimum_fee_sompi, maximum_fee_sompi FROM evaluator_profiles WHERE profile_id=$1")
        .bind(profile_id).fetch_optional(&state.db.pool).await?.ok_or_else(AppError::row_not_found)?;
    if profile.get::<String, _>("identity_key") != evaluator_key
        || profile.get::<String, _>("policy_hash") != str_field(payload, "policyHash")?
        || profile.get::<String, _>("status") != "active"
    {
        return Err(AppError::unprocessable(
            "quote does not match an active evaluator profile",
        ));
    }
    let min_fee = profile.get::<i64, _>("minimum_fee_sompi");
    let max_fee = profile.get::<Option<i64>, _>("maximum_fee_sompi");
    if fee_sompi < min_fee || max_fee.is_some_and(|m| fee_sompi > m) {
        return Err(AppError::unprocessable(
            "feeSompi is outside the evaluator profile fee bounds",
        ));
    }
    let gross: Option<Option<i64>> = sqlx::query_scalar(
        "SELECT k.gross_amount FROM invoices i JOIN kpr1_payment_intents k ON k.invoice_id=i.id WHERE i.public_id=$1 AND i.status='open' ORDER BY k.id DESC LIMIT 1",
    )
    .bind(invoice_id)
    .fetch_optional(&state.db.pool)
    .await?;
    let Some(gross) = gross else {
        return Err(AppError::unprocessable("quote invoice is not open"));
    };
    if let Some(bps) = fee_bps {
        let gross = gross.ok_or_else(|| AppError::unprocessable("quote invoice has no gross amount"))?;
        let from_bps = (i128::from(gross) * i128::from(bps) / 10_000) as i64;
        let expected = fee_cap.map_or(from_bps, |cap| cap.min(from_bps));
        if fee_sompi != expected {
            return Err(AppError::unprocessable(format!(
                "feeSompi must equal min(feeCapSompi, invoiceGross * feeBps / 10000) = {expected}"
            )));
        }
    }
    let now = now_iso();
    let mut tx = state.db.pool.begin().await?;
    consume_nonce(&mut *tx, evaluator_key, &nonce).await?;
    sqlx::query(
        "INSERT INTO evaluator_quotes (quote_id,profile_id,invoice_public_id,customer_key,evaluator_key,case_key_commitment,fee_sompi,fee_payer,reward_address,policy_hash,evidence_format_hash,allowed_outcomes,dispute_deadline,decision_sla_seconds,backup_evaluator_key,quote_version,expires_at,payload_hash,signature,status,created_at,updated_at,fee_bps,fee_cap_sompi) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,'customer',$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'open',$19,$20,$21,$22)",
    )
    .bind(quote_id).bind(profile_id).bind(invoice_id).bind(customer_key).bind(evaluator_key)
    .bind(str_field(payload, "caseKeyCommitment")?).bind(fee_sompi).bind(reward_address)
    .bind(str_field(payload, "policyHash")?).bind(str_field(payload, "evidenceFormatHash")?)
    .bind(serde_json::to_string(&allowed).unwrap()).bind(dispute_deadline).bind(decision_sla)
    .bind(payload.get("backupEvaluatorKey").and_then(Value::as_str)).bind(i64_field(payload, "quoteVersion")?)
    .bind(expires_at).bind(payload_hash).bind(signature).bind(&now).bind(&now).bind(fee_bps).bind(fee_cap)
    .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({ "quoteId": quote_id, "status": "open", "payloadHash": canonical_hash_hex(payload) }),
    ))
}

async fn invoice_seller_key(
    tx: &mut Transaction<'_, Postgres>,
    invoice_id: &str,
) -> AppResult<String> {
    let address: String = sqlx::query_scalar(
        "SELECT k.merchant_address FROM kpr1_payment_intents k JOIN invoices i ON i.id=k.invoice_id WHERE i.public_id=$1",
    )
    .bind(invoice_id).fetch_optional(&mut **tx).await?.ok_or_else(AppError::row_not_found)?;
    let key = kasway_covenant::schnorr_pubkey_from_address(&address)
        .map_err(|_| AppError::unprocessable("invoice merchant address is not Schnorr P2PK"))?;
    Ok(encode_hex(&key))
}

pub async fn engagement_store(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let terms = body
        .get("terms")
        .ok_or_else(|| AppError::unprocessable("terms is required"))?;
    obj(terms, "terms")?;
    let customer_key = str_field(terms, "customerKey")?;
    let seller_key = str_field(terms, "sellerKey")?;
    let evaluator_key = str_field(terms, "evaluatorKey")?;
    let customer_sig = str_field(&body, "customerSignature")?;
    let seller_sig = str_field(&body, "sellerSignature")?;
    let evaluator_sig = str_field(&body, "evaluatorSignature")?;
    let action = ActionRule::Exact("accept_engagement");
    let (engagement_hash, nonce) =
        verify_payload(terms, customer_sig, customer_key, ENGAGEMENT_DOMAIN, action)?;
    verify_payload(terms, seller_sig, seller_key, ENGAGEMENT_DOMAIN, action)?;
    verify_payload(terms, evaluator_sig, evaluator_key, ENGAGEMENT_DOMAIN, action)?;
    let engagement_id = str_field(terms, "engagementId")?;
    let engagement_version = i64_field(terms, "engagementVersion")?;
    if engagement_version < 1 {
        return Err(AppError::unprocessable("engagementVersion must be >= 1"));
    }
    let invoice_id = str_field(terms, "invoiceId")?;
    let order_id = terms.get("orderId").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
    let case_id = str_field(terms, "caseId")?;
    if case_id.len() > MAX_CASE_ID_LEN {
        return Err(AppError::unprocessable(format!(
            "caseId may not exceed {MAX_CASE_ID_LEN} characters"
        )));
    }
    let quote_id = str_field(terms, "quoteId")?;
    let profile_id = str_field(terms, "profileId")?;
    let expires_at = iso_field(terms, "expiresAt")?;
    let messaging_keys = terms
        .get("messagingKeys")
        .ok_or_else(|| AppError::unprocessable("messagingKeys is required"))?;
    for role in ["customer", "seller", "evaluator"] {
        validate_key(
            str_field(messaging_keys, role)?,
            &format!("messagingKeys.{role}"),
        )?;
    }
    let (fee_sompi, fee_bps, fee_cap) = fee_fields(terms)?;
    let mut tx = state.db.pool.begin().await?;
    let expected_seller = invoice_seller_key(&mut tx, invoice_id).await?;
    if !expected_seller.eq_ignore_ascii_case(seller_key) {
        return Err(AppError::unprocessable(
            "sellerKey does not match invoice merchant signing address",
        ));
    }
    if let Some(order_id) = order_id {
        let external_id: Option<String> =
            sqlx::query_scalar("SELECT external_id FROM invoices WHERE public_id=$1")
                .bind(invoice_id)
                .fetch_one(&mut *tx)
                .await?;
        if external_id.is_some_and(|ext| ext != order_id) {
            return Err(AppError::unprocessable(
                "orderId does not match the invoice external id",
            ));
        }
    }
    let quote = sqlx::query("SELECT * FROM evaluator_quotes WHERE quote_id=$1 FOR UPDATE")
        .bind(quote_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::row_not_found)?;
    if quote.get::<String, _>("status") != "open"
        || quote.get::<String, _>("invoice_public_id") != invoice_id
        || quote.get::<String, _>("profile_id") != profile_id
        || quote.get::<String, _>("customer_key") != customer_key
        || quote.get::<String, _>("evaluator_key") != evaluator_key
    {
        return Err(AppError::unprocessable(
            "engagement does not match the open evaluator quote",
        ));
    }
    if validate_time(quote.get::<&str, _>("expires_at"), "quote.expiresAt")? <= Utc::now() {
        return Err(AppError::unprocessable("evaluator quote has expired"));
    }
    let equality = [
        ("caseKeyCommitment", "case_key_commitment"),
        ("rewardAddress", "reward_address"),
        ("policyHash", "policy_hash"),
        ("evidenceFormatHash", "evidence_format_hash"),
        ("disputeDeadline", "dispute_deadline"),
    ];
    for (term_field, quote_column) in equality {
        if str_field(terms, term_field)? != quote.get::<String, _>(quote_column) {
            return Err(AppError::unprocessable(format!(
                "engagement {term_field} differs from evaluator quote"
            )));
        }
    }
    if fee_sompi != quote.get::<i64, _>("fee_sompi")
        || fee_bps != quote.get::<Option<i64>, _>("fee_bps")
        || fee_cap != quote.get::<Option<i64>, _>("fee_cap_sompi")
    {
        return Err(AppError::unprocessable(
            "engagement fee differs from evaluator quote",
        ));
    }
    let allowed_outcomes = terms
        .get("allowedOutcomes")
        .cloned()
        .ok_or_else(|| AppError::unprocessable("allowedOutcomes is required"))?;
    if canonicalize(&allowed_outcomes)
        != canonicalize(
            &serde_json::from_str::<Value>(quote.get::<&str, _>("allowed_outcomes"))
                .unwrap_or(json!([])),
        )
    {
        return Err(AppError::unprocessable(
            "engagement allowedOutcomes differs from evaluator quote",
        ));
    }
    let case_taken: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM evaluator_engagements WHERE case_id=$1)")
            .bind(case_id)
            .fetch_one(&mut *tx)
            .await?;
    if case_taken {
        return Err(AppError::commerce(409, "caseId is already bound to another engagement"));
    }
    for signer in [customer_key, seller_key, evaluator_key] {
        consume_nonce(&mut *tx, signer, &nonce).await?;
    }
    let now = now_iso();
    sqlx::query(
        "INSERT INTO evaluator_engagements (engagement_id,invoice_public_id,quote_id,profile_id,customer_key,seller_key,evaluator_key,messaging_keys,case_key_commitment,fee_sompi,fee_payer,reward_address,policy_hash,evidence_format_hash,allowed_outcomes,dispute_deadline,decision_sla_seconds,backup_evaluator_key,terms_json,engagement_hash,customer_signature,seller_signature,evaluator_signature,status,expires_at,created_at,updated_at,engagement_version,order_id,case_id,fee_bps,fee_cap_sompi) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'customer',$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,'accepted',$23,$24,$25,$26,$27,$28,$29,$30)",
    )
    .bind(engagement_id).bind(invoice_id).bind(quote_id).bind(profile_id).bind(customer_key).bind(seller_key).bind(evaluator_key)
    .bind(canonicalize(messaging_keys)).bind(str_field(terms, "caseKeyCommitment")?).bind(fee_sompi)
    .bind(str_field(terms, "rewardAddress")?).bind(str_field(terms, "policyHash")?).bind(str_field(terms, "evidenceFormatHash")?)
    .bind(canonicalize(&allowed_outcomes)).bind(str_field(terms, "disputeDeadline")?).bind(i64_field(terms, "decisionSlaSeconds")?)
    .bind(terms.get("backupEvaluatorKey").and_then(Value::as_str)).bind(canonicalize(terms)).bind(&engagement_hash)
    .bind(customer_sig).bind(seller_sig).bind(evaluator_sig).bind(expires_at).bind(&now).bind(&now)
    .bind(engagement_version).bind(order_id).bind(case_id).bind(fee_bps).bind(fee_cap)
    .execute(&mut *tx).await?;
    sqlx::query("UPDATE evaluator_quotes SET status='accepted', updated_at=$1 WHERE quote_id=$2")
        .bind(&now)
        .bind(quote_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE kpr1_payment_intents k SET engagement_id=$1,evaluator_fee_sompi=$2,covenant_version='escrow_v3',updated_at=$3 FROM invoices i WHERE i.id=k.invoice_id AND i.public_id=$4 AND k.covenant_state='pending'")
        .bind(engagement_id).bind(fee_sompi).bind(&now).bind(invoice_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({ "engagementId": engagement_id, "engagementHash": engagement_hash, "status": "accepted" }),
    ))
}

/// Public engagement record: the exact signed terms plus all three
/// signatures, so a wallet can re-verify before funding.
pub async fn engagement_show(
    State(state): State<AppState>,
    Path(engagement_id): Path<String>,
) -> AppResult<Json<Value>> {
    let row = sqlx::query(
        "SELECT engagement_id,engagement_hash,status,terms_json,customer_signature,seller_signature,evaluator_signature FROM evaluator_engagements WHERE engagement_id=$1",
    )
    .bind(&engagement_id)
    .fetch_optional(&state.db.pool)
    .await?
    .ok_or_else(AppError::row_not_found)?;
    let terms: Value = serde_json::from_str(row.get::<&str, _>("terms_json")).unwrap_or(Value::Null);
    Ok(Json(json!({
        "engagementId": row.get::<String, _>("engagement_id"),
        "engagementHash": row.get::<String, _>("engagement_hash"),
        "status": row.get::<String, _>("status"),
        "terms": terms,
        "customerSignature": row.get::<String, _>("customer_signature"),
        "sellerSignature": row.get::<String, _>("seller_signature"),
        "evaluatorSignature": row.get::<String, _>("evaluator_signature"),
    })))
}

async fn engagement_keys(
    state: &AppState,
    engagement_id: &str,
) -> AppResult<(String, String, String, String, i64)> {
    sqlx::query_as::<_, (String, String, String, String, i64)>(
        "SELECT customer_key,seller_key,evaluator_key,profile_id,decision_sla_seconds FROM evaluator_engagements WHERE engagement_id=$1",
    )
    .bind(engagement_id).fetch_optional(&state.db.pool).await?.ok_or_else(AppError::row_not_found)
}

pub async fn case_open(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let (payload, signature) = signed_parts(&body)?;
    let opener_key = str_field(payload, "openerKey")?;
    let (payload_hash, nonce) = verify_payload(
        payload, signature, opener_key, CASE_OPEN_DOMAIN, ActionRule::Exact("open_case"),
    )?;
    let engagement_id = str_field(payload, "engagementId")?;
    let (customer_key, seller_key, _, _, decision_sla) =
        engagement_keys(&state, engagement_id).await?;
    let role = str_field(payload, "openerRole")?;
    let expected = match role {
        "customer" => customer_key,
        "seller" => seller_key,
        _ => {
            return Err(AppError::unprocessable(
                "openerRole must be customer or seller",
            ))
        }
    };
    if !expected.eq_ignore_ascii_case(opener_key) {
        return Err(AppError::commerce(
            403,
            "opener key does not match engagement role",
        ));
    }
    validate_hex(
        str_field(payload, "openingReasonHash")?,
        32,
        "openingReasonHash",
    )?;
    let invoice_id = str_field(payload, "invoiceId")?;
    let case_id = str_field(payload, "caseId")?;
    let dispute_tx_id = str_field(payload, "disputeTxId")?;
    validate_hex(dispute_tx_id, 32, "disputeTxId")?;
    let dispute_address = str_field(payload, "disputeCovenantAddress")?;
    let now_dt = Utc::now();
    let now = now_iso();
    let due = (now_dt + Duration::seconds(decision_sla)).to_rfc3339();
    let mut tx = state.db.pool.begin().await?;
    let state_row: Option<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT e.status,k.covenant_state,k.dispute_covenant_address,e.case_id FROM evaluator_engagements e JOIN kpr1_payment_intents k ON k.engagement_id=e.engagement_id WHERE e.engagement_id=$1 AND e.invoice_public_id=$2 FOR UPDATE",
    ).bind(engagement_id).bind(invoice_id).fetch_optional(&mut *tx).await?;
    let Some((engagement_status, covenant_state, expected_dispute_address, expected_case_id)) = state_row else {
        return Err(AppError::row_not_found());
    };
    if expected_case_id.as_deref() != Some(case_id) {
        return Err(AppError::unprocessable(
            "caseId does not match the signed engagement",
        ));
    }
    if engagement_status != "funded" || covenant_state != "dispute_submitted" {
        return Err(AppError::unprocessable(
            "case can open only after the signed dispute covenant transition was submitted",
        ));
    }
    if expected_dispute_address.as_deref() != Some(dispute_address) {
        return Err(AppError::unprocessable(
            "disputeCovenantAddress does not match the covenant committed before funding",
        ));
    }
    consume_nonce(&mut *tx, opener_key, &nonce).await?;
    sqlx::query(
        "INSERT INTO dispute_cases (case_id,engagement_id,invoice_public_id,opener_role,opener_key,opening_reason_hash,opening_payload_hash,opening_signature,dispute_tx_id,dispute_covenant_address,state,opened_at,decision_due_at,updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'open',$11,$12,$13)",
    )
    .bind(case_id).bind(engagement_id).bind(invoice_id).bind(role).bind(opener_key)
    .bind(str_field(payload, "openingReasonHash")?).bind(payload_hash).bind(signature).bind(dispute_tx_id).bind(dispute_address)
    .bind(&now).bind(&due).bind(&now).execute(&mut *tx).await?;
    sqlx::query(
        "UPDATE evaluator_engagements SET status='disputed',updated_at=$1 WHERE engagement_id=$2",
    )
    .bind(&now)
    .bind(engagement_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE kpr1_payment_intents SET covenant_state='dispute_open',updated_at=$1 WHERE engagement_id=$2")
        .bind(&now).bind(engagement_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({ "caseId": case_id, "state": "open", "decisionDueAt": due }),
    ))
}

pub async fn dispute_prepare(
    State(state): State<AppState>,
    Path(engagement_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let role = str_field(&body, "participantRole")?;
    Ok(Json(
        crate::covenant_keeper::evaluator_dispute_prepare(&state, &engagement_id, role).await?,
    ))
}

pub async fn dispute_submit(
    State(state): State<AppState>,
    Path(engagement_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let role = str_field(&body, "participantRole")?;
    let participant_signature = str_field(&body, "participantSignature")?;
    let fee_signature = str_field(&body, "feeSignature")?;
    Ok(Json(
        crate::covenant_keeper::evaluator_dispute_submit(
            &state,
            &engagement_id,
            role,
            participant_signature,
            fee_signature,
        )
        .await?,
    ))
}

async fn case_context(
    state: &AppState,
    case_id: &str,
) -> AppResult<(String, String, String, String, String, i64)> {
    sqlx::query_as::<_, (String, String, String, String, String, i64)>(
        "SELECT d.engagement_id,e.customer_key,e.seller_key,e.evaluator_key,e.profile_id,e.fee_sompi FROM dispute_cases d JOIN evaluator_engagements e ON e.engagement_id=d.engagement_id WHERE d.case_id=$1",
    ).bind(case_id).fetch_optional(&state.db.pool).await?.ok_or_else(AppError::row_not_found)
}

fn key_for_role(role: &str, customer: &str, seller: &str, evaluator: &str) -> AppResult<String> {
    match role {
        "customer" => Ok(customer.to_string()),
        "seller" => Ok(seller.to_string()),
        "evaluator" => Ok(evaluator.to_string()),
        _ => Err(AppError::unprocessable(
            "participantRole must be customer, seller, or evaluator",
        )),
    }
}

pub async fn message_store(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let (payload, signature) = signed_parts(&body)?;
    if str_field(payload, "caseId")? != case_id {
        return Err(AppError::unprocessable("caseId does not match route"));
    }
    let (_, customer, seller, evaluator, _, _) = case_context(&state, &case_id).await?;
    let role = str_field(payload, "participantRole")?;
    let expected_key = key_for_role(role, &customer, &seller, &evaluator)?;
    let sender_key = str_field(payload, "senderKey")?;
    if !expected_key.eq_ignore_ascii_case(sender_key) {
        return Err(AppError::commerce(
            403,
            "message sender key does not match engagement role",
        ));
    }
    let (envelope_hash, nonce) = verify_payload(
        payload, signature, sender_key, MESSAGE_DOMAIN, ActionRule::OneOf(MESSAGE_ACTIONS),
    )?;
    validate_hex(str_field(payload, "payloadHash")?, 32, "payloadHash")?;
    let ciphertext = str_field(payload, "ciphertext")?;
    if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(AppError::unprocessable(
            "ciphertext exceeds 256 KiB case-message limit",
        ));
    }
    let sequence = i64_field(payload, "sequence")?;
    if sequence < 0 {
        return Err(AppError::unprocessable("sequence must be non-negative"));
    }
    // The anchor is deliberately outside the signed envelope. Including a
    // `chainCommitment` field in the value being hashed would require an
    // impossible self-referential fixed point. Participants first sign the
    // immutable encrypted envelope; a Kaspa transaction then commits to that
    // resulting envelope hash.
    let anchor = body
        .get("anchor")
        .ok_or_else(|| AppError::unprocessable("anchor is required"))?;
    obj(anchor, "anchor")?;
    let chain_tx = str_field(anchor, "chainTxId")?;
    let chain_commitment = str_field(anchor, "commitment")?;
    validate_hex(chain_tx, 32, "chainTxId")?;
    validate_hex(chain_commitment, 32, "chainCommitment")?;
    if !chain_commitment.eq_ignore_ascii_case(&envelope_hash) {
        return Err(AppError::unprocessable(
            "anchor.commitment must equal the signed envelope hash",
        ));
    }
    let expected_previous: Option<String> = sqlx::query_scalar(
        "SELECT envelope_hash FROM dispute_messages WHERE case_id=$1 ORDER BY sequence DESC LIMIT 1",
    ).bind(&case_id).fetch_optional(&state.db.pool).await?;
    let supplied_previous = payload
        .get("previousMessageHash")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    if expected_previous.as_deref() != supplied_previous {
        return Err(AppError::commerce(
            409,
            "previousMessageHash does not match case head",
        ));
    }
    let expected_sequence: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(sequence), -1) + 1 FROM dispute_messages WHERE case_id=$1",
    )
    .bind(&case_id)
    .fetch_one(&state.db.pool)
    .await?;
    if sequence != expected_sequence {
        return Err(AppError::commerce(
            409,
            format!("message sequence must be {expected_sequence}"),
        ));
    }
    let message_id = str_field(payload, "messageId")?;
    let created_at = iso_field(payload, "createdAt")?;
    let expires_at = iso_field(payload, "expiresAt")?;
    let mut tx = state.db.pool.begin().await?;
    consume_nonce(&mut *tx, sender_key, &nonce).await?;
    sqlx::query(
        "INSERT INTO dispute_messages (message_id,case_id,sequence,previous_message_hash,participant_role,sender_key,payload_hash,ciphertext,envelope_hash,signature,chain_tx_id,chain_commitment,anchor_status,created_at,expires_at,received_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'submitted',$13,$14,$15)",
    ).bind(message_id).bind(&case_id).bind(sequence).bind(supplied_previous).bind(role).bind(sender_key)
    .bind(str_field(payload, "payloadHash")?).bind(ciphertext).bind(&envelope_hash).bind(signature).bind(chain_tx)
    .bind(chain_commitment).bind(created_at).bind(expires_at).bind(now_iso())
    .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(
        json!({ "messageId": message_id, "sequence": sequence, "envelopeHash": envelope_hash, "anchorStatus": "submitted" }),
    ))
}

pub async fn message_index(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
) -> AppResult<Json<Value>> {
    case_context(&state, &case_id).await?;
    let rows = sqlx::query("SELECT * FROM dispute_messages WHERE case_id=$1 ORDER BY sequence ASC")
        .bind(&case_id)
        .fetch_all(&state.db.pool)
        .await?;
    let data: Vec<Value> = rows.iter().map(|row| json!({
        "messageId": row.get::<String,_>("message_id"), "caseId": case_id,
        "sequence": row.get::<i64,_>("sequence"), "previousMessageHash": row.try_get::<String,_>("previous_message_hash").ok(),
        "participantRole": row.get::<String,_>("participant_role"), "senderKey": row.get::<String,_>("sender_key"),
        "payloadHash": row.get::<String,_>("payload_hash"), "ciphertext": row.get::<String,_>("ciphertext"),
        "envelopeHash": row.get::<String,_>("envelope_hash"), "signature": row.get::<String,_>("signature"),
        "chainTxId": row.get::<String,_>("chain_tx_id"), "chainCommitment": row.get::<String,_>("chain_commitment"),
        "anchorStatus": row.get::<String,_>("anchor_status"), "createdAt": row.get::<String,_>("created_at"),
        "expiresAt": row.try_get::<String,_>("expires_at").ok(),
    })).collect();
    Ok(Json(json!({ "data": data })))
}

pub async fn decision_commit(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let (payload, signature) = signed_parts(&body)?;
    if str_field(payload, "caseId")? != case_id {
        return Err(AppError::unprocessable("caseId does not match route"));
    }
    let (_, _, _, evaluator, _, _) = case_context(&state, &case_id).await?;
    if str_field(payload, "evaluatorKey")? != evaluator {
        return Err(AppError::commerce(
            403,
            "decision signer is not case evaluator",
        ));
    }
    let (payload_hash, nonce) = verify_payload(
        payload, signature, &evaluator, DECISION_COMMIT_DOMAIN, ActionRule::Exact("commit_decision"),
    )?;
    let commitment = str_field(payload, "decisionCommitment")?;
    validate_hex(commitment, 32, "decisionCommitment")?;
    let chain_tx = str_field(payload, "chainTxId")?;
    validate_hex(chain_tx, 32, "chainTxId")?;
    let now = now_iso();
    let mut tx = state.db.pool.begin().await?;
    consume_nonce(&mut *tx, &evaluator, &nonce).await?;
    let result = sqlx::query("UPDATE dispute_cases SET state='committed',decision_commitment=$1,decision_commit_tx_id=$2,decision_signature=$3,updated_at=$4 WHERE case_id=$5 AND state='open'")
        .bind(commitment).bind(chain_tx).bind(signature).bind(&now).bind(&case_id).execute(&mut *tx).await?;
    if result.rows_affected() != 1 {
        return Err(AppError::commerce(
            409,
            "case is not open for a decision commitment",
        ));
    }
    tx.commit().await?;
    Ok(Json(
        json!({ "caseId": case_id, "state": "committed", "decisionCommitment": commitment, "payloadHash": payload_hash }),
    ))
}

pub async fn decision_reveal(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let (payload, signature) = signed_parts(&body)?;
    if str_field(payload, "caseId")? != case_id {
        return Err(AppError::unprocessable("caseId does not match route"));
    }
    let (engagement_id, _, _, evaluator, _, _) = case_context(&state, &case_id).await?;
    if str_field(payload, "evaluatorKey")? != evaluator {
        return Err(AppError::commerce(
            403,
            "decision signer is not case evaluator",
        ));
    }
    let (_, nonce) = verify_payload(
        payload, signature, &evaluator, DECISION_REVEAL_DOMAIN, ActionRule::Exact("reveal_decision"),
    )?;
    let outcome = str_field(payload, "outcome")?;
    if !matches!(outcome, "release" | "refund") {
        return Err(AppError::unprocessable("outcome must be release or refund"));
    }
    let reason_hash = str_field(payload, "reasonHash")?;
    let salt = str_field(payload, "salt")?;
    validate_hex(reason_hash, 32, "reasonHash")?;
    validate_hex(salt, 32, "salt")?;
    let reveal_tx = str_field(payload, "chainTxId")?;
    validate_hex(reveal_tx, 32, "chainTxId")?;
    let committed: String = sqlx::query_scalar(
        "SELECT decision_commitment FROM dispute_cases WHERE case_id=$1 AND state='committed'",
    )
    .bind(&case_id)
    .fetch_optional(&state.db.pool)
    .await?
    .ok_or_else(|| AppError::commerce(409, "case has no decision commitment"))?;
    let engagement_hash: String = sqlx::query_scalar(
        "SELECT engagement_hash FROM evaluator_engagements WHERE engagement_id=$1",
    )
    .bind(&engagement_id)
    .fetch_one(&state.db.pool)
    .await?;
    let preimage = json!({
        "domain": "kasway/evaluator-decision/v1", "protocolVersion": PROTOCOL_VERSION,
        "network": str_field(payload, "network")?, "engagementHash": engagement_hash,
        "caseId": case_id, "outcome": outcome, "reasonHash": reason_hash, "salt": salt,
    });
    let recomputed = canonical_hash_hex(&preimage);
    if !recomputed.eq_ignore_ascii_case(&committed) {
        return Err(AppError::unprocessable(
            "decision reveal does not match commitment",
        ));
    }
    let now = now_iso();
    let mut tx = state.db.pool.begin().await?;
    consume_nonce(&mut *tx, &evaluator, &nonce).await?;
    let result = sqlx::query("UPDATE dispute_cases SET state='revealed',decision_outcome=$1,decision_reason_hash=$2,decision_salt=$3,decision_signature=$4,decision_reveal_tx_id=$5,updated_at=$6 WHERE case_id=$7 AND state='committed'")
        .bind(outcome).bind(reason_hash).bind(salt).bind(signature).bind(reveal_tx).bind(&now).bind(&case_id).execute(&mut *tx).await?;
    if result.rows_affected() != 1 {
        return Err(AppError::commerce(
            409,
            "case is no longer awaiting a decision reveal",
        ));
    }
    tx.commit().await?;
    Ok(Json(
        json!({ "caseId": case_id, "state": "revealed", "outcome": outcome, "decisionCommitment": committed }),
    ))
}

pub async fn settlement_prepare(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let fee_payer = str_field(&body, "feePayerAddress")?;
    Ok(Json(
        crate::covenant_keeper::evaluator_settlement_prepare(&state, &case_id, fee_payer).await?,
    ))
}

pub async fn settlement_submit(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let fee_payer = str_field(&body, "feePayerAddress")?;
    let evaluator_signature = str_field(&body, "evaluatorSignature")?;
    let fee_signature = str_field(&body, "feeSignature")?;
    Ok(Json(
        crate::covenant_keeper::evaluator_settlement_submit(
            &state,
            &case_id,
            fee_payer,
            evaluator_signature,
            fee_signature,
        )
        .await?,
    ))
}

/// `{ split: [{ address, amountSompi }], feePayerAddress }` for the mutual
/// settlement escape hatch.
fn mutual_settlement_body(body: &Value) -> AppResult<(Vec<(String, u64)>, &str)> {
    let split = body
        .get("split")
        .and_then(Value::as_array)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::unprocessable("split must be a non-empty array of { address, amountSompi }"))?;
    let split = split
        .iter()
        .map(|item| {
            let amount = i64_field(item, "amountSompi")?;
            if amount <= 0 {
                return Err(AppError::unprocessable("split amountSompi must be positive"));
            }
            Ok((str_field(item, "address")?.to_string(), amount as u64))
        })
        .collect::<AppResult<Vec<_>>>()?;
    Ok((split, str_field(body, "feePayerAddress")?))
}

pub async fn mutual_settlement_prepare(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let (split, fee_payer) = mutual_settlement_body(&body)?;
    Ok(Json(
        crate::covenant_keeper::dispute_mutual_settle_prepare(&state, &case_id, fee_payer, &split).await?,
    ))
}

pub async fn mutual_settlement_submit(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let (split, fee_payer) = mutual_settlement_body(&body)?;
    let customer_signature = str_field(&body, "customerSignature")?;
    let seller_signature = str_field(&body, "sellerSignature")?;
    let fee_signature = str_field(&body, "feeSignature")?;
    Ok(Json(
        crate::covenant_keeper::dispute_mutual_settle_submit(
            &state,
            &case_id,
            fee_payer,
            &split,
            customer_signature,
            seller_signature,
            fee_signature,
        )
        .await?,
    ))
}

pub async fn feedback_store(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let (payload, signature) = signed_parts(&body)?;
    if str_field(payload, "caseId")? != case_id {
        return Err(AppError::unprocessable("caseId does not match route"));
    }
    let (_, customer, seller, _, profile_id, _) = case_context(&state, &case_id).await?;
    let role = str_field(payload, "authorRole")?;
    let author_key = str_field(payload, "authorKey")?;
    let expected = match role {
        "customer" => customer,
        "seller" => seller,
        _ => {
            return Err(AppError::unprocessable(
                "authorRole must be customer or seller",
            ))
        }
    };
    if !expected.eq_ignore_ascii_case(author_key) {
        return Err(AppError::commerce(
            403,
            "feedback author key does not match case role",
        ));
    }
    let (_, nonce) = verify_payload(
        payload, signature, author_key, FEEDBACK_DOMAIN, ActionRule::Exact("submit_feedback"),
    )?;
    let score = i64_field(payload, "score")?;
    if !(1..=5).contains(&score) {
        return Err(AppError::unprocessable("score must be between 1 and 5"));
    }
    let tags = string_array(payload, "tags", MAX_TAGS)?;
    let state_value: String =
        sqlx::query_scalar("SELECT state FROM dispute_cases WHERE case_id=$1")
            .bind(&case_id)
            .fetch_one(&state.db.pool)
            .await?;
    if state_value != "settled" {
        return Err(AppError::unprocessable("feedback requires a settled case"));
    }
    let commitment = canonical_hash_hex(payload);
    let feedback_id = str_field(payload, "feedbackId")?;
    let mut tx = state.db.pool.begin().await?;
    consume_nonce(&mut *tx, author_key, &nonce).await?;
    let inserted = sqlx::query("INSERT INTO evaluator_feedback (feedback_id,case_id,profile_id,author_role,author_key,score,tags,feedback_commitment,signature,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (case_id, author_role) DO NOTHING")
        .bind(feedback_id).bind(&case_id).bind(&profile_id).bind(role).bind(author_key).bind(score)
        .bind(serde_json::to_string(&tags).unwrap()).bind(&commitment).bind(signature).bind(now_iso())
        .execute(&mut *tx).await?;
    if inserted.rows_affected() == 0 {
        return Err(AppError::commerce(409, "feedback already submitted for this case role"));
    }
    tx.commit().await?;
    Ok(Json(
        json!({ "feedbackId": feedback_id, "caseId": case_id, "commitment": commitment }),
    ))
}

pub async fn reputation_show(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
) -> AppResult<Json<Value>> {
    Ok(Json(reputation_value(&state, &profile_id).await?))
}

pub async fn case_show(
    State(state): State<AppState>,
    Path(case_id): Path<String>,
) -> AppResult<Json<Value>> {
    let row = sqlx::query("SELECT d.*,e.profile_id,e.engagement_hash,e.fee_sompi,e.reward_address FROM dispute_cases d JOIN evaluator_engagements e ON e.engagement_id=d.engagement_id WHERE d.case_id=$1")
        .bind(&case_id).fetch_optional(&state.db.pool).await?.ok_or_else(AppError::row_not_found)?;
    Ok(Json(json!({
        "caseId": row.get::<String,_>("case_id"), "engagementId": row.get::<String,_>("engagement_id"),
        "engagementHash": row.get::<String,_>("engagement_hash"), "invoiceId": row.get::<String,_>("invoice_public_id"),
        "profileId": row.get::<String,_>("profile_id"), "state": row.get::<String,_>("state"),
        "openerRole": row.get::<String,_>("opener_role"), "openingReasonHash": row.get::<String,_>("opening_reason_hash"),
        "disputeTxId": row.try_get::<String,_>("dispute_tx_id").ok(), "disputeCovenantAddress": row.try_get::<String,_>("dispute_covenant_address").ok(),
        "decisionCommitment": row.try_get::<String,_>("decision_commitment").ok(), "decisionOutcome": row.try_get::<String,_>("decision_outcome").ok(),
        "decisionReasonHash": row.try_get::<String,_>("decision_reason_hash").ok(), "decisionCommitTxId": row.try_get::<String,_>("decision_commit_tx_id").ok(),
        "decisionRevealTxId": row.try_get::<String,_>("decision_reveal_tx_id").ok(), "settlementTxId": row.try_get::<String,_>("settlement_tx_id").ok(),
        "feeSompi": row.get::<i64,_>("fee_sompi").to_string(),
        "openedAt": row.get::<String,_>("opened_at"), "decisionDueAt": row.get::<String,_>("decision_due_at"), "settledAt": row.try_get::<String,_>("settled_at").ok(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasway_covenant::KeeperKey;

    #[test]
    fn evaluator_profile_id_is_key_bound() {
        assert_eq!(
            deterministic_id("eval", &"11".repeat(32)),
            deterministic_id("eval", &"11".repeat(32))
        );
        assert_ne!(
            deterministic_id("eval", &"11".repeat(32)),
            deterministic_id("eval", &"22".repeat(32))
        );
    }

    #[test]
    fn decision_preimage_is_unambiguous() {
        let a = json!({"domain":"kasway/evaluator-decision/v1","protocolVersion":"1","network":"tn10","engagementHash":"aa","caseId":"case_1","outcome":"release","reasonHash":"bb","salt":"cc"});
        let b = json!({"salt":"cc","reasonHash":"bb","outcome":"release","caseId":"case_1","engagementHash":"aa","network":"tn10","protocolVersion":"1","domain":"kasway/evaluator-decision/v1"});
        assert_eq!(canonical_hash_hex(&a), canonical_hash_hex(&b));
    }

    fn signed(key: &KeeperKey, payload: &Value) -> String {
        encode_hex(&key.sign_datasig(&canonical_hash(payload)).unwrap())
    }

    fn verify(key: &KeeperKey, payload: &Value) -> AppResult<(String, String)> {
        let sig = signed(key, payload);
        verify_payload(payload, &sig, &encode_hex(&key.x_only_pubkey()), PROFILE_DOMAIN, ActionRule::Exact("publish_profile"))
    }

    #[test]
    fn envelope_requires_action_nonce_and_future_expiry() {
        let key = KeeperKey::from_secret_bytes(&[7u8; 32]).unwrap();
        let future = (Utc::now() + Duration::hours(1)).to_rfc3339();
        let ok = json!({
            "domain": PROFILE_DOMAIN, "protocolVersion": "1", "network": "tn10",
            "action": "publish_profile", "nonce": "ab".repeat(32), "expiresAt": future,
        });
        let (_, nonce) = verify(&key, &ok).expect("valid envelope");
        assert_eq!(nonce, "ab".repeat(32));

        let mut missing_nonce = ok.clone();
        missing_nonce.as_object_mut().unwrap().remove("nonce");
        assert!(verify(&key, &missing_nonce).is_err());

        let mut wrong_action = ok.clone();
        wrong_action["action"] = json!("issue_quote");
        assert!(verify(&key, &wrong_action).is_err());

        let mut expired = ok.clone();
        expired["expiresAt"] = json!((Utc::now() - Duration::seconds(1)).to_rfc3339());
        assert!(verify(&key, &expired).is_err());
    }
}
