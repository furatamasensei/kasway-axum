//! `/api/explorer/kpr1/*` — Kpr1ExplorerController + Kpr1ExplorerService.
//! Public, read-only DB lookups over kpr1_payment_intents / payment_observations
//! / payment_credits / invoices, projecting public payment facts.

use crate::error::AppResult;
use crate::kpr1::{canonicalize, signing_public_key_b64, verify_intent_signature};
use crate::state::AppState;
use crate::util::sha256_hex;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize, Default)]
pub struct ExplorerQuery {
    variant: Option<String>,
    #[serde(rename = "includeIntent")]
    include_intent: Option<bool>,
    network: Option<String>,
    #[serde(rename = "assetId")]
    asset_id: Option<String>,
}

fn include_canonical(q: &ExplorerQuery) -> bool {
    q.variant.as_deref() == Some("wallet") || q.include_intent == Some(true)
}

#[derive(sqlx::FromRow)]
struct IntentRow {
    intent_id: String,
    invoice_id: i64,
    status: String,
    network: String,
    asset_id: String,
    amount_sompi: i64,
    template_id: String,
    template_version: String,
    script_hash: String,
    canonical_hash: String,
    payment_request_uri: String,
    payment_intent_url: String,
    signature_algorithm: String,
    signature_key_id: String,
    tx_id: Option<String>,
    verification_status: Option<String>,
    failure_reason: Option<String>,
    required_outputs: String,
    canonical_intent: String,
    metadata: Option<String>,
    expires_at: Option<String>,
    fetched_at: Option<String>,
    submitted_at: Option<String>,
    observed_at: Option<String>,
    verified_at: Option<String>,
    settled_at: Option<String>,
    created_at: Option<String>,
}

const INTENT_COLS: &str = "intent_id, invoice_id, status, network, asset_id, amount_sompi, template_id, \
    template_version, script_hash, canonical_hash, payment_request_uri, payment_intent_url, \
    signature_algorithm, signature_key_id, tx_id, verification_status, failure_reason, required_outputs, \
    canonical_intent, metadata, expires_at, fetched_at, submitted_at, observed_at, verified_at, settled_at, created_at";

#[derive(sqlx::FromRow)]
struct ObsRow {
    id: i64,
    tx_id: Option<String>,
    output_index: Option<i64>,
    status: String,
    amount: i64,
    block_hash: Option<String>,
    block_daa_score: Option<i64>,
    confirmations: i64,
    accepted_at: Option<String>,
    matched_at: Option<String>,
    settled_at: Option<String>,
    metadata: Option<String>,
}

const OBS_COLS: &str = "id, tx_id, output_index, status, amount, block_hash, block_daa_score, \
    confirmations, accepted_at, matched_at, settled_at, metadata";

const STABLE_REASONS: &[&str] = &[
    "intent_expired", "network_or_asset_mismatch", "tx_id_mismatch", "amount_mismatch",
    "script_hash_mismatch", "missing_full_output_data",
];

// ---- value path helpers ----------------------------------------------------

fn at<'a>(v: &'a Value, path: &[&str]) -> &'a Value {
    let mut cur = v;
    for k in path {
        match cur {
            Value::Object(m) => cur = m.get(*k).unwrap_or(&Value::Null),
            _ => return &Value::Null,
        }
    }
    cur
}
fn str_at(v: &Value, path: &[&str]) -> Option<String> {
    match at(v, path) { Value::String(s) if !s.is_empty() => Some(s.clone()), _ => None }
}
fn arr_at(v: &Value, path: &[&str]) -> Vec<Value> {
    match at(v, path) { Value::Array(a) => a.clone(), _ => vec![] }
}
fn rec_nonempty(v: &Value, path: &[&str]) -> Value {
    match at(v, path) { Value::Object(m) if !m.is_empty() => Value::Object(m.clone()), _ => json!({}) }
}
fn str_val(v: &Value) -> Value {
    match v { Value::String(s) if !s.is_empty() => json!(s), _ => Value::Null }
}
fn safe_reason(v: Option<&str>) -> Value {
    match v {
        Some(s) if !s.is_empty() => {
            if STABLE_REASONS.contains(&s) || (s.starts_with("missing_required_") && s.ends_with("_output")) {
                json!(s)
            } else {
                json!("verification_failed")
            }
        }
        _ => Value::Null,
    }
}

fn parse_json(s: &Option<String>) -> Value {
    s.as_deref().and_then(|x| serde_json::from_str(x).ok()).unwrap_or(json!({}))
}

// ---- DB loads --------------------------------------------------------------

async fn intent_by(state: &AppState, col: &str, val: &str) -> AppResult<Option<IntentRow>> {
    Ok(sqlx::query_as::<_, IntentRow>(&format!("SELECT {INTENT_COLS} FROM kpr1_payment_intents WHERE {col} = $1 LIMIT 1"))
        .bind(val).fetch_optional(&state.db.pool).await?)
}

/// `intent_by` for the BIGINT `invoice_id` column (Postgres rejects bigint = text).
async fn intent_by_invoice(state: &AppState, invoice_id: i64) -> AppResult<Option<IntentRow>> {
    Ok(sqlx::query_as::<_, IntentRow>(&format!("SELECT {INTENT_COLS} FROM kpr1_payment_intents WHERE invoice_id = $1 LIMIT 1"))
        .bind(invoice_id).fetch_optional(&state.db.pool).await?)
}

async fn find_observation(state: &AppState, intent: &IntentRow, tx_id: Option<&str>) -> AppResult<Option<ObsRow>> {
    let tx = match tx_id.or(intent.tx_id.as_deref()) { Some(t) => t.to_string(), None => return Ok(None) };
    Ok(sqlx::query_as::<_, ObsRow>(&format!(
        "SELECT {OBS_COLS} FROM payment_observations WHERE tx_id = $1 AND network = $2 AND asset_id = $3 \
         AND (invoice_id = $4 OR invoice_id IS NULL) ORDER BY created_at DESC LIMIT 1"
    ))
    .bind(&tx).bind(&intent.network).bind(&intent.asset_id).bind(intent.invoice_id)
    .fetch_optional(&state.db.pool).await?)
}

async fn find_credit(state: &AppState, intent: &IntentRow, obs: &Option<ObsRow>) -> AppResult<Option<(i64, Option<String>)>> {
    let row = match obs {
        Some(o) => sqlx::query_as::<_, (i64, Option<String>)>(
            "SELECT amount, credited_at FROM payment_credits WHERE invoice_id = $1 OR payment_observation_id = $2 ORDER BY credited_at DESC LIMIT 1",
        ).bind(intent.invoice_id).bind(o.id),
        None => sqlx::query_as::<_, (i64, Option<String>)>(
            "SELECT amount, credited_at FROM payment_credits WHERE invoice_id = $1 ORDER BY credited_at DESC LIMIT 1",
        ).bind(intent.invoice_id),
    };
    Ok(row.fetch_optional(&state.db.pool).await?)
}

// ---- serialize -------------------------------------------------------------

fn output_matches(required: &Value, candidate: &Value) -> bool {
    if !candidate.is_object() { return false; }
    let role = candidate.get("role").or_else(|| candidate.get("type"));
    let address = candidate.get("address");
    let amount = candidate.get("amountSompi").or_else(|| candidate.get("amount")).or_else(|| candidate.get("amountAtomic"));
    role == required.get("role")
        && address == required.get("address")
        && amount.map(|a| match a { Value::String(s) => s.clone(), other => other.to_string() }) == required.get("amountSompi").and_then(|v| v.as_str()).map(String::from)
}

async fn serialize(
    state: &AppState,
    lookup_type: &str,
    lookup_value: &str,
    intent: &IntentRow,
    obs: &Option<ObsRow>,
    include_canon: bool,
) -> AppResult<Value> {
    let invoice = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT public_id, status, paid_at FROM invoices WHERE id = $1",
    ).bind(intent.invoice_id).fetch_optional(&state.db.pool).await?;
    let (inv_public_id, inv_status, inv_paid_at) = match &invoice {
        Some((p, s, paid)) => (Some(p.clone()), Some(s.clone()), paid.clone()),
        None => (None, None, None),
    };
    let credit = find_credit(state, intent, obs).await?;

    let meta = parse_json(&intent.metadata);
    let obs_meta = obs.as_ref().map(|o| parse_json(&o.metadata)).unwrap_or(json!({}));
    let required_outputs: Value = serde_json::from_str(&intent.required_outputs).unwrap_or(json!([]));

    // observedOutputs: intent.metadata.verification.observedOutputs else observation.metadata.kpr1.outputs
    let mut observed_outputs = arr_at(&meta, &["verification", "observedOutputs"]);
    if observed_outputs.is_empty() {
        observed_outputs = arr_at(&obs_meta, &["kpr1", "outputs"]);
    }

    // output summaries
    let has_full = !observed_outputs.is_empty();
    let outputs: Vec<Value> = required_outputs.as_array().cloned().unwrap_or_default().iter().map(|o| {
        let matched = observed_outputs.iter().any(|c| output_matches(o, c));
        let role = o.get("role").and_then(|v| v.as_str()).unwrap_or("");
        json!({
            "role": o.get("role"), "address": o.get("address"), "amountSompi": o.get("amountSompi"),
            "required": true, "observed": matched, "matched": matched,
            "failureReason": if matched { Value::Null } else if has_full { json!(format!("missing_required_{role}_output")) } else { json!("missing_full_output_data") },
        })
    }).collect();

    // verification
    let all_matched = outputs.iter().all(|o| o["matched"] == json!(true));
    let output_reason = outputs.iter().find(|o| o["matched"] == json!(false)).and_then(|o| o["failureReason"].as_str().map(String::from));
    let meta_status = str_at(&meta, &["verification", "status"]);
    let meta_reason = str_at(&meta, &["verification", "reasonCode"]);
    let v_status = intent.verification_status.clone().or(meta_status).unwrap_or_else(|| {
        match intent.status.as_str() { "verified" | "settled" => "verified".into(), "failed" => "failed".into(), _ => "pending".into() }
    });
    let v_reason = safe_reason(intent.failure_reason.as_deref().or(meta_reason.as_deref()).or(output_reason.as_deref()));
    let verified = v_status == "verified" || intent.status == "verified" || intent.status == "settled";
    let verification = json!({
        "verified": verified,
        "status": v_status,
        "reasonCode": v_reason,
        "checks": [
            { "name": "required_outputs", "status": if all_matched { "passed" } else { "pending" }, "reasonCode": if all_matched { Value::Null } else { output_reason.clone().map(|s| json!(s)).unwrap_or(Value::Null) } },
            { "name": "script_hash", "status": if !intent.script_hash.is_empty() { "available" } else { "pending" }, "reasonCode": Value::Null },
        ],
    });

    // settlement
    let credit_amount = credit.as_ref().map(|(a, _)| a.to_string());
    let credit_at = credit.as_ref().and_then(|(_, c)| c.clone());
    let obs_status = obs.as_ref().map(|o| o.status.clone());
    let settled = intent.status == "settled" || obs_status.as_deref() == Some("settled") || credit.is_some() || inv_status.as_deref() == Some("paid");
    let settled_at = intent.settled_at.clone()
        .or_else(|| obs.as_ref().and_then(|o| o.settled_at.clone()))
        .or(credit_at)
        .or(inv_paid_at);
    let settlement = json!({
        "state": if settled { "settled" } else if intent.status == "verified" { "pending_settlement" } else { "not_settled" },
        "settled": settled,
        "invoiceStatus": inv_status,
        "creditedAmountSompi": credit_amount,
        "settledAt": settled_at,
    });

    // public state
    let now = Utc::now();
    let expired_by_time = intent.expires_at.as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|e| e.with_timezone(&Utc) < now).unwrap_or(false);
    let public_state = if settled { "settled" }
        else if intent.status == "expired" || expired_by_time { "expired" }
        else if intent.status == "unsupported" { "unsupported" }
        else if intent.status == "failed" || v_status == "failed" { "failed_verification" }
        else if verified { "verified_pending_settlement" }
        else if obs.is_some() { "observed_unverified" }
        else if intent.tx_id.is_some() || intent.status == "submitted" { "submitted_unobserved" }
        else { "not_observed" };
    let state_reason = match public_state {
        "expired" => json!("intent_expired"),
        "unsupported" => safe_reason(intent.failure_reason.as_deref()).as_str().map(|s| json!(s)).unwrap_or(json!("unsupported_intent_status")),
        _ => Value::Null,
    };
    let top_reason = if !verification["reasonCode"].is_null() { verification["reasonCode"].clone() } else { state_reason };

    // covenant
    let artifact = rec_nonempty(&meta, &["covenant", "artifact"]);
    let compiled_cov = rec_nonempty(&meta, &["compiledCovenant"]);
    let compiled = rec_nonempty(&meta, &["compiledArtifact"]);
    let source = if artifact.as_object().map(|m| !m.is_empty()).unwrap_or(false) { artifact }
        else if compiled_cov.as_object().map(|m| !m.is_empty()).unwrap_or(false) { compiled_cov }
        else { compiled };
    let covenant = json!({
        "templateId": intent.template_id, "templateVersion": intent.template_version, "scriptHash": intent.script_hash,
        "artifactId": str_val(at(&source, &["artifactId"])), "artifactScope": str_val(at(&source, &["artifactScope"])),
        "sourceHash": str_val(at(&source, &["sourceHash"])), "compilerCommit": str_val(at(&source, &["compilerCommit"])),
        "compilerOutputHash": str_val(at(&source, &["compilerOutputHash"])), "templateStatus": str_val(at(&source, &["templateStatus"])),
        "approvedSourceHash": str_val(at(&source, &["approvedSourceHash"])),
        "productionApproved": if source.get("productionApproved").map(|v| v.is_boolean()).unwrap_or(false) { source["productionApproved"].clone() } else { Value::Null },
        "networkTarget": str_val(at(&source, &["networkTarget"])), "generatedAt": str_val(at(&source, &["generatedAt"])),
    });

    // observation summary
    let observed_script_hash = str_at(&meta, &["verification", "observedScriptHash"]).or_else(|| str_at(&obs_meta, &["kpr1", "scriptHash"]));
    let observation = json!({
        "observed": obs.is_some(),
        "txId": obs.as_ref().and_then(|o| o.tx_id.clone()).or_else(|| intent.tx_id.clone()),
        "outputIndex": obs.as_ref().and_then(|o| o.output_index),
        "status": obs_status,
        "amountSompi": obs.as_ref().map(|o| o.amount.to_string()),
        "blockHash": obs.as_ref().and_then(|o| o.block_hash.clone()),
        "blockDaaScore": obs.as_ref().and_then(|o| o.block_daa_score).map(|v| v.to_string()),
        "confirmations": obs.as_ref().map(|o| o.confirmations).unwrap_or(0),
        "acceptedAt": obs.as_ref().and_then(|o| o.accepted_at.clone()),
        "matchedAt": obs.as_ref().and_then(|o| o.matched_at.clone()),
        "settledAt": obs.as_ref().and_then(|o| o.settled_at.clone()),
        "observedScriptHash": observed_script_hash,
    });

    let mut result = json!({
        "lookup": { "type": lookup_type, "value": lookup_value, "matched": true },
        "payment": {
            "rail": "kpr1_covenant", "intentId": intent.intent_id, "invoicePublicId": inv_public_id,
            "canonicalHash": intent.canonical_hash, "paymentRequestUri": intent.payment_request_uri,
            "paymentIntentUrl": intent.payment_intent_url, "network": intent.network, "assetId": intent.asset_id,
            "amountSompi": intent.amount_sompi.to_string(), "status": intent.status, "publicState": public_state,
            "reasonCode": top_reason,
            "createdAt": intent.created_at, "expiresAt": intent.expires_at, "fetchedAt": intent.fetched_at,
            "submittedAt": intent.submitted_at, "observedAt": intent.observed_at, "verifiedAt": intent.verified_at,
            "settledAt": intent.settled_at,
        },
        "signature": {
            "alg": intent.signature_algorithm, "keyId": intent.signature_key_id, "intentHash": intent.canonical_hash,
            "payloadHashRule": "canonical_kpr1_intent_sha256", "signaturePayloadRule": "sign_canonical_intent_hash",
        },
        "covenant": covenant,
        "outputs": outputs,
        "observation": observation,
        "verification": verification,
        "settlement": settlement,
    });

    if include_canon {
        let canon: Value = serde_json::from_str(&intent.canonical_intent).unwrap_or(json!({}));
        result["wallet"] = json!({ "canonicalIntent": canon });
    }
    Ok(result)
}

// ---- settlement proof (self-verifying) -------------------------------------
//
// Unlike the explorer projection above (which echoes stored DB status flags),
// the settlement proof RECOMPUTES the answer: it re-hashes the stored canonical
// intent, re-verifies the ed25519 signature against the published signing key,
// and surfaces the on-chain settlement tx id + covenant address so a third party
// can independently confirm the outcome on any Kaspa node — without trusting a
// Kasway "paid" flag.

#[derive(sqlx::FromRow)]
struct ProofRow {
    intent_id: String,
    invoice_id: i64,
    network: String,
    asset_id: String,
    amount_sompi: i64,
    canonical_hash: String,
    canonical_intent: String,
    signature_algorithm: String,
    signature_key_id: String,
    script_hash: Option<String>,
    covenant_address: Option<String>,
    covenant_state: Option<String>,
    gross_amount: Option<i64>,
    release_tx_id: Option<String>,
    refund_tx_id: Option<String>,
    settled_at: Option<String>,
}

const PROOF_COLS: &str = "intent_id, invoice_id, network, asset_id, amount_sompi, canonical_hash, \
    canonical_intent, signature_algorithm, signature_key_id, script_hash, covenant_address, \
    covenant_state, gross_amount, release_tx_id, refund_tx_id, settled_at";

async fn proof_by_intent(state: &AppState, intent_id: &str) -> AppResult<Option<ProofRow>> {
    Ok(sqlx::query_as::<_, ProofRow>(&format!(
        "SELECT {PROOF_COLS} FROM kpr1_payment_intents WHERE intent_id = $1 LIMIT 1"
    ))
    .bind(intent_id)
    .fetch_optional(&state.db.pool)
    .await?)
}

/// `proof_by` for the BIGINT `invoice_id` column (Postgres rejects bigint = text).
async fn proof_by_invoice(state: &AppState, invoice_id: i64) -> AppResult<Option<ProofRow>> {
    Ok(sqlx::query_as::<_, ProofRow>(&format!(
        "SELECT {PROOF_COLS} FROM kpr1_payment_intents WHERE invoice_id = $1 LIMIT 1"
    ))
    .bind(invoice_id)
    .fetch_optional(&state.db.pool)
    .await?)
}

/// Strip the `signature` object from a signed intent, yielding the exact payload
/// that was ed25519-signed at mint time.
fn intent_without_signature(intent: &Value) -> Value {
    let mut m = intent.as_object().cloned().unwrap_or_default();
    m.remove("signature");
    Value::Object(m)
}

fn build_settlement_proof(state: &AppState, row: &ProofRow, lookup_type: &str, lookup_value: &str) -> Value {
    let signed_intent: Value = serde_json::from_str(&row.canonical_intent).unwrap_or(json!({}));

    // 1. Recompute the canonical hash from the stored signed intent.
    let recomputed_hash = sha256_hex(canonicalize(&signed_intent).as_bytes());
    let hash_matches = recomputed_hash == row.canonical_hash;

    // 2. Re-verify the ed25519 signature over the unsigned canonical payload
    //    against the published signing key (recomputed, not a stored flag).
    let unsigned_canonical = canonicalize(&intent_without_signature(&signed_intent));
    let sig_value = signed_intent
        .get("signature")
        .and_then(|s| s.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let seed = &state.config.kpr1.signing_seed;
    let signature_verified = !sig_value.is_empty() && verify_intent_signature(seed, &unsigned_canonical, sig_value);

    // 3. On-chain settlement facts anyone can independently check.
    let covenant_state = row.covenant_state.clone().unwrap_or_else(|| "pending".into());
    let settled = covenant_state == "settled"
        || matches!(covenant_state.as_str(), "released" | "captured" | "arbitrated" | "settled_mutual" | "settled_jury")
        || row.release_tx_id.is_some();
    let refunded = covenant_state == "refunded" || row.refund_tx_id.is_some();
    let settlement_tx_id = row.release_tx_id.clone().or_else(|| row.refund_tx_id.clone());
    let outcome = if refunded { "refunded" } else if settled { "settled" } else { "pending" };

    let config_commitment = signed_intent.get("configCommitment").and_then(|v| v.as_str());

    json!({
        "lookup": { "type": lookup_type, "value": lookup_value, "matched": true },
        "payment": {
            "rail": "kpr1_covenant",
            "intentId": row.intent_id,
            "invoiceId": row.invoice_id,
            "network": row.network,
            "assetId": row.asset_id,
            "amountSompi": row.amount_sompi.to_string(),
            "grossSompi": row.gross_amount.map(|g| g.to_string()),
        },
        // Everything a third party needs to verify the intent OFFLINE, plus the
        // recomputed verdict so they need not trust our DB flags.
        "proof": {
            "canonicalHash": row.canonical_hash,
            "recomputedCanonicalHash": recomputed_hash,
            "canonicalHashMatches": hash_matches,
            "signature": {
                "alg": row.signature_algorithm,
                "keyId": row.signature_key_id,
                "publicKey": signing_public_key_b64(seed),
                "publicKeyEncoding": "base64-raw-ed25519",
                "verified": signature_verified,
            },
            "configCommitment": config_commitment,
            "selfVerified": hash_matches && signature_verified,
            "canonicalIntent": signed_intent,
        },
        "settlement": {
            "outcome": outcome,
            "covenantState": covenant_state,
            "covenantAddress": row.covenant_address,
            "scriptHash": row.script_hash,
            "settlementTxId": settlement_tx_id,
            "releaseTxId": row.release_tx_id,
            "refundTxId": row.refund_tx_id,
            "settledAt": row.settled_at,
            "note": "settlementTxId is a Kaspa transaction — verify it against any Kaspa node/explorer to confirm the covenant paid the intent's outputs. Custody and payout are enforced on-chain by the covenant, not by this response.",
        },
    })
}

/// `GET /api/explorer/kpr1/intents/:intentId/settlement-proof`
pub async fn settlement_proof_by_intent(State(state): State<AppState>, Path(intent_id): Path<String>) -> AppResult<Response> {
    match proof_by_intent(&state, &intent_id).await? {
        Some(row) => Ok(Json(build_settlement_proof(&state, &row, "intent_id", &intent_id)).into_response()),
        None => Ok(not_found("intent_id", &intent_id)),
    }
}

/// `GET /api/explorer/kpr1/invoices/:publicId/settlement-proof`
pub async fn settlement_proof_by_invoice(State(state): State<AppState>, Path(public_id): Path<String>) -> AppResult<Response> {
    let invoice_id: Option<i64> = sqlx::query_scalar("SELECT id FROM invoices WHERE public_id = $1")
        .bind(&public_id)
        .fetch_optional(&state.db.pool)
        .await?;
    let row = match invoice_id {
        Some(id) => proof_by_invoice(&state, id).await?,
        None => None,
    };
    match row {
        Some(row) => Ok(Json(build_settlement_proof(&state, &row, "invoice_public_id", &public_id)).into_response()),
        None => Ok(not_found("invoice_public_id", &public_id)),
    }
}

fn not_found(lookup_type: &str, value: &str) -> Response {
    (StatusCode::NOT_FOUND, Json(json!({
        "code": "KPR1_EXPLORER_NOT_FOUND", "lookupType": lookup_type,
        "message": format!("No KPR-1 payment facts matched {value}")
    }))).into_response()
}

fn ambiguous(tx_id: &str) -> Response {
    (StatusCode::CONFLICT, Json(json!({
        "code": "KPR1_EXPLORER_AMBIGUOUS_LOOKUP", "lookupType": "tx_id",
        "message": format!("Multiple KPR-1 payment facts matched {tx_id}. Add network or assetId filters.")
    }))).into_response()
}

// ---- handlers --------------------------------------------------------------

/// `GET /api/explorer/kpr1/intents/:intentId`
pub async fn show_intent(State(state): State<AppState>, Path(intent_id): Path<String>, Query(q): Query<ExplorerQuery>) -> AppResult<Response> {
    match intent_by(&state, "intent_id", &intent_id).await? {
        Some(intent) => {
            let obs = find_observation(&state, &intent, None).await?;
            Ok(Json(serialize(&state, "intent_id", &intent_id, &intent, &obs, include_canonical(&q)).await?).into_response())
        }
        None => Ok(not_found("intent_id", &intent_id)),
    }
}

/// `GET /api/explorer/kpr1/intents/:intentId/wallet-verification`
pub async fn wallet_verification(State(state): State<AppState>, Path(intent_id): Path<String>) -> AppResult<Response> {
    match intent_by(&state, "intent_id", &intent_id).await? {
        Some(intent) => {
            let obs = find_observation(&state, &intent, None).await?;
            Ok(Json(serialize(&state, "intent_id", &intent_id, &intent, &obs, true).await?).into_response())
        }
        None => Ok(not_found("intent_id", &intent_id)),
    }
}

/// `GET /api/explorer/kpr1/payment-requests/:canonicalHash`
pub async fn show_payment_request(State(state): State<AppState>, Path(canonical_hash): Path<String>, Query(q): Query<ExplorerQuery>) -> AppResult<Response> {
    match intent_by(&state, "canonical_hash", &canonical_hash).await? {
        Some(intent) => {
            let obs = find_observation(&state, &intent, None).await?;
            Ok(Json(serialize(&state, "canonical_hash", &canonical_hash, &intent, &obs, include_canonical(&q)).await?).into_response())
        }
        None => Ok(not_found("canonical_hash", &canonical_hash)),
    }
}

/// `GET /api/explorer/kpr1/invoices/:publicId`
pub async fn show_invoice(State(state): State<AppState>, Path(public_id): Path<String>, Query(q): Query<ExplorerQuery>) -> AppResult<Response> {
    let invoice_id: Option<i64> = sqlx::query_scalar("SELECT id FROM invoices WHERE public_id = $1").bind(&public_id).fetch_optional(&state.db.pool).await?;
    let intent = match invoice_id {
        Some(id) => intent_by_invoice(&state, id).await?,
        None => None,
    };
    match intent {
        Some(intent) => {
            let obs = find_observation(&state, &intent, None).await?;
            Ok(Json(serialize(&state, "invoice_public_id", &public_id, &intent, &obs, include_canonical(&q)).await?).into_response())
        }
        None => Ok(not_found("invoice_public_id", &public_id)),
    }
}

/// `GET /api/explorer/kpr1/transactions/:txId`
pub async fn show_transaction(State(state): State<AppState>, Path(tx_id): Path<String>, Query(q): Query<ExplorerQuery>) -> AppResult<Response> {
    // intents by tx_id (ambiguity check)
    let mut n = 1;
    let mut sql = format!("SELECT {INTENT_COLS} FROM kpr1_payment_intents WHERE tx_id = ${n}");
    n += 1;
    if q.network.is_some() { sql.push_str(&format!(" AND network = ${n}")); n += 1; }
    if q.asset_id.is_some() { sql.push_str(&format!(" AND asset_id = ${n}")); n += 1; }
    let _ = n;
    sql.push_str(" ORDER BY created_at DESC, id DESC LIMIT 2");
    let mut iq = sqlx::query_as::<_, IntentRow>(&sql).bind(&tx_id);
    if let Some(n) = &q.network { iq = iq.bind(n.clone()); }
    if let Some(a) = &q.asset_id { iq = iq.bind(a.clone()); }
    let intents = iq.fetch_all(&state.db.pool).await?;
    if intents.len() > 1 {
        return Ok(ambiguous(&tx_id));
    }
    if let Some(intent) = intents.into_iter().next() {
        let obs = find_observation(&state, &intent, Some(&tx_id)).await?;
        return Ok(Json(serialize(&state, "tx_id", &tx_id, &intent, &obs, include_canonical(&q)).await?).into_response());
    }

    // fall back to observations by tx_id → intentId from metadata
    let mut on = 1;
    let mut osql = format!("SELECT {OBS_COLS} FROM payment_observations WHERE tx_id = ${on}");
    on += 1;
    if q.network.is_some() { osql.push_str(&format!(" AND network = ${on}")); on += 1; }
    if q.asset_id.is_some() { osql.push_str(&format!(" AND asset_id = ${on}")); on += 1; }
    let _ = on;
    osql.push_str(" ORDER BY created_at DESC, id DESC LIMIT 2");
    let mut oq = sqlx::query_as::<_, ObsRow>(&osql).bind(&tx_id);
    if let Some(n) = &q.network { oq = oq.bind(n.clone()); }
    if let Some(a) = &q.asset_id { oq = oq.bind(a.clone()); }
    let observations = oq.fetch_all(&state.db.pool).await?;
    if observations.len() > 1 {
        return Ok(ambiguous(&tx_id));
    }
    let observation = match observations.into_iter().next() { Some(o) => o, None => return Ok(not_found("tx_id", &tx_id)) };
    let obs_meta = parse_json(&observation.metadata);
    let intent_id = match str_at(&obs_meta, &["kpr1", "intentId"]) { Some(i) => i, None => return Ok(not_found("tx_id", &tx_id)) };
    match intent_by(&state, "intent_id", &intent_id).await? {
        Some(intent) => Ok(Json(serialize(&state, "tx_id", &tx_id, &intent, &Some(observation), include_canonical(&q)).await?).into_response()),
        None => Ok(not_found("tx_id", &tx_id)),
    }
}
