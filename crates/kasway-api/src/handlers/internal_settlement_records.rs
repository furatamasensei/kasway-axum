//! `/internal/payment-ops/tocatta/covenants/*` — InternalProgrammableSettlementRecordsController
//! + ProgrammableSettlementBetaRecordsService. DB records for beta settlement
//! templates / approvals / artifacts / executions (internal-token tier).
//! Audit-event recording is a no-op side effect. No request validation in Adonis
//! (raw request.body()); the port adds light required-field 422s to avoid 500s.

use crate::auth::InternalToken;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::util::now_iso;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

const APPROVAL_DOMAINS: &[&str] = &["product", "engineering", "support", "finance", "legal", "operations"];

fn parse_json(s: &str, default: Value) -> Value {
    serde_json::from_str(s).unwrap_or(default)
}

// ---- row structs + serializers --------------------------------------------

#[derive(sqlx::FromRow)]
struct TemplateRow {
    id: i64,
    template_id: String,
    template_version: String,
    status: String,
    source_hash: String,
    compiler_commit: Option<String>,
    kill_switch_enabled: i64,
    created_by_user_id: Option<i64>,
    approved_by_user_id: Option<i64>,
    approved_at: Option<String>,
    disabled_by_user_id: Option<i64>,
    disabled_at: Option<String>,
    disable_reason: Option<String>,
    metadata: String,
    created_at: Option<String>,
    updated_at: Option<String>,
}

fn ser_template(t: &TemplateRow, relations: Option<(Vec<Value>, Vec<Value>, Vec<Value>)>) -> Value {
    let mut obj = json!({
        "id": t.id,
        "templateId": t.template_id,
        "templateVersion": t.template_version,
        "status": t.status,
        "sourceHash": t.source_hash,
        "compilerCommit": t.compiler_commit,
        "killSwitchEnabled": t.kill_switch_enabled != 0,
        "createdByUserId": t.created_by_user_id,
        "approvedByUserId": t.approved_by_user_id,
        "approvedAt": t.approved_at,
        "disabledByUserId": t.disabled_by_user_id,
        "disabledAt": t.disabled_at,
        "disableReason": t.disable_reason,
        "metadata": parse_json(&t.metadata, json!({})),
        "createdAt": t.created_at,
        "updatedAt": t.updated_at,
    });
    if let (Value::Object(m), Some((approvals, artifacts, executions))) = (&mut obj, relations) {
        m.insert("approvals".into(), Value::Array(approvals));
        m.insert("artifacts".into(), Value::Array(artifacts));
        m.insert("executions".into(), Value::Array(executions));
    }
    obj
}

#[derive(sqlx::FromRow)]
struct ApprovalRow {
    id: i64,
    template_record_id: i64,
    domain: String,
    status: String,
    approved_by_user_id: Option<i64>,
    approved_at: Option<String>,
    notes: Option<String>,
    metadata: String,
    created_at: Option<String>,
    updated_at: Option<String>,
}

fn ser_approval(a: &ApprovalRow) -> Value {
    json!({
        "id": a.id,
        "templateRecordId": a.template_record_id,
        "domain": a.domain,
        "status": a.status,
        "approvedByUserId": a.approved_by_user_id,
        "approvedAt": a.approved_at,
        "notes": a.notes,
        "metadata": parse_json(&a.metadata, json!({})),
        "createdAt": a.created_at,
        "updatedAt": a.updated_at,
    })
}

#[derive(sqlx::FromRow)]
struct ArtifactRow {
    id: i64,
    template_record_id: i64,
    artifact_id: String,
    source_hash: String,
    compiler_commit: String,
    compiler_output_hash: String,
    script_hash: String,
    network_target: String,
    argument_schema: String,
    warnings: String,
    metadata: String,
    generated_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

fn ser_artifact(a: &ArtifactRow) -> Value {
    json!({
        "id": a.id,
        "templateRecordId": a.template_record_id,
        "artifactId": a.artifact_id,
        "sourceHash": a.source_hash,
        "compilerCommit": a.compiler_commit,
        "compilerOutputHash": a.compiler_output_hash,
        "scriptHash": a.script_hash,
        "networkTarget": a.network_target,
        "argumentSchema": parse_json(&a.argument_schema, json!([])),
        "warnings": parse_json(&a.warnings, json!([])),
        "metadata": parse_json(&a.metadata, json!({})),
        "generatedAt": a.generated_at,
        "createdAt": a.created_at,
        "updatedAt": a.updated_at,
    })
}

#[derive(sqlx::FromRow)]
struct ExecutionRow {
    id: i64,
    template_record_id: i64,
    artifact_record_id: Option<i64>,
    status: String,
    network: String,
    dry_run_payload_hash: Option<String>,
    tx_id: Option<String>,
    evidence_reference: Option<String>,
    sandbox_outcome: Option<String>,
    metadata: String,
    executed_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

fn ser_execution(e: &ExecutionRow) -> Value {
    json!({
        "id": e.id,
        "templateRecordId": e.template_record_id,
        "artifactRecordId": e.artifact_record_id,
        "status": e.status,
        "network": e.network,
        "dryRunPayloadHash": e.dry_run_payload_hash,
        "txId": e.tx_id,
        "evidenceReference": e.evidence_reference,
        "sandboxOutcome": e.sandbox_outcome,
        "metadata": parse_json(&e.metadata, json!({})),
        "executedAt": e.executed_at,
        "createdAt": e.created_at,
        "updatedAt": e.updated_at,
    })
}

// ---- relation loaders ------------------------------------------------------

async fn load_approvals(state: &AppState, tid: i64) -> AppResult<Vec<ApprovalRow>> {
    Ok(sqlx::query_as::<_, ApprovalRow>(
        "SELECT id, template_record_id, domain, status, approved_by_user_id, approved_at, notes, metadata, created_at, updated_at \
         FROM programmable_settlement_approvals WHERE template_record_id = $1 ORDER BY id ASC",
    ).bind(tid).fetch_all(&state.db.pool).await?)
}
async fn load_artifacts(state: &AppState, tid: i64) -> AppResult<Vec<ArtifactRow>> {
    Ok(sqlx::query_as::<_, ArtifactRow>(
        "SELECT id, template_record_id, artifact_id, source_hash, compiler_commit, compiler_output_hash, \
         script_hash, network_target, argument_schema, warnings, metadata, generated_at, created_at, updated_at \
         FROM programmable_settlement_artifacts WHERE template_record_id = $1 ORDER BY id ASC",
    ).bind(tid).fetch_all(&state.db.pool).await?)
}
async fn load_executions(state: &AppState, tid: i64) -> AppResult<Vec<ExecutionRow>> {
    Ok(sqlx::query_as::<_, ExecutionRow>(
        "SELECT id, template_record_id, artifact_record_id, status, network, dry_run_payload_hash, tx_id, \
         evidence_reference, sandbox_outcome, metadata, executed_at, created_at, updated_at \
         FROM programmable_settlement_executions WHERE template_record_id = $1 ORDER BY id ASC",
    ).bind(tid).fetch_all(&state.db.pool).await?)
}

const T_COLS: &str = "id, template_id, template_version, status, source_hash, compiler_commit, \
    kill_switch_enabled, created_by_user_id, approved_by_user_id, approved_at, disabled_by_user_id, \
    disabled_at, disable_reason, metadata, created_at, updated_at";

async fn load_template(state: &AppState, id: i64) -> AppResult<TemplateRow> {
    sqlx::query_as::<_, TemplateRow>(&format!("SELECT {T_COLS} FROM programmable_settlement_templates WHERE id = $1"))
        .bind(id)
        .fetch_optional(&state.db.pool)
        .await?
        .ok_or_else(AppError::row_not_found)
}

// ---- handlers --------------------------------------------------------------

/// `GET /internal/payment-ops/tocatta/covenants/templates`
pub async fn templates(_token: InternalToken, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let rows = sqlx::query_as::<_, TemplateRow>(&format!(
        "SELECT {T_COLS} FROM programmable_settlement_templates ORDER BY created_at DESC, id DESC"
    ))
    .fetch_all(&state.db.pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for t in &rows {
        let approvals = load_approvals(&state, t.id).await?.iter().map(ser_approval).collect();
        let artifacts = load_artifacts(&state, t.id).await?.iter().map(ser_artifact).collect();
        let executions = load_executions(&state, t.id).await?.iter().map(ser_execution).collect();
        out.push(ser_template(t, Some((approvals, artifacts, executions))));
    }
    Ok(Json(json!(out)))
}

fn req_str(body: &Value, field: &str) -> AppResult<String> {
    body.get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::validation_field(field, "required", &format!("The {field} field must be defined")))
}

/// `POST /internal/payment-ops/tocatta/covenants/templates`
pub async fn store_template(_token: InternalToken, State(state): State<AppState>, Json(body): Json<Value>) -> AppResult<Response> {
    let template_id = req_str(&body, "templateId")?;
    let source_hash = req_str(&body, "sourceHash")?;
    let version = body.get("templateVersion").and_then(|v| v.as_str()).unwrap_or("v1").to_string();
    let compiler_commit = body.get("compilerCommit").and_then(|v| v.as_str());
    let created_by = body.get("createdByUserId").and_then(|v| v.as_i64());
    let metadata = body.get("metadata").cloned().unwrap_or(json!({}));
    let now = now_iso();
    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO programmable_settlement_templates \
         (template_id, template_version, status, source_hash, compiler_commit, kill_switch_enabled, \
          created_by_user_id, metadata, created_at, updated_at) \
         VALUES ($1, $2, 'sandbox', $3, $4, 1, $5, $6, $7, $8) RETURNING id",
    )
    .bind(&template_id).bind(&version).bind(&source_hash).bind(compiler_commit)
    .bind(created_by).bind(metadata.to_string()).bind(&now).bind(&now)
    .fetch_one(&state.db.pool).await?;
    let t = load_template(&state, id).await?;
    Ok((StatusCode::OK, Json(ser_template(&t, None))).into_response())
}

/// `POST /internal/payment-ops/tocatta/covenants/artifacts`
pub async fn store_artifact(_token: InternalToken, State(state): State<AppState>, Json(body): Json<Value>) -> AppResult<Response> {
    let template_record_id = body.get("templateRecordId").and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::validation_field("templateRecordId", "required", "The templateRecordId field must be defined"))?;
    let artifact_id = req_str(&body, "artifactId")?;
    let source_hash = req_str(&body, "sourceHash")?;
    let compiler_commit = req_str(&body, "compilerCommit")?;
    let compiler_output_hash = req_str(&body, "compilerOutputHash")?;
    let script_hash = req_str(&body, "scriptHash")?;
    let network_target = req_str(&body, "networkTarget")?;
    let argument_schema = body.get("argumentSchema").cloned().unwrap_or(json!([]));
    let warnings = body.get("warnings").cloned().unwrap_or(json!([]));
    let metadata = body.get("metadata").cloned().unwrap_or(json!({}));
    let now = now_iso();
    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO programmable_settlement_artifacts \
         (template_record_id, artifact_id, source_hash, compiler_commit, compiler_output_hash, script_hash, \
          network_target, argument_schema, warnings, metadata, generated_at, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id",
    )
    .bind(template_record_id).bind(&artifact_id).bind(&source_hash).bind(&compiler_commit)
    .bind(&compiler_output_hash).bind(&script_hash).bind(&network_target)
    .bind(argument_schema.to_string()).bind(warnings.to_string()).bind(metadata.to_string())
    .bind(&now).bind(&now).bind(&now)
    .fetch_one(&state.db.pool).await?;
    let a = sqlx::query_as::<_, ArtifactRow>(
        "SELECT id, template_record_id, artifact_id, source_hash, compiler_commit, compiler_output_hash, \
         script_hash, network_target, argument_schema, warnings, metadata, generated_at, created_at, updated_at \
         FROM programmable_settlement_artifacts WHERE id = $1",
    ).bind(id).fetch_one(&state.db.pool).await?;
    Ok((StatusCode::OK, Json(ser_artifact(&a))).into_response())
}

/// `POST /internal/payment-ops/tocatta/covenants/executions`
pub async fn store_execution(_token: InternalToken, State(state): State<AppState>, Json(body): Json<Value>) -> AppResult<Response> {
    let template_record_id = body.get("templateRecordId").and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::validation_field("templateRecordId", "required", "The templateRecordId field must be defined"))?;
    let artifact_record_id = body.get("artifactRecordId").and_then(|v| v.as_i64());
    let status = body.get("status").and_then(|v| v.as_str()).unwrap_or("simulated").to_string();
    let network = body.get("network").and_then(|v| v.as_str()).unwrap_or("tn10").to_string();
    let dry_run = body.get("dryRunPayloadHash").and_then(|v| v.as_str());
    let tx_id = body.get("txId").and_then(|v| v.as_str());
    let evidence_ref = body.get("evidenceReference").and_then(|v| v.as_str());
    let sandbox_outcome = body.get("sandboxOutcome").and_then(|v| v.as_str());
    let metadata = body.get("metadata").cloned().unwrap_or(json!({}));
    let now = now_iso();
    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO programmable_settlement_executions \
         (template_record_id, artifact_record_id, status, network, dry_run_payload_hash, tx_id, \
          evidence_reference, sandbox_outcome, metadata, executed_at, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id",
    )
    .bind(template_record_id).bind(artifact_record_id).bind(&status).bind(&network)
    .bind(dry_run).bind(tx_id).bind(evidence_ref).bind(sandbox_outcome)
    .bind(metadata.to_string()).bind(&now).bind(&now).bind(&now)
    .fetch_one(&state.db.pool).await?;
    let e = sqlx::query_as::<_, ExecutionRow>(
        "SELECT id, template_record_id, artifact_record_id, status, network, dry_run_payload_hash, tx_id, \
         evidence_reference, sandbox_outcome, metadata, executed_at, created_at, updated_at \
         FROM programmable_settlement_executions WHERE id = $1",
    ).bind(id).fetch_one(&state.db.pool).await?;
    Ok((StatusCode::OK, Json(ser_execution(&e))).into_response())
}

/// `POST /internal/payment-ops/tocatta/covenants/templates/:id/approvals`
pub async fn approve(_token: InternalToken, State(state): State<AppState>, Path(id): Path<i64>, Json(body): Json<Value>) -> AppResult<Json<Value>> {
    let domain = req_str(&body, "domain")?;
    if !APPROVAL_DOMAINS.contains(&domain.as_str()) {
        return Err(AppError::validation_field("domain", "enum", "The selected domain is invalid"));
    }
    let approved_by = body.get("approvedByUserId").and_then(|v| v.as_i64());
    let notes = body.get("notes").and_then(|v| v.as_str());
    let metadata = body.get("metadata").cloned().unwrap_or(json!({}));
    let now = now_iso();

    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT id FROM programmable_settlement_approvals WHERE template_record_id = $1 AND domain = $2",
    ).bind(id).bind(&domain).fetch_optional(&state.db.pool).await?;

    let approval_id = match existing {
        Some(eid) => {
            sqlx::query(
                "UPDATE programmable_settlement_approvals SET status = 'approved', approved_by_user_id = $1, \
                 approved_at = $2, notes = $3, metadata = $4, updated_at = $5 WHERE id = $6",
            ).bind(approved_by).bind(&now).bind(notes).bind(metadata.to_string()).bind(&now).bind(eid)
            .execute(&state.db.pool).await?;
            eid
        }
        None => sqlx::query_scalar::<_, i64>(
            "INSERT INTO programmable_settlement_approvals \
             (template_record_id, domain, status, approved_by_user_id, approved_at, notes, metadata, created_at, updated_at) \
             VALUES ($1, $2, 'approved', $3, $4, $5, $6, $7, $8) RETURNING id",
        ).bind(id).bind(&domain).bind(approved_by).bind(&now).bind(notes).bind(metadata.to_string()).bind(&now).bind(&now)
        .fetch_one(&state.db.pool).await?,
    };
    let a = sqlx::query_as::<_, ApprovalRow>(
        "SELECT id, template_record_id, domain, status, approved_by_user_id, approved_at, notes, metadata, created_at, updated_at \
         FROM programmable_settlement_approvals WHERE id = $1",
    ).bind(approval_id).fetch_one(&state.db.pool).await?;
    Ok(Json(ser_approval(&a)))
}

/// `POST /internal/payment-ops/tocatta/covenants/templates/:id/disable`
pub async fn disable(_token: InternalToken, State(state): State<AppState>, Path(id): Path<i64>, Json(body): Json<Value>) -> AppResult<Json<Value>> {
    let reason = req_str(&body, "reason")?;
    let _ = load_template(&state, id).await?; // 404 if missing
    let disabled_by = body.get("disabledByUserId").and_then(|v| v.as_i64());
    let now = now_iso();
    sqlx::query(
        "UPDATE programmable_settlement_templates SET status = 'disabled', disabled_by_user_id = $1, \
         disabled_at = $2, disable_reason = $3, updated_at = $4 WHERE id = $5",
    ).bind(disabled_by).bind(&now).bind(&reason).bind(&now).bind(id)
    .execute(&state.db.pool).await?;
    let t = load_template(&state, id).await?;
    Ok(Json(ser_template(&t, None)))
}

/// `GET /internal/payment-ops/tocatta/covenants/templates/:id/status`
pub async fn status(_token: InternalToken, State(state): State<AppState>, Path(id): Path<i64>) -> AppResult<Json<Value>> {
    let t = load_template(&state, id).await?;
    let approvals = load_approvals(&state, id).await?;
    let artifacts = load_artifacts(&state, id).await?;
    let executions = load_executions(&state, id).await?;

    let approval_status = |domain: &str| -> bool {
        approvals.iter().any(|a| a.domain == domain && a.status == "approved")
    };
    let has_artifact = !artifacts.is_empty();
    let has_execution_evidence = executions.iter().any(|e| e.status == "released" || e.status == "simulated");

    let mut checks: Vec<(String, bool, String)> = vec![
        ("template.status".into(), t.status == "approved", "Template must be approved before beta exposure".into()),
        ("template.killSwitch".into(), t.kill_switch_enabled != 0, "Kill switch must be active before beta exposure".into()),
        ("template.compiledArtifact".into(), has_artifact, "A compiled artifact record is required".into()),
        ("template.executionEvidence".into(), has_execution_evidence, "Successful TN10 execution evidence is required".into()),
    ];
    for domain in APPROVAL_DOMAINS {
        checks.push((format!("approval.{domain}"), approval_status(domain), format!("{domain} approval is required")));
    }
    let ready = checks.iter().all(|(_, passed, _)| *passed);
    let checks_json: Vec<Value> = checks.iter().map(|(key, passed, message)| {
        json!({ "key": key, "status": if *passed { "pass" } else { "fail" }, "message": message })
    }).collect();

    Ok(Json(json!({ "templateRecordId": id, "ready": ready, "checks": checks_json })))
}

/// `GET /internal/payment-ops/tocatta/covenants/templates/:id/evidence`
pub async fn evidence(_token: InternalToken, State(state): State<AppState>, Path(id): Path<i64>) -> AppResult<Json<Value>> {
    let _ = load_template(&state, id).await?;
    let artifacts = load_artifacts(&state, id).await?;
    let executions = load_executions(&state, id).await?;
    let artifacts_json: Vec<Value> = artifacts.iter().map(|a| json!({
        "artifactId": a.artifact_id, "sourceHash": a.source_hash, "compilerCommit": a.compiler_commit,
        "compilerOutputHash": a.compiler_output_hash, "scriptHash": a.script_hash, "networkTarget": a.network_target,
    })).collect();
    let executions_json: Vec<Value> = executions.iter().map(|e| json!({
        "id": e.id, "status": e.status, "dryRunPayloadHash": e.dry_run_payload_hash, "txId": e.tx_id,
        "evidenceReference": e.evidence_reference, "sandboxOutcome": e.sandbox_outcome,
    })).collect();
    Ok(Json(json!({ "templateRecordId": id, "artifacts": artifacts_json, "executions": executions_json })))
}
