//! `/internal/payment-ops/tocatta/production/*` — InternalTocattaProductionController
//! + TocattaProductionService. Fully static contract (internal-token tier);
//! only `generatedAt` varies.

use crate::auth::InternalToken;
use crate::util::now_iso;
use axum::Json;
use serde_json::{json, Value};

const SOURCE_CHECKED_AT: &str = "2026-05-21";

fn cutover_runbook() -> Value {
    json!({
        "productionEnabled": false,
        "stages": [
            { "key": "preflight", "owner": "operations", "stopConditions": ["dependency_freeze_missing", "support_coverage_missing"] },
            { "key": "dependency_freeze_confirmation", "owner": "engineering", "stopConditions": ["version_mismatch", "checksum_mismatch", "mainnet_activation_unverified"] },
            { "key": "internal_smoke", "owner": "engineering", "stopConditions": ["node_rpc_unhealthy", "template_preview_failed", "evidence_missing"] },
            { "key": "canary_merchant_enablement", "owner": "product", "stopConditions": ["merchant_approval_missing", "risk_limit_missing", "kill_switch_unavailable"] },
            { "key": "monitored_expansion", "owner": "operations", "stopConditions": ["incident_open", "reconciliation_variance", "support_slo_breach"] },
            { "key": "rollback", "owner": "incident_commander", "stopConditions": ["audit_export_missing", "open_hold_recovery_plan_missing"] }
        ],
        "featureFlags": ["global_enable", "merchant_enable", "template_enable", "new_hold_enable", "release_refund_enable", "gateway_enable"],
        "smokeChecks": ["node_rpc_health", "gateway_provenance", "template_preview", "sandbox_simulation", "invoice_creation", "observation", "hold_creation", "release_refund_dry_run", "evidence", "webhook", "reporting"]
    })
}

fn reconciliation_status() -> Value {
    json!({
        "financeFields": ["held_amount", "released_amount", "refunded_amount", "split_destinations", "fees", "taxes", "pending_exposure", "exceptions"],
        "closePeriodCases": ["open_holds", "partial_releases", "refunds_after_close", "stuck_payments", "disputed_payments", "emergency_recovery"],
        "varianceChecks": ["node_explorer_mismatch", "ledger_mismatch", "split_mismatch", "missing_evidence", "close_period_drift"]
    })
}

fn incident_playbooks() -> Value {
    json!([
        { "key": "stuck_hold", "severity": "high", "owners": ["support", "operations", "finance"], "firstActions": ["pause_new_holds", "collect_evidence", "open_support_case"] },
        { "key": "failed_release", "severity": "high", "owners": ["engineering", "operations", "finance"], "firstActions": ["pause_release_refund", "verify_signer", "audit_affected_payments"] },
        { "key": "node_rpc_outage", "severity": "medium", "owners": ["engineering", "operations"], "firstActions": ["disable_gateway", "switch_to_readonly", "publish_internal_update"] },
        { "key": "missing_evidence", "severity": "medium", "owners": ["support", "engineering"], "firstActions": ["block_release", "regenerate_evidence", "audit_template"] },
        { "key": "kill_switch_activation", "severity": "high", "owners": ["incident_commander", "support", "product"], "firstActions": ["disable_new_exposure", "notify_internal_channels", "prepare_merchant_notice"] }
    ])
}

fn communications_status() -> Value {
    json!({
        "publicLaunchEnabled": false,
        "communicationStages": ["internal_launch_status", "canary_merchant_notice", "beta_graduation_notice", "production_availability_notice", "incident_notice", "pause_notice", "rollback_notice"],
        "statusPageTopics": ["node_rpc_degradation", "programmable_settlement_pause", "release_refund_delay", "evidence_generation_delay", "recovery_progress"],
        "approvalRequired": ["product", "support", "legal", "finance", "operations", "engineering"]
    })
}

/// `GET /internal/payment-ops/tocatta/production/status`
pub async fn status(_token: InternalToken) -> Json<Value> {
    let stage_keys: Vec<Value> = cutover_runbook()["stages"].as_array().unwrap()
        .iter().map(|s| s["key"].clone()).collect();
    let playbook_keys: Vec<Value> = incident_playbooks().as_array().unwrap()
        .iter().map(|p| p["key"].clone()).collect();
    let finance_fields = reconciliation_status()["financeFields"].clone();

    let checks = json!([
        { "key": "mainnet.activation", "status": "fail", "message": "Toccata mainnet activation is not confirmed in application configuration", "metadata": { "checkedAt": SOURCE_CHECKED_AT, "requiredEvidence": ["activation_status", "activation_daa_score", "network_id"] } },
        { "key": "dependency.freeze", "status": "fail", "message": "Production dependency freeze is incomplete", "metadata": { "required": ["rusty_kaspa_release", "wasm_sdk_checksum", "silverscript_compiler_provenance", "node_rpc_config", "wallet_signing_compatibility"] } },
        { "key": "cutover.runbook", "status": "pass", "message": "Production cutover runbook is defined", "metadata": { "stages": stage_keys } },
        { "key": "signing.boundary", "status": "fail", "message": "Signing-boundary approvals are not complete", "metadata": { "requiredApprovals": ["finance", "legal", "product", "support", "operations", "engineering"] } },
        { "key": "reconciliation.close", "status": "pass", "message": "Reconciliation and close status fields are defined", "metadata": { "financeFields": finance_fields } },
        { "key": "incident.recovery", "status": "pass", "message": "Incident response playbooks are defined", "metadata": { "playbooks": playbook_keys } },
        { "key": "launch.communications", "status": "warn", "message": "Public launch communications require human approval", "metadata": { "approvals": ["product", "support", "legal", "finance", "operations", "engineering"] } }
    ]);

    Json(json!({
        "stage": "production_status_defined",
        "productionEnabled": false,
        "ready": false,
        "generatedAt": now_iso(),
        "sourceCheckedAt": SOURCE_CHECKED_AT,
        "checks": checks,
        "summary": { "pass": 3, "warn": 1, "fail": 3, "ready": false }
    }))
}

/// `GET /internal/payment-ops/tocatta/production/cutover-runbook`
pub async fn cutover_runbook_handler(_token: InternalToken) -> Json<Value> {
    Json(cutover_runbook())
}

/// `GET /internal/payment-ops/tocatta/production/reconciliation`
pub async fn reconciliation(_token: InternalToken) -> Json<Value> {
    Json(reconciliation_status())
}

/// `GET /internal/payment-ops/tocatta/production/incidents`
pub async fn incidents(_token: InternalToken) -> Json<Value> {
    Json(incident_playbooks())
}

/// `GET /internal/payment-ops/tocatta/production/communications`
pub async fn communications(_token: InternalToken) -> Json<Value> {
    Json(communications_status())
}
