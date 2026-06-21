//! `/internal/payment-ops/tocatta/beta/*` — InternalTocattaBetaController +
//! ToccataBetaStatusService. status/reporting/contract are static; eligibility is
//! computed from the POST body. Internal-token tier.

use crate::auth::InternalToken;
use crate::util::now_iso;
use axum::Json;
use serde_json::{json, Value};

const REQUIRED_APPROVALS: &[&str] = &["product", "support", "finance", "legal", "operations", "engineering"];
// Array.from(Set([...])).sort() — sorted allowlist
const ALLOWED_TEMPLATE_TYPES: &[&str] = &["conditional_hold", "refund_window", "split_settlement"];
const PRODUCTION_HANDOFF: &str = "Production and mainnet launch require a separate roadmap arc with activation, signing-boundary, legal, finance, support, and operations approval.";

fn contract_areas() -> Value {
    json!(["template_preview", "sandbox_simulation", "beta_template_creation", "template_inspection", "template_disablement", "settlement_outcome_inspection"])
}
fn default_risk_limits() -> Value {
    json!({ "monthlyVolumeCapRequired": true, "invoiceCapRequired": true, "activeHoldCapRequired": true, "holdDurationCapRequired": true, "templateCountCapRequired": true, "anomalyThresholdsRequired": true })
}
fn kill_switches() -> Value {
    json!(["global_disable", "merchant_disable", "template_disable", "new_hold_disable", "release_refund_pause", "gateway_disable", "unsupported_network_asset_block"])
}
fn reporting_metrics() -> Value {
    json!(["enrolled_merchants", "active_templates", "simulated_templates", "funded_holds", "release_latency", "refund_latency", "stuck_holds", "exception_rate", "support_contacts", "kill_switch_activations", "total_exposure", "open_holds", "release_refund_aging", "failed_executions", "evidence_gaps", "merchant_support_load"])
}
fn status_language() -> Value {
    json!({
        "compiled": "Template compiled", "simulated": "Sandbox simulation complete", "funded": "Test funds observed",
        "held": "Payment held under beta rules", "releasable": "Payment eligible for release", "released": "Payment released",
        "refunded": "Payment refunded", "failed": "Programmable settlement failed", "disabled": "Beta capability disabled",
        "unsupported": "Programmable settlement unsupported"
    })
}
pub(crate) fn merchant_contract() -> Value {
    json!({
        "enabled": false, "previewOnly": true, "creationEnabled": false, "executionEnabled": false,
        "approvedTemplatesOnly": true, "freeFormScriptsAccepted": false, "mainnetSupported": false,
        "productionSettlementSupported": false,
        "routes": [{ "method": "GET", "path": "/api/payments/tocatta/beta/templates", "purpose": "Preview approved beta template contracts when beta is enabled", "disabledByDefault": true }],
        "allowedTemplateTypes": ALLOWED_TEMPLATE_TYPES,
        "statusLanguage": status_language(),
        "productionHandoff": PRODUCTION_HANDOFF,
    })
}

/// `GET /internal/payment-ops/tocatta/beta/status`
pub async fn status(_token: InternalToken) -> Json<Value> {
    let checks = json!([
        { "key": "beta.globalEnabled", "status": "fail", "message": "Merchant beta is disabled by default", "metadata": { "enabled": false } },
        { "key": "beta.contracts", "status": "pass", "message": "Beta contract areas are drafted internally", "metadata": { "routesArePublic": false, "contractAreas": contract_areas() } },
        { "key": "beta.riskControls", "status": "pass", "message": "Risk limits and kill switches are defined", "metadata": { "limits": default_risk_limits(), "killSwitches": kill_switches() } },
        { "key": "beta.reporting", "status": "pass", "message": "Internal reporting metrics are defined", "metadata": { "metrics": reporting_metrics() } },
        { "key": "beta.approvals", "status": "fail", "message": "Merchant beta requires all approval domains", "metadata": { "requiredApprovals": REQUIRED_APPROVALS } },
        { "key": "beta.provenTemplate", "status": "fail", "message": "Merchant beta requires at least one proven compiled template", "metadata": { "provenTemplateRequired": true } },
        { "key": "beta.tn10Evidence", "status": "fail", "message": "Merchant beta requires successful TN10 evidence", "metadata": { "successfulTn10ExecutionEvidenceRequired": true } },
        { "key": "beta.supportPlaybook", "status": "fail", "message": "Support playbook must be ready", "metadata": { "supportPlaybookRequired": true } },
        { "key": "beta.financeReconciliation", "status": "fail", "message": "Finance reconciliation fields must be ready", "metadata": { "financeReconciliationRequired": true } },
        { "key": "beta.activeKillSwitch", "status": "fail", "message": "Active kill switch is required", "metadata": { "activeKillSwitchRequired": true } }
    ]);
    Json(json!({
        "stage": "merchant_beta_ready_to_evaluate",
        "enabled": false,
        "ready": false,
        "generatedAt": now_iso(),
        "checks": checks,
        "summary": { "pass": 3, "warn": 0, "fail": 7, "ready": false },
        "statusLanguage": status_language(),
        "contract": merchant_contract(),
        "productionHandoff": PRODUCTION_HANDOFF,
    }))
}

/// `GET /internal/payment-ops/tocatta/beta/reporting`
pub async fn reporting(_token: InternalToken) -> Json<Value> {
    Json(json!({
        "generatedAt": now_iso(),
        "dashboardsPublic": false,
        "metrics": reporting_metrics(),
        "financeFields": ["held_amount", "released_amount", "refunded_amount", "pending_exposure", "split_destinations", "reconciliation_variance"],
        "supportFields": ["open_beta_cases", "aging_holds", "missing_evidence", "merchant_escalations", "incident_linked_payments"],
        "productFields": ["enrolled_merchants", "template_usage", "successful_outcomes", "rejected_templates", "merchant_opt_outs"],
        "betaMetrics": ["total_exposure", "open_holds", "release_aging", "refund_aging", "failed_executions", "evidence_gaps", "merchant_support_load"],
        "productionHandoff": PRODUCTION_HANDOFF,
    }))
}

/// `GET /internal/payment-ops/tocatta/beta/contracts`
pub async fn contract(_token: InternalToken) -> Json<Value> {
    Json(merchant_contract())
}

fn check(key: &str, pass: bool, fail_status: &str, message: &str, metadata: Value) -> Value {
    json!({ "key": key, "status": if pass { "pass" } else { fail_status }, "message": message, "metadata": metadata })
}

/// `POST /internal/payment-ops/tocatta/beta/eligibility`
pub async fn eligibility(_token: InternalToken, Json(body): Json<Value>) -> Json<Value> {
    let str_field = |k: &str| body.get(k).and_then(|v| v.as_str());
    let bool_field = |k: &str| body.get(k).and_then(|v| v.as_bool()).unwrap_or(false);

    let account_standing = str_field("accountStanding");
    let payment_history_days = body.get("paymentHistoryDays").and_then(|v| v.as_i64()).unwrap_or(0);
    let support_contact_present = str_field("supportContact").map(|s| !s.trim().is_empty()).unwrap_or(false);
    let approved_use_case = str_field("approvedUseCase");
    let approved_use_case_present = approved_use_case.map(|s| !s.trim().is_empty()).unwrap_or(false);

    let requested: Vec<String> = body.get("requestedTemplateTypes").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let unsupported: Vec<String> = requested.iter()
        .filter(|t| !["split_settlement", "conditional_hold", "refund_window"].contains(&t.as_str()))
        .cloned().collect();

    let approvals = body.get("approvals");
    let missing_approvals: Vec<&str> = REQUIRED_APPROVALS.iter()
        .filter(|d| !approvals.and_then(|a| a.get(**d)).and_then(|v| v.as_bool()).unwrap_or(false))
        .copied().collect();

    let monthly_cap_str: Option<String> = body.get("monthlyVolumeCap").map(|v| match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => v.to_string(),
    }).filter(|_| !body.get("monthlyVolumeCap").map(|v| v.is_null()).unwrap_or(true));
    let active_hold_cap = body.get("activeHoldCap").and_then(|v| v.as_i64());
    let has_risk_limits = monthly_cap_str.as_ref().and_then(|s| s.parse::<i128>().ok()).map(|n| n > 0).unwrap_or(false)
        && active_hold_cap.unwrap_or(0) > 0;

    let proven_ids: Vec<String> = body.get("provenTemplateIds").and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let tn10 = bool_field("successfulTn10ExecutionEvidence");
    let support_playbook = bool_field("supportPlaybookReady");
    let finance_recon = bool_field("financeReconciliationFieldsReady");
    let kill_switch = bool_field("activeKillSwitch");

    let checks = json!([
        check("merchant.accountStanding", account_standing == Some("good"), "fail", "Merchant account must be in good standing", json!({ "accountStanding": account_standing })),
        check("merchant.paymentHistory", payment_history_days >= 30, "warn", "Merchant should have at least 30 days of payment history", json!({ "paymentHistoryDays": payment_history_days })),
        check("merchant.supportContact", support_contact_present, "fail", "Merchant beta requires an operational support contact", json!({ "supportContactPresent": support_contact_present })),
        check("merchant.approvedUseCase", approved_use_case_present, "fail", "Merchant beta requires an approved programmable settlement use case", json!({ "approvedUseCase": approved_use_case })),
        check("merchant.templateTypes", unsupported.is_empty(), "fail", "Requested template types must be supported by the beta", json!({ "requestedTemplateTypes": requested, "unsupportedTemplateTypes": unsupported })),
        check("merchant.approvals", missing_approvals.is_empty(), "fail", "All approval domains must approve before beta access", json!({ "missingApprovals": missing_approvals, "requiredApprovals": REQUIRED_APPROVALS })),
        check("merchant.riskLimits", has_risk_limits, "fail", "Merchant beta requires volume and active-hold caps", json!({ "monthlyVolumeCap": monthly_cap_str, "activeHoldCap": active_hold_cap })),
        check("merchant.provenTemplate", !proven_ids.is_empty(), "fail", "Merchant beta requires a proven compiled template", json!({ "provenTemplateIds": proven_ids })),
        check("merchant.tn10Evidence", tn10, "fail", "Merchant beta requires successful TN10 execution evidence", json!({ "successfulTn10ExecutionEvidence": tn10 })),
        check("merchant.supportPlaybook", support_playbook, "fail", "Merchant beta requires a support playbook", json!({ "supportPlaybookReady": support_playbook })),
        check("merchant.financeReconciliation", finance_recon, "fail", "Merchant beta requires finance reconciliation fields", json!({ "financeReconciliationFieldsReady": finance_recon })),
        check("merchant.killSwitch", kill_switch, "fail", "Merchant beta requires an active kill switch", json!({ "activeKillSwitch": kill_switch })),
    ]);
    let arr = checks.as_array().unwrap();
    let pass = arr.iter().filter(|c| c["status"] == "pass").count();
    let warn = arr.iter().filter(|c| c["status"] == "warn").count();
    let fail = arr.iter().filter(|c| c["status"] == "fail").count();
    let eligible = arr.iter().all(|c| c["status"] == "pass");

    Json(json!({
        "merchantId": body.get("merchantId").and_then(|v| v.as_i64()),
        "eligible": eligible,
        "generatedAt": now_iso(),
        "checks": checks,
        "allowedTemplateTypes": ALLOWED_TEMPLATE_TYPES,
        "disabledByDefault": true,
        "summary": { "pass": pass, "warn": warn, "fail": fail, "ready": eligible },
        "productionHandoff": PRODUCTION_HANDOFF,
    }))
}
