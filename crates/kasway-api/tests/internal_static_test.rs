mod common;

use serde_json::{json, Value};

fn tok() -> &'static str { common::INTERNAL_TOKEN }

#[tokio::test]
async fn silverscript_templates_index() {
    let app = common::spawn_app().await;
    let res: Value = app.client.get(app.url("/internal/payment-ops/tocatta/silverscript/templates"))
        .bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(res["sandboxOnly"], true);
    assert_eq!(res["freeFormScriptsAccepted"], false);
    let templates = res["templates"].as_array().unwrap();
    assert_eq!(templates.len(), 3);
    assert_eq!(templates[0]["id"], "split_settlement");
    assert_eq!(templates[0]["title"], "Split Settlement");
    // sourceHash == approvedSourceHash, 64-hex sha256
    let h = templates[0]["sourceHash"].as_str().unwrap();
    assert_eq!(h.len(), 64);
    assert_eq!(templates[0]["approvedSourceHash"], h);
    assert_eq!(templates[2]["id"], "conditional_release");
}

#[tokio::test]
async fn security_launch_gate_show() {
    let app = common::spawn_app().await;
    let res: Value = app.client.get(app.url("/internal/payment-ops/security/launch-gate"))
        .bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(res["scope"], "milestone41.security_launch_gate");
    assert_eq!(res["environment"], "documentation");
    assert_eq!(res["summary"]["highOpen"], 3);
    assert_eq!(res["summary"]["mediumOpen"], 1);
    assert_eq!(res["summary"]["launchBlocked"], true);
    assert_eq!(res["findings"].as_array().unwrap().len(), 4);
    assert_eq!(res["checks"].as_array().unwrap().len(), 4);
    assert_eq!(res["findings"][0]["id"], "sec-20260524-001");
}

#[tokio::test]
async fn tocatta_production_endpoints() {
    let app = common::spawn_app().await;
    let base = "/internal/payment-ops/tocatta/production";

    let st: Value = app.client.get(app.url(&format!("{base}/status"))).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(st["stage"], "production_status_defined");
    assert_eq!(st["ready"], false);
    assert_eq!(st["sourceCheckedAt"], "2026-05-21");
    assert_eq!(st["summary"], json!({ "pass": 3, "warn": 1, "fail": 3, "ready": false }));
    assert_eq!(st["checks"].as_array().unwrap().len(), 7);

    let rb: Value = app.client.get(app.url(&format!("{base}/cutover-runbook"))).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(rb["stages"].as_array().unwrap().len(), 6);
    assert_eq!(rb["stages"][0]["key"], "preflight");

    let rc: Value = app.client.get(app.url(&format!("{base}/reconciliation"))).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(rc["financeFields"].as_array().unwrap().len(), 8);

    let inc: Value = app.client.get(app.url(&format!("{base}/incidents"))).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(inc.as_array().unwrap().len(), 5);
    assert_eq!(inc[0]["key"], "stuck_hold");

    let comm: Value = app.client.get(app.url(&format!("{base}/communications"))).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(comm["publicLaunchEnabled"], false);
    assert_eq!(comm["approvalRequired"].as_array().unwrap().len(), 6);
}

#[tokio::test]
async fn tocatta_beta_status_reporting_contract() {
    let app = common::spawn_app().await;
    let base = "/internal/payment-ops/tocatta/beta";

    let st: Value = app.client.get(app.url(&format!("{base}/status"))).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(st["stage"], "merchant_beta_ready_to_evaluate");
    assert_eq!(st["summary"], json!({ "pass": 3, "warn": 0, "fail": 7, "ready": false }));
    assert_eq!(st["checks"].as_array().unwrap().len(), 10);
    assert_eq!(st["contract"]["previewOnly"], true);

    let rep: Value = app.client.get(app.url(&format!("{base}/reporting"))).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(rep["dashboardsPublic"], false);
    assert_eq!(rep["metrics"].as_array().unwrap().len(), 16);

    let con: Value = app.client.get(app.url(&format!("{base}/contracts"))).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(con["enabled"], false);
    assert_eq!(con["allowedTemplateTypes"], json!(["conditional_hold", "refund_window", "split_settlement"]));
}

#[tokio::test]
async fn tocatta_beta_eligibility_all_fail_and_all_pass() {
    let app = common::spawn_app().await;
    let url = app.url("/internal/payment-ops/tocatta/beta/eligibility");

    // empty body -> not eligible, accountStanding fail, paymentHistory warn
    let empty: Value = app.client.post(&url).bearer_auth(tok()).json(&json!({})).send().await.unwrap().json().await.unwrap();
    assert_eq!(empty["eligible"], false);
    assert_eq!(empty["checks"].as_array().unwrap().len(), 12);
    let acct = empty["checks"].as_array().unwrap().iter().find(|c| c["key"] == "merchant.accountStanding").unwrap();
    assert_eq!(acct["status"], "fail");
    let hist = empty["checks"].as_array().unwrap().iter().find(|c| c["key"] == "merchant.paymentHistory").unwrap();
    assert_eq!(hist["status"], "warn");

    // full pass
    let full = json!({
        "merchantId": 9,
        "accountStanding": "good",
        "paymentHistoryDays": 60,
        "supportContact": "ops@merchant.test",
        "approvedUseCase": "split settlements",
        "requestedTemplateTypes": ["split_settlement"],
        "approvals": { "product": true, "support": true, "finance": true, "legal": true, "operations": true, "engineering": true },
        "monthlyVolumeCap": "100000",
        "activeHoldCap": 5,
        "provenTemplateIds": ["tpl-1"],
        "successfulTn10ExecutionEvidence": true,
        "supportPlaybookReady": true,
        "financeReconciliationFieldsReady": true,
        "activeKillSwitch": true
    });
    let ok: Value = app.client.post(&url).bearer_auth(tok()).json(&full).send().await.unwrap().json().await.unwrap();
    assert_eq!(ok["eligible"], true);
    assert_eq!(ok["merchantId"], 9);
    assert_eq!(ok["summary"]["fail"], 0);
    assert_eq!(ok["summary"]["warn"], 0);
}

#[tokio::test]
async fn static_contracts_require_internal_token() {
    let app = common::spawn_app().await;
    for p in [
        "/internal/payment-ops/tocatta/silverscript/templates",
        "/internal/payment-ops/security/launch-gate",
        "/internal/payment-ops/tocatta/production/status",
        "/internal/payment-ops/tocatta/beta/status",
    ] {
        assert_eq!(app.client.get(app.url(p)).send().await.unwrap().status(), 401, "{p}");
    }
}
