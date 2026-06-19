mod common;

use serde_json::{json, Value};

const BASE: &str = "/internal/payment-ops/tocatta/covenants";

#[tokio::test]
async fn settlement_records_full_lifecycle() {
    let app = common::spawn_app().await;
    let tok = common::INTERNAL_TOKEN;

    // create template
    let created = app.client.post(app.url(&format!("{BASE}/templates"))).bearer_auth(tok)
        .json(&json!({ "templateId": "tpl-1", "sourceHash": "src-abc", "compilerCommit": "deadbeef" }))
        .send().await.unwrap();
    assert_eq!(created.status(), 200);
    let t: Value = created.json().await.unwrap();
    assert_eq!(t["templateId"], "tpl-1");
    assert_eq!(t["status"], "sandbox");
    assert_eq!(t["templateVersion"], "v1");
    assert_eq!(t["killSwitchEnabled"], true);
    let tid = t["id"].as_i64().unwrap();

    // record artifact
    let art = app.client.post(app.url(&format!("{BASE}/artifacts"))).bearer_auth(tok)
        .json(&json!({ "templateRecordId": tid, "artifactId": "art-1", "sourceHash": "src-abc", "compilerCommit": "deadbeef", "compilerOutputHash": "out-1", "scriptHash": "sh-1", "networkTarget": "tn10" }))
        .send().await.unwrap();
    assert_eq!(art.status(), 200);
    assert_eq!(art.json::<Value>().await.unwrap()["artifactId"], "art-1");

    // record execution (simulated)
    let exec = app.client.post(app.url(&format!("{BASE}/executions"))).bearer_auth(tok)
        .json(&json!({ "templateRecordId": tid, "status": "simulated", "txId": "tx-1" }))
        .send().await.unwrap();
    assert_eq!(exec.status(), 200);
    let e: Value = exec.json().await.unwrap();
    assert_eq!(e["status"], "simulated");
    assert_eq!(e["network"], "tn10");

    // status: not ready yet (template not approved, missing domain approvals)
    let st: Value = app.client.get(app.url(&format!("{BASE}/templates/{tid}/status"))).bearer_auth(tok).send().await.unwrap().json().await.unwrap();
    assert_eq!(st["templateRecordId"], tid);
    assert_eq!(st["ready"], false);
    let checks = st["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 10); // 4 template + 6 domain approvals
    assert!(checks.iter().any(|c| c["key"] == "template.compiledArtifact" && c["status"] == "pass"));
    assert!(checks.iter().any(|c| c["key"] == "template.executionEvidence" && c["status"] == "pass"));
    assert!(checks.iter().any(|c| c["key"] == "approval.finance" && c["status"] == "fail"));

    // approve all 6 domains (updateOrCreate)
    for d in ["product", "engineering", "support", "finance", "legal", "operations"] {
        let r = app.client.post(app.url(&format!("{BASE}/templates/{tid}/approvals"))).bearer_auth(tok)
            .json(&json!({ "domain": d, "approvedByUserId": 7 })).send().await.unwrap();
        assert_eq!(r.status(), 200, "approve {d}");
        assert_eq!(r.json::<Value>().await.unwrap()["status"], "approved");
    }
    // idempotent: approve finance again -> still one row (updateOrCreate)
    let again = app.client.post(app.url(&format!("{BASE}/templates/{tid}/approvals"))).bearer_auth(tok)
        .json(&json!({ "domain": "finance", "notes": "re-confirmed" })).send().await.unwrap();
    assert_eq!(again.status(), 200);

    // evidence
    let ev: Value = app.client.get(app.url(&format!("{BASE}/templates/{tid}/evidence"))).bearer_auth(tok).send().await.unwrap().json().await.unwrap();
    assert_eq!(ev["artifacts"].as_array().unwrap().len(), 1);
    assert_eq!(ev["executions"].as_array().unwrap().len(), 1);
    assert_eq!(ev["artifacts"][0]["artifactId"], "art-1");

    // templates list: one template with relations, approvals deduped to 6
    let list: Value = app.client.get(app.url(&format!("{BASE}/templates"))).bearer_auth(tok).send().await.unwrap().json().await.unwrap();
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["approvals"].as_array().unwrap().len(), 6);
    assert_eq!(list[0]["artifacts"].as_array().unwrap().len(), 1);

    // disable
    let dis = app.client.post(app.url(&format!("{BASE}/templates/{tid}/disable"))).bearer_auth(tok)
        .json(&json!({ "reason": "rollback" })).send().await.unwrap();
    assert_eq!(dis.status(), 200);
    let d: Value = dis.json().await.unwrap();
    assert_eq!(d["status"], "disabled");
    assert_eq!(d["disableReason"], "rollback");
}

#[tokio::test]
async fn store_template_validation_and_missing_404() {
    let app = common::spawn_app().await;
    let tok = common::INTERNAL_TOKEN;

    // missing templateId -> 422
    let bad = app.client.post(app.url(&format!("{BASE}/templates"))).bearer_auth(tok)
        .json(&json!({ "sourceHash": "x" })).send().await.unwrap();
    assert_eq!(bad.status(), 422);
    assert_eq!(bad.json::<Value>().await.unwrap()["errors"][0]["field"], "templateId");

    // status on missing template -> 404 Row not found
    let nf = app.client.get(app.url(&format!("{BASE}/templates/9999/status"))).bearer_auth(tok).send().await.unwrap();
    assert_eq!(nf.status(), 404);
    assert_eq!(nf.json::<Value>().await.unwrap()["message"], "Row not found");

    // disable missing -> 404
    let dnf = app.client.post(app.url(&format!("{BASE}/templates/9999/disable"))).bearer_auth(tok)
        .json(&json!({ "reason": "x" })).send().await.unwrap();
    assert_eq!(dnf.status(), 404);

    // invalid approval domain -> 422
    let t = app.client.post(app.url(&format!("{BASE}/templates"))).bearer_auth(tok)
        .json(&json!({ "templateId": "tpl-x", "sourceHash": "y" })).send().await.unwrap().json::<Value>().await.unwrap();
    let tid = t["id"].as_i64().unwrap();
    let bad_dom = app.client.post(app.url(&format!("{BASE}/templates/{tid}/approvals"))).bearer_auth(tok)
        .json(&json!({ "domain": "marketing" })).send().await.unwrap();
    assert_eq!(bad_dom.status(), 422);
    assert_eq!(bad_dom.json::<Value>().await.unwrap()["errors"][0]["field"], "domain");
}

#[tokio::test]
async fn settlement_records_require_internal_token() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url(&format!("{BASE}/templates"))).send().await.unwrap().status(), 401);
}
