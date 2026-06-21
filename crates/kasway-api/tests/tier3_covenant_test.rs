mod common;

use serde_json::{json, Value};

fn tok() -> &'static str { common::INTERNAL_TOKEN }

#[tokio::test]
async fn silverscript_status_disabled() {
    let app = common::spawn_app().await;
    let r: Value = app.client.get(app.url("/internal/payment-ops/tocatta/silverscript/status")).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(r["status"], "disabled");
    assert_eq!(r["ready"], false);
    assert_eq!(r["compatibilityOutcome"], "blocked");
    assert_eq!(r["targetNetwork"], "tn10");
    assert_eq!(r["checks"][0]["key"], "silverscript.enabled");
    assert_eq!(r["checks"][0]["status"], "fail");
}

#[tokio::test]
async fn silverscript_compile_validation() {
    let app = common::spawn_app().await;
    let base = "/internal/payment-ops/tocatta/silverscript/templates";

    // unknown template
    let bad = app.client.post(app.url(&format!("{base}/bogus/compile"))).bearer_auth(tok()).json(&json!({"args":{}})).send().await.unwrap();
    assert_eq!(bad.status(), 422);
    assert_eq!(bad.json::<Value>().await.unwrap()["code"], "UNSUPPORTED_SILVERSCRIPT_TEMPLATE");

    // missing required arg
    let miss = app.client.post(app.url(&format!("{base}/refund_window/compile"))).bearer_auth(tok()).json(&json!({"args":{}})).send().await.unwrap();
    assert_eq!(miss.status(), 422);
    assert_eq!(miss.json::<Value>().await.unwrap()["code"], "MISSING_SILVERSCRIPT_ARGUMENT");

    // unknown arg
    let unk = app.client.post(app.url(&format!("{base}/refund_window/compile"))).bearer_auth(tok())
        .json(&json!({"args":{"grossAmount":"100","holdReason":"x","timeoutSeconds":"60","responsibleActor":"merchant","bogus":"1"}})).send().await.unwrap();
    assert_eq!(unk.status(), 422);
    assert_eq!(unk.json::<Value>().await.unwrap()["code"], "UNSUPPORTED_SILVERSCRIPT_ARGUMENT");

    // bad enum
    let badenum = app.client.post(app.url(&format!("{base}/refund_window/compile"))).bearer_auth(tok())
        .json(&json!({"args":{"grossAmount":"100","holdReason":"x","timeoutSeconds":"60","responsibleActor":"alien"}})).send().await.unwrap();
    assert_eq!(badenum.status(), 422);
    assert_eq!(badenum.json::<Value>().await.unwrap()["code"], "INVALID_SILVERSCRIPT_ARGUMENT");

    // valid args -> compiler unavailable (disabled config)
    let ok = app.client.post(app.url(&format!("{base}/refund_window/compile"))).bearer_auth(tok())
        .json(&json!({"args":{"grossAmount":"100","holdReason":"x","timeoutSeconds":"60","responsibleActor":"merchant"}})).send().await.unwrap();
    assert_eq!(ok.status(), 422);
    assert_eq!(ok.json::<Value>().await.unwrap()["code"], "SILVERSCRIPT_STATUS_METADATA_MISSING");
}

#[tokio::test]
async fn covenant_dry_run_validation_and_sdk_missing() {
    let app = common::spawn_app().await;
    let url = app.url("/internal/payment-ops/tocatta/covenants/transactions/dry-run");

    // bad amount
    let bad = app.client.post(&url).bearer_auth(tok()).json(&json!({"grossAmount":"0"})).send().await.unwrap();
    assert_eq!(bad.status(), 422);
    assert_eq!(bad.json::<Value>().await.unwrap()["code"], "INVALID_COVENANT_AMOUNT");

    // non-sandbox artifact
    let nonsb = app.client.post(&url).bearer_auth(tok()).json(&json!({
        "grossAmount":"100", "compiledArtifact": {"sandboxOnly": false, "networkTarget":"tn10", "scriptText":"x"}
    })).send().await.unwrap();
    assert_eq!(nonsb.json::<Value>().await.unwrap()["code"], "NON_SANDBOX_ARTIFACT_REJECTED");

    // network mismatch
    let mism = app.client.post(&url).bearer_auth(tok()).json(&json!({
        "grossAmount":"100", "network":"tn10", "compiledArtifact": {"sandboxOnly": true, "networkTarget":"mainnet", "scriptText":"x"}
    })).send().await.unwrap();
    assert_eq!(mism.json::<Value>().await.unwrap()["code"], "COVENANT_NETWORK_MISMATCH");

    // production wallet rejected
    let pw = app.client.post(&url).bearer_auth(tok()).json(&json!({
        "grossAmount":"100", "compiledArtifact": {"sandboxOnly": true, "networkTarget":"tn10", "scriptText":"x"},
        "testWalletReference":"prod-wallet", "testChangeAddress":"kaspatest:change"
    })).send().await.unwrap();
    assert_eq!(pw.json::<Value>().await.unwrap()["code"], "PRODUCTION_WALLET_REJECTED");

    // fully valid -> SDK not configured
    let valid = app.client.post(&url).bearer_auth(tok()).json(&json!({
        "grossAmount":"1000", "compiledArtifact": {"sandboxOnly": true, "networkTarget":"tn10", "scriptText":"covenant"},
        "testWalletReference":"test:wallet-1", "testChangeAddress":"kaspatest:changeaddr",
        "destinations":[{"role":"merchant_net","destination":"kaspatest:merchant","amount":"900"}]
    })).send().await.unwrap();
    assert_eq!(valid.status(), 422);
    assert_eq!(valid.json::<Value>().await.unwrap()["code"], "RUSTY_KASPA_WASM_SDK_NOT_CONFIGURED");
}

#[tokio::test]
async fn tn10_covenant_status_and_execute() {
    let app = common::spawn_app().await;
    let st: Value = app.client.get(app.url("/internal/payment-ops/tocatta/covenants/tn10/status")).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(st["enabled"], false);
    assert_eq!(st["ready"], false);
    assert_eq!(st["checks"][0]["key"], "tn10CovenantExecution.enabled");
    assert!(st["tn10NodeStatus"].is_null());

    for path in ["/internal/payment-ops/tocatta/covenants/tn10/split-executions", "/internal/payment-ops/tocatta/covenants/tn10/hold-release-executions"] {
        let res = app.client.post(app.url(path)).bearer_auth(tok()).json(&json!({})).send().await.unwrap();
        assert_eq!(res.status(), 422, "{path}");
        let b: Value = res.json().await.unwrap();
        assert_eq!(b["code"], "TN10_COVENANT_EXECUTION_NOT_READY");
        assert_eq!(b["metadata"]["failedChecks"][0], "tn10CovenantExecution.enabled");
    }
}

#[tokio::test]
async fn kpr1_status_report() {
    let app = common::spawn_app().await;
    let r: Value = app.client.get(app.url("/internal/payment-ops/kpr1/status")).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(r["enabled"], true);
    assert_eq!(r["ready"], false); // silverscript disabled
    let checks = r["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 4);
    let by = |k: &str| checks.iter().find(|c| c["key"] == k).unwrap().clone();
    assert_eq!(by("kpr1.enabled")["status"], "pass");
    assert_eq!(by("kpr1.config")["status"], "pass");
    assert_eq!(by("kpr1.conformance")["status"], "pass");
    assert_eq!(by("silverscript.status")["status"], "fail");
    assert_eq!(r["conformance"]["ready"], true);
    assert_eq!(r["signingSurface"]["kaswaySignsCustomerTransactions"], false);
    assert_eq!(r["config"]["hasPlatformFeeAddress"], true);
}

#[tokio::test]
async fn tier3_requires_internal_token() {
    let app = common::spawn_app().await;
    for p in [
        "/internal/payment-ops/tocatta/silverscript/status",
        "/internal/payment-ops/tocatta/covenants/tn10/status",
        "/internal/payment-ops/kpr1/status",
    ] {
        assert_eq!(app.client.get(app.url(p)).send().await.unwrap().status(), 401, "{p}");
    }
}
