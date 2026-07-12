mod common;

use serde_json::{json, Value};

fn tok() -> &'static str { common::INTERNAL_TOKEN }

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
async fn tier3_requires_internal_token() {
    let app = common::spawn_app().await;
    assert_eq!(
        app.client.get(app.url("/internal/payment-ops/tocatta/covenants/tn10/status")).send().await.unwrap().status(),
        401
    );
}
