mod common;

use serde_json::Value;

#[tokio::test]
async fn settlement_sandbox_retired() {
    let app = common::spawn_app().await;

    let gets = ["/internal/payment-ops/tocatta/sandbox/overview", "/internal/payment-ops/tocatta/sandbox/promotion-gates"];
    for p in gets {
        let res = app.client.get(app.url(p)).bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap();
        assert_eq!(res.status(), 410, "{p}");
        assert_eq!(res.json::<Value>().await.unwrap()["code"], "PROGRAMMABLE_SETTLEMENT_SANDBOX_RETIRED");
    }
    let posts = ["/internal/payment-ops/tocatta/sandbox/splits/preview", "/internal/payment-ops/tocatta/sandbox/holds/preview"];
    for p in posts {
        let res = app.client.post(app.url(p)).bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap();
        assert_eq!(res.status(), 410, "{p}");
        let body: Value = res.json().await.unwrap();
        assert_eq!(body["code"], "PROGRAMMABLE_SETTLEMENT_SANDBOX_RETIRED");
        assert_eq!(body["replacement"]["kpr1Status"], "/internal/payment-ops/kpr1/status");
    }
}

#[tokio::test]
async fn settlement_sandbox_requires_internal_token() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/internal/payment-ops/tocatta/sandbox/overview")).send().await.unwrap().status(), 401);
}

#[tokio::test]
async fn kpr1_evidence_by_intent_id_and_hash() {
    let app = common::spawn_app().await;
    common::register_merchant(&app, "kev1@example.com", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "kev1@example.com").await;
    let store = common::seed_default_store(&app.db, uid).await;
    let inv = common::seed_invoice(&app.db, uid, store, "inv_kev1", "open", 1000, 1000, 0, None, None, "2026-06-10T00:00:00.000+00:00").await;
    common::seed_kpr1_intent(&app.db, inv, uid, "intent_abc").await;

    // by intent_id
    let res: Value = app.client.get(app.url("/internal/payment-ops/kpr1/intents/intent_abc/evidence"))
        .bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap().json().await.unwrap();
    assert_eq!(res["intentId"], "intent_abc");
    assert_eq!(res["invoiceId"], inv);
    assert_eq!(res["status"], "created");
    assert_eq!(res["canonicalHash"], "canon_intent_abc");
    assert_eq!(res["signature"]["alg"], "ed25519");
    assert_eq!(res["template"]["scriptHash"], "scripthash_intent_abc");
    assert!(res["requiredOutputs"].is_array());
    assert!(res["txId"].is_null());

    // by canonical hash
    let by_hash: Value = app.client.get(app.url("/internal/payment-ops/kpr1/intents/canon_intent_abc/evidence"))
        .bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap().json().await.unwrap();
    assert_eq!(by_hash["intentId"], "intent_abc");
}

#[tokio::test]
async fn kpr1_evidence_missing_404() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/internal/payment-ops/kpr1/intents/nope/evidence"))
        .bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "KPR-1 payment intent not found");
}

#[tokio::test]
async fn kpr1_evidence_requires_internal_token() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/internal/payment-ops/kpr1/intents/x/evidence")).send().await.unwrap().status(), 401);
}

#[tokio::test]
async fn kpr1_conformance_all_checks_pass() {
    let app = common::spawn_app().await;
    let res: Value = app.client.get(app.url("/internal/payment-ops/kpr1/conformance"))
        .bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap().json().await.unwrap();
    let checks = res["checks"].as_array().unwrap();
    // surface any failing check for debuggability
    let failed: Vec<&Value> = checks.iter().filter(|c| c["status"] != "pass").collect();
    assert!(failed.is_empty(), "failing checks: {failed:#?}");
    assert_eq!(res["ready"], true);
    assert_eq!(res["fixtureVersion"], "2026-05-24");
    assert!(checks.iter().any(|c| c["key"] == "kpr1.conformance.signature"));
    assert!(checks.iter().any(|c| c["key"] == "kpr1.conformance.canonicalJson"));
    assert!(checks.iter().any(|c| c["key"].as_str().unwrap().starts_with("kpr1.conformance.outputs.")));
}

#[tokio::test]
async fn kpr1_conformance_requires_internal_token() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/internal/payment-ops/kpr1/conformance")).send().await.unwrap().status(), 401);
}
