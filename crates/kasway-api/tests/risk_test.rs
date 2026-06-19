mod common;

use serde_json::{json, Value};

async fn merchant(app: &common::TestApp, email: &str) -> (String, i64) {
    let token = common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    (token, uid)
}

#[tokio::test]
async fn risk_catalog_static() {
    let app = common::spawn_app().await;
    let (token, _) = merchant(&app, "rk1@example.com").await;
    let body: Value = app.client.get(app.url("/api/payments/ops/risk/catalog")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(body["passiveOnly"], true);
    assert_eq!(body["evaluatorVersion"], "passive-risk-v1");
    assert_eq!(body["rules"].as_array().unwrap().len(), 4);
    assert_eq!(body["rules"][0]["key"], "kpr1_high_value_invoice");
}

#[tokio::test]
async fn risk_rule_hits_index_show_review() {
    let app = common::spawn_app().await;
    let (token, uid) = merchant(&app, "rk2@example.com").await;
    let id = common::seed_risk_hit(&app.db, uid, "kpr1_high_value_invoice", "review", "open").await;
    common::seed_risk_hit(&app.db, uid, "kpr1_payout_address_recent_change", "high", "open").await;

    let list: Value = app.client.get(app.url("/api/payments/ops/risk/rule-hits")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(list["passiveOnly"], true);
    assert_eq!(list["meta"]["total"], 2);

    let high: Value = app.client.get(app.url("/api/payments/ops/risk/rule-hits?severity=high")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(high["meta"]["total"], 1);

    let shown: Value = app.client.get(app.url(&format!("/api/payments/ops/risk/rule-hits/{id}"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(shown["id"], id);
    assert!(shown["reviewEvents"].is_array());

    // acknowledge -> status + review event
    let ack: Value = app.client.post(app.url(&format!("/api/payments/ops/risk/rule-hits/{id}/acknowledge"))).bearer_auth(&token).json(&json!({ "reason": "reviewed" })).send().await.unwrap().json().await.unwrap();
    assert_eq!(ack["status"], "acknowledged");
    assert_eq!(ack["reviewEvents"].as_array().unwrap().len(), 1);
    assert_eq!(ack["reviewEvents"][0]["action"], "acknowledge");

    // note -> status unchanged, another event
    let noted: Value = app.client.post(app.url(&format!("/api/payments/ops/risk/rule-hits/{id}/notes"))).bearer_auth(&token).json(&json!({ "note": "fyi" })).send().await.unwrap().json().await.unwrap();
    assert_eq!(noted["status"], "acknowledged");
    assert_eq!(noted["reviewEvents"].as_array().unwrap().len(), 2);

    // dismiss
    let dis: Value = app.client.post(app.url(&format!("/api/payments/ops/risk/rule-hits/{id}/dismiss"))).bearer_auth(&token).json(&json!({})).send().await.unwrap().json().await.unwrap();
    assert_eq!(dis["status"], "dismissed");

    let missing = app.client.get(app.url("/api/payments/ops/risk/rule-hits/9999")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(missing.status(), 404);
    assert_eq!(missing.json::<Value>().await.unwrap()["message"], "Payment risk rule hit not found");
}

#[tokio::test]
async fn risk_report_aggregates() {
    let app = common::spawn_app().await;
    let (token, uid) = merchant(&app, "rk3@example.com").await;
    common::seed_risk_hit(&app.db, uid, "kpr1_high_value_invoice", "review", "open").await;
    common::seed_risk_hit(&app.db, uid, "kpr1_payout_address_recent_change", "high", "open").await;

    let body: Value = app.client.get(app.url("/api/payments/ops/risk/report")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(body["totals"]["total"], 2);
    assert_eq!(body["totals"]["bySeverity"]["high"], 1);
    assert_eq!(body["activeEnforcement"], false);
    assert_eq!(body["rules"].as_array().unwrap().len(), 4);
    assert_eq!(body["recentHighSeverity"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn risk_requires_auth() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/api/payments/ops/risk/catalog")).send().await.unwrap().status(), 401);
}
