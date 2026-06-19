mod common;

use serde_json::{json, Value};

async fn merchant(app: &common::TestApp, email: &str) -> String {
    common::register_merchant(app, email, "secret123").await
}

fn grant_payload() -> Value {
    json!({
        "email": "auditor@x.com",
        "scope": ["statements", "exports", "statements"],
        "periodStart": "2026-01-01",
        "periodEnd": "2026-01-31",
        "expiresAt": "2099-01-01T00:00:00.000+00:00"
    })
}

#[tokio::test]
async fn audit_access_grant_lifecycle() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "aa1@example.com").await;

    let created = app.client.post(app.url("/api/payments/ops/audit-access")).bearer_auth(&token).json(&grant_payload()).send().await.unwrap();
    assert_eq!(created.status(), 201);
    let g: Value = created.json().await.unwrap();
    assert_eq!(g["email"], "auditor@x.com");
    assert_eq!(g["scope"], json!(["statements", "exports"])); // deduped
    assert!(g["token"].as_str().unwrap().starts_with("pay_audit_"));
    assert!(g["revokedAt"].is_null());
    let id = g["id"].as_i64().unwrap();

    let list: Value = app.client.get(app.url("/api/payments/ops/audit-access")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(list["meta"]["total"], 1);

    let revoked: Value = app.client.post(app.url(&format!("/api/payments/ops/audit-access/{id}/revoke"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert!(!revoked["revokedAt"].is_null());
}

#[tokio::test]
async fn audit_access_validation() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "aa2@example.com").await;

    // bad email
    let bad = app.client.post(app.url("/api/payments/ops/audit-access")).bearer_auth(&token).json(&json!({ "scope": ["statements"], "periodStart": "2026-01-01", "periodEnd": "2026-01-31", "expiresAt": "2099-01-01T00:00:00.000+00:00" })).send().await.unwrap();
    assert_eq!(bad.status(), 422);

    // period reversed -> 422 commerce
    let rev = app.client.post(app.url("/api/payments/ops/audit-access")).bearer_auth(&token).json(&json!({ "email": "a@x.com", "scope": ["statements"], "periodStart": "2026-02-01", "periodEnd": "2026-01-01", "expiresAt": "2099-01-01T00:00:00.000+00:00" })).send().await.unwrap();
    assert_eq!(rev.status(), 422);
    assert_eq!(rev.json::<Value>().await.unwrap()["message"], "Payment audit access grant dates are invalid");

    // expired expiresAt -> 422
    let exp = app.client.post(app.url("/api/payments/ops/audit-access")).bearer_auth(&token).json(&json!({ "email": "a@x.com", "scope": ["statements"], "periodStart": "2026-01-01", "periodEnd": "2026-01-31", "expiresAt": "2000-01-01T00:00:00.000+00:00" })).send().await.unwrap();
    assert_eq!(exp.status(), 422);

    // revoke missing -> 404
    let missing = app.client.post(app.url("/api/payments/ops/audit-access/9999/revoke")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(missing.status(), 404);
    assert_eq!(missing.json::<Value>().await.unwrap()["message"], "Payment audit access grant not found");
}

#[tokio::test]
async fn audit_access_requires_auth() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/api/payments/ops/audit-access")).send().await.unwrap().status(), 401);
}

async fn create_grant(app: &common::TestApp, bearer: &str, scope: Value, start: &str, end: &str) -> String {
    let created = app.client.post(app.url("/api/payments/ops/audit-access")).bearer_auth(bearer)
        .json(&json!({ "email": "auditor@x.com", "scope": scope, "periodStart": start, "periodEnd": end, "expiresAt": "2099-01-01T00:00:00.000+00:00" }))
        .send().await.unwrap();
    assert_eq!(created.status(), 201);
    created.json::<Value>().await.unwrap()["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn audit_token_reads_statements_and_close_periods() {
    let app = common::spawn_app().await;
    let bearer = merchant(&app, "at1@example.com").await;
    let gtoken = create_grant(&app, &bearer, json!(["statements", "close_periods"]), "2026-01-01", "2026-01-31").await;

    let st = app.client.post(app.url("/api/payments/ops/statements")).bearer_auth(&bearer)
        .json(&json!({ "periodStart": "2026-01-01", "periodEnd": "2026-01-31" })).send().await.unwrap();
    assert_eq!(st.status(), 201);

    let cp = app.client.post(app.url("/api/payments/ops/close-periods")).bearer_auth(&bearer)
        .json(&json!({ "periodStart": "2026-01-01", "periodEnd": "2026-01-31" })).send().await.unwrap();
    assert_eq!(cp.status(), 201);

    // public token reads (no bearer)
    let stmts: Value = app.client.get(app.url(&format!("/api/payments/audit/{gtoken}/statements"))).send().await.unwrap().json().await.unwrap();
    assert_eq!(stmts.as_array().unwrap().len(), 1);
    assert_eq!(stmts[0]["periodStart"], "2026-01-01");

    let periods: Value = app.client.get(app.url(&format!("/api/payments/audit/{gtoken}/close-periods"))).send().await.unwrap().json().await.unwrap();
    assert_eq!(periods.as_array().unwrap().len(), 1);
    assert_eq!(periods[0]["status"], "closed");
}

#[tokio::test]
async fn audit_token_reads_exports_and_evidence_packs() {
    let app = common::spawn_app().await;
    let bearer = merchant(&app, "at2@example.com").await;
    let uid = common::merchant_user_id(&app.db, "at2@example.com").await;
    let store = common::seed_default_store(&app.db, uid).await;
    let inv = common::seed_invoice(&app.db, uid, store, "inv_at2", "paid", 1000, 1000, 0, None, None, "2026-06-10T00:00:00.000+00:00").await;
    // grant covers June (when export/evidence manifests are generated)
    let gtoken = create_grant(&app, &bearer, json!(["exports", "evidence_packs"]), "2026-06-01", "2026-06-30").await;

    let exp = app.client.get(app.url("/api/payments/ops/exports/invoices.csv")).bearer_auth(&bearer).send().await.unwrap();
    assert_eq!(exp.status(), 200);
    let ev = app.client.post(app.url(&format!("/api/payments/ops/invoices/{inv}/evidence-packs"))).bearer_auth(&bearer).send().await.unwrap();
    assert_eq!(ev.status(), 202);

    let exports: Value = app.client.get(app.url(&format!("/api/payments/audit/{gtoken}/exports"))).send().await.unwrap().json().await.unwrap();
    assert_eq!(exports.as_array().unwrap().len(), 1);
    assert_eq!(exports[0]["kind"], "invoices");

    let packs: Value = app.client.get(app.url(&format!("/api/payments/audit/{gtoken}/evidence-packs"))).send().await.unwrap().json().await.unwrap();
    assert_eq!(packs.as_array().unwrap().len(), 1);
    assert_eq!(packs[0]["invoiceId"], inv);
}

#[tokio::test]
async fn audit_token_authorization() {
    let app = common::spawn_app().await;
    let bearer = merchant(&app, "at3@example.com").await;
    let gtoken = create_grant(&app, &bearer, json!(["statements"]), "2026-01-01", "2026-01-31").await;

    // scope not granted -> 403
    let wrong = app.client.get(app.url(&format!("/api/payments/audit/{gtoken}/exports"))).send().await.unwrap();
    assert_eq!(wrong.status(), 403);
    assert_eq!(wrong.json::<Value>().await.unwrap()["message"], "Payment audit access grant is not active for this resource");

    // unknown token -> 403
    let unknown = app.client.get(app.url("/api/payments/audit/pay_audit_nope/statements")).send().await.unwrap();
    assert_eq!(unknown.status(), 403);
}
