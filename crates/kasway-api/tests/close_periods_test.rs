mod common;

use serde_json::{json, Value};

async fn merchant(app: &common::TestApp, email: &str) -> (String, i64) {
    let token = common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    (token, uid)
}

#[tokio::test]
async fn close_periods_index_show_reopen() {
    let app = common::spawn_app().await;
    let (token, uid) = merchant(&app, "cp1@example.com").await;
    let id = common::seed_close_period(&app.db, uid).await;

    let list: Value = app.client.get(app.url("/api/payments/ops/close-periods")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(list["meta"]["total"], 1);
    assert_eq!(list["data"][0]["status"], "closed");

    let shown: Value = app.client.get(app.url(&format!("/api/payments/ops/close-periods/{id}"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(shown["id"], id);
    assert_eq!(shown["totalsChecksum"], "abc123");

    let reopened: Value = app.client.post(app.url(&format!("/api/payments/ops/close-periods/{id}/reopen"))).bearer_auth(&token).json(&json!({ "note": "correction needed" })).send().await.unwrap().json().await.unwrap();
    assert_eq!(reopened["status"], "reopened");
    assert!(!reopened["reopenedAt"].is_null());
    assert_eq!(reopened["metadata"]["reopenNote"], "correction needed");

    // reopen again -> 422
    let again = app.client.post(app.url(&format!("/api/payments/ops/close-periods/{id}/reopen"))).bearer_auth(&token).json(&json!({ "note": "x" })).send().await.unwrap();
    assert_eq!(again.status(), 422);
    assert_eq!(again.json::<Value>().await.unwrap()["message"], "Only closed periods can be reopened");
}

#[tokio::test]
async fn close_periods_reopen_requires_note_and_404() {
    let app = common::spawn_app().await;
    let (token, uid) = merchant(&app, "cp2@example.com").await;
    let id = common::seed_close_period(&app.db, uid).await;

    let no_note = app.client.post(app.url(&format!("/api/payments/ops/close-periods/{id}/reopen"))).bearer_auth(&token).json(&json!({})).send().await.unwrap();
    assert_eq!(no_note.status(), 422);
    assert_eq!(no_note.json::<Value>().await.unwrap()["errors"][0]["field"], "note");

    let missing = app.client.get(app.url("/api/payments/ops/close-periods/9999")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(missing.status(), 404);
    assert_eq!(missing.json::<Value>().await.unwrap()["message"], "Payment close period not found");
}

#[tokio::test]
async fn close_periods_requires_auth() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/api/payments/ops/close-periods")).send().await.unwrap().status(), 401);
}

#[tokio::test]
async fn close_store_generates_statement_and_persists() {
    let app = common::spawn_app().await;
    let (token, _uid) = merchant(&app, "cps1@example.com").await;

    let res = app.client.post(app.url("/api/payments/ops/close-periods")).bearer_auth(&token)
        .json(&json!({ "periodStart": "2026-01-01", "periodEnd": "2026-01-31", "note": "Jan close" }))
        .send().await.unwrap();
    assert_eq!(res.status(), 201);
    let cp: Value = res.json().await.unwrap();
    assert_eq!(cp["status"], "closed");
    assert_eq!(cp["periodStart"], "2026-01-01");
    assert!(!cp["statementId"].is_null());
    assert!(cp["totalsChecksum"].as_str().unwrap().starts_with("sha256:"));
    assert_eq!(cp["metadata"]["note"], "Jan close");
    assert_eq!(cp["metadata"]["overrideHighSeverityExceptions"], false);

    // overlapping closed period -> 422
    let overlap = app.client.post(app.url("/api/payments/ops/close-periods")).bearer_auth(&token)
        .json(&json!({ "periodStart": "2026-01-15", "periodEnd": "2026-02-15" }))
        .send().await.unwrap();
    assert_eq!(overlap.status(), 422);
    assert_eq!(overlap.json::<Value>().await.unwrap()["message"], "Payment close period overlaps an existing closed period");
}

#[tokio::test]
async fn close_store_reuses_existing_statement() {
    let app = common::spawn_app().await;
    let (token, _uid) = merchant(&app, "cps2@example.com").await;

    let st = app.client.post(app.url("/api/payments/ops/statements")).bearer_auth(&token)
        .json(&json!({ "periodStart": "2026-03-01", "periodEnd": "2026-03-31" }))
        .send().await.unwrap();
    assert_eq!(st.status(), 201);
    let statement_id = st.json::<Value>().await.unwrap()["id"].as_i64().unwrap();

    let cp = app.client.post(app.url("/api/payments/ops/close-periods")).bearer_auth(&token)
        .json(&json!({ "periodStart": "2026-03-01", "periodEnd": "2026-03-31" }))
        .send().await.unwrap();
    assert_eq!(cp.status(), 201);
    assert_eq!(cp.json::<Value>().await.unwrap()["statementId"], statement_id);
}

#[tokio::test]
async fn close_store_validation() {
    let app = common::spawn_app().await;
    let (token, _uid) = merchant(&app, "cps3@example.com").await;

    let bad = app.client.post(app.url("/api/payments/ops/close-periods")).bearer_auth(&token)
        .json(&json!({ "periodStart": "2026-03-31", "periodEnd": "2026-03-01" }))
        .send().await.unwrap();
    assert_eq!(bad.status(), 422);
    assert_eq!(bad.json::<Value>().await.unwrap()["message"], "Payment reporting period is invalid");

    let missing = app.client.post(app.url("/api/payments/ops/close-periods")).bearer_auth(&token)
        .json(&json!({ "periodEnd": "2026-03-01" }))
        .send().await.unwrap();
    assert_eq!(missing.status(), 422);
    assert_eq!(missing.json::<Value>().await.unwrap()["errors"][0]["field"], "periodStart");
}
