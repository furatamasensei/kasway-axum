mod common;

use serde_json::Value;

async fn merchant_with_invoice(app: &common::TestApp, email: &str) -> (String, i64, i64) {
    let token = common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    let store = common::seed_default_store(&app.db, uid).await;
    let inv = common::seed_invoice(
        &app.db, uid, store, &format!("inv_{email}"), "open", 1000, 1000, 0, None, None,
        "2026-01-01T00:00:00.000+00:00",
    )
    .await;
    (token, inv, uid)
}

#[tokio::test]
async fn store_queues_pack_and_lists() {
    let app = common::spawn_app().await;
    let (token, inv, uid) = merchant_with_invoice(&app, "ev1@example.com").await;

    let res = app.client.post(app.url(&format!("/api/payments/ops/invoices/{inv}/evidence-packs"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(res.status(), 202);
    let m: Value = res.json().await.unwrap();
    assert_eq!(m["status"], "queued");
    assert_eq!(m["invoiceId"], inv);
    assert_eq!(m["userId"], uid);
    let pid = m["id"].as_i64().unwrap();

    let list: Value = app.client.get(app.url("/api/payments/ops/evidence-packs")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(list["meta"]["total"], 1);
    assert_eq!(list["data"][0]["id"], pid);

    let shown: Value = app.client.get(app.url(&format!("/api/payments/ops/evidence-packs/{pid}"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(shown["id"], pid);

    // queued pack is not downloadable
    let dl = app.client.get(app.url(&format!("/api/payments/ops/evidence-packs/{pid}/download"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(dl.status(), 422);
    assert_eq!(dl.json::<Value>().await.unwrap()["message"], "Payment evidence pack is not downloadable");
}

#[tokio::test]
async fn store_invalid_invoice() {
    let app = common::spawn_app().await;
    let (token, _inv, _uid) = merchant_with_invoice(&app, "ev2@example.com").await;

    let nf = app.client.post(app.url("/api/payments/ops/invoices/99999/evidence-packs")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(nf.status(), 404);
    assert_eq!(nf.json::<Value>().await.unwrap()["message"], "Invoice not found");

    let bad = app.client.post(app.url("/api/payments/ops/invoices/0/evidence-packs")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(bad.status(), 422);
    assert_eq!(bad.json::<Value>().await.unwrap()["message"], "Invalid invoice id");
}

#[tokio::test]
async fn show_missing_404() {
    let app = common::spawn_app().await;
    let (token, _inv, _uid) = merchant_with_invoice(&app, "ev3@example.com").await;
    let res = app.client.get(app.url("/api/payments/ops/evidence-packs/9999")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "Payment evidence pack not found");
}

#[tokio::test]
async fn evidence_packs_require_auth() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/api/payments/ops/evidence-packs")).send().await.unwrap().status(), 401);
}
