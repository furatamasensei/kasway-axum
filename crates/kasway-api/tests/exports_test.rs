mod common;

use serde_json::{json, Value};

async fn merchant_with_invoice(app: &common::TestApp, email: &str) -> (String, i64, i64) {
    let token = common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    let store = common::seed_default_store(&app.db, uid).await;
    let inv = common::seed_invoice(
        &app.db, uid, store, &format!("inv_{email}"), "paid", 1000, 1000, 0, None, None,
        "2026-01-01T00:00:00.000+00:00",
    )
    .await;
    (token, inv, uid)
}

#[tokio::test]
async fn invoices_csv_streams_and_persists_manifest() {
    let app = common::spawn_app().await;
    let (token, _inv, _uid) = merchant_with_invoice(&app, "exp1@example.com").await;

    let res = app.client.get(app.url("/api/payments/ops/exports/invoices.csv")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers().get("content-type").unwrap(), "text/csv; charset=utf-8");
    assert_eq!(res.headers().get("x-kasway-export-row-count").unwrap(), "1");
    let checksum = res.headers().get("x-kasway-export-checksum").unwrap().to_str().unwrap().to_string();
    assert!(checksum.starts_with("sha256:"));
    let export_id = res.headers().get("x-kasway-export-id").unwrap().to_str().unwrap().to_string();
    let body = res.text().await.unwrap();
    assert!(body.starts_with("id,public_id,external_id,status,"));
    assert!(body.contains("inv_exp1@example.com"));

    // manifest persisted -> visible in index + show
    let list: Value = app.client.get(app.url("/api/payments/ops/exports")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(list["meta"]["total"], 1);
    assert_eq!(list["data"][0]["kind"], "invoices");
    assert_eq!(list["data"][0]["status"], "succeeded");
    assert_eq!(list["data"][0]["checksum"], checksum);

    let shown: Value = app.client.get(app.url(&format!("/api/payments/ops/exports/{export_id}"))).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(shown["rowCount"], 1);
    assert_eq!(shown["format"], "csv");
}

#[tokio::test]
async fn observations_and_credits_csv_headers() {
    let app = common::spawn_app().await;
    let (token, _inv, _uid) = merchant_with_invoice(&app, "exp2@example.com").await;

    let obs = app.client.get(app.url("/api/payments/ops/exports/observations.csv")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(obs.status(), 200);
    assert!(obs.text().await.unwrap().starts_with("id,network,asset_id,tx_id,"));

    let cr = app.client.get(app.url("/api/payments/ops/exports/credits.csv")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(cr.status(), 200);
    assert!(cr.text().await.unwrap().starts_with("id,payment_observation_id,invoice_id,"));
}

#[tokio::test]
async fn date_filter_validation() {
    let app = common::spawn_app().await;
    let (token, _inv, _uid) = merchant_with_invoice(&app, "exp3@example.com").await;

    let bad = app.client.get(app.url("/api/payments/ops/exports/invoices.csv?from=not-a-date")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(bad.status(), 422);
    assert_eq!(bad.json::<Value>().await.unwrap()["message"], "Payment operations export `from` date must be a valid ISO date.");

    let order = app.client.get(app.url("/api/payments/ops/exports/invoices.csv?from=2026-02-01&to=2026-01-01")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(order.status(), 422);
    assert_eq!(order.json::<Value>().await.unwrap()["message"], "Payment operations export `from` date must be before or equal to `to` date.");

    let inv = app.client.get(app.url("/api/payments/ops/exports/invoices.csv?invoiceId=0")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(inv.status(), 422);
    assert_eq!(inv.json::<Value>().await.unwrap()["message"], "Payment operations export `invoiceId` filter must be a positive integer.");
}

#[tokio::test]
async fn store_queues_manifest() {
    let app = common::spawn_app().await;
    let (token, _inv, _uid) = merchant_with_invoice(&app, "exp4@example.com").await;

    let res = app.client.post(app.url("/api/payments/ops/exports")).bearer_auth(&token)
        .json(&json!({ "kind": "invoices", "filters": { "status": "paid" } }))
        .send().await.unwrap();
    assert_eq!(res.status(), 202);
    let m: Value = res.json().await.unwrap();
    assert_eq!(m["status"], "queued");
    assert_eq!(m["kind"], "invoices");
    assert_eq!(m["filters"]["status"], "paid");
    let mid = m["id"].as_i64().unwrap();

    // queued manifest is not downloadable -> 422
    let dl = app.client.get(app.url(&format!("/api/payments/ops/exports/{mid}/download"))).bearer_auth(&token).send().await.unwrap();
    assert_eq!(dl.status(), 422);
    assert_eq!(dl.json::<Value>().await.unwrap()["message"], "Payment operation export is not downloadable");
}

#[tokio::test]
async fn store_validates_kind() {
    let app = common::spawn_app().await;
    let (token, _inv, _uid) = merchant_with_invoice(&app, "exp5@example.com").await;

    let res = app.client.post(app.url("/api/payments/ops/exports")).bearer_auth(&token)
        .json(&json!({ "kind": "bogus" }))
        .send().await.unwrap();
    assert_eq!(res.status(), 422);
    assert_eq!(res.json::<Value>().await.unwrap()["errors"][0]["field"], "kind");
}

#[tokio::test]
async fn show_and_download_missing_404() {
    let app = common::spawn_app().await;
    let (token, _inv, _uid) = merchant_with_invoice(&app, "exp6@example.com").await;

    let show = app.client.get(app.url("/api/payments/ops/exports/9999")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(show.status(), 404);
    assert_eq!(show.json::<Value>().await.unwrap()["message"], "Payment operation export not found");

    let dl = app.client.get(app.url("/api/payments/ops/exports/9999/download")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(dl.status(), 404);
}

#[tokio::test]
async fn exports_require_auth() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/api/payments/ops/exports")).send().await.unwrap().status(), 401);
    assert_eq!(app.client.get(app.url("/api/payments/ops/exports/invoices.csv")).send().await.unwrap().status(), 401);
}
