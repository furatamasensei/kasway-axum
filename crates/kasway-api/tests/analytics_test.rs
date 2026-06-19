mod common;

use serde_json::Value;

async fn merchant(app: &common::TestApp, email: &str) -> (String, i64, i64) {
    let token = common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    let store = common::seed_default_store(&app.db, uid).await;
    (token, uid, store)
}

fn now_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string()
}

#[tokio::test]
async fn summary_aggregates_payment_states() {
    let app = common::spawn_app().await;
    let (token, uid, store) = merchant(&app, "an1@example.com").await;
    let now = now_iso();
    // paid
    common::seed_invoice(&app.db, uid, store, "an_paid", "paid", 1000, 1000, 0, None, None, &now).await;
    // underpaid (credit < total)
    let up = common::seed_invoice(&app.db, uid, store, "an_under", "open", 1000, 1000, 0, None, None, &now).await;
    common::seed_credit(&app.db, up, 400).await;
    // overpaid (credit > total)
    let op = common::seed_invoice(&app.db, uid, store, "an_over", "open", 1000, 1000, 0, None, None, &now).await;
    common::seed_credit(&app.db, op, 1500).await;
    // awaiting (open, no credit)
    common::seed_invoice(&app.db, uid, store, "an_await", "open", 1000, 1000, 0, None, None, &now).await;

    let res: Value = app.client.get(app.url("/api/payments/ops/analytics/summary")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(res["invoiceCount"], 4);
    assert_eq!(res["invoiceAmount"], "4000");
    assert_eq!(res["paidCount"], 1);
    assert_eq!(res["paidAmount"], "1000");
    assert_eq!(res["underpaidCount"], 1);
    assert_eq!(res["overpaidCount"], 1);
    assert_eq!(res["exceptionCountsBySeverity"], serde_json::json!({ "high": 0, "medium": 2, "low": 0 })); // under+over derive medium exceptions
    assert_eq!(res["webhookSummary"]["deliveryCount"], 0);
    assert!(res["webhookSummary"]["successRate"].is_null());
    assert!(res["range"]["interval"] == "day");
}

#[tokio::test]
async fn timeseries_buckets_invoices() {
    let app = common::spawn_app().await;
    let (token, uid, store) = merchant(&app, "an2@example.com").await;
    let now = now_iso();
    common::seed_invoice(&app.db, uid, store, "ts_paid", "paid", 500, 500, 0, None, None, &now).await;

    let res: Value = app.client.get(app.url("/api/payments/ops/analytics/timeseries?interval=day")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(res["interval"], "day");
    let buckets = res["buckets"].as_array().unwrap();
    assert!(!buckets.is_empty());
    let total_invoices: i64 = buckets.iter().map(|b| b["invoiceCount"].as_i64().unwrap()).sum();
    assert_eq!(total_invoices, 1);
    let total_paid: i64 = buckets.iter().map(|b| b["paidCount"].as_i64().unwrap()).sum();
    assert_eq!(total_paid, 1);
}

#[tokio::test]
async fn breakdown_by_payment_state_and_currency() {
    let app = common::spawn_app().await;
    let (token, uid, store) = merchant(&app, "an3@example.com").await;
    let now = now_iso();
    common::seed_invoice(&app.db, uid, store, "bd_paid1", "paid", 1000, 1000, 0, None, None, &now).await;
    common::seed_invoice(&app.db, uid, store, "bd_paid2", "paid", 2000, 2000, 0, None, None, &now).await;
    let up = common::seed_invoice(&app.db, uid, store, "bd_under", "open", 1000, 1000, 0, None, None, &now).await;
    common::seed_credit(&app.db, up, 100).await;

    let ps: Value = app.client.get(app.url("/api/payments/ops/analytics/breakdown?dimension=paymentState")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(ps["dimension"], "paymentState");
    let rows = ps["rows"].as_array().unwrap();
    // sorted by count desc: paid(2) first
    assert_eq!(rows[0]["key"], "paid");
    assert_eq!(rows[0]["invoiceCount"], 2);
    assert_eq!(rows[0]["paidAmount"], "3000");
    assert!(rows.iter().any(|r| r["key"] == "underpaid" && r["invoiceCount"] == 1));

    let cur: Value = app.client.get(app.url("/api/payments/ops/analytics/breakdown?dimension=currency")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(cur["rows"][0]["key"], "KAS");
    assert_eq!(cur["rows"][0]["invoiceCount"], 3);

    // webhookStatus with no deliveries -> {none:0}
    let wh: Value = app.client.get(app.url("/api/payments/ops/analytics/breakdown?dimension=webhookStatus")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(wh["rows"][0]["key"], "none");
    assert_eq!(wh["rows"][0]["invoiceCount"], 0);
}

#[tokio::test]
async fn validation_and_auth() {
    let app = common::spawn_app().await;
    let (token, _uid, _store) = merchant(&app, "an4@example.com").await;

    let bad = app.client.get(app.url("/api/payments/ops/analytics/summary?from=not-a-date")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(bad.status(), 422);
    assert_eq!(bad.json::<Value>().await.unwrap()["message"], "Analytics date filters must be valid ISO date strings.");

    let order = app.client.get(app.url("/api/payments/ops/analytics/summary?from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(order.status(), 422);
    assert_eq!(order.json::<Value>().await.unwrap()["message"], "Analytics `from` date must be before or equal to `to` date.");

    let badps = app.client.get(app.url("/api/payments/ops/analytics/summary?paymentState=bogus")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(badps.status(), 422);
    assert_eq!(badps.json::<Value>().await.unwrap()["errors"][0]["field"], "paymentState");

    let nodim = app.client.get(app.url("/api/payments/ops/analytics/breakdown")).bearer_auth(&token).send().await.unwrap();
    assert_eq!(nodim.status(), 422);
    assert_eq!(nodim.json::<Value>().await.unwrap()["errors"][0]["field"], "dimension");

    assert_eq!(app.client.get(app.url("/api/payments/ops/analytics/summary")).send().await.unwrap().status(), 401);
}
