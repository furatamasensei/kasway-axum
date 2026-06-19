mod common;

use serde_json::Value;

fn tok() -> &'static str { common::INTERNAL_TOKEN }

// ---------- SLO ----------

#[tokio::test]
async fn slo_report_empty_db_indexer_critical() {
    let app = common::spawn_app().await;
    let res: Value = app.client.get(app.url("/internal/payment-ops/slo")).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(res["overallStatus"], "critical"); // no checkpoint
    assert_eq!(res["indicators"]["indexerFreshness"]["status"], "critical");
    assert_eq!(res["indicators"]["indexerFreshness"]["metadata"]["reason"], "no_recent_checkpoint");
    assert_eq!(res["indicators"]["observationIngestionLag"]["status"], "ok");
    assert_eq!(res["incidents"]["critical"], 1);
    assert_eq!(res["thresholds"]["indexer"]["warnAgeSeconds"], 180);
}

#[tokio::test]
async fn slo_report_fresh_checkpoint_ok() {
    let app = common::spawn_app().await;
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string();
    sqlx::query("INSERT INTO payment_indexer_checkpoints (network, asset_id, source, checkpoint, created_at, updated_at) VALUES ('tn10','KAS','rusty-kaspa-node','{}', ?, ?)")
        .bind(&now).bind(&now).execute(&app.db.pool).await.unwrap();
    let res: Value = app.client.get(app.url("/internal/payment-ops/slo")).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(res["indicators"]["indexerFreshness"]["status"], "ok");
    assert_eq!(res["indicators"]["indexerFreshness"]["sampleCount"], 1);
    assert_eq!(res["overallStatus"], "ok");
    assert_eq!(res["incidents"]["open"], 0);
}

#[tokio::test]
async fn slo_queues_and_incidents() {
    let app = common::spawn_app().await;
    let q: Value = app.client.get(app.url("/internal/payment-ops/slo/queues")).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    let queues = q["queues"].as_array().unwrap();
    assert_eq!(queues.len(), 7);
    assert_eq!(queues[0]["name"], "payments_ingest");
    assert_eq!(queues[5]["name"], "exports");

    let inc: Value = app.client.get(app.url("/internal/payment-ops/slo/incidents")).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(inc["summary"]["total"], 7);
    assert!(inc["incidents"].as_array().unwrap().iter().any(|i| i["type"] == "indexer_freshness"));
}

#[tokio::test]
async fn slo_requires_internal_token() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/internal/payment-ops/slo")).send().await.unwrap().status(), 401);
}

// ---------- observability ----------

async fn merchant_with_invoice(app: &common::TestApp, email: &str, status: &str) -> (i64, i64) {
    common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    let store = common::seed_default_store(&app.db, uid).await;
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string();
    let inv = common::seed_invoice(&app.db, uid, store, &format!("inv_{email}"), status, 1000, 1000, 0, None, None, &now).await;
    (uid, inv)
}

#[tokio::test]
async fn overview_empty_and_with_data() {
    let app = common::spawn_app().await;
    // empty
    let empty: Value = app.client.get(app.url("/internal/payment-ops/overview")).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(empty["activeMerchants"], 0);
    assert_eq!(empty["invoiceVolume"]["total"], 0);
    assert_eq!(empty["tn10NodeStatus"]["status"], "disabled");
    assert_eq!(empty["tn10NodeStatus"]["metadata"]["expectedNetworkId"], "testnet-10");

    // with a paid invoice
    let (uid, _inv) = merchant_with_invoice(&app, "obs1@example.com", "paid").await;
    let res: Value = app.client.get(app.url("/internal/payment-ops/overview")).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(res["activeMerchants"], 1);
    assert_eq!(res["invoiceVolume"]["total"], 1);
    assert_eq!(res["invoiceVolume"]["byStatus"]["paid"], 1);
    assert_eq!(res["invoiceVolume"]["totalAmount"], "1000");
    let _ = uid;
}

#[tokio::test]
async fn merchants_list_and_detail() {
    let app = common::spawn_app().await;
    let (uid, _) = merchant_with_invoice(&app, "obs2@example.com", "open").await;

    let list: Value = app.client.get(app.url("/internal/payment-ops/merchants")).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(list["meta"]["total"], 1);
    assert_eq!(list["data"][0]["merchant"]["id"], uid);
    assert_eq!(list["data"][0]["merchant"]["email"], "obs2@example.com");
    assert_eq!(list["data"][0]["totals"]["invoiceVolume"]["total"], 1);

    let detail: Value = app.client.get(app.url(&format!("/internal/payment-ops/merchants/{uid}"))).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(detail["merchant"]["id"], uid);
    assert_eq!(detail["totals"]["invoiceVolume"]["total"], 1);

    // merchant with no invoices in window -> 404 'merchant not found'
    let nf = app.client.get(app.url("/internal/payment-ops/merchants/4242")).bearer_auth(tok()).send().await.unwrap();
    assert_eq!(nf.status(), 404);
    assert_eq!(nf.json::<Value>().await.unwrap()["message"], "merchant not found");

    // bad id -> 400
    let bad = app.client.get(app.url("/internal/payment-ops/merchants/0")).bearer_auth(tok()).send().await.unwrap();
    assert_eq!(bad.status(), 400);
    assert_eq!(bad.json::<Value>().await.unwrap()["message"], "Merchant id must be a positive integer.");
}

#[tokio::test]
async fn failures_includes_exception_row() {
    let app = common::spawn_app().await;
    let (_uid, inv) = merchant_with_invoice(&app, "obs3@example.com", "open").await;
    common::seed_credit(&app.db, inv, 400).await; // underpaid -> exception

    let res: Value = app.client.get(app.url("/internal/payment-ops/failures")).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(res["meta"]["total"], 1);
    assert_eq!(res["data"][0]["type"], "exception");
    assert_eq!(res["data"][0]["severity"], "medium");
    assert_eq!(res["data"][0]["resource"]["extra"]["exceptionType"], "underpaid");
}

#[tokio::test]
async fn observability_date_validation_and_auth() {
    let app = common::spawn_app().await;
    let bad = app.client.get(app.url("/internal/payment-ops/overview?from=not-a-date")).bearer_auth(tok()).send().await.unwrap();
    assert_eq!(bad.status(), 422);
    assert_eq!(bad.json::<Value>().await.unwrap()["message"], "Payment platform observability date filters must be valid ISO date strings.");

    let order = app.client.get(app.url("/internal/payment-ops/overview?from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z")).bearer_auth(tok()).send().await.unwrap();
    assert_eq!(order.status(), 422);
    assert_eq!(order.json::<Value>().await.unwrap()["message"], "Payment platform observability `from` date must be before or equal to `to` date.");

    assert_eq!(app.client.get(app.url("/internal/payment-ops/overview")).send().await.unwrap().status(), 401);
}

#[tokio::test]
async fn tn10_status_disabled() {
    let app = common::spawn_app().await;
    let res: Value = app.client.get(app.url("/internal/payment-ops/tn10/status")).bearer_auth(tok()).send().await.unwrap().json().await.unwrap();
    assert_eq!(res["status"], "disabled");
    assert_eq!(res["ready"], false);
    assert_eq!(res["checks"][0]["key"], "tn10.enabled");
    assert_eq!(app.client.get(app.url("/internal/payment-ops/tn10/status")).send().await.unwrap().status(), 401);
}
