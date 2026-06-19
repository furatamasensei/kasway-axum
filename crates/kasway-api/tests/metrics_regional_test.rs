mod common;

use serde_json::{json, Value};

async fn merchant(app: &common::TestApp, email: &str) -> String {
    common::register_merchant(app, email, "secret123").await
}

// --- metrics ---

#[tokio::test]
async fn metrics_overview_requires_auth() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/api/metrics/overview")).send().await.unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn metrics_overview_empty_shape() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "mx1@example.com").await;

    let body: Value = app.client.get(app.url("/api/metrics/overview")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(body["range"]["interval"], "day");
    assert_eq!(body["totalPaidInvoiceVolume"], 0.0);
    assert_eq!(body["invoiceCounts"], json!({ "open": 0, "paid": 0, "expired": 0, "cancelled": 0 }));
    assert_eq!(body["paymentCounts"], json!({ "pending": 0, "submitted": 0, "confirmed": 0, "failed": 0 }));
    assert_eq!(body["paymentObservationSummary"]["counts"], json!({ "pending": 0, "matched": 0, "settled": 0, "ignored": 0 }));
    assert_eq!(body["paymentCreditSummary"], json!({ "totalCount": 0, "totalAmount": 0, "invoiceCount": 0 }));
    assert_eq!(body["webhookDeliveryCounts"], json!({ "success": 0, "failure": 0 }));
}

#[tokio::test]
async fn metrics_revenue_counts_paid_invoices() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "mx2@example.com").await;
    let uid = common::merchant_user_id(&app.db, "mx2@example.com").await;
    let store = common::seed_default_store(&app.db, uid).await;
    let now = "2026-06-18T00:00:00.000+00:00";
    // a paid invoice with paid_at within the default 30d window
    let id = common::seed_invoice(&app.db, uid, store, "inv_paid_m", "paid", 1000, 1000, 0, None, None, now).await;
    sqlx::query("UPDATE invoices SET paid_at = ? WHERE id = ?").bind(now).bind(id).execute(&app.db.pool).await.unwrap();

    let body: Value = app
        .client
        .get(app.url(&format!("/api/metrics/revenue?from=2026-06-01&to=2026-06-30")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["totalPaidInvoiceVolume"], 1000.0);
    assert_eq!(body["averagePaidInvoiceValue"], 1000.0);
    assert_eq!(body["series"].as_array().unwrap().len(), 1);
    assert_eq!(body["series"][0]["paidInvoiceCount"], 1);
}

#[tokio::test]
async fn metrics_invalid_range_422() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "mx3@example.com").await;
    let res = app
        .client
        .get(app.url("/api/metrics/overview?from=2026-06-30&to=2026-06-01"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "Metrics `from` date must be before or equal to `to` date.");
}

#[tokio::test]
async fn metrics_other_endpoints_shapes() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "mx4@example.com").await;

    for path in ["/api/metrics/payments", "/api/metrics/payment-observations", "/api/metrics/payment-credits", "/api/metrics/webhooks"] {
        let res = app.client.get(app.url(path)).bearer_auth(&token).send().await.unwrap();
        assert_eq!(res.status(), 200, "{path}");
        let body: Value = res.json().await.unwrap();
        assert!(body["range"].is_object(), "{path} has range");
    }
}

// --- regional pricing ---

#[tokio::test]
async fn regional_countries_lists_supported() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "rp1@example.com").await;
    let body: Value = app.client.get(app.url("/api/regional-pricing/countries")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    let arr = body.as_array().unwrap();
    assert!(arr.len() >= 10);
    assert!(arr.iter().any(|c| c["code"] == "US"));
}

#[tokio::test]
async fn regional_settings_default_then_update() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "rp2@example.com").await;

    // default settings (lazily created) -> fail_closed, no countries
    let def: Value = app.client.get(app.url("/api/regional-pricing/settings")).bearer_auth(&token).send().await.unwrap().json().await.unwrap();
    assert_eq!(def["fallbackPolicy"], "fail_closed");
    assert_eq!(def["countryCodes"], json!([]));

    // update
    let upd: Value = app
        .client
        .put(app.url("/api/regional-pricing/settings"))
        .bearer_auth(&token)
        .json(&json!({ "fallbackPolicy": "allow_default_price", "countryCodes": ["us", "GB"] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(upd["fallbackPolicy"], "allow_default_price");
    assert_eq!(upd["countryCodes"], json!(["GB", "US"])); // normalized + sorted
    assert!(upd["countries"].as_array().unwrap().iter().any(|c| c["code"] == "US" && c["name"] == "United States"));
}

#[tokio::test]
async fn regional_update_rejects_unsupported_and_duplicates() {
    let app = common::spawn_app().await;
    let token = merchant(&app, "rp3@example.com").await;

    let unsupported = app
        .client
        .put(app.url("/api/regional-pricing/settings"))
        .bearer_auth(&token)
        .json(&json!({ "fallbackPolicy": "fail_closed", "countryCodes": ["ZZ"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(unsupported.status(), 422);
    assert_eq!(unsupported.json::<Value>().await.unwrap()["message"], "Unsupported country code: ZZ");

    let dup = app
        .client
        .put(app.url("/api/regional-pricing/settings"))
        .bearer_auth(&token)
        .json(&json!({ "fallbackPolicy": "fail_closed", "countryCodes": ["US", "us"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(dup.status(), 422);
    assert_eq!(dup.json::<Value>().await.unwrap()["message"], "countryCodes must not contain duplicate countries");

    let bad_policy = app
        .client
        .put(app.url("/api/regional-pricing/settings"))
        .bearer_auth(&token)
        .json(&json!({ "fallbackPolicy": "nope" }))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_policy.status(), 422);
    assert_eq!(bad_policy.json::<Value>().await.unwrap()["errors"][0]["field"], "fallbackPolicy");
}
