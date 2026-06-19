mod common;

use serde_json::Value;

#[tokio::test]
async fn invoices_index_requires_auth() {
    let app = common::spawn_app().await;
    let res = app.client.get(app.url("/api/invoices")).send().await.unwrap();
    assert_eq!(res.status(), 401);
}

// Empty index lazily creates the default store and returns paginator shape.
#[tokio::test]
async fn invoices_index_empty() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "inv1@example.com", "secret123").await;

    let res = app
        .client
        .get(app.url("/api/invoices"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["data"], serde_json::json!([]));
    assert_eq!(body["meta"]["total"], 0);
    assert_eq!(body["meta"]["currentPage"], 1);

    // default store was created
    let stores: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stores WHERE is_default = 1")
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    assert_eq!(stores, 1);
}

#[tokio::test]
async fn invoices_index_orders_and_paginates() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "inv2@example.com", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "inv2@example.com").await;
    let store = common::seed_default_store(&app.db, uid).await;
    common::seed_invoice(&app.db, uid, store, "inv_old", "open", 100, 100, 0, None, None, "2026-01-01T00:00:00.000+00:00").await;
    common::seed_invoice(&app.db, uid, store, "inv_new", "open", 200, 200, 0, None, None, "2026-02-01T00:00:00.000+00:00").await;

    let res = app
        .client
        .get(app.url("/api/invoices?page=1&perPage=1"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let data = body["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["publicId"], "inv_new"); // newest first
    assert_eq!(body["meta"]["total"], 2);
    assert_eq!(body["meta"]["nextPageUrl"], "/?page=2");
}

#[tokio::test]
async fn invoices_index_source_payment_link_filter() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "inv3@example.com", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "inv3@example.com").await;
    let store = common::seed_default_store(&app.db, uid).await;
    common::seed_invoice(&app.db, uid, store, "inv_plain", "open", 100, 100, 0, None, None, "2026-01-01T00:00:00.000+00:00").await;
    common::seed_invoice(&app.db, uid, store, "inv_linked", "open", 100, 100, 0, Some(42), None, "2026-02-01T00:00:00.000+00:00").await;

    let res = app
        .client
        .get(app.url("/api/invoices?source=payment_link"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    let data = body["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["publicId"], "inv_linked");
}

// show: full serialize contract with a KPR-1 intent present.
#[tokio::test]
async fn invoices_show_with_intent_contract() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "inv4@example.com", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "inv4@example.com").await;
    let store = common::seed_default_store(&app.db, uid).await;
    let id = common::seed_invoice(&app.db, uid, store, "inv_show", "open", 1000, 1010, 10, None, None, "2026-01-01T00:00:00.000+00:00").await;
    common::seed_invoice_item(&app.db, id, "Widget", 2, 500, 1000).await;
    common::seed_kpr1_intent(&app.db, id, uid, "kpr1_show").await;

    let res = app
        .client
        .get(app.url(&format!("/api/invoices/{id}")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["status"], "open");
    // bigint amounts serialized as strings
    assert_eq!(body["subtotalAmount"], "1000");
    assert_eq!(body["totalAmount"], "1010");
    assert_eq!(body["serviceFeeAmount"], "10");
    // items
    assert_eq!(body["items"][0]["name"], "Widget");
    assert_eq!(body["items"][0]["unitAmount"], "500");
    assert_eq!(body["items"][0]["totalAmount"], "1000");
    // KPR-1 hoisting
    assert_eq!(body["paymentRail"], "kpr1_covenant");
    assert!(body.get("paymentAddress").is_none(), "paymentAddress dropped when intent present");
    assert_eq!(body["paymentIntentHash"], "canon_kpr1_show");
    assert_eq!(body["platformFee"]["bps"], 100);
    assert_eq!(body["platformFee"]["amountSompi"], "10");
    assert_eq!(body["kpr1PaymentIntent"]["intentId"], "kpr1_show");
    // requiredOutputs + splitOutputs filter
    assert_eq!(body["requiredOutputs"].as_array().unwrap().len(), 2);
    let splits = body["splitOutputs"].as_array().unwrap();
    assert_eq!(splits.len(), 1);
    assert_eq!(splits[0]["role"], "split");
    // tax null (taxBps null)
    assert_eq!(body["tax"], Value::Null);
}

// show: no intent -> paymentRail "unsupported", paymentAddress present.
#[tokio::test]
async fn invoices_show_without_intent_unsupported() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "inv5@example.com", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "inv5@example.com").await;
    let store = common::seed_default_store(&app.db, uid).await;
    let id = common::seed_invoice(&app.db, uid, store, "inv_noint", "open", 100, 100, 0, None, None, "2026-01-01T00:00:00.000+00:00").await;

    let res = app
        .client
        .get(app.url(&format!("/api/invoices/{id}")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["paymentRail"], "unsupported");
    assert_eq!(body["paymentAddress"], "kpr1:pending:inv_noint");
    assert_eq!(body["kpr1PaymentIntent"], Value::Null);
}

#[tokio::test]
async fn invoices_show_missing_404() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "inv6@example.com", "secret123").await;

    let res = app
        .client
        .get(app.url("/api/invoices/9999"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "Invoice not found");
}

// another merchant's invoice -> 404 (scoped by user_id + store_id)
#[tokio::test]
async fn invoices_show_foreign_404() {
    let app = common::spawn_app().await;
    let _a = common::register_merchant(&app, "owner-a@example.com", "secret123").await;
    let token_b = common::register_merchant(&app, "owner-b@example.com", "secret123").await;
    let uid_a = common::merchant_user_id(&app.db, "owner-a@example.com").await;
    let store_a = common::seed_default_store(&app.db, uid_a).await;
    let id = common::seed_invoice(&app.db, uid_a, store_a, "inv_a", "open", 100, 100, 0, None, None, "2026-01-01T00:00:00.000+00:00").await;

    let res = app
        .client
        .get(app.url(&format!("/api/invoices/{id}")))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test]
async fn invoices_cancel_open_succeeds() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "inv7@example.com", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "inv7@example.com").await;
    let store = common::seed_default_store(&app.db, uid).await;
    let id = common::seed_invoice(&app.db, uid, store, "inv_cancel", "open", 100, 100, 0, None, None, "2026-01-01T00:00:00.000+00:00").await;

    let res = app
        .client
        .post(app.url(&format!("/api/invoices/{id}/cancel")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["status"], "cancelled");
    assert!(!body["cancelledAt"].is_null());
}

#[tokio::test]
async fn invoices_cancel_non_open_422() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "inv8@example.com", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "inv8@example.com").await;
    let store = common::seed_default_store(&app.db, uid).await;
    let id = common::seed_invoice(&app.db, uid, store, "inv_paid", "paid", 100, 100, 0, None, None, "2026-01-01T00:00:00.000+00:00").await;

    let res = app
        .client
        .post(app.url(&format!("/api/invoices/{id}/cancel")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "Only open invoices can be cancelled");
}

// past-expiry open invoice -> expireIfNeeded flips to expired -> cancel 422
#[tokio::test]
async fn invoices_cancel_expired_422() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "inv9@example.com", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "inv9@example.com").await;
    let store = common::seed_default_store(&app.db, uid).await;
    let id = common::seed_invoice(&app.db, uid, store, "inv_exp", "open", 100, 100, 0, None, Some("2020-01-01T00:00:00.000+00:00"), "2019-01-01T00:00:00.000+00:00").await;

    let res = app
        .client
        .post(app.url(&format!("/api/invoices/{id}/cancel")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "Only open invoices can be cancelled");

    // and it is now expired
    let status: String = sqlx::query_scalar("SELECT status FROM invoices WHERE id = ?")
        .bind(id)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    assert_eq!(status, "expired");
}
