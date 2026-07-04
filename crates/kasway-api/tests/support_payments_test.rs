mod common;

use serde_json::{json, Value};

async fn seed(app: &common::TestApp, email: &str) -> (i64, i64) {
    common::register_merchant(app, email, "secret123").await;
    let uid = common::merchant_user_id(&app.db, email).await;
    let store = common::seed_default_store(&app.db, uid).await;
    let inv = common::seed_invoice(&app.db, uid, store, &format!("inv_{email}"), "paid", 1000, 1000, 0, None, None, "2026-06-10T00:00:00.000+00:00").await;
    (uid, inv)
}

#[tokio::test]
async fn search_returns_invoice_with_support_shape() {
    let app = common::spawn_app().await;
    let (uid, inv) = seed(&app, "sup1@example.com").await;

    let res = app.client.get(app.url(&format!("/api/support/payments/search?merchantId={uid}")))
        .bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["meta"]["total"], 1);
    assert_eq!(body["data"][0]["id"], inv);
    assert_eq!(body["data"][0]["supportMerchant"]["id"], uid);
    assert_eq!(body["data"][0]["supportMerchant"]["email"], "sup1@example.com");
    assert!(body["data"][0]["paymentStatus"].is_object());
    assert_eq!(body["data"][0]["supportNotesCount"], 0);
}

#[tokio::test]
async fn invoice_detail_and_timeline() {
    let app = common::spawn_app().await;
    let (_uid, inv) = seed(&app, "sup2@example.com").await;

    let detail: Value = app.client.get(app.url(&format!("/api/support/payments/invoices/{inv}")))
        .bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap().json().await.unwrap();
    assert_eq!(detail["id"], inv);
    assert!(detail["supportNotes"].is_array());

    let tl: Value = app.client.get(app.url(&format!("/api/support/payments/invoices/{inv}/timeline")))
        .bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap().json().await.unwrap();
    assert!(tl["data"].as_array().unwrap().iter().any(|e| e["type"] == "invoice.created"));

    // missing -> 404
    let nf = app.client.get(app.url("/api/support/payments/invoices/99999")).bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap();
    assert_eq!(nf.status(), 404);
    assert_eq!(nf.json::<Value>().await.unwrap()["message"], "Invoice not found");
}

#[tokio::test]
async fn add_note_and_regenerate_evidence() {
    let app = common::spawn_app().await;
    let (uid, inv) = seed(&app, "sup3@example.com").await;

    let created = app.client.post(app.url(&format!("/api/support/payments/invoices/{inv}/notes")))
        .bearer_auth(common::INTERNAL_TOKEN)
        .header("x-support-actor-id", "op-42")
        .json(&json!({ "note": "Investigated underpayment", "metadata": { "ticket": "T-1", "apiKey": "should-redact" } }))
        .send().await.unwrap();
    assert_eq!(created.status(), 201);
    let note: Value = created.json().await.unwrap();
    assert_eq!(note["actorType"], "support");
    assert_eq!(note["actorId"], "op-42");
    assert_eq!(note["userId"], uid);
    assert_eq!(note["metadata"]["ticket"], "T-1");
    assert_eq!(note["metadata"]["apiKey"], "[redacted]");

    // note now visible in detail
    let detail: Value = app.client.get(app.url(&format!("/api/support/payments/invoices/{inv}")))
        .bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap().json().await.unwrap();
    assert_eq!(detail["supportNotesCount"], 1);

    // empty note -> 422
    let bad = app.client.post(app.url(&format!("/api/support/payments/invoices/{inv}/notes")))
        .bearer_auth(common::INTERNAL_TOKEN).json(&json!({ "note": "" })).send().await.unwrap();
    assert_eq!(bad.status(), 422);
    assert_eq!(bad.json::<Value>().await.unwrap()["errors"][0]["field"], "note");

    // regenerate evidence pack -> 202 queued
    let regen = app.client.post(app.url(&format!("/api/support/payments/invoices/{inv}/evidence-packs/regenerate")))
        .bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap();
    assert_eq!(regen.status(), 202);
    let m: Value = regen.json().await.unwrap();
    assert_eq!(m["status"], "queued");
    assert_eq!(m["invoiceId"], inv);
}

#[tokio::test]
async fn get_webhook_delivery_masks_secrets() {
    let app = common::spawn_app().await;
    let (uid, inv) = seed(&app, "sup4@example.com").await;

    // seed an endpoint, event, delivery directly
    let ep = sqlx::query_scalar::<_, i64>("INSERT INTO webhook_endpoints (user_id, url, events, signing_secret, is_active, created_at, updated_at) VALUES ($1, 'https://x.test/hook', '[\"invoice.paid\"]', 'whsec_supersecret', 1, '2026-06-10T00:00:00.000+00:00', '2026-06-10T00:00:00.000+00:00') RETURNING id")
        .bind(uid).fetch_one(&app.db.pool).await.unwrap();
    let ev = sqlx::query_scalar::<_, i64>("INSERT INTO webhook_events (user_id, event_type, resource_type, resource_id, payload, created_at, updated_at) VALUES ($1, 'invoice.paid', 'invoice', $2, '{\"token\":\"abc\",\"amount\":100}', '2026-06-10T00:00:00.000+00:00', '2026-06-10T00:00:00.000+00:00') RETURNING id")
        .bind(uid).bind(inv.to_string()).fetch_one(&app.db.pool).await.unwrap();
    let dl = sqlx::query_scalar::<_, i64>("INSERT INTO webhook_deliveries (webhook_event_id, webhook_endpoint_id, status, attempt_count, response_body, is_replay, created_at, updated_at) VALUES ($1, $2, 'delivered', 1, 'OK body', 0, '2026-06-10T00:00:00.000+00:00', '2026-06-10T00:00:00.000+00:00') RETURNING id")
        .bind(ev).bind(ep).fetch_one(&app.db.pool).await.unwrap();

    let res: Value = app.client.get(app.url(&format!("/api/support/payments/webhook-deliveries/{dl}")))
        .bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap().json().await.unwrap();
    assert_eq!(res["id"], dl);
    assert_eq!(res["responseBody"], Value::Null);
    assert_eq!(res["responseBodyLength"], 7);
    assert_eq!(res["merchantId"], uid);
    assert_eq!(res["endpoint"]["signingSecret"], "[redacted]");
    assert_eq!(res["event"]["payload"]["token"], "[redacted]");
    assert_eq!(res["event"]["payload"]["amount"], 100);

    let nf = app.client.get(app.url("/api/support/payments/webhook-deliveries/99999")).bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap();
    assert_eq!(nf.status(), 404);
}

#[tokio::test]
async fn exceptions_cross_merchant() {
    let app = common::spawn_app().await;
    // merchant A: underpaid invoice
    common::register_merchant(&app, "exa@example.com", "secret123").await;
    let uid_a = common::merchant_user_id(&app.db, "exa@example.com").await;
    let store_a = common::seed_default_store(&app.db, uid_a).await;
    let inv_a = common::seed_invoice(&app.db, uid_a, store_a, "inv_exa", "open", 1000, 1000, 0, None, None, "2026-06-10T00:00:00.000+00:00").await;
    common::seed_credit(&app.db, inv_a, 400).await;
    // merchant B: underpaid invoice
    common::register_merchant(&app, "exb@example.com", "secret123").await;
    let uid_b = common::merchant_user_id(&app.db, "exb@example.com").await;
    let store_b = common::seed_default_store(&app.db, uid_b).await;
    let inv_b = common::seed_invoice(&app.db, uid_b, store_b, "inv_exb", "open", 2000, 2000, 0, None, None, "2026-06-11T00:00:00.000+00:00").await;
    common::seed_credit(&app.db, inv_b, 100).await;

    // all merchants
    let all: Value = app.client.get(app.url("/api/support/payments/exceptions"))
        .bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap().json().await.unwrap();
    assert_eq!(all["meta"]["total"], 2);
    // each row carries its merchant
    let merchants: Vec<i64> = all["data"].as_array().unwrap().iter().map(|r| r["merchant"]["id"].as_i64().unwrap()).collect();
    assert!(merchants.contains(&uid_a) && merchants.contains(&uid_b));

    // filter by merchantId
    let only_a: Value = app.client.get(app.url(&format!("/api/support/payments/exceptions?merchantId={uid_a}")))
        .bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap().json().await.unwrap();
    assert_eq!(only_a["meta"]["total"], 1);
    assert_eq!(only_a["data"][0]["merchant"]["id"], uid_a);
    assert_eq!(only_a["data"][0]["type"], "underpaid");
    assert_eq!(only_a["data"][0]["merchant"]["email"], "exa@example.com");

    // filter by invoice identifier resolves to merchant B
    let by_pub: Value = app.client.get(app.url("/api/support/payments/exceptions?publicId=inv_exb"))
        .bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap().json().await.unwrap();
    assert_eq!(by_pub["meta"]["total"], 1);
    assert_eq!(by_pub["data"][0]["merchant"]["id"], uid_b);

    let _ = inv_a;
    let _ = inv_b;
}

#[tokio::test]
async fn exceptions_unknown_merchant_empty() {
    let app = common::spawn_app().await;
    let res: Value = app.client.get(app.url("/api/support/payments/exceptions?merchantEmail=nobody@nowhere.test"))
        .bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap().json().await.unwrap();
    assert_eq!(res["meta"]["total"], 0);
    assert!(res["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn replay_webhook_delivery_creates_replay() {
    let app = common::spawn_app().await;
    let (uid, inv) = seed(&app, "sup5@example.com").await;
    let ep = sqlx::query_scalar::<_, i64>("INSERT INTO webhook_endpoints (user_id, url, events, signing_secret, is_active, created_at, updated_at) VALUES ($1, 'https://x.test/hook', '[\"invoice.paid\"]', 'whsec_s', 1, '2026-06-10T00:00:00.000+00:00', '2026-06-10T00:00:00.000+00:00') RETURNING id")
        .bind(uid).fetch_one(&app.db.pool).await.unwrap();
    let ev = sqlx::query_scalar::<_, i64>("INSERT INTO webhook_events (user_id, event_type, resource_type, resource_id, payload, created_at, updated_at) VALUES ($1, 'invoice.paid', 'invoice', $2, '{}', '2026-06-10T00:00:00.000+00:00', '2026-06-10T00:00:00.000+00:00') RETURNING id")
        .bind(uid).bind(inv.to_string()).fetch_one(&app.db.pool).await.unwrap();
    let dl = sqlx::query_scalar::<_, i64>("INSERT INTO webhook_deliveries (webhook_event_id, webhook_endpoint_id, status, attempt_count, is_replay, created_at, updated_at) VALUES ($1, $2, 'failed', 3, 0, '2026-06-10T00:00:00.000+00:00', '2026-06-10T00:00:00.000+00:00') RETURNING id")
        .bind(ev).bind(ep).fetch_one(&app.db.pool).await.unwrap();

    let res = app.client.post(app.url(&format!("/api/support/payments/webhook-deliveries/{dl}/replay")))
        .bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap();
    assert_eq!(res.status(), 202);
    let r: Value = res.json().await.unwrap();
    assert_eq!(r["status"], "pending");
    assert_eq!(r["isReplay"], true);
    assert_eq!(r["attemptCount"], 0);
    assert_eq!(r["webhookEventId"], ev);
    assert_eq!(r["merchantId"], uid);
    assert_ne!(r["id"], dl); // a new row

    // two delivery rows now exist for the event
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_event_id = $1").bind(ev).fetch_one(&app.db.pool).await.unwrap();
    assert_eq!(count, 2);

    // replay missing -> 404
    let nf = app.client.post(app.url("/api/support/payments/webhook-deliveries/99999/replay")).bearer_auth(common::INTERNAL_TOKEN).send().await.unwrap();
    assert_eq!(nf.status(), 404);
    assert_eq!(nf.json::<Value>().await.unwrap()["message"], "Webhook delivery not found");
}

#[tokio::test]
async fn support_requires_internal_token() {
    let app = common::spawn_app().await;
    assert_eq!(app.client.get(app.url("/api/support/payments/search")).send().await.unwrap().status(), 401);
    assert_eq!(app.client.get(app.url("/api/support/payments/exceptions")).send().await.unwrap().status(), 401);
}
