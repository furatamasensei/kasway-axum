mod common;

use serde_json::{json, Value};

#[tokio::test]
async fn create_requires_auth() {
    let app = common::spawn_app().await;
    let res = app
        .client
        .post(app.url("/api/invoices"))
        .json(&json!({ "items": [{ "name": "x", "quantity": 1, "unitAmount": "100" }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

// Missing merchant payout address -> 422 CommerceError from KPR-1 minter.
#[tokio::test]
async fn create_without_setup_address_422() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "cinv1@example.com", "secret123").await;

    let res = app
        .client
        .post(app.url("/api/invoices"))
        .bearer_auth(&token)
        .json(&json!({ "items": [{ "name": "Widget", "quantity": 1, "unitAmount": "200000000" }] }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 422);
    assert_eq!(
        res.json::<Value>().await.unwrap()["message"],
        "Merchant-owned Kaspa payout address is required before creating KPR-1 invoices"
    );
}

#[tokio::test]
async fn create_validation_empty_items() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "cinv2@example.com", "secret123").await;

    let res = app
        .client
        .post(app.url("/api/invoices"))
        .bearer_auth(&token)
        .json(&json!({ "items": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["errors"][0]["field"], "items");
    assert_eq!(body["errors"][0]["rule"], "minLength");
}

#[tokio::test]
async fn create_validation_bad_unit_amount() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "cinv3@example.com", "secret123").await;

    let res = app
        .client
        .post(app.url("/api/invoices"))
        .bearer_auth(&token)
        .json(&json!({ "items": [{ "name": "x", "quantity": 1, "unitAmount": "0123" }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 422);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["errors"][0]["field"], "items.0.unitAmount");
    assert_eq!(body["errors"][0]["rule"], "regex");
}

// Happy path: merchant_subsidized -> total == subtotal, intent minted.
#[tokio::test]
async fn create_success_merchant_subsidized() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "cinv4@example.com", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "cinv4@example.com").await;
    let store = common::seed_default_store(&app.db, uid).await;
    common::seed_setup(&app.db, uid, store, "kaspatest:merchantpayout00001").await;

    let res = app
        .client
        .post(app.url("/api/invoices"))
        .bearer_auth(&token)
        .json(&json!({
            "items": [
                { "name": "Widget", "quantity": 2, "unitAmount": "200000000" },
                { "name": "Gizmo", "quantity": 1, "unitAmount": "100000000" }
            ]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["status"], "open");
    assert!(body["publicId"].as_str().unwrap().starts_with("inv_"));
    // subtotal = 2*200000000 + 100000000 = 500000000; merchant_subsidized => total == subtotal
    assert_eq!(body["subtotalAmount"], "500000000");
    assert_eq!(body["totalAmount"], "500000000");
    assert_eq!(body["serviceFeeAmount"], "0");
    assert_eq!(body["feeDelegation"], "merchant_subsidized");
    assert_eq!(body["items"].as_array().unwrap().len(), 2);

    // KPR-1 intent present + contract hoisting
    assert_eq!(body["paymentRail"], "kpr1_covenant");
    assert!(body.get("paymentAddress").is_none());
    let intent = &body["kpr1PaymentIntent"];
    assert!(intent["intentId"].as_str().unwrap().starts_with("kpr1_"));
    assert_eq!(intent["amountSompi"], "500000000");
    // platform fee = 2% of 500000000 = 10000000
    assert_eq!(body["platformFee"]["bps"], 200);
    assert_eq!(body["platformFee"]["amountSompi"], "10000000");
    // requiredOutputs: merchant_net (490000000) + kasway_fee (10000000)
    let outs = body["requiredOutputs"].as_array().unwrap();
    assert_eq!(outs.len(), 2);
    let net = outs.iter().find(|o| o["role"] == "merchant_net").unwrap();
    assert_eq!(net["amountSompi"], "490000000");
    let fee = outs.iter().find(|o| o["role"] == "kasway_fee").unwrap();
    assert_eq!(fee["amountSompi"], "10000000");
    // canonical hash + request uri present
    assert!(intent["canonicalHash"].as_str().unwrap().len() == 64);
    assert!(intent["paymentRequestUri"].as_str().unwrap().starts_with("kaspa-payment:v1?request="));
}

// customer_pays grosses up the total so merchant nets the full subtotal.
#[tokio::test]
async fn create_customer_pays_grosses_up() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "cinv5@example.com", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "cinv5@example.com").await;
    let store = common::seed_default_store(&app.db, uid).await;
    common::seed_setup(&app.db, uid, store, "kaspatest:merchantpayout00001").await;

    let res = app
        .client
        .post(app.url("/api/invoices"))
        .bearer_auth(&token)
        .json(&json!({
            "feeDelegation": "customer_pays",
            "items": [{ "name": "Widget", "quantity": 1, "unitAmount": "500000000" }]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["subtotalAmount"], "500000000");
    // total grossed up so that total - 1% fee >= 500000000; net must cover the full subtotal
    let total: i64 = body["totalAmount"].as_str().unwrap().parse().unwrap();
    assert!(total > 500000000, "total grossed up above subtotal");
    let service_fee: i64 = body["serviceFeeAmount"].as_str().unwrap().parse().unwrap();
    assert_eq!(service_fee, total - 500000000);
    // merchant_net must be >= the requested subtotal
    let outs = body["requiredOutputs"].as_array().unwrap();
    let net: i64 = outs
        .iter()
        .find(|o| o["role"] == "merchant_net")
        .unwrap()["amountSompi"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(net >= 500000000, "merchant nets at least the subtotal");
}

#[tokio::test]
async fn create_duplicate_external_id_422() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "cinv6@example.com", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "cinv6@example.com").await;
    let store = common::seed_default_store(&app.db, uid).await;
    common::seed_setup(&app.db, uid, store, "kaspatest:merchantpayout00001").await;

    let payload = json!({
        "externalId": "ext-123",
        "items": [{ "name": "Widget", "quantity": 1, "unitAmount": "500000000" }]
    });

    let first = app
        .client
        .post(app.url("/api/invoices"))
        .bearer_auth(&token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);

    let second = app
        .client
        .post(app.url("/api/invoices"))
        .bearer_auth(&token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 422);
    assert_eq!(
        second.json::<Value>().await.unwrap()["message"],
        "External id has already been used"
    );
}

// Round-trip: created invoice is retrievable via show with the same intent.
#[tokio::test]
async fn create_then_show_roundtrip() {
    let app = common::spawn_app().await;
    let token = common::register_merchant(&app, "cinv7@example.com", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "cinv7@example.com").await;
    let store = common::seed_default_store(&app.db, uid).await;
    common::seed_setup(&app.db, uid, store, "kaspatest:merchantpayout00001").await;

    let created: Value = app
        .client
        .post(app.url("/api/invoices"))
        .bearer_auth(&token)
        .json(&json!({ "items": [{ "name": "Widget", "quantity": 1, "unitAmount": "500000000" }] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_i64().unwrap();
    let hash = created["kpr1PaymentIntent"]["canonicalHash"].as_str().unwrap().to_string();

    let shown: Value = app
        .client
        .get(app.url(&format!("/api/invoices/{id}")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(shown["kpr1PaymentIntent"]["canonicalHash"], hash);
}

// A caller asking for a far-future expiry gets clamped: an intent commits to a
// fixed payout set, so it is never payable for more than 15 minutes.
#[tokio::test]
async fn intent_expiry_is_clamped_to_15_minutes() {
    let app = common::spawn_app().await;
    let token = common::merchant_with_setup(&app, "cinvexp@example.com").await;

    let far_future = (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339();
    let body: Value = app
        .client
        .post(app.url("/api/invoices"))
        .bearer_auth(&token)
        .json(&json!({
            "items": [{ "name": "Widget", "quantity": 1, "unitAmount": "500000000" }],
            "expiresAt": far_future,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let expires_at = body["kpr1PaymentIntent"]["expiresAt"].as_str().expect("intent expiresAt");
    let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at).expect("rfc3339 expiresAt");
    let minutes_out = (expires_at.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_minutes();
    assert!(
        (13..=15).contains(&minutes_out),
        "expiry should be clamped to ~15 minutes, got {minutes_out}m ({expires_at})"
    );
}

async fn create_with_expires_at(app: &common::TestApp, token: &str, expires_at: &str) -> reqwest::Response {
    app.client
        .post(app.url("/api/invoices"))
        .bearer_auth(token)
        .json(&json!({
            "items": [{ "name": "Widget", "quantity": 1, "unitAmount": "500000000" }],
            "expiresAt": expires_at,
        }))
        .send()
        .await
        .unwrap()
}

fn seconds_from_now(value: &Value) -> i64 {
    let at = chrono::DateTime::parse_from_rfc3339(value.as_str().expect("expiresAt")).expect("rfc3339 expiresAt");
    (at.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_seconds()
}

// A SHORTER `expiresAt` is honored: the 15-minute window is a cap, not the only
// contract. Both the invoice and its signed intent carry the requested deadline.
#[tokio::test]
async fn shorter_expires_at_is_honored() {
    let app = common::spawn_app().await;
    let token = common::merchant_with_setup(&app, "cinvexp2@example.com").await;

    let requested = (chrono::Utc::now() + chrono::Duration::seconds(300)).to_rfc3339();
    let res = create_with_expires_at(&app, &token, &requested).await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    for expires_at in [&body["expiresAt"], &body["kpr1PaymentIntent"]["expiresAt"]] {
        let secs = seconds_from_now(expires_at);
        assert!((295..=305).contains(&secs), "expected ~300 s, got {secs} s ({expires_at})");
    }
}

// A LONGER `expiresAt` (1 h) is clamped to the 15-minute cap.
#[tokio::test]
async fn longer_expires_at_is_clamped_to_the_window() {
    let app = common::spawn_app().await;
    let token = common::merchant_with_setup(&app, "cinvexp3@example.com").await;

    let requested = (chrono::Utc::now() + chrono::Duration::seconds(3600)).to_rfc3339();
    let body: Value = create_with_expires_at(&app, &token, &requested).await.json().await.unwrap();
    for expires_at in [&body["expiresAt"], &body["kpr1PaymentIntent"]["expiresAt"]] {
        let secs = seconds_from_now(expires_at);
        assert!((890..=900).contains(&secs), "expected ~900 s, got {secs} s ({expires_at})");
    }
}

// A past `expiresAt` is a request for an unpayable invoice: reject it.
#[tokio::test]
async fn past_expires_at_is_rejected() {
    let app = common::spawn_app().await;
    let token = common::merchant_with_setup(&app, "cinvexp4@example.com").await;

    let past = (chrono::Utc::now() - chrono::Duration::seconds(60)).to_rfc3339();
    let res = create_with_expires_at(&app, &token, &past).await;
    assert_eq!(res.status(), 422);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "expiresAt must be at least 60 seconds in the future");

    // Under the 60-second floor is just as unpayable.
    let too_soon = (chrono::Utc::now() + chrono::Duration::seconds(10)).to_rfc3339();
    let res = create_with_expires_at(&app, &token, &too_soon).await;
    assert_eq!(res.status(), 422);
    assert_eq!(res.json::<Value>().await.unwrap()["message"], "expiresAt must be at least 60 seconds in the future");
}
