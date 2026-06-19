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
        .json(&json!({ "items": [{ "name": "Widget", "quantity": 1, "unitAmount": "1000" }] }))
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
                { "name": "Widget", "quantity": 2, "unitAmount": "500" },
                { "name": "Gizmo", "quantity": 1, "unitAmount": "1000" }
            ]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["status"], "open");
    assert!(body["publicId"].as_str().unwrap().starts_with("inv_"));
    // subtotal = 2*500 + 1000 = 2000; merchant_subsidized => total == subtotal
    assert_eq!(body["subtotalAmount"], "2000");
    assert_eq!(body["totalAmount"], "2000");
    assert_eq!(body["serviceFeeAmount"], "0");
    assert_eq!(body["feeDelegation"], "merchant_subsidized");
    assert_eq!(body["items"].as_array().unwrap().len(), 2);

    // KPR-1 intent present + contract hoisting
    assert_eq!(body["paymentRail"], "kpr1_covenant");
    assert!(body.get("paymentAddress").is_none());
    let intent = &body["kpr1PaymentIntent"];
    assert!(intent["intentId"].as_str().unwrap().starts_with("kpr1_"));
    assert_eq!(intent["amountSompi"], "2000");
    // platform fee = 1% of 2000 = 20
    assert_eq!(body["platformFee"]["bps"], 100);
    assert_eq!(body["platformFee"]["amountSompi"], "20");
    // requiredOutputs: merchant_net (1980) + kasway_fee (20)
    let outs = body["requiredOutputs"].as_array().unwrap();
    assert_eq!(outs.len(), 2);
    let net = outs.iter().find(|o| o["role"] == "merchant_net").unwrap();
    assert_eq!(net["amountSompi"], "1980");
    let fee = outs.iter().find(|o| o["role"] == "kasway_fee").unwrap();
    assert_eq!(fee["amountSompi"], "20");
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
            "items": [{ "name": "Widget", "quantity": 1, "unitAmount": "10000" }]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["subtotalAmount"], "10000");
    // total grossed up so that total - 1% fee >= 10000 => total = 10102 (fee 101), net 10001? check >= subtotal
    let total: i64 = body["totalAmount"].as_str().unwrap().parse().unwrap();
    assert!(total > 10000, "total grossed up above subtotal");
    let service_fee: i64 = body["serviceFeeAmount"].as_str().unwrap().parse().unwrap();
    assert_eq!(service_fee, total - 10000);
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
    assert!(net >= 10000, "merchant nets at least the subtotal");
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
        "items": [{ "name": "Widget", "quantity": 1, "unitAmount": "1000" }]
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
        .json(&json!({ "items": [{ "name": "Widget", "quantity": 1, "unitAmount": "1000" }] }))
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
