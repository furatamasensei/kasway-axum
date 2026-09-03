mod common;

use serde_json::Value;

async fn seed(app: &common::TestApp) -> (i64, String) {
    common::register_merchant(app, "exp_kpr1@example.com", "secret123").await;
    let uid = common::merchant_user_id(&app.db, "exp_kpr1@example.com").await;
    let store = common::seed_default_store(&app.db, uid).await;
    let inv = common::seed_invoice(&app.db, uid, store, "inv_explorer", "open", 1000, 1000, 0, None, None, "2026-06-10T00:00:00.000+00:00").await;
    common::seed_kpr1_intent(&app.db, inv, uid, "intent_xyz").await;
    (inv, "intent_xyz".to_string())
}

#[tokio::test]
async fn show_intent_projects_payment_facts() {
    let app = common::spawn_app().await;
    let (_inv, intent_id) = seed(&app).await;

    let res: Value = app.client.get(app.url(&format!("/api/explorer/kpr1/intents/{intent_id}"))).send().await.unwrap().json().await.unwrap();
    assert_eq!(res["lookup"]["type"], "intent_id");
    assert_eq!(res["lookup"]["matched"], true);
    assert_eq!(res["payment"]["rail"], "kpr1_covenant");
    assert_eq!(res["payment"]["intentId"], intent_id);
    assert_eq!(res["payment"]["invoicePublicId"], "inv_explorer");
    assert_eq!(res["payment"]["canonicalHash"], "canon_intent_xyz");
    assert_eq!(res["payment"]["publicState"], "not_observed");
    assert_eq!(res["payment"]["amountSompi"], "1000");
    assert_eq!(res["signature"]["alg"], "ed25519");
    assert_eq!(res["signature"]["payloadHashRule"], "canonical_kpr1_intent_sha256");
    assert_eq!(res["signature"]["signaturePayloadRule"], "sign_canonical_unsigned_intent");
    assert_eq!(res["signature"]["canonicalization"], "json_sorted_keys_utf8");
    assert_eq!(res["outputs"].as_array().unwrap().len(), 2);
    assert_eq!(res["outputs"][0]["role"], "merchant_net");
    assert_eq!(res["outputs"][0]["matched"], false);
    assert_eq!(res["outputs"][0]["failureReason"], "missing_full_output_data");
    assert_eq!(res["observation"]["observed"], false);
    assert_eq!(res["settlement"]["settled"], false);
    assert!(res.get("wallet").is_none()); // no includeIntent
}

#[tokio::test]
async fn include_intent_and_wallet_verification_add_canonical() {
    let app = common::spawn_app().await;
    let (_inv, intent_id) = seed(&app).await;

    let inc: Value = app.client.get(app.url(&format!("/api/explorer/kpr1/intents/{intent_id}?includeIntent=true"))).send().await.unwrap().json().await.unwrap();
    assert!(inc["wallet"]["canonicalIntent"].is_object());

    let wv: Value = app.client.get(app.url(&format!("/api/explorer/kpr1/intents/{intent_id}/wallet-verification"))).send().await.unwrap().json().await.unwrap();
    assert!(wv.get("wallet").is_some());
    assert_eq!(wv["payment"]["intentId"], intent_id);
}

#[tokio::test]
async fn lookup_by_canonical_hash_and_invoice() {
    let app = common::spawn_app().await;
    let (_inv, _id) = seed(&app).await;

    let byhash: Value = app.client.get(app.url("/api/explorer/kpr1/payment-requests/canon_intent_xyz")).send().await.unwrap().json().await.unwrap();
    assert_eq!(byhash["lookup"]["type"], "canonical_hash");
    assert_eq!(byhash["payment"]["intentId"], "intent_xyz");

    let byinv: Value = app.client.get(app.url("/api/explorer/kpr1/invoices/inv_explorer")).send().await.unwrap().json().await.unwrap();
    assert_eq!(byinv["lookup"]["type"], "invoice_public_id");
    assert_eq!(byinv["payment"]["intentId"], "intent_xyz");
}

#[tokio::test]
async fn not_found_responses() {
    let app = common::spawn_app().await;
    let _ = seed(&app).await;

    let nf = app.client.get(app.url("/api/explorer/kpr1/intents/missing")).send().await.unwrap();
    assert_eq!(nf.status(), 404);
    let body: Value = nf.json().await.unwrap();
    assert_eq!(body["code"], "KPR1_EXPLORER_NOT_FOUND");
    assert_eq!(body["lookupType"], "intent_id");
    assert_eq!(body["message"], "No KPR-1 payment facts matched missing");

    // tx with no intent/observation -> 404
    let tx = app.client.get(app.url("/api/explorer/kpr1/transactions/0xdeadbeef")).send().await.unwrap();
    assert_eq!(tx.status(), 404);
    assert_eq!(tx.json::<Value>().await.unwrap()["lookupType"], "tx_id");

    let inv = app.client.get(app.url("/api/explorer/kpr1/invoices/inv_missing")).send().await.unwrap();
    assert_eq!(inv.status(), 404);
}
