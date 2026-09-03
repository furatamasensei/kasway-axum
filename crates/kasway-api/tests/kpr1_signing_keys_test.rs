//! `GET /api/kpr1/signing-keys`: the published Ed25519 intent signing key lets a
//! wallet or auditor verify any minted intent offline, with no Kasway flag.

mod common;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Value};

const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

#[tokio::test]
async fn published_key_verifies_a_freshly_minted_intent() {
    let app = common::spawn_app().await;

    let res = app.client.get(app.url("/api/kpr1/signing-keys")).send().await.unwrap();
    assert_eq!(res.status(), 200, "public, unauthenticated");
    let body: Value = res.json().await.unwrap();
    let keys = body["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    let key = &keys[0];
    assert_eq!(key["keyId"], app.state.config.kpr1.signing_key_id);
    assert_eq!(key["alg"], "ed25519");

    let raw = B64.decode(key["publicKey"].as_str().unwrap()).unwrap();
    assert_eq!(raw.len(), 32);
    let pem = key["publicKeyPem"].as_str().unwrap();
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"), "{pem}");
    assert!(pem.ends_with("\n-----END PUBLIC KEY-----"), "{pem}");
    let der = B64.decode(pem.lines().nth(1).unwrap()).unwrap();
    assert_eq!(&der[..12], &ED25519_SPKI_PREFIX);
    assert_eq!(&der[12..], &raw[..], "PEM wraps the same raw key");

    // Mint an intent and verify its signature with the published key, using the
    // same ed25519 crate the server signs with. The signature is over the
    // canonical (sorted-key, no-whitespace) JSON of the intent WITHOUT `signature`.
    let token = common::merchant_with_setup(&app, "keys@example.com").await;
    let invoice: Value = app
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
    let public_id = invoice["publicId"].as_str().expect("invoice minted");
    let mut intent: Value = app
        .client
        .get(app.url(&format!("/api/checkout/invoices/{public_id}/kpr1-intent")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let signature = intent.as_object_mut().unwrap().remove("signature").expect("signed intent");
    assert_eq!(signature["keyId"], key["keyId"]);
    assert_eq!(signature["alg"], "ed25519");
    let sig = Signature::from_slice(&B64.decode(signature["value"].as_str().unwrap()).unwrap()).unwrap();
    let verifying = VerifyingKey::from_bytes(&raw.clone().try_into().unwrap()).unwrap();

    let canonical = serde_json::to_string(&intent).unwrap(); // serde_json sorts keys = KPR-1 canonical JSON
    verifying
        .verify(canonical.as_bytes(), &sig)
        .expect("intent signature verifies against the published key");

    // Tampering with a signed term breaks it.
    intent["amountSompi"] = json!("1");
    assert!(verifying.verify(serde_json::to_string(&intent).unwrap().as_bytes(), &sig).is_err());
}
