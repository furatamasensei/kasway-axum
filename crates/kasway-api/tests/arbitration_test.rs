//! Evaluator protocol v1.1 contract: signed envelopes with nonce replay
//! protection, fee bounds, three-party engagements, case lifecycle, and the
//! SQL-side reputation/listing. Chain-dependent steps are seeded in the DB.

mod common;

use kasway_covenant::{KeeperKey, Prefix};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};

const PROFILE: &str = "kasway/evaluator-profile/v1";
const QUOTE: &str = "kasway/evaluator-quote/v1";
const ENGAGEMENT: &str = "kasway/evaluator-engagement/v1";
const CASE_OPEN: &str = "kasway/dispute-open/v1";
const MESSAGE: &str = "kasway/case-message/v1";
const COMMIT: &str = "kasway/evaluator-decision-commit/v1";
const REVEAL: &str = "kasway/evaluator-decision-reveal/v1";
const FEEDBACK: &str = "kasway/evaluator-feedback/v1";
/// Quote and engagement must carry the identical deadline string.
const DISPUTE_DEADLINE: &str = "2030-01-01T00:00:00+00:00";

fn key(byte: u8) -> KeeperKey {
    KeeperKey::from_secret_bytes(&[byte; 32]).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn pubkey(k: &KeeperKey) -> String {
    hex(&k.x_only_pubkey())
}

fn address(k: &KeeperKey) -> String {
    k.address(Prefix::Testnet).to_string()
}

/// Canonical JSON = `serde_json::to_string` (sorted keys, no whitespace).
fn canonical_hash(v: &Value) -> [u8; 32] {
    Sha256::digest(serde_json::to_string(v).unwrap().as_bytes()).into()
}

fn sign(k: &KeeperKey, v: &Value) -> String {
    hex(&k.sign_datasig(&canonical_hash(v)).unwrap())
}

fn future(secs: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(secs)).to_rfc3339()
}

fn nonce() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    hex(&Sha256::digest(format!("nonce-{}-{n}", std::process::id())))
}

fn envelope(domain: &str, action: &str, fields: Value) -> Value {
    let mut payload = json!({
        "domain": domain, "protocolVersion": "1", "network": "tn10",
        "action": action, "nonce": nonce(), "expiresAt": future(3600),
    });
    for (k, v) in fields.as_object().unwrap() {
        payload[k] = v.clone();
    }
    payload
}

fn signed_body(k: &KeeperKey, payload: Value) -> Value {
    let signature = sign(k, &payload);
    json!({ "payload": payload, "signature": signature })
}

fn profile_id(evaluator: &KeeperKey) -> String {
    format!("eval_{}", &hex(&Sha256::digest(pubkey(evaluator).as_bytes()))[..32])
}

async fn post(app: &common::TestApp, path: &str, body: &Value) -> (u16, Value) {
    let res = app.client.post(app.url(path)).json(body).send().await.unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

async fn get(app: &common::TestApp, path: &str) -> (u16, Value) {
    let res = app.client.get(app.url(path)).send().await.unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
}

struct Fixture {
    app: common::TestApp,
    customer: KeeperKey,
    seller: KeeperKey,
    evaluator: KeeperKey,
    invoice_id: String,
    profile_id: String,
}

/// Merchant whose payout address is the seller key, one open KPR-1 invoice,
/// and one published evaluator profile (fixed fee 1000, minimum 1000).
async fn fixture(email: &str) -> Fixture {
    let app = common::spawn_app().await;
    let (customer, seller, evaluator) = (key(3), key(4), key(5));
    let token = common::merchant_with_setup_at(&app, email, &address(&seller)).await;
    let res = app
        .client
        .post(app.url("/api/commerce/invoices"))
        .bearer_auth(&token)
        .json(&json!({ "items": [{ "name": "Widget", "quantity": 1, "unitAmount": "500000000" }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let invoice: Value = res.json().await.unwrap();
    let invoice_id = invoice["publicId"].as_str().unwrap().to_string();

    let profile_id = profile_id(&evaluator);
    let (status, body) = post(&app, "/api/arbitration/evaluators", &profile_body(&evaluator, &profile_id)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["profileId"], profile_id);
    Fixture { app, customer, seller, evaluator, invoice_id, profile_id }
}

fn profile_body(evaluator: &KeeperKey, profile_id: &str) -> Value {
    signed_body(evaluator, envelope(PROFILE, "publish_profile", json!({
        "profileId": profile_id, "identityKey": pubkey(evaluator), "messagingKey": pubkey(evaluator),
        "pseudonym": "Eval One", "categories": ["electronics"], "languages": ["en"],
        "policyHash": "11".repeat(32),
        "fee": { "kind": "fixed", "value": "1000", "minimumSompi": "1000", "maximumSompi": null },
        "responseSlaSeconds": 3600, "decisionSlaSeconds": 7200, "profileVersion": 1,
    })))
}

fn quote_fields(f: &Fixture, quote_id: &str, fee_sompi: &str) -> Value {
    json!({
        "quoteId": quote_id, "profileId": f.profile_id, "invoiceId": f.invoice_id,
        "customerKey": pubkey(&f.customer), "evaluatorKey": pubkey(&f.evaluator),
        "caseKeyCommitment": "22".repeat(32), "policyHash": "11".repeat(32), "evidenceFormatHash": "33".repeat(32),
        "feeSompi": fee_sompi, "feePayer": "customer", "allowedOutcomes": ["release", "refund"],
        "disputeDeadline": DISPUTE_DEADLINE, "decisionSlaSeconds": 7200,
        "rewardAddress": address(&f.evaluator), "quoteVersion": 1,
    })
}

async fn quote(f: &Fixture, quote_id: &str, fee_sompi: &str, expires_secs: i64) -> (u16, Value) {
    let mut payload = envelope(QUOTE, "issue_quote", quote_fields(f, quote_id, fee_sompi));
    payload["expiresAt"] = json!(future(expires_secs));
    post(&f.app, "/api/arbitration/quotes", &signed_body(&f.evaluator, payload)).await
}

fn engagement_terms(f: &Fixture, engagement_id: &str, quote_id: &str, case_id: Option<&str>) -> Value {
    let mut terms = envelope(ENGAGEMENT, "accept_engagement", json!({
        "engagementId": engagement_id, "engagementVersion": 1, "invoiceId": f.invoice_id,
        "quoteId": quote_id, "profileId": f.profile_id,
        "customerKey": pubkey(&f.customer), "sellerKey": pubkey(&f.seller), "evaluatorKey": pubkey(&f.evaluator),
        "messagingKeys": { "customer": pubkey(&f.customer), "seller": pubkey(&f.seller), "evaluator": pubkey(&f.evaluator) },
        "caseKeyCommitment": "22".repeat(32), "policyHash": "11".repeat(32), "evidenceFormatHash": "33".repeat(32),
        "rewardAddress": address(&f.evaluator), "disputeDeadline": DISPUTE_DEADLINE, "decisionSlaSeconds": 7200,
        "feeSompi": "1000", "feePayer": "customer", "allowedOutcomes": ["release", "refund"],
    }));
    if let Some(case_id) = case_id {
        terms["caseId"] = json!(case_id);
    }
    terms
}

/// Returns `(status, response, request body)`; BIP-340 signatures are
/// randomized, so callers compare against the submitted request.
async fn engagement(f: &Fixture, terms: &Value) -> (u16, Value, Value) {
    let body = json!({
        "terms": terms,
        "customerSignature": sign(&f.customer, terms),
        "sellerSignature": sign(&f.seller, terms),
        "evaluatorSignature": sign(&f.evaluator, terms),
    });
    let (status, response) = post(&f.app, "/api/arbitration/engagements", &body).await;
    (status, response, body)
}

#[tokio::test]
async fn profile_lists_with_reputation_and_rejects_replay() {
    let f = fixture("arb_profile@example.com").await;
    let (status, body) = get(&f.app, "/api/arbitration/evaluators").await;
    assert_eq!(status, 200);
    assert_eq!(body["data"][0]["profileId"], f.profile_id);
    assert_eq!(body["data"][0]["reputation"]["verifiedCases"], 0);
    assert_eq!(body["data"][0]["reputation"]["outcomes"]["release"], 0);
    assert_eq!(body["meta"]["offset"], 0);

    // Same signed payload again: the nonce is spent.
    let replay = profile_body(&f.evaluator, &f.profile_id);
    let (status, _) = post(&f.app, "/api/arbitration/evaluators", &replay).await;
    assert_eq!(status, 200, "fresh nonce publishes again");
    let (status, body) = post(&f.app, "/api/arbitration/evaluators", &replay).await;
    assert_eq!(status, 409);
    assert_eq!(body["code"], "ARBITRATION_NONCE_REPLAY");

    let (status, _) = get(&f.app, "/api/arbitration/evaluators?sort=bogus").await;
    assert_eq!(status, 422);
}

#[tokio::test]
async fn quote_enforces_fee_bounds_and_expiry() {
    let f = fixture("arb_quote@example.com").await;
    let (status, body) = quote(&f, "q_low", "500", 3600).await;
    assert_eq!(status, 422, "{body}");
    assert!(body["message"].as_str().unwrap().contains("fee bounds"));

    let (status, body) = quote(&f, "q_ok", "1000", 3600).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "open");

    // A quote that expires before the engagement lands is refused.
    let (status, body) = quote(&f, "q_short", "1000", 1).await;
    assert_eq!(status, 200, "{body}");
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let terms = engagement_terms(&f, "eng_short", "q_short", Some("case_short"));
    let (status, body, _) = engagement(&f, &terms).await;
    assert_eq!(status, 422, "{body}");
    assert!(body["message"].as_str().unwrap().contains("expired"), "{body}");
}

#[tokio::test]
async fn engagement_requires_case_id() {
    let f = fixture("arb_caseid@example.com").await;
    let (status, _) = quote(&f, "q1", "1000", 3600).await;
    assert_eq!(status, 200);
    let terms = engagement_terms(&f, "eng_1", "q1", None);
    let (status, body, _) = engagement(&f, &terms).await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["message"], "caseId is required");
}

#[tokio::test]
async fn engagement_case_messages_decision_feedback_and_reputation() {
    let f = fixture("arb_flow@example.com").await;
    let (status, _) = quote(&f, "q1", "1000", 3600).await;
    assert_eq!(status, 200);

    // --- engagement: three signatures over the same terms ---
    let terms = engagement_terms(&f, "eng_1", "q1", Some("case_1"));
    let (status, body, request) = engagement(&f, &terms).await;
    assert_eq!(status, 200, "{body}");
    let engagement_hash = hex(&canonical_hash(&terms));
    assert_eq!(body["engagementHash"], engagement_hash);

    let (status, shown) = get(&f.app, "/api/arbitration/engagements/eng_1").await;
    assert_eq!(status, 200);
    assert_eq!(shown["engagementHash"], engagement_hash);
    assert_eq!(shown["status"], "accepted");
    assert_eq!(shown["terms"], terms);
    for field in ["customerSignature", "sellerSignature", "evaluatorSignature"] {
        assert_eq!(shown[field], request[field], "{field}");
        assert_eq!(shown[field].as_str().unwrap().len(), 128);
    }
    let (status, _) = get(&f.app, "/api/arbitration/engagements/eng_missing").await;
    assert_eq!(status, 404);

    // --- pretend the escrow was funded and the dispute transition broadcast ---
    sqlx::query("UPDATE evaluator_engagements SET status='funded' WHERE engagement_id='eng_1'")
        .execute(&f.app.db.pool).await.unwrap();
    sqlx::query("UPDATE kpr1_payment_intents SET covenant_state='dispute_submitted', dispute_covenant_address='kaspatest:disputecov' WHERE engagement_id='eng_1'")
        .execute(&f.app.db.pool).await.unwrap();

    let open_fields = |case_id: &str| json!({
        "engagementId": "eng_1", "invoiceId": f.invoice_id, "caseId": case_id,
        "openerRole": "customer", "openerKey": pubkey(&f.customer),
        "openingReasonHash": "44".repeat(32), "disputeTxId": "55".repeat(32),
        "disputeCovenantAddress": "kaspatest:disputecov",
    });
    let wrong = signed_body(&f.customer, envelope(CASE_OPEN, "open_case", open_fields("case_other")));
    let (status, body) = post(&f.app, "/api/arbitration/cases", &wrong).await;
    assert_eq!(status, 422, "{body}");
    assert_eq!(body["message"], "caseId does not match the signed engagement");
    let right = signed_body(&f.customer, envelope(CASE_OPEN, "open_case", open_fields("case_1")));
    let (status, body) = post(&f.app, "/api/arbitration/cases", &right).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["state"], "open");

    // --- messages: envelope hash is the anchor commitment ---
    let message = |seq: i64, action: &str, previous: Option<&str>, role: &str, signer: &KeeperKey, created_at: &str| {
        let mut fields = json!({
            "messageId": format!("msg_{seq}"), "caseId": "case_1", "participantRole": role,
            "senderKey": pubkey(signer), "sequence": seq, "payloadHash": "66".repeat(32),
            "ciphertext": "deadbeef", "createdAt": created_at,
        });
        if let Some(previous) = previous {
            fields["previousMessageHash"] = json!(previous);
        }
        let payload = envelope(MESSAGE, action, fields);
        let commitment = hex(&canonical_hash(&payload));
        let mut body = signed_body(signer, payload);
        body["anchor"] = json!({ "chainTxId": "77".repeat(32), "commitment": commitment });
        body
    };
    let now = || chrono::Utc::now().to_rfc3339();
    let (status, body) = post(&f.app, "/api/arbitration/cases/case_1/messages", &message(0, "statement", None, "customer", &f.customer, &now())).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["anchorStatus"], "submitted");
    let (status, _) = post(&f.app, "/api/arbitration/cases/case_1/messages", &message(1, "evidence", Some(&"00".repeat(32)), "customer", &f.customer, &now())).await;
    assert_eq!(status, 409);
    let head = body["envelopeHash"].as_str().unwrap().to_string();
    let (status, body) = post(&f.app, "/api/arbitration/cases/case_1/messages", &message(1, "bogus", Some(&head), "customer", &f.customer, &now())).await;
    assert_eq!(status, 422, "{body}");
    // Evaluator reply with a forged, far-past `createdAt` at a +20:00 offset:
    // chrono parses it, Postgres cannot cast it. Response time is measured from
    // server receipt, so the listing and reputation stay alive and non-negative.
    let forged = "2020-01-01T00:00:00+20:00";
    let (status, body) = post(&f.app, "/api/arbitration/cases/case_1/messages", &message(1, "statement", Some(&head), "evaluator", &f.evaluator, forged)).await;
    assert_eq!(status, 200, "{body}");
    let (status, _) = get(&f.app, "/api/arbitration/evaluators").await;
    assert_eq!(status, 200);
    let (status, _) = get(&f.app, &format!("/api/arbitration/evaluators/{}/reputation", f.profile_id)).await;
    assert_eq!(status, 200);

    // --- commit / reveal ---
    let salt = "88".repeat(32);
    let reason = "99".repeat(32);
    let preimage = json!({
        "domain": "kasway/evaluator-decision/v1", "protocolVersion": "1", "network": "tn10",
        "engagementHash": engagement_hash, "caseId": "case_1", "outcome": "release",
        "reasonHash": reason, "salt": salt,
    });
    let commitment = hex(&canonical_hash(&preimage));
    let commit = signed_body(&f.evaluator, envelope(COMMIT, "commit_decision", json!({
        "caseId": "case_1", "evaluatorKey": pubkey(&f.evaluator),
        "decisionCommitment": commitment, "chainTxId": "aa".repeat(32),
    })));
    let (status, body) = post(&f.app, "/api/arbitration/cases/case_1/decision/commit", &commit).await;
    assert_eq!(status, 200, "{body}");
    let reveal = |salt: &str| signed_body(&f.evaluator, envelope(REVEAL, "reveal_decision", json!({
        "caseId": "case_1", "evaluatorKey": pubkey(&f.evaluator), "outcome": "release",
        "reasonHash": reason, "salt": salt, "chainTxId": "bb".repeat(32),
    })));
    let (status, body) = post(&f.app, "/api/arbitration/cases/case_1/decision/reveal", &reveal(&"cc".repeat(32))).await;
    assert_eq!(status, 422, "{body}");
    let (status, body) = post(&f.app, "/api/arbitration/cases/case_1/decision/reveal", &reveal(&salt)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["state"], "revealed");

    // --- settled on chain (seeded), then feedback + reputation ---
    let settled_at = chrono::Utc::now().to_rfc3339();
    sqlx::query("UPDATE dispute_cases SET state='settled', settled_at=$1, decision_outcome='release' WHERE case_id='case_1'")
        .bind(&settled_at).execute(&f.app.db.pool).await.unwrap();
    let feedback = |id: &str| signed_body(&f.customer, envelope(FEEDBACK, "submit_feedback", json!({
        "feedbackId": id, "caseId": "case_1", "authorRole": "customer",
        "authorKey": pubkey(&f.customer), "score": 5, "tags": ["fast"],
    })));
    let (status, body) = post(&f.app, "/api/arbitration/cases/case_1/feedback", &feedback("fb_1")).await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = post(&f.app, "/api/arbitration/cases/case_1/feedback", &feedback("fb_2")).await;
    assert_eq!(status, 409, "{body}");

    let (status, rep) = get(&f.app, &format!("/api/arbitration/evaluators/{}/reputation", f.profile_id)).await;
    assert_eq!(status, 200);
    assert_eq!(rep["verifiedCases"], 1);
    assert_eq!(rep["ratings"], 1);
    assert_eq!(rep["customerAverage"], 5.0);
    assert!(rep["sellerAverage"].is_null());
    assert_eq!(rep["outcomes"]["release"], 1);
    assert_eq!(rep["outcomes"]["refund"], 0);
    assert!(rep["medianResolutionSeconds"].is_number(), "{rep}");
    assert!(
        rep["medianResponseSeconds"].as_f64().is_some_and(|s| s >= 0.0),
        "response time from server receipt, not the forged createdAt: {rep}"
    );
    assert_eq!(rep["slaCompletionRate"], 1.0);

    let (status, list) = get(&f.app, "/api/arbitration/evaluators?sort=rating&order=desc").await;
    assert_eq!(status, 200);
    assert_eq!(list["data"][0]["profileId"], f.profile_id);
    assert_eq!(list["data"][0]["reputation"]["verifiedCases"], 1);
    let (status, list) = get(&f.app, "/api/arbitration/evaluators?maxFeeSompi=1").await;
    assert_eq!(status, 200);
    assert_eq!(list["meta"]["count"], 0);

    // --- mutual settlement: precondition failure needs no chain ---
    let body = json!({
        "split": [{ "address": address(&f.seller), "amountSompi": "500001000" }],
        "feePayerAddress": address(&f.seller),
    });
    let (status, body) = post(&f.app, "/api/arbitration/cases/case_1/mutual-settlement/prepare", &body).await;
    assert!((400..500).contains(&status), "{status} {body}");
}
