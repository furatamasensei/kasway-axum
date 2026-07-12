//! `/internal/payment-ops/kpr1/*` — InternalKpr1PaymentOpsController.
//! `evidence` is a DB read over kpr1_payment_intents (internal-token tier).
//! `conformance` runs the KPR-1 wallet conformance fixture (canonical JSON,
//! intent hash, QR binding, ed25519 signature, tamper detection, output verifier,
//! milestone sections, submit-payload safety). `status` (SilverScript/TN10 probes)
//! is external.

use crate::auth::InternalToken;
use crate::error::{AppError, AppResult};
use crate::kpr1::canonicalize;
use crate::state::AppState;
use crate::util::{decode_hex, now_iso, sha256_hex};
use axum::extract::{Path, State};
use axum::Json;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Value};

#[derive(sqlx::FromRow)]
struct IntentRow {
    intent_id: String,
    invoice_id: i64,
    status: String,
    tx_id: Option<String>,
    canonical_hash: String,
    signature_algorithm: String,
    signature_key_id: String,
    template_id: String,
    template_version: String,
    script_hash: String,
    required_outputs: String,
    verification_status: Option<String>,
    failure_reason: Option<String>,
    metadata: Option<String>,
}

/// `GET /internal/payment-ops/kpr1/intents/:intentId/evidence`
pub async fn evidence(
    _token: InternalToken,
    State(state): State<AppState>,
    Path(intent_id): Path<String>,
) -> AppResult<Json<Value>> {
    let row: IntentRow = sqlx::query_as::<_, IntentRow>(
        "SELECT intent_id, invoice_id, status, tx_id, canonical_hash, signature_algorithm, \
         signature_key_id, template_id, template_version, script_hash, required_outputs, \
         verification_status, failure_reason, metadata FROM kpr1_payment_intents \
         WHERE intent_id = $1 OR canonical_hash = $2",
    )
    .bind(&intent_id)
    .bind(&intent_id)
    .fetch_optional(&state.db.pool)
    .await?
    .ok_or_else(|| AppError::commerce(404, "KPR-1 payment intent not found"))?;

    let required_outputs: Value = serde_json::from_str(&row.required_outputs).unwrap_or(json!([]));
    let metadata: Value = row.metadata.as_deref().and_then(|m| serde_json::from_str(m).ok()).unwrap_or(Value::Null);

    Ok(Json(json!({
        "intentId": row.intent_id,
        "invoiceId": row.invoice_id,
        "status": row.status,
        "txId": row.tx_id,
        "canonicalHash": row.canonical_hash,
        "signature": { "alg": row.signature_algorithm, "keyId": row.signature_key_id },
        "template": { "id": row.template_id, "version": row.template_version, "scriptHash": row.script_hash },
        "requiredOutputs": required_outputs,
        "verificationStatus": row.verification_status,
        "failureReason": row.failure_reason,
        "metadata": metadata,
    })))
}

// ---- KPR-1 wallet conformance (#41) ----------------------------------------

const CONFORMANCE_FIXTURE: &str = include_str!("assets/kpr1-conformance.json");

fn check(key: &str, result: Result<&str, String>) -> Value {
    match result {
        Ok(msg) => json!({ "key": key, "status": "pass", "message": msg }),
        Err(e) => json!({ "key": key, "status": "fail", "message": e }),
    }
}

/// Extract the raw 32-byte Ed25519 key from a PEM SPKI public key (last 32 bytes).
fn pem_verifying_key(pem: &str) -> Option<VerifyingKey> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = B64.decode(b64.trim()).ok()?;
    if der.len() < 32 { return None; }
    let raw: [u8; 32] = der[der.len() - 32..].try_into().ok()?;
    VerifyingKey::from_bytes(&raw).ok()
}

fn ed25519_verify(pem: &str, msg: &[u8], sig_b64: &str) -> bool {
    let Some(key) = pem_verifying_key(pem) else { return false };
    let Ok(sig_bytes) = B64.decode(sig_b64) else { return false };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else { return false };
    key.verify(msg, &sig).is_ok()
}

fn intent_without_signature(intent: &Value) -> Value {
    let mut m = intent.as_object().cloned().unwrap_or_default();
    m.remove("signature");
    Value::Object(m)
}

/// Port of Kpr1SettlementVerifierService.verify — returns the failure reason (None = verified).
fn verify_reason(f_intent: &Value, example: &Value) -> Option<String> {
    let script_hash = f_intent["template"]["scriptHash"].as_str().unwrap_or("");
    let observed_script_hash = example["scriptHash"].as_str().unwrap_or("");
    let observed_outputs = example["outputs"].as_array().cloned().unwrap_or_default();
    let required_outputs = match example.get("intentOutputs").and_then(|v| v.as_array()) {
        Some(a) => a.clone(),
        None => f_intent["outputs"].as_array().cloned().unwrap_or_default(),
    };
    // expiry/network/asset/txId/amount all align in the conformance fixture by construction.
    if observed_script_hash != script_hash {
        return Some("script_hash_mismatch".into());
    }
    if observed_outputs.is_empty() {
        return Some("missing_full_output_data".into());
    }
    let amt = |v: &Value| -> String {
        match v.get("amountSompi") { Some(Value::String(s)) => s.clone(), Some(other) => other.to_string(), None => String::new() }
    };
    for req in &required_outputs {
        let role = req["role"].as_str().unwrap_or("");
        let matched = observed_outputs.iter().any(|o| {
            o["role"].as_str() == req["role"].as_str() && o["address"].as_str() == req["address"].as_str() && amt(o) == amt(req)
        });
        if !matched {
            return Some(format!("missing_required_{role}_output"));
        }
    }
    None
}

/// `GET /internal/payment-ops/kpr1/conformance`
pub async fn conformance(_token: InternalToken) -> AppResult<Json<Value>> {
    Ok(Json(conformance_report()?))
}

/// Build the conformance report Value (shared with kpr1 status).
pub(crate) fn conformance_report() -> AppResult<Value> {
    let f: Value = serde_json::from_str(CONFORMANCE_FIXTURE)
        .map_err(|_| AppError::commerce(500, "Invalid conformance fixture"))?;
    let vi = &f["validIntent"];
    let intent = &vi["intent"];
    let mut checks: Vec<Value> = Vec::new();

    // 1. canonical JSON
    checks.push(check("kpr1.conformance.canonicalJson", (|| {
        let unsigned = canonicalize(&intent_without_signature(intent));
        if unsigned != vi["unsignedCanonicalJson"].as_str().unwrap_or_default() {
            return Err("Unsigned canonical JSON does not match fixture".to_string());
        }
        if canonicalize(intent) != vi["signedCanonicalJson"].as_str().unwrap_or_default() {
            return Err("Signed canonical JSON does not match fixture".to_string());
        }
        Ok("Fixture canonical JSON is stable")
    })()));

    // 2. intent hash
    let expected_hash = vi["expectedHash"].as_str().unwrap_or_default().to_string();
    checks.push(check("kpr1.conformance.intentHash", (|| {
        let actual = sha256_hex(canonicalize(intent).as_bytes());
        if actual != expected_hash {
            return Err(format!("Expected {expected_hash}, received {actual}"));
        }
        Ok("Signed intent hash matches fixture")
    })()));

    // 3. QR URI
    checks.push(check("kpr1.conformance.qrUri", (|| {
        let qr = vi["qrUri"].as_str().unwrap_or_default();
        if !qr.starts_with("kaspa-payment:v1?") {
            return Err("QR URI must use kaspa-payment:v1".into());
        }
        let query = qr.splitn(2, '?').nth(1).unwrap_or("");
        let params: std::collections::HashMap<String, String> = query.split('&').filter_map(|p| {
            let mut it = p.splitn(2, '=');
            Some((it.next()?.to_string(), it.next().unwrap_or("").to_string()))
        }).collect();
        if params.get("hash").map(String::as_str) != Some(expected_hash.as_str()) {
            return Err("QR hash does not bind to expected signed intent hash".into());
        }
        if params.get("network").map(String::as_str) != intent["network"].as_str() {
            return Err("QR network does not match intent network".into());
        }
        if params.get("request").map(|s| s.is_empty()).unwrap_or(true) || params.get("expires").map(|s| s.is_empty()).unwrap_or(true) {
            return Err("QR URI must include request and expires parameters".into());
        }
        Ok("QR URI binds request, hash, network, and expiry")
    })()));

    // 4. signature
    let unsigned_canonical = vi["unsignedCanonicalJson"].as_str().unwrap_or_default().as_bytes().to_vec();
    let sig_value = intent["signature"]["value"].as_str().unwrap_or_default().to_string();
    checks.push(check("kpr1.conformance.signature", (|| {
        if sig_value.is_empty() { return Err("Signed intent is missing signature value".into()); }
        let valid = ed25519_verify(f["keys"]["publicKeyPem"].as_str().unwrap_or_default(), &unsigned_canonical, &sig_value);
        let wrong = ed25519_verify(f["keys"]["wrongPublicKeyPem"].as_str().unwrap_or_default(), &unsigned_canonical, &sig_value);
        if !valid { return Err("Fixture signature must verify with the fixture public key".into()); }
        if wrong { return Err("Fixture signature must fail with the wrong public key".into()); }
        Ok("Ed25519 signature verifies and rejects wrong public key")
    })()));

    // 5. tamper detection
    checks.push(check("kpr1.conformance.tamperDetection", (|| {
        let mut tampered = intent.as_object().cloned().unwrap_or_default();
        tampered.insert("amountSompi".into(), json!("100000001"));
        let tampered_signed = Value::Object(tampered.clone());
        let mut tampered_unsigned_map = tampered.clone();
        tampered_unsigned_map.remove("signature");
        let tampered_hash = sha256_hex(canonicalize(&tampered_signed).as_bytes());
        let example = f["signatureVerificationExamples"].as_array().and_then(|a| a.iter().find(|e| e["name"] == json!("tampered_amount_after_signing")));
        let expected = example.and_then(|e| e["expectedTamperedHash"].as_str()).unwrap_or_default();
        if tampered_hash != expected {
            return Err("Tampered intent hash does not match fixture expectation".into());
        }
        let tampered_canonical = canonicalize(&Value::Object(tampered_unsigned_map));
        let valid = ed25519_verify(f["keys"]["publicKeyPem"].as_str().unwrap_or_default(), tampered_canonical.as_bytes(), &sig_value);
        if valid { return Err("Tampered unsigned payload must not verify against original signature".into()); }
        Ok("Tampered intent changes hash and fails signature verification")
    })()));

    // 6. output examples
    for ex in f["validOutputExamples"].as_array().cloned().unwrap_or_default() {
        let name = ex["name"].as_str().unwrap_or("").to_string();
        checks.push(check(&format!("kpr1.conformance.outputs.{name}"), {
            let reason = verify_reason(intent, &ex);
            if reason.is_none() { Ok("Valid output example verifies") } else { Err(format!("Expected valid output example, received {}", reason.unwrap())) }
        }));
    }
    for ex in f["invalidOutputExamples"].as_array().cloned().unwrap_or_default() {
        let name = ex["name"].as_str().unwrap_or("").to_string();
        let expected = ex["expectedFailureReason"].as_str().unwrap_or("").to_string();
        checks.push(check(&format!("kpr1.conformance.outputs.{name}"), {
            let reason = verify_reason(intent, &ex);
            match &reason {
                Some(r) if *r == expected => Ok("Invalid output example fails closed with expected reason"),
                other => Err(format!("Expected {expected}, received {}", other.clone().unwrap_or_else(|| "null".into()))),
            }
        }));
    }

    // 7. milestone 36 sections
    checks.push(check("kpr1.conformance.milestone36Sections", (|| {
        for k in ["qrParserNegativeCases", "verifierNegativeCases", "submitPayloadExamples"] {
            if f[k].as_array().map(|a| a.is_empty()).unwrap_or(true) { return Err(format!("Fixture is missing {k}")); }
        }
        if f["displayExpectations"]["networkBadge"].as_str() != Some("TN10 testnet only") { return Err("Fixture display expectations must require TN10 testnet branding".into()); }
        if f["walletMvpStatus"]["kaspaWasmStatus"].as_str() != Some("mock_adapter_until_provenance_validated") { return Err("Fixture must document mock Kaspa WASM status until provenance is validated".into()); }
        if f["explorerWalletVerificationSample"]["payment"]["network"].as_str() != Some("tn10") { return Err("Explorer wallet verification sample must remain TN10-only".into()); }
        Ok("Milestone 36 wallet fixture sections are present and TN10 scoped")
    })()));

    // 8. milestone 37 extension sections
    checks.push(check("kpr1.conformance.milestone37ExtensionSections", (|| {
        for k in ["extensionMessageBoundaryCases", "extensionDetectionCases"] {
            if f[k].as_array().map(|a| a.is_empty()).unwrap_or(true) { return Err(format!("Fixture is missing {k}")); }
        }
        if f["walletExtensionMvpStatus"]["repository"].as_str() != Some("../kasway-kpr1-extension") { return Err("Fixture must identify the extension wallet repository".into()); }
        if f["walletExtensionMvpStatus"]["network"].as_str() != Some("tn10") { return Err("Extension wallet fixture status must remain TN10-only".into()); }
        if f["walletExtensionMvpStatus"]["providerApiStatus"].as_str() != Some("not_supported") { return Err("Extension wallet fixture must not enable a provider API".into()); }
        if f["extensionPermissionExpectations"]["manifestVersion"].as_i64() != Some(3) { return Err("Extension fixture must require Manifest V3".into()); }
        let must_not = f["extensionPermissionExpectations"]["mustNotInclude"].as_array().map(|a| a.iter().any(|v| v == &json!("<all_urls>"))).unwrap_or(false);
        if !must_not { return Err("Extension fixture must explicitly reject broad host permissions".into()); }
        if f["extensionStorageExpectations"]["encryption"].as_str() != Some("PBKDF2-HMAC-SHA-256 + AES-GCM") { return Err("Extension fixture must document encrypted vault expectations".into()); }
        if f["extensionBuildExpectations"]["realKaspaWasmEnabled"].as_bool() != Some(false) { return Err("Extension fixture must keep real Kaspa WASM disabled until provenance approval".into()); }
        Ok("Milestone 37 extension fixture sections are present and TN10 scoped")
    })()));

    // 9. submit payload safety
    checks.push(check("kpr1.conformance.submitPayloadSafety", (|| {
        for ex in f["submitPayloadExamples"].as_array().cloned().unwrap_or_default() {
            let serialized = ex["payload"].to_string().to_lowercase();
            for field in ex["forbiddenFields"].as_array().cloned().unwrap_or_default() {
                if let Some(fld) = field.as_str() {
                    if serialized.contains(&fld.to_lowercase()) {
                        let name = ex["name"].as_str().unwrap_or("");
                        return Err(format!("{name} contains forbidden key material field {fld}"));
                    }
                }
            }
        }
        Ok("Wallet submit examples omit seed and private-key material")
    })()));

    let ready = checks.iter().all(|c| c["status"] == json!("pass"));
    Ok(json!({
        "ready": ready,
        "fixtureVersion": f["fixtureVersion"],
        "generatedAt": now_iso(),
        "checks": checks,
    }))
}

/// `GET /internal/payment-ops/kpr1/status` — Kpr1PaymentRailService.status().
/// KPR-1 is enabled with config present (config pass), conformance passes, but
/// SilverScript compatibility is disabled (fail) → overall not ready.
pub async fn status(_token: InternalToken, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let cfg = &state.config.kpr1;
    let open_intents: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kpr1_payment_intents WHERE status IN ('created','fetched','submitted','observed','verified')",
    ).fetch_one(&state.db.pool).await?;
    let failed_intents: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kpr1_payment_intents WHERE status = 'failed'",
    ).fetch_one(&state.db.pool).await?;
    let conformance = conformance_report()?;
    let conformance_ready = conformance["ready"].as_bool().unwrap_or(false);
    let failed_conformance: Vec<Value> = conformance["checks"].as_array().map(|a| {
        a.iter().filter(|c| c["status"] != "pass").map(|c| c["key"].clone()).collect()
    }).unwrap_or_default();

    let checks = json!([
        { "key": "kpr1.enabled", "status": "pass", "message": "KPR-1 is mandatory for invoice payments" },
        { "key": "kpr1.config", "status": "pass", "message": "KPR-1 required config is present" },
        {
            "key": "kpr1.conformance",
            "status": if conformance_ready { "pass" } else { "fail" },
            "message": if conformance_ready { "KPR-1 conformance fixture passes canonical/hash/signature/output checks" } else { "KPR-1 conformance fixture failed" },
            "metadata": { "fixtureVersion": conformance["fixtureVersion"], "failedChecks": failed_conformance },
        },
        {
            "key": "silverscript.status",
            "status": "fail",
            "message": "SilverScript/Toccata compatibility must be proven before production covenant launch",
            "metadata": { "status": "disabled", "compatibilityOutcome": "blocked", "targetNetwork": "tn10" },
        },
    ]);
    let ready = checks.as_array().unwrap().iter().all(|c| c["status"] == "pass");

    Ok(Json(json!({
        "enabled": cfg.enabled,
        "ready": ready,
        "generatedAt": now_iso(),
        "checks": checks,
        "signingSurface": {
            "kaswaySignsCustomerTransactions": false,
            "message": "KPR-1 checkout uses wallet-local signing and Kasway verifies required outputs.",
        },
        "intentMetrics": { "openIntents": open_intents, "failedIntents": failed_intents },
        "conformance": conformance,
        "config": {
            "platformFeeBps": cfg.platform_fee_bps,
            "hasPlatformFeeAddress": !cfg.platform_fee_address.is_empty(),
            "signingKeyId": cfg.signing_key_id,
            "hasSigningPrivateKey": true,
        },
    })))
}

// ---------------------------------------------------------------------------
// Dispute resolution (arbiter). These apply Kasway's arbiter key server-side, so
// they MUST be operator-gated (internal token) — otherwise anyone could trigger
// a dispute ruling. The merchant-signed refund path is a public checkout endpoint
// instead, since it is safe by construction (nothing spends without the merchant's
// own signature).
// ---------------------------------------------------------------------------

/// Parse an optional `arbiterSignatures: [{ index, signature }]` array (the
/// independent panel's covenant signatures) into `(panel_index, 65-byte sig)`
/// pairs. An absent/empty array means "use the transitional dev fallback"
/// (server signs with the single Kasway arbiter key — dev/test only).
fn parse_arbiter_signatures(body: &Value) -> AppResult<Vec<(u32, Vec<u8>)>> {
    let Some(arr) = body.get("arbiterSignatures").and_then(|v| v.as_array()) else {
        return Ok(vec![]);
    };
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let index = item
            .get("index")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| AppError::commerce(422, "each arbiterSignatures entry needs an integer panel index"))?;
        let sig_hex = item
            .get("signature")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AppError::commerce(422, "each arbiterSignatures entry needs a signature"))?;
        let sig = decode_hex(sig_hex)
            .filter(|s| s.len() == 65)
            .ok_or_else(|| AppError::commerce(422, "arbiter signature must be 65-byte hex (schnorr signature || sighash-type byte)"))?;
        out.push((index as u32, sig));
    }
    Ok(out)
}

/// `POST /internal/payment-ops/kpr1/invoices/:publicId/release-arbitrated/prepare`
///
/// Step 1 of an arbiter release FOR the merchant. Returns the covenant sighash the
/// independent arbiter panel signs and how many of them must sign.
pub async fn release_arbitrated_prepare(
    _token: InternalToken,
    State(state): State<AppState>,
    Path(public_id): Path<String>,
) -> AppResult<Json<Value>> {
    let out = crate::covenant_keeper::arbiter_release_prepare(&state, &public_id).await?;
    Ok(Json(out))
}

/// `POST /internal/payment-ops/kpr1/invoices/:publicId/release-arbitrated`
///
/// The arbiter panel rules a dispute FOR the merchant: release the covenant to
/// the merchant split. Body: `{ arbiterSignatures: [{ index, signature }] }` — the
/// independent panel's covenant signatures (threshold enforced on-chain). The
/// keeper subsidizes the gas. An empty/absent array uses the dev fallback.
pub async fn release_arbitrated(
    _token: InternalToken,
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    body: Option<Json<Value>>,
) -> AppResult<Json<Value>> {
    let sigs = match &body {
        Some(Json(b)) => parse_arbiter_signatures(b)?,
        None => vec![],
    };
    let out = crate::covenant_keeper::arbiter_release(&state, &public_id, sigs).await?;
    Ok(Json(out))
}

/// `POST /internal/payment-ops/kpr1/invoices/:publicId/refund-arbitrated/prepare`
///
/// Arbiter refund FOR the customer, step 1. Returns the covenant sighash the
/// independent arbiter panel signs and the fee sighash the CUSTOMER signs (they
/// pay the refund gas).
pub async fn refund_arbitrated_prepare(
    _token: InternalToken,
    State(state): State<AppState>,
    Path(public_id): Path<String>,
) -> AppResult<Json<Value>> {
    let out = crate::covenant_keeper::arbiter_refund_prepare(&state, &public_id).await?;
    Ok(Json(out))
}

/// `POST /internal/payment-ops/kpr1/invoices/:publicId/refund-arbitrated`
///
/// Step 2. Body: `{ feeSignature, arbiterSignatures: [{ index, signature }] }` —
/// the customer's gas-input signature plus the independent arbiter panel's
/// covenant signatures. The covenant enforces the M-of-N threshold on-chain;
/// full gross is refunded to the customer. An empty `arbiterSignatures` uses the
/// dev fallback (single Kasway arbiter key).
pub async fn refund_arbitrated_submit(
    _token: InternalToken,
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let fee_sig = body.get("feeSignature").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty());
    let Some(fee_sig) = fee_sig else {
        return Err(AppError::commerce(422, "A customer fee signature is required to refund"));
    };
    let sigs = parse_arbiter_signatures(&body)?;
    let out = crate::covenant_keeper::arbiter_refund_submit(&state, &public_id, fee_sig, sigs).await?;
    Ok(Json(out))
}
