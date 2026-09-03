//! `GET /api/kpr1/signing-keys` — the Ed25519 key(s) KPR-1 intents are signed
//! with, so a wallet or auditor can verify any intent offline instead of
//! trusting a Kasway "verified" flag. Public, unauthenticated.

use crate::kpr1::{signing_public_key_b64, signing_public_key_pem};
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

pub async fn index(State(state): State<AppState>) -> Json<Value> {
    let cfg = &state.config.kpr1;
    Json(json!({
        "keys": [{
            "keyId": cfg.signing_key_id,
            "alg": "ed25519",
            "publicKey": signing_public_key_b64(&cfg.signing_seed),
            "publicKeyPem": signing_public_key_pem(&cfg.signing_seed),
        }]
    }))
}
