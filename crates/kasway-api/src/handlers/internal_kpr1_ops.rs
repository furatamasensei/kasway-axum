//! `/internal/payment-ops/kpr1/*` — arbiter dispute resolution (internal-token tier).

use crate::auth::InternalToken;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::util::decode_hex;
use axum::extract::{Path, State};
use axum::Json;
use serde_json::Value;

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
