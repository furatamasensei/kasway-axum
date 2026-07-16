//! `/api/checkout/subscriptions/*` — public Subscription Pocket autopay surface
//! (no auth; the subscription publicId is the capability, plus a schnorr
//! signature by the customer's refund key for the destructive actions once the
//! cell has been funded).
//!
//! Flow: `prepare` derives the SubscriptionV1 covenant cell for the plan's payout
//! split and returns the address to fund; `autopay` records the funding txid the
//! wallet broadcast (only declared txids are ever recognized as cell funds — see
//! `subscription_keeper`); the keeper then claims one period per billing cycle.
//! `withdraw` lets the customer exit any time (it does NOT cancel the
//! subscription — the next cycle simply goes past due); `cancel` stops billing.

use crate::covenant_keeper::{decode_sig65, keeper_key, pick_fee_utxo};
use crate::error::{AppError, AppResult};
use crate::handlers::checkout::body_str;
use crate::handlers::subscriptions::cancel_subscription;
use crate::kaspa_wrpc::KaspaWrpcClient;
use crate::kpr1::compute_split_plan;
use crate::state::AppState;
use crate::store_context::resolve_request_store;
use crate::subscription_keeper::{cell_params, load_cell, CellRow};
use crate::util::{decode_hex, decode_hex32, encode_hex, now_iso};
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use kasway_covenant::subscription_v1::{compile_subscription_v1, complete_withdraw, prepare_withdraw, SubscriptionV1Params};
use kasway_covenant::{covenant_address, network_prefix, rpc_submit_params, verify_schnorr_digest, Destination, Payout, Utxo};
use serde_json::{json, Value};
use sha2::Digest;

fn serr(msg: impl AsRef<str>) -> AppError {
    AppError::unprocessable(msg.as_ref())
}

/// One DAA score ≈ one block ≈ 0.1s on Kaspa: 864_000 per day.
const DAA_PER_DAY: u64 = 864_000;

#[derive(sqlx::FromRow)]
struct PublicSub {
    id: i64,
    user_id: i64,
    public_id: String,
    status: String,
    payment_mode: String,
    plan_snapshot: String,
    next_billing_at: Option<String>,
    current_period_start: Option<String>,
    current_period_end: Option<String>,
}

async fn load_public_sub(state: &AppState, public_id: &str) -> AppResult<PublicSub> {
    sqlx::query_as::<_, PublicSub>(
        "SELECT id, user_id, public_id, status, payment_mode, plan_snapshot, next_billing_at, \
         current_period_start, current_period_end FROM subscriptions WHERE public_id = $1",
    )
    .bind(public_id)
    .fetch_optional(&state.db.pool)
    .await?
    .ok_or_else(|| AppError::commerce(404, "Subscription not found"))
}

fn snapshot(sub: &PublicSub) -> Value {
    serde_json::from_str(&sub.plan_snapshot).unwrap_or_else(|_| json!({}))
}

/// The challenge the customer's refund key signs to authorize cancelling a
/// funded autopay subscription: `sha256("kasway.subscription.cancel.v1:<publicId>")`.
fn cancel_challenge(public_id: &str) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(b"kasway.subscription.cancel.v1:");
    h.update(public_id.as_bytes());
    h.finalize().into()
}

fn recorded_txids(cell: &CellRow) -> Vec<String> {
    serde_json::from_str(&cell.recorded_funding_txids).unwrap_or_default()
}

fn cell_json(cell: &CellRow) -> Value {
    let cycles_remaining = match cell.active_amount {
        Some(a) if cell.claim_total > 0 => Some(a / cell.claim_total),
        _ => None,
    };
    json!({
        "state": cell.state,
        "covenantAddress": cell.covenant_address,
        "claimTotal": cell.claim_total.to_string(),
        "activeAmount": cell.active_amount.map(|a| a.to_string()),
        "cyclesRemaining": cycles_remaining,
        "recordedFundingTxIds": recorded_txids(cell),
        "refundAddress": cell.refund_address,
        "lastClaimTxId": cell.last_claim_tx_id,
        "lastClaimAt": cell.last_claim_at,
    })
}

/// `GET /api/checkout/subscriptions/:publicId` — public status: plan snapshot,
/// billing position, and the autopay cell (if prepared).
pub async fn show(State(state): State<AppState>, Path(public_id): Path<String>) -> AppResult<Json<Value>> {
    let sub = load_public_sub(&state, &public_id).await?;
    let snap = snapshot(&sub);
    let cell = load_cell(&state, sub.id).await?;
    Ok(Json(json!({
        "publicId": sub.public_id,
        "status": sub.status,
        "paymentMode": sub.payment_mode,
        "nextBillingAt": sub.next_billing_at,
        "currentPeriodStart": sub.current_period_start,
        "currentPeriodEnd": sub.current_period_end,
        "plan": {
            "name": snap["name"],
            "amount": snap["amount"],
            "currency": snap["currency"],
            "paymentNetwork": snap["paymentNetwork"],
            "paymentAsset": snap["paymentAsset"],
            "intervalUnit": snap["intervalUnit"],
            "intervalCount": snap["intervalCount"],
        },
        "cell": cell.as_ref().map(cell_json),
        "cancelChallengeHex": encode_hex(&cancel_challenge(&sub.public_id)),
    })))
}

/// `POST /api/checkout/subscriptions/:publicId/autopay/prepare`
/// Body: `{ refundAddress }`. Derives (and upserts) the subscription's covenant
/// cell; the wallet then funds `covenantAddress` and reports the txid.
pub async fn autopay_prepare(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let Some(refund_address) = body_str(&body, "refundAddress") else {
        return Err(serr("A refundAddress (the customer's schnorr P2PK address) is required"));
    };
    let customer = Destination::parse(refund_address)
        .map_err(|e| serr(format!("refundAddress is not a supported Kaspa address: {e}")))?;

    let sub = load_public_sub(&state, &public_id).await?;
    if sub.status == "cancelled" {
        return Err(serr("Subscription is cancelled"));
    }
    let cell = load_cell(&state, sub.id).await?;
    if let Some(cell) = &cell {
        // A funded cell is a live covenant; re-deriving would strand its value.
        if !recorded_txids(cell).is_empty() && !matches!(cell.state.as_str(), "withdrawn" | "cancelled") {
            return Err(serr("Autopay cell already exists; withdraw it before re-preparing"));
        }
    }

    let Some(keeper) = keeper_key(&state) else {
        return Err(serr("Subscription autopay is not available (keeper is not configured)"));
    };

    let snap = snapshot(&sub);
    let amount: i64 = snap["amount"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .filter(|a| *a > 0)
        .ok_or_else(|| serr("Subscription plan snapshot has no valid amount"))?;
    let network = snap["paymentNetwork"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| state.config.kpr1.default_network.clone());
    let prefix = network_prefix(&network).map_err(|e| serr(e.to_string()))?;

    // The exact per-claim payout split the KPR-1 intent minter would pin for an
    // invoice of this amount (merchant_net, [tax], splits…, kasway_fee).
    let store_id = resolve_request_store(&state, sub.user_id, None).await?;
    let split = compute_split_plan(&state, sub.user_id, Some(store_id), amount as i128).await?;
    let outputs = split.outputs_json();
    let mut payouts = Vec::with_capacity(outputs.len());
    for out in &outputs {
        let role = out["role"].as_str().unwrap_or_default();
        let addr = out["address"].as_str().unwrap_or_default();
        let destination = Destination::parse(addr)
            .map_err(|e| serr(format!("{role} payout address is not covenant-compatible: {e}")))?;
        let value: u64 = out["amountSompi"].as_str().and_then(|s| s.parse().ok()).ok_or_else(|| serr("bad payout amount"))?;
        payouts.push(Payout { destination, value });
    }

    // ponytail: interval → days uses coarse 30/365-day months and years; the CSV
    // claim lock is set to 90% of the interval precisely so this calendar drift
    // can never delay a due claim. Tighten to real calendar math if periods ever
    // need to be exact on-chain.
    let unit = snap["intervalUnit"].as_str().unwrap_or("month");
    let count = snap["intervalCount"].as_i64().unwrap_or(1).max(1) as u64;
    let days = match unit {
        "day" => count,
        "week" => count * 7,
        "year" => count * 365,
        _ => count * 30,
    };
    let period_daa = (days * DAA_PER_DAY * 9 / 10).clamp(1, u32::MAX as u64);

    let params = SubscriptionV1Params {
        payouts,
        keeper_pubkey: keeper.x_only_pubkey(),
        customer,
        period_daa,
        sweep_threshold: 0, // set below from claim_total
    };
    let claim_total = params.claim_total().map_err(|e| serr(e.to_string()))?;
    // Sweep leftovers below 10% of one claim: too small to ever fund a period.
    let sweep_threshold = (claim_total / 10).max(1);
    let params = SubscriptionV1Params { sweep_threshold, ..params };

    let compiled = compile_subscription_v1(&params).map_err(|e| serr(e.to_string()))?;
    let address = covenant_address(&compiled, prefix).map_err(|e| serr(e.to_string()))?.to_string();
    let redeem_hex = encode_hex(&compiled.script);

    let params_json = json!({
        "network": network,
        "payouts": outputs,
        "periodDaa": period_daa,
        "sweepThreshold": sweep_threshold,
        "keeperPubkey": encode_hex(&params.keeper_pubkey),
        "customer": refund_address,
    });
    let now = now_iso();
    sqlx::query(
        "INSERT INTO subscription_cells (subscription_id, user_id, network, covenant_address, params_json, \
             claim_total, refund_address, state, recorded_funding_txids, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'awaiting_funding', '[]', $8, $8) \
         ON CONFLICT (subscription_id) DO UPDATE SET network = $3, covenant_address = $4, params_json = $5, \
             claim_total = $6, refund_address = $7, state = 'awaiting_funding', recorded_funding_txids = '[]', \
             active_outpoint_txid = NULL, active_outpoint_index = NULL, active_amount = NULL, \
             last_claim_tx_id = NULL, last_claim_at = NULL, withdraw_destination = NULL, withdraw_sighash = NULL, \
             updated_at = $8",
    )
    .bind(sub.id)
    .bind(sub.user_id)
    .bind(&network)
    .bind(&address)
    .bind(params_json.to_string())
    .bind(claim_total as i64)
    .bind(refund_address)
    .bind(&now)
    .execute(&state.db.pool)
    .await?;

    let suggested: Vec<Value> = [3u64, 6, 12]
        .iter()
        .map(|periods| json!({ "periods": periods, "amountSompi": (claim_total * periods).to_string() }))
        .collect();
    Ok(Json(json!({
        "covenantAddress": address,
        "redeemScriptHex": redeem_hex,
        "claimTotal": claim_total.to_string(),
        "params": params_json,
        "suggestedFunding": suggested,
        "note": "fund covenantAddress with a multiple of claimTotal, then POST the funding txId to /autopay; only declared txids are recognized as cell funds",
    })))
}

/// `POST /api/checkout/subscriptions/:publicId/autopay`
/// Body: `{ txId }`. Records a funding (or top-up) txid — callable repeatedly —
/// and switches the subscription to `wallet_autopay`. The keeper verifies the
/// funds on-chain before activating the cell.
pub async fn autopay_record(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let tx_id = body_str(&body, "txId")
        .filter(|t| decode_hex32(t).is_some())
        .map(str::to_lowercase)
        .ok_or_else(|| serr("txId must be a 64-char hex transaction id"))?;

    let sub = load_public_sub(&state, &public_id).await?;
    if sub.status == "cancelled" {
        return Err(serr("Subscription is cancelled"));
    }
    let cell = load_cell(&state, sub.id)
        .await?
        .ok_or_else(|| serr("Prepare the autopay covenant first (POST /autopay/prepare)"))?;
    if cell.state == "cancelled" {
        return Err(serr("Autopay cell is cancelled"));
    }

    let mut txids = recorded_txids(&cell);
    if !txids.iter().any(|t| t.eq_ignore_ascii_case(&tx_id)) {
        if txids.len() >= 50 {
            return Err(serr("Too many recorded funding txids for this cell"));
        }
        txids.push(tx_id);
    }
    // A withdrawn cell can be re-funded at the same covenant address.
    let new_state = if cell.state == "withdrawn" { "awaiting_funding" } else { cell.state.as_str() };
    let now = now_iso();
    sqlx::query("UPDATE subscription_cells SET recorded_funding_txids = $1, state = $2, updated_at = $3 WHERE id = $4")
        .bind(serde_json::to_string(&txids).unwrap_or_else(|_| "[]".into()))
        .bind(new_state)
        .bind(&now)
        .bind(cell.id)
        .execute(&state.db.pool)
        .await?;
    sqlx::query("UPDATE subscriptions SET payment_mode = 'wallet_autopay', updated_at = $1 WHERE id = $2")
        .bind(&now)
        .bind(sub.id)
        .execute(&state.db.pool)
        .await?;

    Ok(Json(json!({ "recorded": true, "txIds": txids, "cellState": new_state, "paymentMode": "wallet_autopay" })))
}

/// `POST /api/checkout/subscriptions/:publicId/cancel`
/// Body: `{ signatureHex? }`. Once the cell has been funded, cancelling requires
/// the customer's refund key to schnorr-sign the cancel challenge (see
/// `cancelChallengeHex` in the GET response); an unfunded subscription cancels
/// on the publicId capability alone.
pub async fn cancel(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Response> {
    let sub = load_public_sub(&state, &public_id).await?;
    if sub.status == "cancelled" {
        return Ok(Json(json!({ "cancelled": true, "status": "cancelled" })).into_response());
    }
    let cell = load_cell(&state, sub.id).await?;
    let funded = cell.as_ref().is_some_and(|c| !recorded_txids(c).is_empty());
    if funded {
        let cell = cell.as_ref().unwrap();
        let challenge = cancel_challenge(&sub.public_id);
        let Some(sig) = body_str(&body, "signatureHex").and_then(decode_hex).filter(|s| s.len() == 64 || s.len() == 65) else {
            return Ok((
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "message": "A schnorr signature by the refund key over the cancel challenge is required",
                    "challengeHex": encode_hex(&challenge),
                })),
            )
                .into_response());
        };
        let pubkey: [u8; 32] = Destination::parse(&cell.refund_address)
            .ok()
            .and_then(|d| d.address().payload.as_slice().try_into().ok())
            .ok_or_else(|| serr("Cell refund address is invalid"))?;
        if !verify_schnorr_digest(&pubkey, &challenge, &sig[..64]) {
            return Err(serr("Cancel signature does not verify against the refund key"));
        }
    }
    cancel_subscription(&state, sub.user_id, &public_id).await?;
    Ok(Json(json!({ "cancelled": true, "status": "cancelled" })).into_response())
}

/// Load the withdraw context shared by prepare and submit.
async fn withdrawable_cell(state: &AppState, public_id: &str) -> AppResult<(PublicSub, CellRow)> {
    let sub = load_public_sub(state, public_id).await?;
    let cell = load_cell(state, sub.id)
        .await?
        .ok_or_else(|| serr("Subscription has no autopay cell"))?;
    if cell.state == "claiming" {
        return Err(serr("A claim is in flight; retry shortly"));
    }
    if cell.active_outpoint_txid.is_none() || cell.active_amount.unwrap_or(0) <= 0 {
        return Err(serr("Autopay cell has no recognized funds to withdraw"));
    }
    Ok((sub, cell))
}

/// Rebuild the (deterministic) withdraw draft for a cell.
async fn build_withdraw_draft(
    state: &AppState,
    cell: &CellRow,
    destination: &str,
) -> AppResult<(kasway_covenant::CompiledContract<'static>, kasway_covenant::subscription_v1::SubscriptionDraft)> {
    let dest = Destination::parse(destination)
        .map_err(|e| serr(format!("destinationAddress is not a supported Kaspa address: {e}")))?;
    let (params, prefix) = cell_params(&cell.params_json)?;
    let compiled = compile_subscription_v1(&params).map_err(|e| serr(e.to_string()))?;
    let derived = covenant_address(&compiled, prefix).map_err(|e| serr(e.to_string()))?.to_string();
    if derived != cell.covenant_address {
        return Err(serr("covenant address mismatch"));
    }
    let keeper = keeper_key(state).ok_or_else(|| serr("covenant keeper fee key is not configured"))?;
    let client = KaspaWrpcClient::from_env().ok_or_else(|| serr("Kaspa node is not configured"))?;
    let min_fee = state.config.covenant.keeper_min_fee_sompi;
    let fee_utxos = client
        .fetch_utxos(&keeper.address(prefix).to_string())
        .await
        .map_err(|e| serr(e.to_string()))?;
    let fee_utxo = pick_fee_utxo(fee_utxos, min_fee)
        .map(|(t, i, v)| Utxo { transaction_id: t, index: i, value: v })
        .ok_or_else(|| serr("no keeper fee UTXO available for withdraw"))?;
    let amount = cell.active_amount.unwrap_or(0) as u64;
    let covenant_utxo = Utxo {
        transaction_id: cell.active_outpoint_txid.as_deref().and_then(decode_hex32).ok_or_else(|| serr("bad cell outpoint"))?,
        index: cell.active_outpoint_index.unwrap_or(0) as u32,
        value: amount,
    };
    // The full cell value goes to the destination; the keeper subsidizes the
    // miner fee from its own input (the covenant does not constrain this split —
    // the customer's SIG_HASH_ALL signature does).
    let draft = prepare_withdraw(&compiled, &[(dest, amount)], &covenant_utxo, &fee_utxo, min_fee, &keeper, prefix)
        .map_err(|e| serr(e.to_string()))?;
    Ok((compiled, draft))
}

/// `POST /api/checkout/subscriptions/:publicId/autopay/withdraw/prepare`
/// Body: `{ destinationAddress }`. Returns the covenant sighash the customer
/// signs with their refund key. Withdrawing does NOT cancel the subscription.
pub async fn withdraw_prepare(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let Some(destination) = body_str(&body, "destinationAddress") else {
        return Err(serr("A destinationAddress is required"));
    };
    let (_sub, cell) = withdrawable_cell(&state, &public_id).await?;
    let (_compiled, draft) = build_withdraw_draft(&state, &cell, destination).await?;
    let sighash_hex = encode_hex(&draft.covenant_sighash);
    sqlx::query("UPDATE subscription_cells SET withdraw_destination = $1, withdraw_sighash = $2, updated_at = $3 WHERE id = $4")
        .bind(destination)
        .bind(&sighash_hex)
        .bind(now_iso())
        .bind(cell.id)
        .execute(&state.db.pool)
        .await?;
    Ok(Json(json!({
        "sighashHex": sighash_hex,
        "destinationAddress": destination,
        "amountSompi": cell.active_amount.unwrap_or(0).to_string(),
        "sigHashType": "SIG_HASH_ALL",
        "algorithm": "schnorr",
        "note": "sign this 32-byte sighash with the customer refund key; submit the 65-byte signature (schnorr || sighash-type byte) as hex. Withdrawing does not cancel the subscription.",
    })))
}

/// `POST /api/checkout/subscriptions/:publicId/autopay/withdraw`
/// Body: `{ signatureHex }` (65-byte: schnorr || sighash-type). Rebuilds the
/// prepared draft, attaches the customer signature, broadcasts, and empties the
/// cell (`withdrawn`). The subscription itself stays active — the next cycle
/// will go past due unless the customer re-funds or cancels.
pub async fn withdraw_submit(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let sig = decode_sig65(body_str(&body, "signatureHex").unwrap_or_default())?;
    let (_sub, cell) = withdrawable_cell(&state, &public_id).await?;
    let destination = cell
        .withdraw_destination
        .clone()
        .ok_or_else(|| serr("No withdraw draft prepared; call /autopay/withdraw/prepare first"))?;
    let (compiled, draft) = build_withdraw_draft(&state, &cell, &destination).await?;
    if cell.withdraw_sighash.as_deref() != Some(encode_hex(&draft.covenant_sighash).as_str()) {
        return Err(serr("Withdraw draft is stale (chain state changed); prepare again"));
    }
    let spend = complete_withdraw(&compiled, draft, &sig).map_err(|e| serr(e.to_string()))?;
    let client = KaspaWrpcClient::from_env().ok_or_else(|| serr("Kaspa node is not configured"))?;
    let tx_id = client.submit_transaction(rpc_submit_params(&spend)).await.map_err(|e| serr(e.to_string()))?;

    sqlx::query(
        "UPDATE subscription_cells SET state = 'withdrawn', active_outpoint_txid = NULL, active_outpoint_index = NULL, \
         active_amount = NULL, withdraw_destination = NULL, withdraw_sighash = NULL, updated_at = $1 WHERE id = $2",
    )
    .bind(now_iso())
    .bind(cell.id)
    .execute(&state.db.pool)
    .await?;

    Ok(Json(json!({ "withdrawn": true, "txId": tx_id, "destinationAddress": destination })))
}
