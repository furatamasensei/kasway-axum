//! HTTP surface for the Tier-3 community-jury dispute flow.
//!
//! Public (checkout): open a dispute with evidence. Internal (operator token):
//! draw the committee, collect committee votes, and settle on-chain once a
//! verdict reaches K-of-N. The orchestration logic lives in [`crate::dispute`].

use crate::auth::InternalToken;
use crate::dispute;
use crate::error::{AppError, AppResult};
use crate::kaspa_wrpc::KaspaWrpcClient;
use crate::kpr1::parse_required_outputs;
use crate::state::AppState;
use crate::util::{decode_hex, decode_hex32, encode_hex, now_iso};
use axum::extract::{Path, State};
use axum::Json;
use kasway_covenant::{covenant_address, network_prefix, Destination, KeeperKey, Payout};
use serde_json::{json, Value};

fn derr(msg: impl AsRef<str>) -> AppError {
    AppError::commerce(422, msg.as_ref())
}

/// The funded intent backing a dispute (subset needed to rebuild the covenant).
#[derive(sqlx::FromRow)]
struct DisputeIntent {
    intent_pk: i64,
    network: String,
    required_outputs: String,
    customer_refund_address: Option<String>,
    gross_amount: Option<i64>,
}

async fn load_intent(state: &AppState, public_id: &str) -> AppResult<DisputeIntent> {
    sqlx::query_as::<_, DisputeIntent>(
        "SELECT i.id AS intent_pk, i.network, i.required_outputs, i.customer_refund_address, i.gross_amount \
         FROM kpr1_payment_intents i JOIN invoices inv ON inv.id = i.invoice_id WHERE inv.public_id = $1",
    )
    .bind(public_id)
    .fetch_optional(&state.db.pool)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| derr("KPR-1 intent not found"))
}

/// The active juror pool (pubkeys), ordered for a stable pool root.
async fn load_pool(state: &AppState) -> AppResult<Vec<[u8; 32]>> {
    let rows = sqlx::query_scalar::<_, String>(
        "SELECT juror_pubkey FROM kpr1_juror_pool WHERE active = TRUE ORDER BY juror_pubkey",
    )
    .fetch_all(&state.db.pool)
    .await
    .map_err(AppError::Database)?;
    Ok(rows.iter().filter_map(|h| decode_hex32(h)).collect())
}

/// `POST /api/checkout/invoices/:publicId/dispute/open`
/// Body: `{ customerEvidenceHash, merchantEvidenceHash, party, signature }`.
///
/// Opening a dispute FREEZES a funded escrow, so it is NOT a public endpoint: the
/// caller must prove they are a party to the escrow (customer or merchant). They
/// pick `party` (`"customer"`|`"merchant"`) and supply a 64-byte schnorr
/// `signature` (hex) by that party's key over the domain-separated request digest
/// `sha256("KASWAY/dispute/open" || public_id || customerEvidenceHash ||
/// merchantEvidenceHash)`. The party pubkeys are the intent's
/// `customer_refund_address` (customer) and its `merchant_net` payout (merchant).
pub async fn open_dispute(
    State(state): State<AppState>,
    Path(public_id): Path<String>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let ch = body.get("customerEvidenceHash").and_then(|v| v.as_str()).and_then(decode_hex32);
    let mh = body.get("merchantEvidenceHash").and_then(|v| v.as_str()).and_then(decode_hex32);
    let (Some(ch), Some(mh)) = (ch, mh) else {
        return Err(derr("customerEvidenceHash and merchantEvidenceHash (32-byte hex) are required"));
    };
    let party = body.get("party").and_then(|v| v.as_str()).unwrap_or_default();
    if party != "customer" && party != "merchant" {
        return Err(derr("party must be 'customer' or 'merchant'"));
    }
    let signature = body
        .get("signature")
        .and_then(|v| v.as_str())
        .and_then(decode_hex)
        .filter(|s| s.len() == 64)
        .ok_or_else(|| derr("signature must be a 64-byte hex Schnorr signature"))?;

    let intent = load_intent(&state, &public_id).await?;

    // The escrow is funded/finalized by this point, so both party pubkeys exist:
    // the customer (refund address) and the merchant (merchant_net payout).
    let refund_addr = intent
        .customer_refund_address
        .as_deref()
        .ok_or_else(|| derr("customer refund address missing (escrow not funded)"))?;
    let customer_pk = Destination::parse(refund_addr)
        .ok()
        .and_then(|d| pk32(&d))
        .ok_or_else(|| derr("customer refund address is not a schnorr P2PK address"))?;
    let outs = parse_required_outputs(&intent.required_outputs);
    let merchant_pk = outs
        .iter()
        .find(|o| o.role == "merchant_net")
        .and_then(|o| Destination::parse(&o.address).ok())
        .and_then(|d| pk32(&d))
        .ok_or_else(|| derr("merchant payout address missing or not a schnorr P2PK address"))?;

    // Domain-separated digest binding this request to the escrow + evidence set.
    let digest = dispute::sha256_bytes(&[b"KASWAY/dispute/open", public_id.as_bytes(), &ch, &mh]);
    let signer_pk = if party == "customer" { &customer_pk } else { &merchant_pk };
    if !kasway_covenant::verify_datasig(signer_pk, &digest, &signature) {
        return Err(AppError::commerce(403, "dispute open must be signed by the customer or merchant"));
    }

    let dispute_id = dispute::open_dispute(&state, intent.intent_pk, "jury", &ch, &mh).await?;
    Ok(Json(json!({ "disputeId": dispute_id, "state": "open", "evidenceRoot": encode_hex(&dispute::evidence_root(&ch, &mh)) })))
}

/// `POST /internal/payment-ops/kpr1/disputes/:disputeId/committee`
/// Draw the K-of-N committee from the bonded pool using a beacon seed, bake the
/// verdict digests, and store them. Body: `{ beaconSeed, juryThreshold }`.
pub async fn draw_committee(
    _token: InternalToken,
    State(state): State<AppState>,
    Path(dispute_id): Path<i64>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let (public_id, intent, disp_id_bytes, evidence_root, party_pks) = load_dispute_ctx(&state, dispute_id).await?;
    let seed = body
        .get("beaconSeed")
        .and_then(|v| v.as_str())
        .and_then(decode_hex32)
        .ok_or_else(|| derr("beaconSeed (32-byte hex) is required"))?;
    let k = body.get("juryThreshold").and_then(|v| v.as_u64()).unwrap_or(3) as u32;
    let n = body.get("committeeSize").and_then(|v| v.as_u64()).unwrap_or(5) as usize;

    let pool = load_pool(&state).await?;
    let committee = dispute::select_committee(&pool, &seed, &disp_id_bytes, &party_pks, n);
    if (committee.len() as u32) < k {
        return Err(derr("bonded juror pool too small to draw the committee"));
    }
    let params = build_params(&intent, committee.clone(), k, &disp_id_bytes, &evidence_root)?;
    let prefix = network_prefix(&intent.network).map_err(|e| derr(e.to_string()))?;
    let compiled = kasway_covenant::jury_escrow::compile_jury_escrow(&params).map_err(|e| derr(e.to_string()))?;
    let cov_addr = covenant_address(&compiled, prefix).map_err(|e| derr(e.to_string()))?.to_string();

    let committee_json = serde_json::to_string(&committee.iter().map(|p| encode_hex(p)).collect::<Vec<_>>()).unwrap_or_default();
    sqlx::query(
        "UPDATE kpr1_disputes SET state = 'jury_voting', committee_json = $1, jury_threshold = $2, \
         verdict_digest_merchant = $3, verdict_digest_customer = $4, updated_at = $5 WHERE id = $6",
    )
    .bind(&committee_json)
    .bind(k as i32)
    .bind(encode_hex(&params.verdict_digest_merchant))
    .bind(encode_hex(&params.verdict_digest_customer))
    .bind(now_iso())
    .bind(dispute_id)
    .execute(&state.db.pool)
    .await
    .map_err(AppError::Database)?;

    Ok(Json(json!({
        "disputeId": dispute_id,
        "publicId": public_id,
        "committee": committee.iter().map(|p| encode_hex(p)).collect::<Vec<_>>(),
        "juryThreshold": k,
        "juryCovenantAddress": cov_addr,
        "verdictDigestMerchant": encode_hex(&params.verdict_digest_merchant),
        "verdictDigestCustomer": encode_hex(&params.verdict_digest_customer),
    })))
}

/// `POST /internal/payment-ops/kpr1/disputes/:disputeId/votes`
/// Body: `{ jurorPubkey, committeeIndex, verdict: "merchant"|"customer", datasig }`.
pub async fn cast_vote(
    _token: InternalToken,
    State(state): State<AppState>,
    Path(dispute_id): Path<i64>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let pk = body.get("jurorPubkey").and_then(|v| v.as_str()).and_then(decode_hex32).ok_or_else(|| derr("jurorPubkey required"))?;
    let idx = body.get("committeeIndex").and_then(|v| v.as_u64()).ok_or_else(|| derr("committeeIndex required"))? as u32;
    let verdict = match body.get("verdict").and_then(|v| v.as_str()) {
        Some("merchant") => dispute::VERDICT_MERCHANT_BIT,
        Some("customer") => dispute::VERDICT_CUSTOMER_BIT,
        _ => return Err(derr("verdict must be 'merchant' or 'customer'")),
    };
    let datasig = body
        .get("datasig")
        .and_then(|v| v.as_str())
        .and_then(decode_hex)
        .filter(|s| s.len() == 64)
        .ok_or_else(|| derr("datasig must be a 64-byte hex Schnorr signature"))?;

    dispute::record_vote(&state, dispute_id, &pk, idx, verdict, &datasig).await?;
    let votes = dispute::load_votes(&state, dispute_id).await?;
    let k = jury_threshold(&state, dispute_id).await?;
    let reached = dispute::tally(&votes, k).map(|(v, _, _)| v);
    Ok(Json(json!({
        "recorded": true,
        "votes": votes.len(),
        "verdictReached": reached.map(|v| if v == dispute::VERDICT_MERCHANT_BIT { "merchant" } else { "customer" }),
    })))
}

/// `POST /internal/payment-ops/kpr1/disputes/:disputeId/settle-jury`
/// Once K committee votes agree, assemble and broadcast the on-chain settlement.
pub async fn settle_jury(
    _token: InternalToken,
    State(state): State<AppState>,
    Path(dispute_id): Path<i64>,
) -> AppResult<Json<Value>> {
    let (_public_id, intent, disp_id_bytes, evidence_root, _party) = load_dispute_ctx(&state, dispute_id).await?;
    let (committee, k) = load_committee(&state, dispute_id).await?;
    let params = build_params(&intent, committee, k, &disp_id_bytes, &evidence_root)?;

    let votes = dispute::load_votes(&state, dispute_id).await?;
    let (verdict_byte, signer_idx, datasigs) = dispute::tally(&votes, k).ok_or_else(|| derr("no K-of-N verdict yet"))?;

    // A customer verdict refunds the customer, who must pay their own gas — that
    // fee signature is client-side, so it is settled via a client-signed flow,
    // not this operator endpoint. A merchant verdict is keeper-subsidized here.
    if verdict_byte == dispute::VERDICT_CUSTOMER_BIT {
        return Err(derr("customer-verdict settlement requires a client-signed fee input (settle client-side)"));
    }

    let client = KaspaWrpcClient::from_env().ok_or_else(|| derr("Kaspa node is not configured"))?;
    let prefix = network_prefix(&intent.network).map_err(|e| derr(e.to_string()))?;
    let keeper = keeper_key(&state).ok_or_else(|| derr("covenant keeper fee key is not configured"))?;
    let min_fee = state.config.covenant.keeper_min_fee_sompi;

    // `customer` param is unused on the merchant path; pass the keeper as a placeholder.
    let txid = dispute::settle_jury_onchain(
        &client, &params, prefix, &keeper, &keeper, min_fee, verdict_byte, &signer_idx, &datasigs,
    )
    .await?;

    let now = now_iso();
    let resolution = if verdict_byte == dispute::VERDICT_MERCHANT_BIT { "merchant" } else { "customer" };
    sqlx::query(
        "UPDATE kpr1_disputes SET state = 'settled_jury', resolution = $1, resolved_at = $2, updated_at = $2 WHERE id = $3",
    )
    .bind(resolution)
    .bind(&now)
    .bind(dispute_id)
    .execute(&state.db.pool)
    .await
    .map_err(AppError::Database)?;
    sqlx::query("UPDATE kpr1_payment_intents SET covenant_state = 'settled_jury', updated_at = $1 WHERE id = $2")
        .bind(&now)
        .bind(intent.intent_pk)
        .execute(&state.db.pool)
        .await
        .map_err(AppError::Database)?;

    Ok(Json(json!({ "settled": true, "resolution": resolution, "settleTxId": txid })))
}

/// `GET /internal/payment-ops/kpr1/disputes/:disputeId`
pub async fn dispute_status(
    _token: InternalToken,
    State(state): State<AppState>,
    Path(dispute_id): Path<i64>,
) -> AppResult<Json<Value>> {
    let row = sqlx::query_as::<_, (String, Option<String>, Option<i32>, Option<String>)>(
        "SELECT state, resolution, jury_threshold, committee_json FROM kpr1_disputes WHERE id = $1",
    )
    .bind(dispute_id)
    .fetch_optional(&state.db.pool)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| derr("dispute not found"))?;
    let votes = dispute::load_votes(&state, dispute_id).await?;
    Ok(Json(json!({
        "disputeId": dispute_id,
        "state": row.0,
        "resolution": row.1,
        "juryThreshold": row.2,
        "committee": row.3.and_then(|j| serde_json::from_str::<Value>(&j).ok()),
        "votes": votes.len(),
    })))
}

// ---- shared reconstruction ----

async fn load_dispute_ctx(
    state: &AppState,
    dispute_id: i64,
) -> AppResult<(String, DisputeIntent, [u8; 32], [u8; 32], Vec<[u8; 32]>)> {
    let row = sqlx::query_as::<_, (i64, Option<String>, Option<String>)>(
        "SELECT intent_id, evidence_root, evidence_customer_hash FROM kpr1_disputes WHERE id = $1",
    )
    .bind(dispute_id)
    .fetch_optional(&state.db.pool)
    .await
    .map_err(AppError::Database)?
    .ok_or_else(|| derr("dispute not found"))?;
    let (intent_id, evidence_root_hex, _) = row;
    let evidence_root = evidence_root_hex.and_then(|h| decode_hex32(&h)).ok_or_else(|| derr("dispute evidence_root missing"))?;

    let public_id = sqlx::query_scalar::<_, String>(
        "SELECT inv.public_id FROM kpr1_payment_intents i JOIN invoices inv ON inv.id = i.invoice_id WHERE i.id = $1",
    )
    .bind(intent_id)
    .fetch_one(&state.db.pool)
    .await
    .map_err(AppError::Database)?;
    let intent = load_intent(state, &public_id).await?;

    // dispute_id bytes = sha256 of the numeric id (stable, opaque anchor).
    let disp_id_bytes = dispute::sha256_bytes(&[b"KASWAY/jury/dispute-id", &dispute_id.to_le_bytes()]);

    // Parties excluded from the committee (customer + merchant pubkeys).
    let outs = parse_required_outputs(&intent.required_outputs);
    let mut party = Vec::new();
    if let Some(addr) = &intent.customer_refund_address {
        if let Ok(d) = Destination::parse(addr) {
            if let Some(pk) = pk32(&d) {
                party.push(pk);
            }
        }
    }
    if let Some(m) = outs.iter().find(|o| o.role == "merchant_net") {
        if let Ok(d) = Destination::parse(&m.address) {
            if let Some(pk) = pk32(&d) {
                party.push(pk);
            }
        }
    }
    Ok((public_id, intent, disp_id_bytes, evidence_root, party))
}

fn build_params(
    intent: &DisputeIntent,
    committee: Vec<[u8; 32]>,
    k: u32,
    disp_id_bytes: &[u8; 32],
    evidence_root: &[u8; 32],
) -> AppResult<kasway_covenant::jury_escrow::JuryEscrowParams> {
    let gross = intent.gross_amount.ok_or_else(|| derr("intent gross missing"))? as u64;
    let refund_addr = intent.customer_refund_address.clone().ok_or_else(|| derr("customer refund address missing"))?;
    let customer_refund = Destination::parse(&refund_addr).map_err(|e| derr(e.to_string()))?;
    let outs = parse_required_outputs(&intent.required_outputs);
    let mut payouts = Vec::new();
    for out in &outs {
        let destination = Destination::parse(&out.address).map_err(|e| derr(e.to_string()))?;
        let value = u64::try_from(out.amount_sompi).map_err(|_| derr("bad payout"))?;
        payouts.push(Payout { destination, value });
    }
    Ok(dispute::jury_escrow_params(payouts, customer_refund, committee, k, disp_id_bytes, evidence_root, gross))
}

async fn load_committee(state: &AppState, dispute_id: i64) -> AppResult<(Vec<[u8; 32]>, u32)> {
    let (json, k) = sqlx::query_as::<_, (Option<String>, Option<i32>)>(
        "SELECT committee_json, jury_threshold FROM kpr1_disputes WHERE id = $1",
    )
    .bind(dispute_id)
    .fetch_one(&state.db.pool)
    .await
    .map_err(AppError::Database)?;
    let hexes: Vec<String> = json.and_then(|j| serde_json::from_str(&j).ok()).ok_or_else(|| derr("committee not drawn yet"))?;
    let committee: Vec<[u8; 32]> = hexes.iter().filter_map(|h| decode_hex32(h)).collect();
    Ok((committee, k.unwrap_or(3) as u32))
}

async fn jury_threshold(state: &AppState, dispute_id: i64) -> AppResult<u32> {
    let k = sqlx::query_scalar::<_, Option<i32>>("SELECT jury_threshold FROM kpr1_disputes WHERE id = $1")
        .bind(dispute_id)
        .fetch_one(&state.db.pool)
        .await
        .map_err(AppError::Database)?;
    Ok(k.unwrap_or(3) as u32)
}

fn pk32(d: &Destination) -> Option<[u8; 32]> {
    let b = d.address().payload.to_vec();
    b.try_into().ok()
}

fn keeper_key(state: &AppState) -> Option<KeeperKey> {
    let hex = state.config.covenant.keeper_fee_secret_hex.as_deref()?;
    let bytes = decode_hex32(hex.trim())?;
    KeeperKey::from_secret_bytes(&bytes).ok()
}
