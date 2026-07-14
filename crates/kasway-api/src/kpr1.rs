//! KPR-1 payment-intent minter — port of `kpr1_payment_intent_service.ts`.
//!
//! FAITHFUL: fee/tax/split math, output composition, canonical-intent JSON +
//! canonicalization (sorted keys via serde_json's BTreeMap, matching
//! `JSON.stringify(sortCanonicalValue(...))`), sha256 canonical hash, real
//! ed25519 signing, payment-request URI, all validation/error contracts
//! (every `Kpr1PaymentIntentError` surfaces as CommerceError 422).
//!
//! SETTLEMENT: covenant is the sole path (zero legacy). The minter records the
//! ordered payout split (merchant_net, tax, splits, kasway_fee) in
//! `required_outputs` and the gross/expiry the covenant will enforce. The
//! covenant P2SH address depends on the payer's refund address and is derived at
//! finalize (`kpr1_finalize`), so `script_hash`/`covenant_address` are filled in
//! then; at mint `covenant_state = 'pending'`.

use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::util::{decode_hex32, encode_hex, now_iso, sha256_hex, to_iso};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde_json::{json, Value};

const KPR1_VERSION: &str = "kpr-1";
const TEMPLATE_ID: &str = "split_settlement";
const TEMPLATE_VERSION: &str = "v1";
const SIGNATURE_ALGORITHM: &str = "ed25519";
pub(crate) const MAX_BPS: i128 = 10_000;
pub(crate) const MAX_SPLIT_ADDRESSES: usize = 5;

/// Invoice fields the minter needs.
pub struct IntentInvoiceCtx {
    pub invoice_id: i64,
    pub user_id: i64,
    pub store_id: Option<i64>,
    pub public_id: String,
    pub total_amount: i64,
    pub payment_network: String,
    pub payment_asset: String,
    pub expires_at: Option<String>,
}

fn err(msg: &str) -> AppError {
    // Every Kpr1PaymentIntentError becomes CommerceError(422, message).
    AppError::commerce(422, msg)
}

pub(crate) fn is_kaspa_address(value: &str) -> bool {
    let v = value.trim();
    let rest = if let Some(r) = v.strip_prefix("kaspatest:") {
        r
    } else if let Some(r) = v.strip_prefix("kaspa:") {
        r
    } else {
        return false;
    };
    rest.len() >= 12
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-'))
}

// --- fee math (bigint via i128) ---

fn bps_amount(gross: i128, bps: i64, msg: &str) -> AppResult<i128> {
    if bps < 0 || bps as i128 > MAX_BPS {
        return Err(err(msg));
    }
    Ok(gross * bps as i128 / MAX_BPS)
}

pub fn platform_fee_total(gross: i128, bps: i64, flat: i64) -> AppResult<i128> {
    if flat < 0 {
        return Err(err("KPR-1 platform flat fee must be a non-negative amount in sompi"));
    }
    Ok(bps_amount(gross, bps, "KPR-1 platform fee bps invalid")? + flat as i128)
}

/// percentage (e.g. 2.5) -> bps (250), at most 2 decimals.
pub(crate) fn percentage_to_bps(percentage: Option<&str>) -> AppResult<i64> {
    let Some(p) = percentage else { return Ok(0) };
    let p = p.trim();
    if p.is_empty() {
        return Ok(0);
    }
    let val: f64 = p
        .parse()
        .map_err(|_| err("KPR-1 percentage values must support at most two decimal places"))?;
    let bps = (val * 100.0).round();
    if !val.is_finite() || (bps / 100.0 - val).abs() > 0.0000001 {
        return Err(err("KPR-1 percentage values must support at most two decimal places"));
    }
    Ok(bps as i64)
}

/// customer_pays gross-up — port of calculateKpr1CustomerPaidAmounts.
/// Returns (service_fee, total, platform_fee).
pub fn customer_paid_amounts(
    requested: i128,
    bps: i64,
    flat: i64,
) -> AppResult<(i128, i128, i128)> {
    if flat < 0 {
        return Err(err("KPR-1 platform flat fee must be a non-negative amount in sompi"));
    }
    if bps as i128 >= MAX_BPS {
        return Err(err("KPR-1 customer-paid fees require platform fee bps below 10000"));
    }
    let flat = flat as i128;
    let target = requested + flat;
    let denominator = MAX_BPS - bps as i128;
    let mut total = (target * MAX_BPS + denominator - 1) / denominator;
    let pf = |g: i128| g * bps as i128 / MAX_BPS;
    while total - pf(total) < target {
        total += 1;
    }
    while total > target && (total - 1) - pf(total - 1) >= target {
        total -= 1;
    }
    let platform_fee = pf(total) + flat;
    Ok((total - requested, total, platform_fee))
}

// --- canonicalization + signing ---

/// `JSON.stringify(sortCanonicalValue(value))`. serde_json's default Map is a
/// BTreeMap, so `to_string` already emits keys in sorted order at every depth.
pub fn canonicalize(value: &Value) -> String {
    serde_json::to_string(value).expect("canonicalize")
}

fn sign(message: &str, seed: &[u8; 32]) -> String {
    let key = SigningKey::from_bytes(seed);
    B64.encode(key.sign(message.as_bytes()).to_bytes())
}

/// The raw ed25519 public key (32 bytes, base64) for the KPR-1 signing seed.
/// Published in the settlement proof so a third party can verify intents offline.
pub fn signing_public_key_b64(seed: &[u8; 32]) -> String {
    B64.encode(SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

/// Verify a base64 ed25519 `signature` over `message` against the seed's public
/// key. Used by the self-verifying settlement proof — it recomputes the answer
/// instead of trusting a stored DB flag.
pub fn verify_intent_signature(seed: &[u8; 32], message: &str, signature_b64: &str) -> bool {
    let key = SigningKey::from_bytes(seed);
    let Ok(sig_bytes) = B64.decode(signature_b64) else { return false };
    let Ok(sig) = Signature::from_slice(&sig_bytes) else { return false };
    key.verifying_key().verify(message.as_bytes(), &sig).is_ok()
}

/// Deterministic commitment to the merchant's *rate configuration* — payout
/// address, tax, revenue splits, and platform fee — independent of any single
/// invoice's amounts. sha256 over canonical JSON, so identical config always
/// yields the same commitment. A merchant can publish this once; a customer then
/// checks that the `configCommitment` inside their signed KPR-1 intent matches
/// the published value, proving the config was not swapped between publication
/// and mint. `splits` is `(identifier, address, bps)` in any order (sorted here).
pub fn compute_config_commitment(
    merchant_address: &str,
    tax_enabled: bool,
    tax_bps: i64,
    tax_address: Option<&str>,
    splits: &[(String, String, i64)],
    platform_fee_bps: i64,
    platform_fee_flat_sompi: i64,
    platform_fee_address: &str,
) -> String {
    let mut ordered: Vec<&(String, String, i64)> = splits.iter().collect();
    ordered.sort_by(|a, b| a.0.cmp(&b.0));
    let split_json: Vec<Value> = ordered
        .iter()
        .map(|(id, addr, bps)| json!({ "identifier": id, "address": addr, "bps": bps }))
        .collect();
    let config = json!({
        "version": 1,
        "merchantAddress": merchant_address,
        "tax": { "enabled": tax_enabled, "bps": tax_bps, "address": tax_address },
        "splits": split_json,
        "platformFee": { "bps": platform_fee_bps, "flatSompi": platform_fee_flat_sompi, "address": platform_fee_address },
    });
    sha256_hex(canonicalize(&config).as_bytes())
}

fn url_host(app_url: &str) -> String {
    let no_scheme = app_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(app_url);
    no_scheme
        .split(['/', ':'])
        .next()
        .unwrap_or(no_scheme)
        .to_string()
}

fn form_encode(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// --- setup-driven tax/split config ---

#[derive(sqlx::FromRow)]
struct SetupRow {
    kaspa_main_address: Option<String>,
    kaspa_tax_enabled: Option<i64>,
    kaspa_tax_address: Option<String>,
    kaspa_tax_percentage: Option<String>,
    kaspa_split_enabled: Option<i64>,
    kaspa_split_addresses: Option<String>,
}

struct TaxConfig {
    enabled: bool,
    bps: i64,
    address: Option<String>,
}

struct SplitOut {
    address: String,
    identifier: String,
    percentage: f64,
    bps: i64,
}

fn resolve_tax_config(setup: &SetupRow) -> AppResult<TaxConfig> {
    if setup.kaspa_tax_enabled.unwrap_or(0) == 0 {
        return Ok(TaxConfig { enabled: false, bps: 0, address: None });
    }
    let address = setup.kaspa_tax_address.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let address = match address {
        Some(a) if is_kaspa_address(a) => a.to_string(),
        _ => return Err(err("Merchant tax address must be a Kaspa address when tax is enabled")),
    };
    let bps = percentage_to_bps(setup.kaspa_tax_percentage.as_deref())?;
    if bps <= 0 {
        return Err(err("Merchant tax percentage must be greater than 0 when tax is enabled"));
    }
    Ok(TaxConfig { enabled: true, bps, address: Some(address) })
}

fn resolve_split_config(setup: &SetupRow) -> AppResult<(i64, Vec<SplitOut>)> {
    if setup.kaspa_split_enabled.unwrap_or(0) == 0 {
        return Ok((0, vec![]));
    }
    let raw = setup.kaspa_split_addresses.as_deref().unwrap_or("[]");
    let parsed: Value = serde_json::from_str(raw).unwrap_or(json!([]));
    let arr = parsed.as_array().cloned().unwrap_or_default();
    if arr.is_empty() {
        return Err(err("At least one split payment address is required when split payments are enabled"));
    }
    if arr.len() > MAX_SPLIT_ADDRESSES {
        return Err(err("Split payments support up to 5 addresses"));
    }
    let mut splits = Vec::new();
    for item in &arr {
        let address = item.get("address").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        let identifier = item.get("identifier").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        let percentage = item
            .get("percentage")
            .map(|v| match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default();
        let bps = percentage_to_bps(Some(&percentage))?;
        if address.is_empty() || !is_kaspa_address(&address) {
            return Err(err("Every split payment row must define a valid Kaspa address"));
        }
        if identifier.is_empty() {
            return Err(err("Every split payment row must define an identifier"));
        }
        if bps <= 0 {
            return Err(err("Every split payment row must define a percentage greater than 0"));
        }
        splits.push(SplitOut { address, identifier, percentage: percentage.parse().unwrap_or(0.0), bps });
    }
    let ids: std::collections::HashSet<_> = splits.iter().map(|s| &s.identifier).collect();
    if ids.len() != splits.len() {
        return Err(err("Split payment identifiers must be unique"));
    }
    let addrs: std::collections::HashSet<_> = splits.iter().map(|s| &s.address).collect();
    if addrs.len() != splits.len() {
        return Err(err("Split payment addresses must be unique"));
    }
    let total_bps: i64 = splits.iter().map(|s| s.bps).sum();
    if total_bps as i128 > MAX_BPS {
        return Err(err("Split payment percentages cannot total more than 100%"));
    }
    Ok((total_bps, splits))
}

// --- required outputs (parsed at finalize and by the covenant keeper / dispute ops) ---

/// One required output of a KPR-1 intent (parsed from `required_outputs`).
pub struct RequiredOutput {
    pub role: String,
    pub address: String,
    pub amount_sompi: i128,
}

/// Parse the intent's stored `required_outputs` JSON
/// (`[{ "role", "address", "amountSompi" }, ...]`).
pub fn parse_required_outputs(raw: &str) -> Vec<RequiredOutput> {
    let parsed: Value = serde_json::from_str(raw).unwrap_or(json!([]));
    parsed
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|o| {
                    let role = o.get("role")?.as_str()?.to_string();
                    let address = o.get("address")?.as_str()?.to_string();
                    let amount_sompi = o.get("amountSompi")?.as_str()?.parse().ok()?;
                    Some(RequiredOutput { role, address, amount_sompi })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// KIP-9 storage-mass parameter (sompi·mass), measured against a live TN10 node:
/// a release paying an output of value `v` contributes ~`STORAGE_MASS_PARAM / v`
/// storage mass. Consensus caps a transaction's storage mass at 500_000.
const STORAGE_MASS_PARAM: u128 = 1_000_000_000_000;
/// Safe ceiling for a covenant release's storage mass. Below the 500_000
/// consensus cap, leaving margin for the keeper's (large, negligible-mass)
/// fee-change output.
const MAX_SETTLEMENT_STORAGE_MASS: u128 = 450_000;

/// Estimated storage mass of a covenant release paying these payout values (the
/// dominant term; the large fee-change output is negligible). A covenant release
/// creates one output per payout plus a change output, so with >1 payout it has
/// more outputs than inputs and the node charges ~`STORAGE_MASS_PARAM/value` per
/// output — tiny payouts blow the cap and make the covenant unspendable.
fn settlement_storage_mass(payout_values: &[i128]) -> u128 {
    payout_values
        .iter()
        .filter(|v| **v > 0)
        .map(|v| STORAGE_MASS_PARAM / (*v as u128))
        .sum()
}

/// Mint and persist a KPR-1 intent for an invoice; returns the intentId.
pub async fn create_for_invoice(state: &AppState, ctx: &IntentInvoiceCtx) -> AppResult<String> {
    let cfg = &state.config.kpr1;
    if !cfg.enabled {
        return Err(err("KPR-1 covenant payments are disabled"));
    }

    // Reject small invoices up front, with a number a merchant can act on. The
    // storage-mass guard below already refuses them — but only after the fact and
    // in terms of "smallest payout" and KIP-9 mass, which says nothing a merchant
    // can price against. The floor exists because the covenant splits the payment
    // into several outputs, and KIP-9 charges ~1e12/value per output: the platform
    // fee slice of a tiny invoice is tiny, and a tiny output is expensive. At 2%
    // the hard technical limit is ~1.13 KAS; this floor keeps ~2x headroom so that
    // adding a tax or split output does not silently push an invoice over the cap.
    if ctx.total_amount < cfg.min_invoice_sompi {
        return Err(err(&format!(
            "KPR-1 invoices must be at least {} KAS (got {} KAS): below this the covenant's payout slices are too small to settle on-chain.",
            cfg.min_invoice_sompi as f64 / 100_000_000.0,
            ctx.total_amount as f64 / 100_000_000.0,
        )));
    }

    // Setup lookup: (user, store) then fall back to (user, store IS NULL).
    let mut setup: Option<SetupRow> = None;
    if let Some(store_id) = ctx.store_id {
        setup = sqlx::query_as::<_, SetupRow>(
            "SELECT kaspa_main_address, kaspa_tax_enabled, kaspa_tax_address, kaspa_tax_percentage, \
             kaspa_split_enabled, kaspa_split_addresses FROM setups WHERE user_id = $1 AND store_id = $2",
        )
        .bind(ctx.user_id)
        .bind(store_id)
        .fetch_optional(&state.db.pool)
        .await?;
    }
    if setup.is_none() {
        setup = sqlx::query_as::<_, SetupRow>(
            "SELECT kaspa_main_address, kaspa_tax_enabled, kaspa_tax_address, kaspa_tax_percentage, \
             kaspa_split_enabled, kaspa_split_addresses FROM setups WHERE user_id = $1 AND store_id IS NULL",
        )
        .bind(ctx.user_id)
        .fetch_optional(&state.db.pool)
        .await?;
    }

    let Some(setup) = setup else {
        return Err(err(
            "Merchant-owned Kaspa payout address is required before creating KPR-1 invoices",
        ));
    };
    let merchant_address = setup
        .kaspa_main_address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let merchant_address = match merchant_address {
        Some(a) if is_kaspa_address(a) => a.to_string(),
        _ => {
            return Err(err(
                "Merchant-owned Kaspa payout address is required before creating KPR-1 invoices",
            ))
        }
    };

    let platform_fee_address = cfg.platform_fee_address.clone();
    if !is_kaspa_address(&platform_fee_address) {
        return Err(err("KPR-1 platform fee address must be a Kaspa address"));
    }

    let tax = resolve_tax_config(&setup)?;
    let (split_total_bps, split_outs) = resolve_split_config(&setup)?;

    // Commit to the merchant's rate configuration (payout/tax/splits/platform
    // fee) so the customer can verify it was not swapped before this intent was
    // minted. Bound into the signed intent below (and thus into its canonical
    // hash and the covenant the customer funds).
    let commitment_splits: Vec<(String, String, i64)> =
        split_outs.iter().map(|s| (s.identifier.clone(), s.address.clone(), s.bps)).collect();
    let config_commitment = compute_config_commitment(
        &merchant_address,
        tax.enabled,
        tax.bps,
        tax.address.as_deref(),
        &commitment_splits,
        cfg.platform_fee_bps,
        cfg.platform_fee_flat_sompi,
        &platform_fee_address,
    );

    let amount = ctx.total_amount as i128;
    let platform_fee = platform_fee_total(amount, cfg.platform_fee_bps, cfg.platform_fee_flat_sompi)?;
    let tax_amount = bps_amount(amount, tax.bps, "KPR-1 tax bps invalid")?;
    let mut split_amounts = Vec::new();
    for s in &split_outs {
        split_amounts.push(bps_amount(amount, s.bps, "KPR-1 split bps invalid")?);
    }

    if tax.enabled && tax_amount <= 0 {
        return Err(err("KPR-1 tax amount must be at least 1 sompi when tax is enabled"));
    }
    if split_amounts.iter().any(|a| *a <= 0) {
        return Err(err("KPR-1 split amount must be at least 1 sompi when split payments are enabled"));
    }

    let split_total: i128 = split_amounts.iter().sum();
    let merchant_net = amount - platform_fee - tax_amount - split_total;
    let total_configured_bps = tax.bps as i128 + cfg.platform_fee_bps as i128 + split_total_bps as i128;
    if total_configured_bps > MAX_BPS {
        return Err(err(
            "KPR-1 tax, split, and platform fee percentages cannot exceed 100% of the invoice amount",
        ));
    }
    if amount <= 0 || merchant_net <= 0 {
        return Err(err(
            "KPR-1 invoice amount must leave a positive merchant-net output after tax, split payments, and fees",
        ));
    }

    // Storage-mass guard (KIP-9): the covenant release pays each of these outputs,
    // and the node charges ~STORAGE_MASS_PARAM/value of storage mass per output
    // (capped at 500_000). A too-small payout (e.g. a tiny fee/split slice on a
    // small invoice) would make the covenant unspendable, so reject up front.
    let mut payout_values: Vec<i128> = vec![merchant_net];
    if tax.enabled && tax_amount > 0 {
        payout_values.push(tax_amount);
    }
    payout_values.extend(split_amounts.iter().copied());
    payout_values.push(platform_fee);
    let storage_mass = settlement_storage_mass(&payout_values);
    if storage_mass > MAX_SETTLEMENT_STORAGE_MASS {
        let min_payout = payout_values.iter().filter(|v| **v > 0).min().copied().unwrap_or(0);
        return Err(err(&format!(
            "KPR-1 covenant settlement storage mass (~{storage_mass}) would exceed the safe limit ({MAX_SETTLEMENT_STORAGE_MASS}; consensus cap 500000): the smallest payout ({min_payout} sompi) is too small to settle on-chain. Increase the invoice amount or remove tiny tax/split/fee slices."
        )));
    }

    // intentId: kpr1_<16 random bytes hex>
    let mut id_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id_bytes);
    let intent_id: String = format!("kpr1_{}", encode_hex(&id_bytes));

    let expires_at = ctx
        .expires_at
        .clone()
        .unwrap_or_else(|| to_iso(chrono::Utc::now() + chrono::Duration::minutes(30)));

    // outputs: merchant_net, [tax], splits..., kasway_fee
    let mut outputs: Vec<Value> = vec![json!({
        "role": "merchant_net",
        "address": merchant_address,
        "amountSompi": merchant_net.to_string(),
    })];
    if tax.enabled && tax_amount > 0 {
        if let Some(addr) = &tax.address {
            outputs.push(json!({ "role": "tax", "address": addr, "amountSompi": tax_amount.to_string() }));
        }
    }
    for (s, amt) in split_outs.iter().zip(split_amounts.iter()) {
        outputs.push(json!({
            "role": "split",
            "address": s.address,
            "amountSompi": amt.to_string(),
            "identifier": s.identifier,
            "percentage": s.percentage,
        }));
    }
    outputs.push(json!({
        "role": "kasway_fee",
        "address": platform_fee_address,
        "amountSompi": platform_fee.to_string(),
    }));

    // Covenant settlement (the only path). The covenant P2SH address is derived
    // at finalize once the payer supplies a refund address, so it and the real
    // script hash are unknown here. The signed intent commits to the economic
    // terms (ordered payouts, gross, expiry); the covenant address is a
    // deterministic function of those plus the refund address.
    // The merchant's own name, falling back to the platform's only when the
    // invoice has no store (the "included" default store path).
    let merchant_name: String = match ctx.store_id {
        Some(store_id) => sqlx::query_scalar("SELECT name FROM stores WHERE id = $1")
            .bind(store_id)
            .fetch_optional(&state.db.pool)
            .await?
            .unwrap_or_else(|| cfg.app_name.clone()),
        None => cfg.app_name.clone(),
    };

    // What the payer is actually buying. `imageUrl` only exists if the merchant
    // put one in the item's metadata — there is no image column to read.
    let items = sqlx::query_as::<_, (String, i64, i64, i64, Option<String>)>(
        "SELECT name, quantity, unit_amount, total_amount, metadata FROM invoice_items \
         WHERE invoice_id = $1 ORDER BY id",
    )
    .bind(ctx.invoice_id)
    .fetch_all(&state.db.pool)
    .await?;
    let display_items: Vec<Value> = items
        .iter()
        .map(|(name, quantity, unit_amount, total_amount, metadata)| {
            let image_url = metadata
                .as_deref()
                .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
                .and_then(|m| m.get("imageUrl").and_then(|v| v.as_str()).map(str::to_string));
            json!({
                "name": name,
                "quantity": quantity,
                "unitAmount": unit_amount.to_string(),
                "totalAmount": total_amount.to_string(),
                "imageUrl": image_url,
            })
        })
        .collect();

    let capture_window = state.config.covenant.capture_window_secs;
    let expiry_ts = chrono::Utc::now().timestamp() + capture_window;
    let gross_amount = amount; // the covenant holds the full invoice amount

    let template = json!({
        "id": TEMPLATE_ID,
        "version": TEMPLATE_VERSION,
        "kind": "refund_window_covenant",
        "status": "pending_finalize",
    });
    let intent_unsigned = json!({
        "version": KPR1_VERSION,
        "network": ctx.payment_network,
        "asset": ctx.payment_asset,
        "intentId": intent_id,
        "invoiceId": ctx.public_id,
        "amountSompi": amount.to_string(),
        "grossSompi": gross_amount.to_string(),
        "expiresAt": expires_at,
        "expiryTs": expiry_ts,
        "template": template,
        "outputs": outputs,
        "configCommitment": config_commitment,
        "settlement": { "mode": "covenant", "addressRequiredFromWallet": true, "captureWindowSeconds": capture_window },
        "refund": { "addressRequiredFromWallet": true, "captureWindowSeconds": capture_window },
        // The merchant is the STORE, not the platform. This used to be
        // `cfg.app_name`, so every payment request in every wallet claimed to
        // come from "Kasway".
        "merchant": { "name": merchant_name, "domain": url_host(&cfg.app_url) },
        // Items ride INSIDE the signature. The review screen is what the payer
        // consents to, so what they are buying must be as tamper-proof as the
        // amount — otherwise a compromised API could show one basket and have the
        // covenant pay for another.
        "display": {
            "memo": format!("Invoice {}", ctx.public_id),
            "currencyCode": ctx.payment_asset,
            "items": display_items,
        },
    });

    let unsigned_payload = canonicalize(&intent_unsigned);
    let signature_value = sign(&unsigned_payload, &cfg.signing_seed);

    let mut signed_intent = intent_unsigned;
    signed_intent["signature"] = json!({
        "alg": SIGNATURE_ALGORITHM,
        "keyId": cfg.signing_key_id,
        "value": signature_value,
    });
    let canonical_hash = sha256_hex(canonicalize(&signed_intent).as_bytes());

    let payment_intent_url = format!(
        "{}/api/checkout/invoices/{}/kpr1-intent",
        cfg.app_url.trim_end_matches('/'),
        ctx.public_id
    );
    let expires_epoch = chrono::DateTime::parse_from_rfc3339(&expires_at)
        .map(|dt| dt.timestamp())
        .unwrap_or(0);
    let payment_request_uri = format!(
        "kaspa-payment:v1?request={}&hash={}&network={}&expires={}",
        form_encode(&payment_intent_url),
        form_encode(&canonical_hash),
        form_encode(&ctx.payment_network),
        expires_epoch
    );

    let metadata = json!({
        "nonCustodial": true,
        "noKaswaySigning": true,
        "walletLocalSigningRequired": true,
        "settlementMode": "covenant",
        "covenantTemplate": { "id": TEMPLATE_ID, "version": TEMPLATE_VERSION, "kind": "refund_window" },
        "configCommitment": config_commitment,
    });

    let now = now_iso();
    let script_hash: Option<String> = None; // covenant script hash is set at finalize

    sqlx::query(
        "INSERT INTO kpr1_payment_intents \
         (invoice_id, user_id, intent_id, status, network, asset_id, amount_sompi, platform_fee_bps, \
          platform_fee_amount, tax_bps, tax_amount, tax_address, merchant_address, platform_fee_address, \
          template_id, template_version, script_hash, canonical_hash, payment_request_uri, payment_intent_url, \
          signature_algorithm, signature_key_id, signature_value, required_outputs, canonical_intent, metadata, \
          gross_amount, expiry_ts, covenant_state, expires_at, created_at, updated_at) \
         VALUES ($1, $2, $3, 'created', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, 'pending', $28, $29, $30)",
    )
    .bind(ctx.invoice_id)
    .bind(ctx.user_id)
    .bind(&intent_id)
    .bind(&ctx.payment_network)
    .bind(&ctx.payment_asset)
    .bind(amount as i64)
    .bind(cfg.platform_fee_bps)
    .bind(platform_fee as i64)
    .bind(tax.bps)
    .bind(tax_amount as i64)
    .bind(&tax.address)
    .bind(&merchant_address)
    .bind(&platform_fee_address)
    .bind(TEMPLATE_ID)
    .bind(TEMPLATE_VERSION)
    .bind(script_hash)
    .bind(&canonical_hash)
    .bind(&payment_request_uri)
    .bind(&payment_intent_url)
    .bind(SIGNATURE_ALGORITHM)
    .bind(&cfg.signing_key_id)
    .bind(&signature_value)
    .bind(Value::Array(outputs).to_string())
    .bind(signed_intent.to_string())
    .bind(metadata.to_string())
    .bind(gross_amount as i64)
    .bind(expiry_ts)
    .bind(&expires_at)
    .bind(&now)
    .bind(&now)
    .execute(&state.db.pool)
    .await?;

    Ok(intent_id)
}

/// Finalize a covenant intent: the payer supplies their refund address, we derive
/// the covenant P2SH address (deterministically, from the signed payouts + gross +
/// expiry + this refund address), persist it, and point the invoice at it so the
/// payer funds the covenant. Idempotent: re-finalizing returns the same address.
pub async fn finalize_covenant_for_invoice(
    state: &AppState,
    public_id: &str,
    refund_address: &str,
) -> AppResult<Value> {
    let invoice = sqlx::query_as::<_, (i64, String)>("SELECT id, status FROM invoices WHERE public_id = $1")
        .bind(public_id)
        .fetch_optional(&state.db.pool)
        .await?;
    let Some((inv_id, inv_status)) = invoice else {
        return Err(err("KPR-1 payment intent not found"));
    };

    let row = sqlx::query_as::<_, (i64, String, String, Option<i64>, Option<i64>, String, Option<String>, Option<String>)>(
        "SELECT id, network, required_outputs, gross_amount, expiry_ts, covenant_state, covenant_address, \
         customer_refund_address FROM kpr1_payment_intents WHERE invoice_id = $1",
    )
    .bind(inv_id)
    .fetch_optional(&state.db.pool)
    .await?;
    let Some((intent_pk, network, required_outputs, gross_opt, expiry_opt, covenant_state, existing_address, existing_refund)) = row else {
        return Err(err("KPR-1 payment intent not found"));
    };

    let gross = gross_opt.ok_or_else(|| err("KPR-1 covenant gross amount is missing"))? as u64;
    let expiry = expiry_opt.ok_or_else(|| err("KPR-1 covenant expiry is missing"))? as u64;

    // Idempotent: already finalized -> return the existing covenant, receipted
    // with the refund address BAKED INTO IT rather than the one just requested.
    // A second payer must be able to see that this escrow refunds elsewhere.
    if covenant_state != "pending" {
        if let Some(addr) = existing_address {
            let refund = existing_refund.unwrap_or_default();
            return Ok(finalize_response(state, &addr, gross, expiry, &covenant_state, &refund));
        }
    }
    if inv_status != "open" {
        return Err(err("KPR-1 covenant can only be finalized for open invoices"));
    }

    let prefix = kasway_covenant::network_prefix(&network).map_err(|e| err(&e.to_string()))?;
    let customer_refund = kasway_covenant::Destination::parse(refund_address)
        .map_err(|e| err(&format!("KPR-1 refund address is not a supported Kaspa address: {e}")))?;

    // EscrowV2 M-of-N arbiter panel (consented at funding). Falls back to a
    // 1-of-1 panel of the configured Kasway arbiter during migration.
    let (arbiter_panel, arbiter_threshold) = escrow_arbiter_panel(state)?;

    let outs = parse_required_outputs(&required_outputs);
    // The merchant's signing identity is the merchant_net payout address (schnorr P2PK).
    let merchant_addr = outs
        .iter()
        .find(|o| o.role == "merchant_net")
        .map(|o| o.address.clone())
        .ok_or_else(|| err("KPR-1 intent has no merchant_net payout"))?;
    let merchant = kasway_covenant::Destination::parse(&merchant_addr)
        .map_err(|e| err(&format!("KPR-1 merchant address must be a schnorr P2PK address: {e}")))?;

    let mut payouts = Vec::new();
    for out in &outs {
        let destination = kasway_covenant::Destination::parse(&out.address)
            .map_err(|e| err(&format!("KPR-1 {} payout address is not covenant-compatible: {e}", out.role)))?;
        let value = u64::try_from(out.amount_sompi).map_err(|_| err("KPR-1 payout amount is invalid"))?;
        payouts.push(kasway_covenant::Payout { destination, value });
    }

    let params = kasway_covenant::escrow_v2::EscrowV2Params {
        payouts,
        customer_refund,
        merchant,
        arbiter_panel,
        arbiter_threshold,
        gross_amount: gross,
        // `capture_time` is an on-chain lock_time. Kaspa treats lock_time values
        // >= 500e9 as millisecond wall-clock timestamps and smaller values as DAA
        // scores; `expiry` is Unix SECONDS, so scale to milliseconds to get a
        // correct wall-clock auto-capture deadline (not a far-future DAA score).
        capture_time: expiry.saturating_mul(1000),
    };
    let compiled = kasway_covenant::escrow_v2::compile_escrow_v2(&params)
        .map_err(|e| err(&format!("KPR-1 covenant compilation failed: {e}")))?;
    let address = kasway_covenant::covenant_address(&compiled, prefix)
        .map_err(|e| err(&e.to_string()))?
        .to_string();
    let script_hash: String = encode_hex(&kasway_covenant::covenant_script_hash(&compiled));

    // Snapshot the arbiter panel so settlement rebuilds this exact covenant even
    // if the configured panel later changes.
    let panel_hex: Vec<String> =
        params.arbiter_panel.iter().map(|k| encode_hex(k)).collect();
    let panel_json = serde_json::to_string(&panel_hex).unwrap_or_else(|_| "[]".to_string());
    let arbiter_threshold_i = params.arbiter_threshold as i32;

    let now = now_iso();
    sqlx::query(
        "UPDATE kpr1_payment_intents SET covenant_address = $1, customer_refund_address = $2, script_hash = $3, \
         arbiter_panel_json = $4, arbiter_threshold = $5, covenant_state = 'awaiting_funding', updated_at = $6 WHERE id = $7",
    )
    .bind(&address)
    .bind(refund_address)
    .bind(&script_hash)
    .bind(&panel_json)
    .bind(arbiter_threshold_i)
    .bind(&now)
    .bind(intent_pk)
    .execute(&state.db.pool)
    .await?;
    sqlx::query("UPDATE invoices SET payment_address = $1, updated_at = $2 WHERE id = $3")
        .bind(&address)
        .bind(&now)
        .bind(inv_id)
        .execute(&state.db.pool)
        .await?;

    Ok(finalize_response(state, &address, gross, expiry, "awaiting_funding", refund_address))
}

/// The Kasway arbiter public key baked into every covenant, derived from the
/// configured arbiter secret.
fn arbiter_pubkey(state: &AppState) -> AppResult<[u8; 32]> {
    let hex = state
        .config
        .covenant
        .arbiter_secret_hex
        .as_deref()
        .ok_or_else(|| err("KPR-1 covenant arbiter key is not configured (COVENANT_ARBITER_SECRET)"))?;
    let bytes = decode_hex32(hex.trim()).ok_or_else(|| err("KPR-1 arbiter secret must be 32-byte hex"))?;
    let key = kasway_covenant::KeeperKey::from_secret_bytes(&bytes).map_err(|e| err(&e.to_string()))?;
    Ok(key.x_only_pubkey())
}

/// The EscrowV2 arbiter panel `(pubkeys, threshold)` baked into every covenant.
/// If `COVENANT_ARBITER_PANEL` is configured, uses that independent panel;
/// otherwise falls back to a 1-of-1 panel of the configured Kasway arbiter
/// (behaviour-preserving migration). `threshold` is clamped to `1..=panel.len()`.
pub(crate) fn escrow_arbiter_panel(state: &AppState) -> AppResult<(Vec<[u8; 32]>, u32)> {
    let cfg = &state.config.covenant;
    if cfg.arbiter_panel_hex.is_empty() {
        let panel = vec![arbiter_pubkey(state)?];
        return Ok((panel, 1));
    }
    let mut panel = Vec::with_capacity(cfg.arbiter_panel_hex.len());
    for hex in &cfg.arbiter_panel_hex {
        let pk = decode_hex32(hex.trim()).ok_or_else(|| err("KPR-1 arbiter panel entry must be 32-byte hex"))?;
        panel.push(pk);
    }
    let threshold = cfg.arbiter_threshold.clamp(1, panel.len() as u32);
    Ok((panel, threshold))
}

/// Signed finalize receipt. `refund_address` is the address actually compiled
/// into the covenant — NOT whatever the caller just asked for. Finalize is
/// first-writer-wins, so a wallet that blindly trusted `covenantAddress` could
/// fund an escrow that refunds to whoever finalized first. Signing the receipt
/// with the KPR-1 key (the anchor wallets already pin) lets the payer verify
/// both that Kasway issued it and that the refund path is theirs.
fn finalize_response(
    state: &AppState,
    address: &str,
    gross: u64,
    expiry: u64,
    covenant_state: &str,
    refund_address: &str,
) -> Value {
    let cfg = &state.config.kpr1;
    let unsigned = json!({
        "covenantAddress": address,
        "amountSompi": gross.to_string(),
        "expiryTs": expiry,
        "covenantState": covenant_state,
        "refundAddress": refund_address,
    });
    let signature_value = sign(&canonicalize(&unsigned), &cfg.signing_seed);
    let mut signed = unsigned;
    signed["signature"] = json!({
        "alg": SIGNATURE_ALGORITHM,
        "keyId": cfg.signing_key_id,
        "value": signature_value,
    });
    signed
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 2 KAS floor is not arbitrary: it is the point where a 2% invoice keeps
    /// ~2x headroom under the consensus mass cap, so a merchant can still add a
    /// tax or split output. Guard the arithmetic that justifies it — if someone
    /// lowers the floor or raises the fee, this fails before production does.
    #[test]
    fn the_min_invoice_leaves_headroom_for_a_tax_or_split_output() {
        let min_invoice: i128 = 200_000_000; // 2 KAS
        let fee = platform_fee_total(min_invoice, 200, 0).unwrap();
        let merchant = min_invoice - fee;
        let base = settlement_storage_mass(&[merchant, fee]);
        assert!(base < MAX_SETTLEMENT_STORAGE_MASS, "base settlement already over budget: {base}");
        // ~1.96x headroom against the 500k consensus cap (255,102 of it used).
        assert!(base * 19 <= 500_000 * 10, "not enough headroom: {base}");
        // And the leftover budget must still fit a realistic tax slice (11% VAT).
        let tax = min_invoice * 11 / 100;
        let with_tax = settlement_storage_mass(&[merchant - tax, fee, tax]);
        assert!(
            with_tax < MAX_SETTLEMENT_STORAGE_MASS,
            "a merchant enabling an 11% tax would break the floor: {with_tax}"
        );
    }

    fn splits_a() -> Vec<(String, String, i64)> {
        vec![
            ("partner-b".into(), "kaspatest:bbb0000000001".into(), 500),
            ("partner-a".into(), "kaspatest:aaa0000000001".into(), 250),
        ]
    }

    #[test]
    fn config_commitment_is_deterministic_and_order_independent() {
        let a = compute_config_commitment(
            "kaspatest:merchant0001", true, 500, Some("kaspatest:tax0001"),
            &splits_a(), 100, 0, "kaspatest:fee0001",
        );
        // Same config, splits supplied in the opposite order → identical hash.
        let mut reordered = splits_a();
        reordered.reverse();
        let b = compute_config_commitment(
            "kaspatest:merchant0001", true, 500, Some("kaspatest:tax0001"),
            &reordered, 100, 0, "kaspatest:fee0001",
        );
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // sha256 hex
    }

    #[test]
    fn config_commitment_changes_when_a_rate_changes() {
        let base = compute_config_commitment(
            "kaspatest:merchant0001", true, 500, Some("kaspatest:tax0001"),
            &splits_a(), 100, 0, "kaspatest:fee0001",
        );
        // Bump the tax bps: the commitment must differ.
        let bumped = compute_config_commitment(
            "kaspatest:merchant0001", true, 750, Some("kaspatest:tax0001"),
            &splits_a(), 100, 0, "kaspatest:fee0001",
        );
        assert_ne!(base, bumped);
    }

    #[test]
    fn intent_signature_roundtrips_and_rejects_tampering() {
        let seed = [9u8; 32];
        let msg = r#"{"amountSompi":"1000","intentId":"kpr1_test"}"#;
        let sig = sign(msg, &seed);
        assert!(verify_intent_signature(&seed, msg, &sig));
        // Tampered message must fail.
        assert!(!verify_intent_signature(&seed, r#"{"amountSompi":"9999"}"#, &sig));
        // Wrong key must fail.
        assert!(!verify_intent_signature(&[8u8; 32], msg, &sig));
        // Public key export is stable base64.
        assert_eq!(signing_public_key_b64(&seed), signing_public_key_b64(&seed));
    }
}
