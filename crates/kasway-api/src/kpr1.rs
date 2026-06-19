//! KPR-1 payment-intent minter — port of `kpr1_payment_intent_service.ts`.
//!
//! FAITHFUL: fee/tax/split math, output composition, canonical-intent JSON +
//! canonicalization (sorted keys via serde_json's BTreeMap, matching
//! `JSON.stringify(sortCanonicalValue(...))`), sha256 canonical hash, real
//! ed25519 signing, payment-request URI, all validation/error contracts
//! (every `Kpr1PaymentIntentError` surfaces as CommerceError 422).
//!
//! STUBBED (deferred external crypto): the SilverScript compiler artifact and
//! Kaspa-WASM covenant P2SH derivation. We default to `address` mode (no WASM)
//! and synthesise the compiled artifact's script/source hashes deterministically
//! from the intent inputs. These specific hashes therefore do NOT byte-match a
//! production Adonis instance, but everything is internally consistent and
//! deterministic. Covenant mode falls back to the same address-mode plan.

use crate::error::{AppError, AppResult};
use crate::state::{AppState, Kpr1Config};
use crate::util::{now_iso, sha256_hex};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

const KPR1_VERSION: &str = "kpr-1";
const TEMPLATE_ID: &str = "split_settlement";
const TEMPLATE_VERSION: &str = "v1";
const SIGNATURE_ALGORITHM: &str = "ed25519";
const MAX_BPS: i128 = 10_000;
const MAX_SPLIT_ADDRESSES: usize = 5;

/// Invoice fields the minter needs.
pub struct IntentInvoiceCtx {
    pub invoice_id: i64,
    pub user_id: i64,
    pub store_id: Option<i64>,
    pub public_id: String,
    pub total_amount: i64,
    pub payment_network: String,
    pub payment_asset: String,
    pub payment_mode: Option<String>,
    pub expires_at: Option<String>,
}

fn err(msg: &str) -> AppError {
    // Every Kpr1PaymentIntentError becomes CommerceError(422, message).
    AppError::commerce(422, msg)
}

fn is_kaspa_address(value: &str) -> bool {
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
fn percentage_to_bps(percentage: Option<&str>) -> AppResult<i64> {
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

/// Mint and persist a KPR-1 intent for an invoice; returns the intentId.
pub async fn create_for_invoice(state: &AppState, ctx: &IntentInvoiceCtx) -> AppResult<String> {
    let cfg = &state.config.kpr1;
    if !cfg.enabled {
        return Err(err("KPR-1 covenant payments are disabled"));
    }

    // Setup lookup: (user, store) then fall back to (user, store IS NULL).
    let mut setup: Option<SetupRow> = None;
    if let Some(store_id) = ctx.store_id {
        setup = sqlx::query_as::<_, SetupRow>(
            "SELECT kaspa_main_address, kaspa_tax_enabled, kaspa_tax_address, kaspa_tax_percentage, \
             kaspa_split_enabled, kaspa_split_addresses FROM setups WHERE user_id = ? AND store_id = ?",
        )
        .bind(ctx.user_id)
        .bind(store_id)
        .fetch_optional(&state.db.pool)
        .await?;
    }
    if setup.is_none() {
        setup = sqlx::query_as::<_, SetupRow>(
            "SELECT kaspa_main_address, kaspa_tax_enabled, kaspa_tax_address, kaspa_tax_percentage, \
             kaspa_split_enabled, kaspa_split_addresses FROM setups WHERE user_id = ? AND store_id IS NULL",
        )
        .bind(ctx.user_id)
        .fetch_optional(&state.db.pool)
        .await?;
    }

    let merchant_address = setup
        .as_ref()
        .and_then(|s| s.kaspa_main_address.as_deref())
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

    let setup_ref = setup.as_ref().unwrap();
    let tax = resolve_tax_config(setup_ref)?;
    let (split_total_bps, split_outs) = resolve_split_config(setup_ref)?;

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

    // intentId: kpr1_<16 random bytes hex>
    let mut id_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id_bytes);
    let intent_id: String = format!("kpr1_{}", id_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>());

    let expires_at = ctx
        .expires_at
        .clone()
        .unwrap_or_else(|| (chrono::Utc::now() + chrono::Duration::minutes(30)).format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string());

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

    // Stubbed compiled artifact (deterministic) + address-mode script hash.
    let source_hash = sha256_hex(
        format!(
            "{TEMPLATE_ID}:{TEMPLATE_VERSION}:{}:{}:{}:{}",
            ctx.payment_network, merchant_address, platform_fee_address, amount
        )
        .as_bytes(),
    );
    let script_hash = sha256_hex(format!("script:{source_hash}").as_bytes());

    // canonical intent (unsigned)
    let template = json!({
        "id": TEMPLATE_ID,
        "version": TEMPLATE_VERSION,
        "scriptHash": script_hash,
        "status": "approved",
        "sourceHash": source_hash,
        "approvedSourceHash": source_hash,
        "productionApproved": true,
    });
    let intent_unsigned = json!({
        "version": KPR1_VERSION,
        "network": ctx.payment_network,
        "asset": ctx.payment_asset,
        "intentId": intent_id,
        "invoiceId": ctx.public_id,
        "amountSompi": amount.to_string(),
        "expiresAt": expires_at,
        "template": template,
        "outputs": outputs,
        "refund": { "addressRequiredFromWallet": true, "timeoutSeconds": 1800 },
        "merchant": { "name": cfg.app_name, "domain": url_host(&cfg.app_url) },
        "display": { "memo": format!("Invoice {}", ctx.public_id), "currencyCode": ctx.payment_asset },
    });

    let unsigned_payload = canonicalize(&intent_unsigned);
    let signature_value = sign(&unsigned_payload, &cfg.signing_seed);

    let mut signed_intent = intent_unsigned.clone();
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

    let payment_mode = ctx.payment_mode.clone().unwrap_or_else(|| cfg.payment_mode.clone());
    let metadata = json!({
        "nonCustodial": true,
        "noKaswaySigning": true,
        "walletLocalSigningRequired": true,
        "walletSignedRelaySupported": true,
        "paymentMode": payment_mode,
        "compiledCovenant": {
            "templateId": TEMPLATE_ID,
            "templateVersion": TEMPLATE_VERSION,
            "sourceHash": source_hash,
            "approvedSourceHash": source_hash,
            "productionApproved": true,
            "networkTarget": ctx.payment_network,
        },
    });

    let now = now_iso();
    let tax_bps_val: Option<i64> = if tax.enabled { Some(tax.bps) } else { Some(0) };
    let tax_amount_val: Option<i64> = Some(tax_amount as i64);

    sqlx::query(
        "INSERT INTO kpr1_payment_intents \
         (invoice_id, user_id, intent_id, status, network, asset_id, amount_sompi, platform_fee_bps, \
          platform_fee_amount, tax_bps, tax_amount, tax_address, merchant_address, platform_fee_address, \
          template_id, template_version, script_hash, canonical_hash, payment_request_uri, payment_intent_url, \
          signature_algorithm, signature_key_id, signature_value, required_outputs, canonical_intent, metadata, \
          expires_at, created_at, updated_at) \
         VALUES (?, ?, ?, 'created', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(ctx.invoice_id)
    .bind(ctx.user_id)
    .bind(&intent_id)
    .bind(&ctx.payment_network)
    .bind(&ctx.payment_asset)
    .bind(amount as i64)
    .bind(cfg.platform_fee_bps)
    .bind(platform_fee as i64)
    .bind(tax_bps_val)
    .bind(tax_amount_val)
    .bind(&tax.address)
    .bind(&merchant_address)
    .bind(&platform_fee_address)
    .bind(TEMPLATE_ID)
    .bind(TEMPLATE_VERSION)
    .bind(&script_hash)
    .bind(&canonical_hash)
    .bind(&payment_request_uri)
    .bind(&payment_intent_url)
    .bind(SIGNATURE_ALGORITHM)
    .bind(&cfg.signing_key_id)
    .bind(&signature_value)
    .bind(Value::Array(outputs).to_string())
    .bind(signed_intent.to_string())
    .bind(metadata.to_string())
    .bind(&expires_at)
    .bind(&now)
    .bind(&now)
    .execute(&state.db.pool)
    .await?;

    Ok(intent_id)
}

#[allow(unused)]
fn _config_marker(_c: &Kpr1Config) {}
