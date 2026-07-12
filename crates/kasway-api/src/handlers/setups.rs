//! `/api/setup` (default store) + `/api/stores/:id/setup*` — SetupsController /
//! StoreSetupsController / StoreSetupService.
//!
//! Input is the nested `{ kaspa: {...}, redirectUrl, webhookUrl }` shape; the
//! RESPONSE is the flat serialized Setup model (Lucid). Tax/split validation
//! mirrors StoreSetupService (StoreContextError -> 422 `{ message }`).

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::kpr1::{compute_config_commitment, is_kaspa_address, percentage_to_bps, MAX_BPS, MAX_SPLIT_ADDRESSES};
use crate::state::AppState;
use crate::store_context::{ensure_default_store, resolve_owned_store};
use crate::util::{json_or_null, now_iso};
use axum::extract::{Path, State};
use axum::Json;
use serde_json::{json, Value};

const SETUP_SECTIONS: &[&str] = &["payout", "tax", "split", "redirects", "webhook"];

#[derive(sqlx::FromRow, Clone)]
struct SetupRow {
    id: i64,
    user_id: i64,
    store_id: Option<i64>,
    tos_agreed: Option<i64>,
    kaspa_main_address: Option<String>,
    kaspa_tax_enabled: Option<i64>,
    kaspa_tax_address: Option<String>,
    kaspa_tax_percentage: Option<String>,
    kaspa_split_enabled: Option<i64>,
    kaspa_split_addresses: Option<String>,
    igra_main_address: Option<String>,
    igra_tax_enabled: Option<i64>,
    igra_tax_address: Option<String>,
    igra_tax_percentage: Option<String>,
    igra_split_enabled: Option<i64>,
    igra_split_addresses: Option<String>,
    kasplex_main_address: Option<String>,
    kasplex_tax_enabled: Option<i64>,
    kasplex_tax_address: Option<String>,
    kasplex_tax_percentage: Option<String>,
    kasplex_split_enabled: Option<i64>,
    kasplex_split_addresses: Option<String>,
    redirect_url: Option<String>,
    webhook_url: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

const SETUP_COLS: &str = "id, user_id, store_id, tos_agreed, kaspa_main_address, kaspa_tax_enabled, \
    kaspa_tax_address, kaspa_tax_percentage, kaspa_split_enabled, kaspa_split_addresses, \
    igra_main_address, igra_tax_enabled, igra_tax_address, igra_tax_percentage, igra_split_enabled, \
    igra_split_addresses, kasplex_main_address, kasplex_tax_enabled, kasplex_tax_address, \
    kasplex_tax_percentage, kasplex_split_enabled, kasplex_split_addresses, redirect_url, \
    webhook_url, created_at, updated_at";

/// Commitment to this store's Kaspa rate config, matching the `configCommitment`
/// the KPR-1 minter bakes into every intent. A merchant publishes this so a
/// customer can check the config bound to their payment. `None` until a valid
/// payout address is configured. Percentages go through the SAME `percentage_to_bps`
/// the minter uses, so the hashes line up exactly.
fn config_commitment(state: &AppState, s: &SetupRow) -> Option<String> {
    let merchant = s.kaspa_main_address.as_deref().map(str::trim).filter(|x| !x.is_empty())?;
    if !is_kaspa_address(merchant) {
        return None;
    }
    let tax_enabled = s.kaspa_tax_enabled.unwrap_or(0) != 0;
    let (tax_bps, tax_address) = if tax_enabled {
        let bps = percentage_to_bps(s.kaspa_tax_percentage.as_deref()).ok()?;
        let addr = s.kaspa_tax_address.as_deref().map(str::trim).filter(|x| !x.is_empty()).map(String::from);
        (bps, addr)
    } else {
        (0, None)
    };
    let mut splits: Vec<(String, String, i64)> = Vec::new();
    if s.kaspa_split_enabled.unwrap_or(0) != 0 {
        let parsed: Value = serde_json::from_str(s.kaspa_split_addresses.as_deref().unwrap_or("[]")).ok()?;
        for item in parsed.as_array()? {
            let id = item.get("identifier").and_then(|v| v.as_str())?.to_string();
            let addr = item.get("address").and_then(|v| v.as_str())?.to_string();
            // Match the minter: percentage may be a string or a number.
            let pct = match item.get("percentage") {
                Some(Value::String(p)) => p.clone(),
                Some(other) => other.to_string(),
                None => return None,
            };
            let bps = percentage_to_bps(Some(&pct)).ok()?;
            splits.push((id, addr, bps));
        }
    }
    let cfg = &state.config.kpr1;
    Some(compute_config_commitment(
        merchant,
        tax_enabled,
        tax_bps,
        tax_address.as_deref(),
        &splits,
        cfg.platform_fee_bps,
        cfg.platform_fee_flat_sompi,
        &cfg.platform_fee_address,
    ))
}

fn serialize_setup(state: &AppState, s: &SetupRow) -> Value {
    json!({
        "id": s.id,
        "userId": s.user_id,
        "storeId": s.store_id,
        "tosAgreed": s.tos_agreed.unwrap_or(0) != 0,
        "configCommitment": config_commitment(state, s),
        "kaspaMainAddress": s.kaspa_main_address,
        "kaspaTaxEnabled": s.kaspa_tax_enabled.unwrap_or(0) != 0,
        "kaspaTaxAddress": s.kaspa_tax_address,
        "kaspaTaxPercentage": s.kaspa_tax_percentage,
        "kaspaSplitEnabled": s.kaspa_split_enabled.unwrap_or(0) != 0,
        "kaspaSplitAddresses": json_or_null(&s.kaspa_split_addresses),
        "igraMainAddress": s.igra_main_address,
        "igraTaxEnabled": s.igra_tax_enabled.unwrap_or(0) != 0,
        "igraTaxAddress": s.igra_tax_address,
        "igraTaxPercentage": s.igra_tax_percentage,
        "igraSplitEnabled": s.igra_split_enabled.unwrap_or(0) != 0,
        "igraSplitAddresses": json_or_null(&s.igra_split_addresses),
        "kasplexMainAddress": s.kasplex_main_address,
        "kasplexTaxEnabled": s.kasplex_tax_enabled.unwrap_or(0) != 0,
        "kasplexTaxAddress": s.kasplex_tax_address,
        "kasplexTaxPercentage": s.kasplex_tax_percentage,
        "kasplexSplitEnabled": s.kasplex_split_enabled.unwrap_or(0) != 0,
        "kasplexSplitAddresses": json_or_null(&s.kasplex_split_addresses),
        "redirectUrl": s.redirect_url,
        "webhookUrl": s.webhook_url,
        "createdAt": s.created_at,
        "updatedAt": s.updated_at,
    })
}

// --- input parsing ---

struct KaspaInput {
    main_address: String,
    tax_enabled: bool,
    tax_address: Option<String>,
    tax_percentage: Option<f64>,
    split_enabled: bool,
    /// normalized split addresses JSON (already validated), or None
    split_json: Option<String>,
}

fn validate_tax(state: &AppState, tax_enabled: bool, tax_address: &Option<String>, tax_percentage: Option<f64>) -> AppResult<()> {
    if !tax_enabled {
        return Ok(());
    }
    match tax_address {
        Some(a) if is_kaspa_address(a) => {}
        _ => return Err(AppError::commerce(422, "Kaspa tax address is required when tax is enabled")),
    }
    let max_tax = (MAX_BPS - state.config.kpr1.platform_fee_bps as i128) as f64 / 100.0;
    let p = tax_percentage.unwrap_or(0.0);
    if tax_percentage.is_none() || p <= 0.0 || p > max_tax {
        return Err(AppError::commerce(
            422,
            &format!("Kaspa tax percentage must be greater than 0 and less than or equal to {max_tax} when tax is enabled"),
        ));
    }
    if ((p * 100.0).round() / 100.0 - p).abs() > 0.0000001 {
        return Err(AppError::commerce(422, "Kaspa tax percentage supports at most two decimal places"));
    }
    Ok(())
}

/// Validate + normalize split addresses; returns the JSON string or None.
fn normalize_splits(split_enabled: bool, raw: Option<&Value>) -> AppResult<Option<String>> {
    if !split_enabled {
        return Ok(None);
    }
    let arr = raw.and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if arr.is_empty() {
        return Err(AppError::commerce(422, "At least one split payment address is required when split payments are enabled"));
    }
    if arr.len() > MAX_SPLIT_ADDRESSES {
        return Err(AppError::commerce(422, "Split payments support up to 5 addresses"));
    }
    let mut out = Vec::new();
    for item in &arr {
        let address = item.get("address").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        let identifier = item.get("identifier").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        let percentage = item.get("percentage").and_then(|v| v.as_f64()).unwrap_or(f64::NAN);
        let pct_ok = percentage.is_finite()
            && percentage > 0.0
            && percentage <= 100.0
            && ((percentage * 100.0).round() / 100.0 - percentage).abs() <= 0.0000001;
        if address.is_empty() || !is_kaspa_address(&address) || identifier.is_empty() || !pct_ok {
            return Err(AppError::commerce(422, "Each split payment needs a valid address, identifier, and percentage between 0 and 100 with at most two decimal places"));
        }
        out.push(json!({ "address": address, "identifier": identifier, "percentage": percentage }));
    }
    let ids: std::collections::HashSet<_> = out.iter().map(|o| o["identifier"].as_str().unwrap().to_string()).collect();
    if ids.len() != out.len() {
        return Err(AppError::commerce(422, "Split payment identifiers must be unique"));
    }
    let addrs: std::collections::HashSet<_> = out.iter().map(|o| o["address"].as_str().unwrap().to_string()).collect();
    if addrs.len() != out.len() {
        return Err(AppError::commerce(422, "Split payment addresses must be unique"));
    }
    let total: f64 = out.iter().map(|o| o["percentage"].as_f64().unwrap()).sum();
    if total > 100.0 {
        return Err(AppError::commerce(422, "Split payment percentages cannot total more than 100"));
    }
    Ok(Some(Value::Array(out).to_string()))
}

/// Parse + validate the `kaspa` object for a full store (mainAddress required).
fn parse_kaspa_required(state: &AppState, body: &Value) -> AppResult<KaspaInput> {
    let kaspa = body.get("kaspa");
    let main_address = kaspa
        .and_then(|k| k.get("mainAddress"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(main_address) = main_address else {
        return Err(AppError::Validation(vec![ValidationFailure {
            message: "The kaspa.mainAddress field is required".into(),
            rule: "required".into(),
            field: "kaspa.mainAddress".into(),
        }]));
    };
    let k = kaspa.unwrap();
    let tax_enabled = k.get("taxEnabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let tax_address = k.get("taxAddress").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let tax_percentage = k.get("taxPercentage").and_then(|v| v.as_f64());
    let split_enabled = k.get("splitEnabled").and_then(|v| v.as_bool()).unwrap_or(false);

    validate_tax(state, tax_enabled, &tax_address, tax_percentage)?;
    let split_json = normalize_splits(split_enabled, k.get("splitAddresses"))?;

    Ok(KaspaInput {
        main_address,
        tax_enabled,
        tax_address: if tax_enabled { tax_address } else { None },
        tax_percentage: if tax_enabled { tax_percentage } else { None },
        split_enabled,
        split_json,
    })
}

async fn find_setup(
    state: &AppState,
    user_id: i64,
    store_id: i64,
    store_is_default: bool,
) -> AppResult<Option<SetupRow>> {
    let row = sqlx::query_as::<_, SetupRow>(&format!(
        "SELECT {SETUP_COLS} FROM setups WHERE user_id = $1 AND store_id = $2"
    ))
    .bind(user_id)
    .bind(store_id)
    .fetch_optional(&state.db.pool)
    .await?;
    if row.is_some() {
        return Ok(row);
    }
    if !store_is_default {
        return Ok(None);
    }
    // adopt a legacy (store_id IS NULL) setup onto the default store
    let legacy = sqlx::query_as::<_, SetupRow>(&format!(
        "SELECT {SETUP_COLS} FROM setups WHERE user_id = $1 AND store_id IS NULL ORDER BY id ASC"
    ))
    .bind(user_id)
    .fetch_optional(&state.db.pool)
    .await?;
    if let Some(mut row) = legacy {
        sqlx::query("UPDATE setups SET store_id = $1 WHERE id = $2")
            .bind(store_id)
            .bind(row.id)
            .execute(&state.db.pool)
            .await?;
        row.store_id = Some(store_id);
        return Ok(Some(row));
    }
    Ok(None)
}

/// Insert or update the kaspa section of a setup (storeSetupForStore).
async fn upsert_kaspa_setup(
    state: &AppState,
    user_id: i64,
    store_id: i64,
    store_is_default: bool,
    kaspa: &KaspaInput,
    redirect_url: Option<String>,
    webhook_url: Option<String>,
) -> AppResult<SetupRow> {
    let existing = find_setup(state, user_id, store_id, store_is_default).await?;
    let now = now_iso();
    let tax_pct = kaspa.tax_percentage.map(|p| p.to_string());

    if let Some(row) = existing {
        sqlx::query(
            "UPDATE setups SET kaspa_main_address = $1, kaspa_tax_enabled = $2, kaspa_tax_address = $3, \
             kaspa_tax_percentage = $4, kaspa_split_enabled = $5, kaspa_split_addresses = $6, \
             redirect_url = $7, webhook_url = $8, updated_at = $9 WHERE id = $10",
        )
        .bind(&kaspa.main_address)
        .bind(kaspa.tax_enabled as i64)
        .bind(&kaspa.tax_address)
        .bind(&tax_pct)
        .bind(kaspa.split_enabled as i64)
        .bind(&kaspa.split_json)
        .bind(&redirect_url)
        .bind(&webhook_url)
        .bind(&now)
        .bind(row.id)
        .execute(&state.db.pool)
        .await?;
    } else {
        sqlx::query(
            "INSERT INTO setups (user_id, store_id, tos_agreed, kaspa_main_address, kaspa_tax_enabled, \
             kaspa_tax_address, kaspa_tax_percentage, kaspa_split_enabled, kaspa_split_addresses, \
             redirect_url, webhook_url, created_at, updated_at) \
             VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(user_id)
        .bind(store_id)
        .bind(&kaspa.main_address)
        .bind(kaspa.tax_enabled as i64)
        .bind(&kaspa.tax_address)
        .bind(&tax_pct)
        .bind(kaspa.split_enabled as i64)
        .bind(&kaspa.split_json)
        .bind(&redirect_url)
        .bind(&webhook_url)
        .bind(&now)
        .bind(&now)
        .execute(&state.db.pool)
        .await?;
    }

    sqlx::query("UPDATE users SET onboarded = 1 WHERE id = $1")
        .bind(user_id)
        .execute(&state.db.pool)
        .await?;

    Ok(find_setup(state, user_id, store_id, store_is_default).await?.unwrap())
}

// --- handlers: default store (/api/setup) ---

/// `GET /api/setup`
pub async fn index(auth: AuthMerchant, State(state): State<AppState>) -> AppResult<Json<Value>> {
    let store_id = ensure_default_store(&state, auth.user_id).await?;
    let setup = find_setup(&state, auth.user_id, store_id, true).await?;
    Ok(Json(setup.map(|s| serialize_setup(&state, &s)).unwrap_or(Value::Null)))
}

/// `POST /api/setup`
pub async fn store(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let store_id = ensure_default_store(&state, auth.user_id).await?;
    let setup = store_setup_for_store(&state, auth.user_id, store_id, true, &body).await?;
    Ok(Json(serialize_setup(&state, &setup)))
}

/// `PUT /api/setup`
pub async fn update(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let store_id = ensure_default_store(&state, auth.user_id).await?;
    let setup = update_setup_for_store(&state, auth.user_id, store_id, true, &body).await?;
    Ok(Json(serialize_setup(&state, &setup)))
}

// --- handlers: per-store (/api/stores/:id/setup) ---

/// `GET /api/stores/:id/setup`
pub async fn store_show(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> AppResult<Json<Value>> {
    let (store_id, is_default) = resolve_owned_store(&state, auth.user_id, id).await?;
    let setup = find_setup(&state, auth.user_id, store_id, is_default).await?;
    Ok(Json(setup.map(|s| serialize_setup(&state, &s)).unwrap_or(Value::Null)))
}

/// `POST /api/stores/:id/setup`
pub async fn store_store(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let (store_id, is_default) = resolve_owned_store(&state, auth.user_id, id).await?;
    let setup = store_setup_for_store(&state, auth.user_id, store_id, is_default, &body).await?;
    Ok(Json(serialize_setup(&state, &setup)))
}

/// `PUT /api/stores/:id/setup`
pub async fn store_update(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let (store_id, is_default) = resolve_owned_store(&state, auth.user_id, id).await?;
    let setup = update_setup_for_store(&state, auth.user_id, store_id, is_default, &body).await?;
    Ok(Json(serialize_setup(&state, &setup)))
}

/// `POST /api/stores/:id/setup/clone`
pub async fn store_clone(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let source_id = source_store_id(&body)?;
    let sections: Vec<String> = SETUP_SECTIONS.iter().map(|s| s.to_string()).collect();
    let setup = copy_sections(&state, auth.user_id, id, source_id, &sections).await?;
    Ok(Json(serialize_setup(&state, &setup)))
}

/// `POST /api/stores/:id/setup/copy` and `/sync`
pub async fn store_copy(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let source_id = source_store_id(&body)?;
    let sections = sections_input(&body)?;
    let setup = copy_sections(&state, auth.user_id, id, source_id, &sections).await?;
    Ok(Json(serialize_setup(&state, &setup)))
}

// --- core service logic ---

async fn store_setup_for_store(
    state: &AppState,
    user_id: i64,
    store_id: i64,
    is_default: bool,
    body: &Value,
) -> AppResult<SetupRow> {
    let kaspa = parse_kaspa_required(state, body)?;
    let redirect_url = body.get("redirectUrl").and_then(|v| v.as_str()).map(|s| s.to_string());
    let webhook_url = body.get("webhookUrl").and_then(|v| v.as_str()).map(|s| s.to_string());
    upsert_kaspa_setup(state, user_id, store_id, is_default, &kaspa, redirect_url, webhook_url).await
}

async fn update_setup_for_store(
    state: &AppState,
    user_id: i64,
    store_id: i64,
    is_default: bool,
    body: &Value,
) -> AppResult<SetupRow> {
    let setup = find_setup(state, user_id, store_id, is_default)
        .await?
        .ok_or_else(|| AppError::commerce(404, "Setup not found"))?;

    let now = now_iso();
    if let Some(k) = body.get("kaspa").filter(|v| !v.is_null()) {
        // merge against existing
        let main_address = k.get("mainAddress").and_then(|v| v.as_str()).map(|s| s.trim().to_string());
        let main_address = match main_address.filter(|s| !s.is_empty()) {
            Some(a) => a,
            None => {
                return Err(AppError::Validation(vec![ValidationFailure {
                    message: "The kaspa.mainAddress field is required".into(),
                    rule: "required".into(),
                    field: "kaspa.mainAddress".into(),
                }]))
            }
        };
        let tax_enabled = k.get("taxEnabled").and_then(|v| v.as_bool()).unwrap_or(setup.kaspa_tax_enabled.unwrap_or(0) != 0);
        let tax_address = if k.get("taxAddress").is_some() {
            k.get("taxAddress").and_then(|v| v.as_str()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        } else {
            setup.kaspa_tax_address.clone()
        };
        let tax_percentage = if k.get("taxPercentage").is_some() {
            k.get("taxPercentage").and_then(|v| v.as_f64())
        } else {
            setup.kaspa_tax_percentage.as_deref().and_then(|s| s.parse().ok())
        };
        let split_enabled = k.get("splitEnabled").and_then(|v| v.as_bool()).unwrap_or(setup.kaspa_split_enabled.unwrap_or(0) != 0);
        let split_value: Option<Value> = if k.get("splitAddresses").is_some() {
            k.get("splitAddresses").cloned()
        } else {
            setup.kaspa_split_addresses.as_deref().and_then(|s| serde_json::from_str(s).ok())
        };
        let split_json = normalize_splits(split_enabled, split_value.as_ref())?;
        validate_tax(state, tax_enabled, &tax_address, tax_percentage)?;

        let tax_pct = if tax_enabled { tax_percentage.map(|p| p.to_string()) } else { None };
        sqlx::query(
            "UPDATE setups SET kaspa_main_address = $1, kaspa_tax_enabled = $2, kaspa_tax_address = $3, \
             kaspa_tax_percentage = $4, kaspa_split_enabled = $5, kaspa_split_addresses = $6, updated_at = $7 WHERE id = $8",
        )
        .bind(&main_address)
        .bind(tax_enabled as i64)
        .bind(if tax_enabled { tax_address } else { None })
        .bind(&tax_pct)
        .bind(split_enabled as i64)
        .bind(&split_json)
        .bind(&now)
        .bind(setup.id)
        .execute(&state.db.pool)
        .await?;
    }

    if let Some(r) = body.get("redirectUrl").and_then(|v| v.as_str()) {
        sqlx::query("UPDATE setups SET redirect_url = $1, updated_at = $2 WHERE id = $3")
            .bind(r).bind(&now).bind(setup.id).execute(&state.db.pool).await?;
    }
    if let Some(w) = body.get("webhookUrl").and_then(|v| v.as_str()) {
        sqlx::query("UPDATE setups SET webhook_url = $1, updated_at = $2 WHERE id = $3")
            .bind(w).bind(&now).bind(setup.id).execute(&state.db.pool).await?;
    }

    Ok(find_setup(state, user_id, store_id, is_default).await?.unwrap())
}

async fn copy_sections(
    state: &AppState,
    user_id: i64,
    target_store_id_path: i64,
    source_store_id: i64,
    sections: &[String],
) -> AppResult<SetupRow> {
    let (source_id, source_default) = resolve_owned_store(state, user_id, source_store_id).await?;
    let (target_id, target_default) = resolve_owned_store(state, user_id, target_store_id_path).await?;

    let source = find_setup(state, user_id, source_id, source_default)
        .await?
        .ok_or_else(|| AppError::commerce(404, "Source setup not found"))?;

    let mut target = match find_setup(state, user_id, target_id, target_default).await? {
        Some(t) => t,
        None => new_setup_row(user_id, target_id),
    };
    let existing_id = if target.id != 0 { Some(target.id) } else { None };

    apply_sections(&source, &mut target, sections);
    upsert_full_setup(state, &target, existing_id).await?;

    Ok(find_setup(state, user_id, target_id, target_default).await?.unwrap())
}

fn new_setup_row(user_id: i64, store_id: i64) -> SetupRow {
    SetupRow {
        id: 0,
        user_id,
        store_id: Some(store_id),
        tos_agreed: Some(1),
        kaspa_main_address: None,
        kaspa_tax_enabled: Some(0),
        kaspa_tax_address: None,
        kaspa_tax_percentage: None,
        kaspa_split_enabled: Some(0),
        kaspa_split_addresses: None,
        igra_main_address: None,
        igra_tax_enabled: Some(0),
        igra_tax_address: None,
        igra_tax_percentage: None,
        igra_split_enabled: Some(0),
        igra_split_addresses: None,
        kasplex_main_address: None,
        kasplex_tax_enabled: Some(0),
        kasplex_tax_address: None,
        kasplex_tax_percentage: None,
        kasplex_split_enabled: Some(0),
        kasplex_split_addresses: None,
        redirect_url: None,
        webhook_url: None,
        created_at: None,
        updated_at: None,
    }
}

fn apply_sections(source: &SetupRow, target: &mut SetupRow, sections: &[String]) {
    for section in sections {
        match section.as_str() {
            "payout" => {
                target.kaspa_main_address = source.kaspa_main_address.clone();
                target.igra_main_address = source.igra_main_address.clone();
                target.kasplex_main_address = source.kasplex_main_address.clone();
            }
            "tax" => {
                target.kaspa_tax_enabled = source.kaspa_tax_enabled;
                target.kaspa_tax_address = source.kaspa_tax_address.clone();
                target.kaspa_tax_percentage = source.kaspa_tax_percentage.clone();
                target.igra_tax_enabled = source.igra_tax_enabled;
                target.igra_tax_address = source.igra_tax_address.clone();
                target.igra_tax_percentage = source.igra_tax_percentage.clone();
                target.kasplex_tax_enabled = source.kasplex_tax_enabled;
                target.kasplex_tax_address = source.kasplex_tax_address.clone();
                target.kasplex_tax_percentage = source.kasplex_tax_percentage.clone();
            }
            "split" => {
                target.kaspa_split_enabled = source.kaspa_split_enabled;
                target.kaspa_split_addresses = source.kaspa_split_addresses.clone();
                target.igra_split_enabled = source.igra_split_enabled;
                target.igra_split_addresses = source.igra_split_addresses.clone();
                target.kasplex_split_enabled = source.kasplex_split_enabled;
                target.kasplex_split_addresses = source.kasplex_split_addresses.clone();
            }
            "redirects" => target.redirect_url = source.redirect_url.clone(),
            "webhook" => target.webhook_url = source.webhook_url.clone(),
            _ => {}
        }
    }
}

async fn upsert_full_setup(state: &AppState, t: &SetupRow, existing_id: Option<i64>) -> AppResult<()> {
    let now = now_iso();
    let b = |o: Option<i64>| o.unwrap_or(0);
    if let Some(id) = existing_id {
        sqlx::query(
            "UPDATE setups SET kaspa_main_address=$1, kaspa_tax_enabled=$2, kaspa_tax_address=$3, \
             kaspa_tax_percentage=$4, kaspa_split_enabled=$5, kaspa_split_addresses=$6, \
             igra_main_address=$7, igra_tax_enabled=$8, igra_tax_address=$9, igra_tax_percentage=$10, \
             igra_split_enabled=$11, igra_split_addresses=$12, kasplex_main_address=$13, kasplex_tax_enabled=$14, \
             kasplex_tax_address=$15, kasplex_tax_percentage=$16, kasplex_split_enabled=$17, kasplex_split_addresses=$18, \
             redirect_url=$19, webhook_url=$20, updated_at=$21 WHERE id=$22",
        )
        .bind(&t.kaspa_main_address).bind(b(t.kaspa_tax_enabled)).bind(&t.kaspa_tax_address)
        .bind(&t.kaspa_tax_percentage).bind(b(t.kaspa_split_enabled)).bind(&t.kaspa_split_addresses)
        .bind(&t.igra_main_address).bind(b(t.igra_tax_enabled)).bind(&t.igra_tax_address).bind(&t.igra_tax_percentage)
        .bind(b(t.igra_split_enabled)).bind(&t.igra_split_addresses).bind(&t.kasplex_main_address).bind(b(t.kasplex_tax_enabled))
        .bind(&t.kasplex_tax_address).bind(&t.kasplex_tax_percentage).bind(b(t.kasplex_split_enabled)).bind(&t.kasplex_split_addresses)
        .bind(&t.redirect_url).bind(&t.webhook_url).bind(&now).bind(id)
        .execute(&state.db.pool).await?;
    } else {
        sqlx::query(
            "INSERT INTO setups (user_id, store_id, tos_agreed, kaspa_main_address, kaspa_tax_enabled, \
             kaspa_tax_address, kaspa_tax_percentage, kaspa_split_enabled, kaspa_split_addresses, \
             igra_main_address, igra_tax_enabled, igra_tax_address, igra_tax_percentage, igra_split_enabled, \
             igra_split_addresses, kasplex_main_address, kasplex_tax_enabled, kasplex_tax_address, \
             kasplex_tax_percentage, kasplex_split_enabled, kasplex_split_addresses, redirect_url, webhook_url, \
             created_at, updated_at) VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)",
        )
        .bind(t.user_id).bind(t.store_id)
        .bind(&t.kaspa_main_address).bind(b(t.kaspa_tax_enabled)).bind(&t.kaspa_tax_address)
        .bind(&t.kaspa_tax_percentage).bind(b(t.kaspa_split_enabled)).bind(&t.kaspa_split_addresses)
        .bind(&t.igra_main_address).bind(b(t.igra_tax_enabled)).bind(&t.igra_tax_address).bind(&t.igra_tax_percentage)
        .bind(b(t.igra_split_enabled)).bind(&t.igra_split_addresses).bind(&t.kasplex_main_address).bind(b(t.kasplex_tax_enabled))
        .bind(&t.kasplex_tax_address).bind(&t.kasplex_tax_percentage).bind(b(t.kasplex_split_enabled)).bind(&t.kasplex_split_addresses)
        .bind(&t.redirect_url).bind(&t.webhook_url).bind(&now).bind(&now)
        .execute(&state.db.pool).await?;
    }
    Ok(())
}

fn source_store_id(body: &Value) -> AppResult<i64> {
    body.get("sourceStoreId")
        .and_then(|v| v.as_i64())
        .filter(|n| *n > 0)
        .ok_or_else(|| {
            AppError::Validation(vec![ValidationFailure {
                message: "The sourceStoreId field is required".into(),
                rule: "required".into(),
                field: "sourceStoreId".into(),
            }])
        })
}

fn sections_input(body: &Value) -> AppResult<Vec<String>> {
    let arr = body.get("sections").and_then(|v| v.as_array());
    let mut out = Vec::new();
    match arr {
        Some(a) if !a.is_empty() => {
            for (i, item) in a.iter().enumerate() {
                match item.as_str() {
                    Some(s) if SETUP_SECTIONS.contains(&s) => out.push(s.to_string()),
                    _ => {
                        return Err(AppError::Validation(vec![ValidationFailure {
                            message: format!("The selected sections.{i} is invalid"),
                            rule: "enum".into(),
                            field: format!("sections.{i}"),
                        }]))
                    }
                }
            }
            Ok(out)
        }
        _ => Err(AppError::Validation(vec![ValidationFailure {
            message: "The sections field must have at least 1 items".into(),
            rule: "minLength".into(),
            field: "sections".into(),
        }])),
    }
}
