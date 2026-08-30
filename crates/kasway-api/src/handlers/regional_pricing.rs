//! `/api/regional-pricing/*` — RegionalPricingController + RegionalPricingService.

use crate::auth::AuthMerchant;
use crate::error::{AppError, AppResult, ValidationFailure};
use crate::state::AppState;
use crate::store_context::resolve_request_store;
use crate::util::now_iso;
use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

const FALLBACK_POLICIES: &[&str] = &["fail_closed", "allow_default_price"];

#[derive(Deserialize, Default)]
pub struct StoreIdQuery {
    #[serde(rename = "storeId")]
    store_id: Option<i64>,
}

/// `GET /api/regional-pricing/countries`
pub async fn countries(
    _auth: AuthMerchant,
    State(state): State<AppState>,
) -> AppResult<Json<Value>> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT code, name FROM supported_countries ORDER BY name ASC",
    )
    .fetch_all(&state.db.pool)
    .await?;
    let data: Vec<Value> = rows.into_iter().map(|(code, name)| json!({ "code": code, "name": name })).collect();
    Ok(Json(Value::Array(data)))
}

async fn get_or_create_settings(state: &AppState, user_id: i64, store_id: i64) -> AppResult<String> {
    let existing: Option<String> =
        sqlx::query_scalar("SELECT fallback_policy FROM store_regional_pricing_settings WHERE store_id = $1")
            .bind(store_id)
            .fetch_optional(&state.db.pool)
            .await?;
    if let Some(p) = existing {
        return Ok(p);
    }
    let now = now_iso();
    sqlx::query(
        "INSERT INTO store_regional_pricing_settings (user_id, store_id, fallback_policy, created_at, updated_at) \
         VALUES ($1, $2, 'fail_closed', $3, $4)",
    )
    .bind(user_id)
    .bind(store_id)
    .bind(&now)
    .bind(&now)
    .execute(&state.db.pool)
    .await?;
    Ok("fail_closed".to_string())
}

async fn settings_payload(state: &AppState, user_id: i64, store_id: i64) -> AppResult<Value> {
    let fallback = get_or_create_settings(state, user_id, store_id).await?;
    let rows = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT ssc.country_code, sc.name FROM store_sellable_countries ssc \
         LEFT JOIN supported_countries sc ON sc.code = ssc.country_code \
         WHERE ssc.user_id = $1 AND ssc.store_id = $2 ORDER BY ssc.country_code ASC",
    )
    .bind(user_id)
    .bind(store_id)
    .fetch_all(&state.db.pool)
    .await?;

    let country_codes: Vec<Value> = rows.iter().map(|(c, _)| json!(c)).collect();
    let countries: Vec<Value> = rows
        .iter()
        .map(|(c, n)| json!({ "code": c, "name": n.clone().unwrap_or_else(|| c.clone()) }))
        .collect();

    Ok(json!({
        "fallbackPolicy": fallback,
        "countryCodes": country_codes,
        "countries": countries,
    }))
}

/// `GET /api/regional-pricing/settings`
pub async fn settings(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Query(q): Query<StoreIdQuery>,
) -> AppResult<Json<Value>> {
    let store_id = resolve_request_store(&state, auth.user_id, q.store_id).await?;
    Ok(Json(settings_payload(&state, auth.user_id, store_id).await?))
}

/// `PUT /api/regional-pricing/settings`
pub async fn update_settings(
    auth: AuthMerchant,
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> AppResult<Json<Value>> {
    let fallback = match body.get("fallbackPolicy").and_then(|v| v.as_str()) {
        Some(p) if FALLBACK_POLICIES.contains(&p) => p.to_string(),
        _ => {
            return Err(AppError::Validation(vec![ValidationFailure {
                message: "The selected fallbackPolicy is invalid".into(),
                rule: "enum".into(),
                field: "fallbackPolicy".into(),
            }]))
        }
    };
    let store_id_in = body.get("storeId").and_then(|v| v.as_i64());

    // countryCodes optional; normalize + validate
    let country_codes: Option<Vec<String>> = match body.get("countryCodes") {
        None | Some(Value::Null) => None,
        Some(Value::Array(arr)) => {
            let mut out = Vec::new();
            for item in arr {
                let code = item.as_str().unwrap_or("").trim().to_uppercase();
                if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_uppercase()) {
                    return Err(AppError::commerce(422, "countryCode must be an ISO 3166-1 alpha-2 country code"));
                }
                out.push(code);
            }
            Some(out)
        }
        Some(_) => None,
    };

    if let Some(codes) = &country_codes {
        let mut seen = std::collections::HashSet::new();
        if !codes.iter().all(|c| seen.insert(c.clone())) {
            return Err(AppError::commerce(422, "countryCodes must not contain duplicate countries"));
        }
        for code in codes {
            let supported: Option<String> =
                sqlx::query_scalar("SELECT code FROM supported_countries WHERE code = $1")
                    .bind(code)
                    .fetch_optional(&state.db.pool)
                    .await?;
            if supported.is_none() {
                return Err(AppError::commerce(422, &format!("Unsupported country code: {code}")));
            }
        }
    }

    let store_id = resolve_request_store(&state, auth.user_id, store_id_in).await?;
    let now = now_iso();

    // upsert setting
    let existing: Option<i64> =
        sqlx::query_scalar("SELECT id FROM store_regional_pricing_settings WHERE store_id = $1")
            .bind(store_id)
            .fetch_optional(&state.db.pool)
            .await?;
    if let Some(id) = existing {
        sqlx::query("UPDATE store_regional_pricing_settings SET fallback_policy = $1, updated_at = $2 WHERE id = $3")
            .bind(&fallback).bind(&now).bind(id).execute(&state.db.pool).await?;
    } else {
        sqlx::query("INSERT INTO store_regional_pricing_settings (user_id, store_id, fallback_policy, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)")
            .bind(auth.user_id).bind(store_id).bind(&fallback).bind(&now).bind(&now).execute(&state.db.pool).await?;
    }

    if let Some(codes) = &country_codes {
        sqlx::query("DELETE FROM store_sellable_countries WHERE user_id = $1 AND store_id = $2")
            .bind(auth.user_id).bind(store_id).execute(&state.db.pool).await?;
        for code in codes {
            sqlx::query("INSERT INTO store_sellable_countries (user_id, store_id, country_code, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)")
                .bind(auth.user_id).bind(store_id).bind(code).bind(&now).bind(&now).execute(&state.db.pool).await?;
        }
    }

    Ok(Json(settings_payload(&state, auth.user_id, store_id).await?))
}
