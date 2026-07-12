//! Public misc endpoint: GET /api/price
//! (PricesController.index — CoinGecko passthrough, cached 1 minute).

use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use serde_json::Value;
use std::sync::Mutex;

const CURRENCY_CODES: &str = "usd,aed,ars,aud,bdt,bhd,bmd,brl,cad,chf,clp,cny,czk,dkk,eur,gbp,gel,hkd,huf,idr,ils,inr,jpy,krw,kwd,lkr,mmk,mxn,myr,ngn,nok,nzd,php,pkr,pln,ron,rub,sar,sek,sgd,thb,try,twd,uah,vef,vnd,zar";

// 1-minute price cache (cache.getOrSet ttl '1m'). Stores (unix_secs, value).
static PRICE_CACHE: Mutex<Option<(i64, Value)>> = Mutex::new(None);

/// `GET /api/price` — CoinGecko kaspa price across all supported currencies.
pub async fn price(State(state): State<AppState>) -> Json<Value> {
    let now = chrono::Utc::now().timestamp();
    if let Ok(guard) = PRICE_CACHE.lock() {
        if let Some((ts, v)) = guard.as_ref() {
            if now - ts < 60 {
                return Json(v.clone());
            }
        }
    }

    let url = format!("{}?ids=kaspa&vs_currencies={CURRENCY_CODES}", state.config.price_api_url);
    let fetched: Value = match reqwest::Client::new().get(&url).header("accept", "application/json").send().await {
        Ok(resp) => resp.json().await.unwrap_or(Value::Null),
        Err(_) => Value::Null, // PRICE LOAD ERROR → undefined/empty (logger.error in Adonis)
    };

    if !fetched.is_null() {
        if let Ok(mut guard) = PRICE_CACHE.lock() {
            *guard = Some((now, fetched.clone()));
        }
    }
    Json(fetched)
}
