//! `GET /api/currencies` -> CurrenciesController.index
//!
//! Adonis: `Currency.all()` returns rows ordered by id DESC; `.toReversed()`
//! flips that to id ASC. Serialized via Lucid (camelCase keys).

use crate::auth::AuthMerchant;
use crate::error::AppResult;
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use serde::Serialize;

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Currency {
    pub id: i64,
    #[serde(rename = "type")]
    pub r#type: String,
    pub code: String,
    pub name: String,
    pub symbol: String,
    pub country: String,
    pub locale: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

pub async fn index(
    _auth: AuthMerchant,
    State(state): State<AppState>,
) -> AppResult<Json<Vec<Currency>>> {
    let currencies = sqlx::query_as::<_, Currency>(
        "SELECT id, type, code, name, symbol, country, locale, created_at, updated_at \
         FROM currencies ORDER BY id ASC",
    )
    .fetch_all(&state.db.pool)
    .await?;

    Ok(Json(currencies))
}
