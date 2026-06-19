//! Port of StoreContextService: resolve the request store, lazily creating the
//! per-user default store (+ included entitlement) on first use.

use crate::error::{AppError, AppResult};
use crate::state::AppState;
use crate::util::now_iso;

/// `resolveRequestStore(user, storeId)` -> store id.
pub async fn resolve_request_store(
    state: &AppState,
    user_id: i64,
    store_id: Option<i64>,
) -> AppResult<i64> {
    match store_id {
        Some(id) => {
            let found: Option<i64> =
                sqlx::query_scalar("SELECT id FROM stores WHERE user_id = ? AND id = ?")
                    .bind(user_id)
                    .bind(id)
                    .fetch_optional(&state.db.pool)
                    .await?;
            found.ok_or_else(|| AppError::commerce(404, "Store not found"))
        }
        None => ensure_default_store(state, user_id).await,
    }
}

/// `resolveOwnedStore(user, id)` -> (store id, is_default). 404 when not owned.
pub async fn resolve_owned_store(
    state: &AppState,
    user_id: i64,
    id: i64,
) -> AppResult<(i64, bool)> {
    let row: Option<(i64, i64)> =
        sqlx::query_as("SELECT id, is_default FROM stores WHERE user_id = ? AND id = ?")
            .bind(user_id)
            .bind(id)
            .fetch_optional(&state.db.pool)
            .await?;
    row.map(|(id, is_default)| (id, is_default == 1))
        .ok_or_else(|| AppError::commerce(404, "Store not found"))
}

/// assertCanCreateNewPayments: included stores always allowed; otherwise an
/// active/grace entitlement is required on an active store.
pub async fn assert_can_create_new_payments(state: &AppState, store_id: i64) -> AppResult<()> {
    let row: Option<(i64, String)> =
        sqlx::query_as("SELECT is_included, status FROM stores WHERE id = ?")
            .bind(store_id)
            .fetch_optional(&state.db.pool)
            .await?;
    let Some((is_included, status)) = row else {
        return Err(AppError::commerce(404, "Store not found"));
    };
    if is_included == 1 {
        return Ok(());
    }
    let entitlement: Option<String> = sqlx::query_scalar(
        "SELECT status FROM store_entitlements WHERE store_id = ? AND status IN ('active','grace') LIMIT 1",
    )
    .bind(store_id)
    .fetch_optional(&state.db.pool)
    .await?;
    if entitlement.is_some() && status == "active" {
        Ok(())
    } else {
        Err(AppError::commerce(402, "Active store entitlement is required"))
    }
}

/// `ensureDefaultStore(user)` -> default store id (created if absent).
pub async fn ensure_default_store(state: &AppState, user_id: i64) -> AppResult<i64> {
    let existing: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM stores WHERE user_id = ? AND is_default = 1")
            .bind(user_id)
            .fetch_all(&state.db.pool)
            .await?;

    if existing.len() > 1 {
        return Err(AppError::commerce(500, "Default store invariant violated"));
    }
    if let Some(id) = existing.first() {
        return Ok(*id);
    }

    let now = now_iso();
    let public_id = format!("store_{user_id}_default");
    let res = sqlx::query(
        "INSERT INTO stores \
         (user_id, public_id, name, slug, status, is_included, is_default, metadata, created_at, updated_at) \
         VALUES (?, ?, 'Default store', 'default', 'active', 1, 1, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(&public_id)
    .bind(r#"{"backfilled":false,"lazyCreated":true}"#)
    .bind(&now)
    .bind(&now)
    .execute(&state.db.pool)
    .await?;
    let store_id = res.last_insert_rowid();

    sqlx::query(
        "INSERT INTO store_entitlements \
         (user_id, store_id, status, source, price_cents, currency, metadata, created_at, updated_at) \
         VALUES (?, ?, 'active', 'included', 0, 'USD', ?, ?, ?)",
    )
    .bind(user_id)
    .bind(store_id)
    .bind(r#"{"lazyCreated":true}"#)
    .bind(&now)
    .bind(&now)
    .execute(&state.db.pool)
    .await?;

    Ok(store_id)
}
