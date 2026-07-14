//! AdonisJS-compatible opaque access tokens (`DbAccessTokensProvider`).
//!
//! Token string = `oat_{base64url("{id}.{secret}")}`; the DB stores only
//! `sha256(secret)` (hex). Verification decodes the id, loads the row, and
//! constant-time compares the recomputed hash. Mirrors the merchant (`oat_`)
//! guard in `config/auth.ts`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sqlx::PgPool;

use crate::util::{constant_time_eq, now_iso, sha256_hex};

const PREFIX: &str = "oat_";
const TOKEN_TYPE: &str = "auth_token";

pub struct Verified {
    pub tokenable_id: i64,
    pub token_id: i64,
}

/// Create and persist a token for `tokenable_id`; returns the public value.
pub async fn mint(pool: &PgPool, tokenable_id: i64) -> Result<String, sqlx::Error> {
    let mut secret_bytes = [0u8; 40];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
    let hash = sha256_hex(secret.as_bytes());
    let now = now_iso();

    let id: i64 = sqlx::query_scalar::<_, i64>(
        "INSERT INTO auth_access_tokens \
         (tokenable_id, type, name, hash, abilities, created_at, updated_at, last_used_at, expires_at) \
         VALUES ($1, $2, NULL, $3, '[\"*\"]', $4, $5, NULL, NULL) RETURNING id",
    )
    .bind(tokenable_id)
    .bind(TOKEN_TYPE)
    .bind(&hash)
    .bind(&now)
    .bind(&now)
    .fetch_one(pool)
    .await?;

    Ok(format!(
        "{PREFIX}{}",
        URL_SAFE_NO_PAD.encode(format!("{id}.{secret}"))
    ))
}

/// Verify a token string; returns the tokenable + token row id when valid.
pub async fn verify(pool: &PgPool, token: &str) -> Result<Option<Verified>, sqlx::Error> {
    let Some(rest) = token.strip_prefix(PREFIX) else {
        return Ok(None);
    };
    let Ok(decoded) = URL_SAFE_NO_PAD.decode(rest) else {
        return Ok(None);
    };
    let Ok(payload) = String::from_utf8(decoded) else {
        return Ok(None);
    };
    let Some((id_str, secret)) = payload.split_once('.') else {
        return Ok(None);
    };
    let Ok(token_id) = id_str.parse::<i64>() else {
        return Ok(None);
    };

    let row = sqlx::query_as::<_, (i64, String, Option<String>)>(
        "SELECT tokenable_id, hash, expires_at FROM auth_access_tokens WHERE id = $1 AND type = $2",
    )
    .bind(token_id)
    .bind(TOKEN_TYPE)
    .fetch_optional(pool)
    .await?;

    let Some((tokenable_id, stored_hash, expires_at)) = row else {
        return Ok(None);
    };

    if let Some(exp) = expires_at {
        if exp <= now_iso() {
            return Ok(None);
        }
    }

    if constant_time_eq(sha256_hex(secret.as_bytes()).as_bytes(), stored_hash.as_bytes()) {
        Ok(Some(Verified { tokenable_id, token_id }))
    } else {
        Ok(None)
    }
}

/// Delete a token row (logout). Matches `accessTokens.delete(user, identifier)`.
pub async fn delete(pool: &PgPool, token_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM auth_access_tokens WHERE id = $1")
        .bind(token_id)
        .execute(pool)
        .await?;
    Ok(())
}
