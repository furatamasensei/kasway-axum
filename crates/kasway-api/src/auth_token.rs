//! AdonisJS-compatible opaque access tokens (`DbAccessTokensProvider`).
//!
//! Token string = `{prefix}{base64url("{id}.{secret}")}`; the DB stores only
//! `sha256(secret)` (hex). Verification decodes the id, loads the row, and
//! constant-time compares the recomputed hash. Mirrors the merchant (`oat_`)
//! guard in `config/auth.ts`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::util::{constant_time_eq, now_iso};

pub struct TokenKind {
    pub table: &'static str,
    pub type_: &'static str,
    pub prefix: &'static str,
}

pub const MERCHANT: TokenKind = TokenKind {
    table: "auth_access_tokens",
    type_: "auth_token",
    prefix: "oat_",
};

pub struct Verified {
    pub tokenable_id: i64,
    pub token_id: i64,
}

fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

/// Create and persist a token for `tokenable_id`; returns the public value.
pub async fn mint(
    pool: &PgPool,
    kind: &TokenKind,
    tokenable_id: i64,
) -> Result<String, sqlx::Error> {
    let mut secret_bytes = [0u8; 40];
    rand::thread_rng().fill_bytes(&mut secret_bytes);
    let secret = URL_SAFE_NO_PAD.encode(secret_bytes);
    let hash = sha256_hex(secret.as_bytes());
    let now = now_iso();

    let sql = format!(
        "INSERT INTO {} (tokenable_id, type, name, hash, abilities, created_at, updated_at, last_used_at, expires_at) \
         VALUES ($1, $2, NULL, $3, '[\"*\"]', $4, $5, NULL, NULL) RETURNING id",
        kind.table
    );
    let id: i64 = sqlx::query_scalar::<_, i64>(&sql)
        .bind(tokenable_id)
        .bind(kind.type_)
        .bind(&hash)
        .bind(&now)
        .bind(&now)
        .fetch_one(pool)
        .await?;

    let value = format!(
        "{}{}",
        kind.prefix,
        URL_SAFE_NO_PAD.encode(format!("{}.{}", id, secret))
    );
    Ok(value)
}

/// Verify a token string; returns the tokenable + token row id when valid.
pub async fn verify(
    pool: &PgPool,
    kind: &TokenKind,
    token: &str,
) -> Result<Option<Verified>, sqlx::Error> {
    let Some(rest) = token.strip_prefix(kind.prefix) else {
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

    let sql = format!(
        "SELECT tokenable_id, hash, expires_at FROM {} WHERE id = $1 AND type = $2",
        kind.table
    );
    let row = sqlx::query_as::<_, (i64, String, Option<String>)>(&sql)
        .bind(token_id)
        .bind(kind.type_)
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
pub async fn delete(pool: &PgPool, kind: &TokenKind, token_id: i64) -> Result<(), sqlx::Error> {
    let sql = format!("DELETE FROM {} WHERE id = $1", kind.table);
    sqlx::query(&sql).bind(token_id).execute(pool).await?;
    Ok(())
}
