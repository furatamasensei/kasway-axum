//! Database layer for the Kasway Axum API.
//!
//! Wraps a PostgreSQL connection pool (sqlx) and runs the embedded migrations.
//! Mirrors the schema produced by the AdonisJS/Lucid migrations in
//! `kasway-v2-api/database/migrations`, adapted to PostgreSQL.

use sqlx::postgres::{PgPoolOptions, PgConnectOptions};
use sqlx::PgPool;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};

pub use sqlx;

/// A disposable database is fair game for the sweeper once it is this old.
/// Long enough that a run in progress is never a candidate, short enough that
/// the leftovers of the previous run go away at the start of the next one.
const STALE_AFTER_MS: u128 = 10 * 60 * 1000;

/// Shared connection pool handle.
#[derive(Clone, Debug)]
pub struct Db {
    pub pool: PgPool,
}

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

impl Db {
    /// Connect to a PostgreSQL database at `url` (e.g.
    /// `postgres://user:pass@host:5432/kasway`) and run all pending
    /// migrations.
    pub async fn connect(url: &str) -> Result<Self, DbError> {
        let opts = PgConnectOptions::from_str(url)?;

        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect_with(opts)
            .await?;

        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    /// Create a fresh, disposable PostgreSQL database (unique name per call)
    /// and connect to it. Used by the integration-test harness so every test
    /// gets an isolated schema, mirroring the old in-memory SQLite behavior.
    ///
    /// The server/credentials come from `DATABASE_URL` (default
    /// `postgres://postgres:postgres@localhost:5432/kasway`); the database name
    /// in that URL is ignored — the admin connection uses the `postgres`
    /// maintenance database to `CREATE DATABASE kasway_test_<unique>`.
    pub async fn connect_memory() -> Result<Self, DbError> {
        let base = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/kasway".to_string());

        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let db_name = format!(
            "kasway_test_{}_{}_{}",
            std::process::id(),
            now_ms(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        );
        Self::connect_fresh(&base, &db_name).await
    }

    /// `connect_memory` with a caller-chosen server and database name. The name
    /// must embed a millisecond epoch (see [`disposable_created_ms`]) or the
    /// sweeper will never reclaim it.
    pub async fn connect_fresh(base_url: &str, db_name: &str) -> Result<Self, DbError> {
        let opts = PgConnectOptions::from_str(base_url)?;

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(opts.clone().database("postgres"))
            .await?;

        // Nothing drops these databases at the end of a run: a test that panics,
        // a cancelled `cargo test`, or the smoke example (which keeps its
        // database on purpose) all leave one behind, and they used to pile up
        // until the disk was full. Reclaiming last run's leftovers here is the
        // only cleanup that runs unconditionally.
        static SWEPT: AtomicBool = AtomicBool::new(false);
        if !SWEPT.swap(true, Ordering::Relaxed) {
            sweep_disposable(&admin).await;
        }

        sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
            .execute(&admin)
            .await?;
        admin.close().await;

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(opts.database(db_name))
            .await?;
        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    pub async fn migrate(&self) -> Result<(), DbError> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Millisecond epoch embedded in a disposable database name, or `None` if the
/// name is not one of ours. Both shapes carry it as their only 13-digit
/// segment: `kasway_test_<pid>_<ms>_<counter>` and `kasway_smoke_<ms>`.
fn disposable_created_ms(name: &str) -> Option<u128> {
    if !name.starts_with("kasway_test_") && !name.starts_with("kasway_smoke_") {
        return None;
    }
    name.split('_')
        .filter_map(|s| s.parse::<u128>().ok())
        .find(|&n| n > 1_000_000_000_000)
}

/// Drop disposable databases left over by earlier runs.
///
/// Deliberately best-effort: every error is swallowed, because failing to
/// reclaim disk must never fail a test. `DROP DATABASE` is issued *without*
/// `FORCE`, so a database that a concurrently running test process is still
/// connected to errors out and is skipped rather than yanked out from under it.
async fn sweep_disposable(admin: &PgPool) {
    let now = now_ms();
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT datname FROM pg_database \
         WHERE datname LIKE 'kasway\\_test\\_%' OR datname LIKE 'kasway\\_smoke\\_%'",
    )
    .fetch_all(admin)
    .await
    .unwrap_or_default();

    for name in names {
        let Some(created) = disposable_created_ms(&name) else {
            continue;
        };
        if now.saturating_sub(created) < STALE_AFTER_MS {
            continue;
        }
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{name}\""))
            .execute(admin)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::disposable_created_ms;

    #[test]
    fn only_our_disposable_names_are_sweepable() {
        assert_eq!(
            disposable_created_ms("kasway_test_4242_1753900000000_7"),
            Some(1753900000000)
        );
        assert_eq!(
            disposable_created_ms("kasway_smoke_1753900000000"),
            Some(1753900000000)
        );
        // Real databases must never be reclaimed.
        assert_eq!(disposable_created_ms("kasway"), None);
        assert_eq!(disposable_created_ms("kasway_e2e"), None);
        assert_eq!(disposable_created_ms("postgres"), None);
        // Ours in shape but with no timestamp to age: left alone, not guessed at.
        assert_eq!(disposable_created_ms("kasway_test_manual"), None);
    }
}
