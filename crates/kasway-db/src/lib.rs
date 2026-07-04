//! Database layer for the Kasway Axum API.
//!
//! Wraps a PostgreSQL connection pool (sqlx) and runs the embedded migrations.
//! Mirrors the schema produced by the AdonisJS/Lucid migrations in
//! `kasway-v2-api/database/migrations`, adapted to PostgreSQL.

use sqlx::postgres::{PgPoolOptions, PgConnectOptions};
use sqlx::PgPool;
use std::str::FromStr;

pub use sqlx;

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
        let opts = PgConnectOptions::from_str(&base)?;

        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let db_name = format!(
            "kasway_test_{}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(opts.clone().database("postgres"))
            .await?;
        sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
            .execute(&admin)
            .await?;
        admin.close().await;

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(opts.database(&db_name))
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
