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

    /// Connect using the same pool configuration as [`connect`]. Retained for
    /// the integration test harness, which points `url` at a disposable
    /// PostgreSQL database.
    pub async fn connect_memory() -> Result<Self, DbError> {
        Self::connect_from_env().await
    }

    async fn connect_from_env() -> Result<Self, DbError> {
        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/kasway".to_string());
        Self::connect(&url).await
    }

    pub async fn migrate(&self) -> Result<(), DbError> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }
}
