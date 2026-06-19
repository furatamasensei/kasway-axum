//! Database layer for the Kasway Axum API.
//!
//! Wraps a SQLite connection pool (sqlx) and runs the embedded migrations.
//! Mirrors the schema produced by the AdonisJS/Lucid migrations in
//! `kasway-v2-api/database/migrations`, adapted to SQLite.

use sqlx::sqlite::{SqlitePoolOptions, SqliteConnectOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

pub use sqlx;

/// Shared connection pool handle.
#[derive(Clone, Debug)]
pub struct Db {
    pub pool: SqlitePool,
}

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

impl Db {
    /// Connect to a SQLite database at `url` (e.g. `sqlite::memory:` or
    /// `sqlite:///abs/path/kasway.db`), creating the file if needed, and run
    /// all pending migrations.
    pub async fn connect(url: &str) -> Result<Self, DbError> {
        let opts = SqliteConnectOptions::from_str(url)?
            .create_if_missing(true)
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;

        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    /// Connect to a fresh in-memory database (one shared connection so the
    /// schema survives across queries). Used by the integration test harness.
    pub async fn connect_memory() -> Result<Self, DbError> {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")?.foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
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
