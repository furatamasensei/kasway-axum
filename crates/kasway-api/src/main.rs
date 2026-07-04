use std::sync::Arc;

use kasway_api::state::{AppConfig, AppState};
use kasway_db::Db;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://kasway.db".to_string());
    let db = Db::connect(&db_url).await?;

    let state = AppState {
        db,
        config: Arc::new(AppConfig::from_env()),
    };

    // Background webhook delivery worker (WEBHOOK_WORKER_ENABLED, default on).
    if kasway_api::webhook_worker::enabled_from_env() {
        kasway_api::webhook_worker::spawn(state.clone());
    } else {
        tracing::info!("webhook delivery worker disabled via WEBHOOK_WORKER_ENABLED");
    }

    let app = kasway_api::build_router(state);

    let addr = std::env::var("HOST_PORT").unwrap_or_else(|_| "0.0.0.0:3333".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("kasway-api listening on {addr}");
    axum::serve(listener, app).await?;

    Ok(())
}
