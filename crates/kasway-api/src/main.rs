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

    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@db:5432/kasway".to_string());
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

    // Background chain observer (CHAIN_OBSERVER_ENABLED; default on only when
    // KASPA_NODE_URL is configured).
    if kasway_api::chain_observer::enabled_from_env() {
        kasway_api::chain_observer::spawn(state.clone());
    } else {
        tracing::info!("chain observer disabled (CHAIN_OBSERVER_ENABLED / KASPA_NODE_URL unset)");
    }

    // Background covenant keeper (COVENANT_KEEPER_ENABLED; default on only when a
    // keeper fee key and KASPA_NODE_URL are configured). Auto-captures funded
    // covenants to the merchant after the capture window (no auto-refund).
    if kasway_api::covenant_keeper::keeper_enabled("COVENANT_KEEPER_ENABLED") {
        kasway_api::covenant_keeper::spawn(state.clone());
    } else {
        tracing::info!("covenant keeper disabled (COVENANT_KEEPER_ENABLED / fee key / KASPA_NODE_URL unset)");
    }

    // Background subscription biller (SUBSCRIPTION_BILLER_ENABLED, default on).
    // Mints due subscription cycles/invoices; needs no chain access.
    if kasway_api::subscription_biller::enabled_from_env() {
        kasway_api::subscription_biller::spawn(state.clone());
    } else {
        tracing::info!("subscription biller disabled via SUBSCRIPTION_BILLER_ENABLED");
    }

    // Background invoice expirer (INVOICE_EXPIRER_ENABLED, default on). Every
    // KPR-1 payment address is single-use and payable for at most 15 minutes;
    // timely submissions remain open while confirmations finish.
    if kasway_api::invoice_expirer::enabled_from_env() {
        kasway_api::invoice_expirer::spawn(state.clone());
    } else {
        tracing::info!("invoice expirer disabled via INVOICE_EXPIRER_ENABLED");
    }

    let app = kasway_api::build_router(state);

    let addr = std::env::var("HOST_PORT").unwrap_or_else(|_| "0.0.0.0:3333".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("kasway-api listening on {addr}");
    // ConnectInfo: the rate limiter needs the peer address as a fallback when the
    // request carries no proxy IP header.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}
