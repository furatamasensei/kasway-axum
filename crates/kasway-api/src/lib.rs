//! Kasway API — Axum port of the AdonisJS `kasway-v2-api` HTTP surface.
//!
//! `build_router` assembles the full route tree (mirroring `start/routes.ts`),
//! grouped by the same auth tiers.

pub mod auth;
pub mod auth_token;
pub mod arbitration;
pub mod chain_observer;
pub mod chain_source;
pub mod invoice_expirer;
pub mod covenant_keeper;
pub mod error;
pub mod handlers;
pub mod kaspa_wrpc;
pub mod kpr1;
pub mod password;
pub mod rate_limit;
pub mod state;
pub mod store_context;
pub mod subscription_biller;
pub mod util;
pub(crate) mod validate;
pub mod webhook_worker;

use axum::extract::DefaultBodyLimit;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderValue, Method};
use axum::routing::{delete, get, post};
use axum::Router;
use state::AppState;
use tower_http::cors::CorsLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnResponse, TraceLayer};
use tracing::Level;

/// Global request timeout applied to every route.
const REQUEST_TIMEOUT_SECS: u64 = 30;
/// Global request body cap (2 MB). The media upload route raises this to its
/// own larger limit so `medias.rs`'s streaming `MAX_SIZE` check governs uploads.
const GLOBAL_BODY_LIMIT: usize = 2 * 1024 * 1024;
/// Body cap for the media upload route (above `medias::MAX_SIZE` so the
/// handler's own streaming size check is what rejects oversized uploads).
const MEDIA_BODY_LIMIT: usize = 110 * 1024 * 1024;

/// Build the application router. Shared by the binary and the integration tests.
pub fn build_router(state: AppState) -> Router {
    // CORS: the frontend at https://kasway.xyz must reach the API at
    // https://api-staging.kasway.xyz. Credentials are allowed (cookies/auth
    // headers), which per the CORS spec forbids wildcard origin/headers, so the
    // origin and headers are listed explicitly.
    let cors = CorsLayer::new()
        .allow_origin("https://kasway.xyz".parse::<HeaderValue>().unwrap())
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::OPTIONS,
        ])
        .allow_headers([CONTENT_TYPE, AUTHORIZATION])
        .allow_credentials(true);

    Router::new()
        // --- Unauthenticated ---
        .route("/internal/healthz", get(handlers::health::healthz))
        // --- Public payments networks (paymentApiVersioning) ---
        .route("/api/payments/networks", get(handlers::payments_networks::networks))
        .route("/api/payments/networks/:network/assets", get(handlers::payments_networks::network_assets))
        // --- Internal (internalApiToken) ---
        .route(
            "/internal/payment-indexer/healthz",
            get(handlers::internal_payment_indexer::healthz),
        )
        .route(
            "/internal/payment-indexer/checkpoints",
            get(handlers::internal_payment_indexer::checkpoints),
        )
        // --- Internal KPR-1 dispute resolution (independent M-of-N arbiter panel; internal token) ---
        .route("/internal/payment-ops/kpr1/invoices/:publicId/release-arbitrated/prepare", post(handlers::internal_kpr1_ops::release_arbitrated_prepare))
        .route("/internal/payment-ops/kpr1/invoices/:publicId/release-arbitrated", post(handlers::internal_kpr1_ops::release_arbitrated))
        .route("/internal/payment-ops/kpr1/invoices/:publicId/refund-arbitrated/prepare", post(handlers::internal_kpr1_ops::refund_arbitrated_prepare))
        .route("/internal/payment-ops/kpr1/invoices/:publicId/refund-arbitrated", post(handlers::internal_kpr1_ops::refund_arbitrated_submit))
        // --- Media (merchant) ---
        // The upload route raises the global body cap so `medias.rs`'s own
        // streaming size check governs (rejecting oversize without buffering).
        .route(
            "/api/media",
            post(handlers::medias::store).layer(DefaultBodyLimit::max(MEDIA_BODY_LIMIT)),
        )
        .route("/api/media/:id", delete(handlers::medias::destroy))
        // --- Public misc (price) ---
        .route("/api/price", get(handlers::public_misc::price))
        // --- Public KPR-1 signing keys (verify intents offline) ---
        .route("/api/kpr1/signing-keys", get(handlers::kpr1_keys::index))
        // --- Public KPR-1 explorer ---
        .route("/api/explorer/kpr1/intents/:intentId", get(handlers::explorer_kpr1::show_intent))
        .route("/api/explorer/kpr1/intents/:intentId/wallet-verification", get(handlers::explorer_kpr1::wallet_verification))
        .route("/api/explorer/kpr1/intents/:intentId/settlement-proof", get(handlers::explorer_kpr1::settlement_proof_by_intent))
        .route("/api/explorer/kpr1/invoices/:publicId/settlement-proof", get(handlers::explorer_kpr1::settlement_proof_by_invoice))
        .route("/api/explorer/kpr1/payment-requests/:canonicalHash", get(handlers::explorer_kpr1::show_payment_request))
        .route("/api/explorer/kpr1/transactions/:txId", get(handlers::explorer_kpr1::show_transaction))
        .route("/api/explorer/kpr1/invoices/:publicId", get(handlers::explorer_kpr1::show_invoice))
        // --- Permissionless evaluator marketplace + encrypted case protocol ---
        // Every write is authenticated by a participant BIP-340 signature;
        // these routes intentionally do not require a Kasway account.
        .route("/api/arbitration/evaluators", get(arbitration::evaluator_index).post(arbitration::evaluator_store))
        .route("/api/arbitration/evaluators/:profileId", get(arbitration::evaluator_show))
        .route("/api/arbitration/evaluators/:profileId/reputation", get(arbitration::reputation_show))
        .route("/api/arbitration/quotes", post(arbitration::quote_store))
        .route("/api/arbitration/engagements", post(arbitration::engagement_store))
        .route("/api/arbitration/engagements/:engagementId", get(arbitration::engagement_show))
        .route("/api/arbitration/engagements/:engagementId/dispute/prepare", post(arbitration::dispute_prepare))
        .route("/api/arbitration/engagements/:engagementId/dispute/submit", post(arbitration::dispute_submit))
        .route("/api/arbitration/cases", post(arbitration::case_open))
        .route("/api/arbitration/cases/:caseId", get(arbitration::case_show))
        .route("/api/arbitration/cases/:caseId/messages", get(arbitration::message_index).post(arbitration::message_store))
        .route("/api/arbitration/cases/:caseId/decision/commit", post(arbitration::decision_commit))
        .route("/api/arbitration/cases/:caseId/decision/reveal", post(arbitration::decision_reveal))
        .route("/api/arbitration/cases/:caseId/settlement/prepare", post(arbitration::settlement_prepare))
        .route("/api/arbitration/cases/:caseId/settlement/submit", post(arbitration::settlement_submit))
        .route("/api/arbitration/cases/:caseId/mutual-settlement/prepare", post(arbitration::mutual_settlement_prepare))
        .route("/api/arbitration/cases/:caseId/mutual-settlement/submit", post(arbitration::mutual_settlement_submit))
        .route("/api/arbitration/cases/:caseId/feedback", post(arbitration::feedback_store))
        // --- Public auth (/api/auth) ---
        .route("/api/auth/login", post(handlers::auth::login))
        .route("/api/auth/register", post(handlers::auth::register))
        .route("/api/auth/profile", get(handlers::auth::profile))
        .route("/api/auth/google/redirect", get(handlers::auth::redirect_google))
        .route("/auth/google/callback", get(handlers::auth::callback_google))
        .route("/api/auth/logout", post(handlers::auth::logout))
        // --- Merchant API (auth) ---
        .route("/api/currencies", get(handlers::currencies::index))
        // --- Regional pricing ---
        .route("/api/regional-pricing/countries", get(handlers::regional_pricing::countries))
        .route(
            "/api/regional-pricing/settings",
            get(handlers::regional_pricing::settings).put(handlers::regional_pricing::update_settings),
        )
        .route(
            "/api/api-keys",
            get(handlers::api_keys::index).post(handlers::api_keys::store),
        )
        .route("/api/api-keys/:id", get(handlers::api_keys::show))
        .route("/api/api-keys/:id/revoke", post(handlers::api_keys::revoke))
        .route("/api/api-keys/:id/rotate", post(handlers::api_keys::rotate))
        .route(
            "/api/invoices",
            get(handlers::invoices::index).post(handlers::invoices::store),
        )
        .route("/api/invoices/:id", get(handlers::invoices::show))
        .route("/api/invoices/:id/cancel", post(handlers::invoices::cancel))
        // --- Payment-ops confirmation policy (auth) — read by the chain observer ---
        .route(
            "/api/payments/ops/confirmation-policy",
            get(handlers::payment_ops_settings::confirmation_policy).put(handlers::payment_ops_settings::update_confirmation_policy),
        )
        // --- Payment links (auth) ---
        .route(
            "/api/payment-links",
            get(handlers::payment_links::index).post(handlers::payment_links::store),
        )
        .route("/api/payment-links/:id", get(handlers::payment_links::show))
        .route("/api/payment-links/:id/disable", post(handlers::payment_links::disable))
        .route("/api/payment-links/:id/enable", post(handlers::payment_links::enable))
        // --- Commerce subscription plans + customers (auth) ---
        .route(
            "/api/commerce/subscription-plans",
            get(handlers::subscriptions::plans_index).post(handlers::subscriptions::plans_store),
        )
        .route(
            "/api/commerce/subscription-plans/:publicId",
            get(handlers::subscriptions::plans_show).put(handlers::subscriptions::plans_update),
        )
        .route("/api/commerce/subscription-plans/:publicId/archive", post(handlers::subscriptions::plans_archive))
        .route(
            "/api/commerce/subscription-customers",
            get(handlers::subscriptions::customers_index).post(handlers::subscriptions::customers_store),
        )
        .route(
            "/api/commerce/subscription-customers/:publicId",
            get(handlers::subscriptions::customers_show).put(handlers::subscriptions::customers_update),
        )
        // --- Commerce subscriptions (auth) ---
        .route(
            "/api/commerce/subscriptions",
            get(handlers::subscriptions::subs_index).post(handlers::subscriptions::subs_store),
        )
        .route("/api/commerce/subscriptions/:publicId", get(handlers::subscriptions::subs_show))
        .route("/api/commerce/subscriptions/:publicId/invoices", get(handlers::subscriptions::subs_invoices))
        .route("/api/commerce/subscriptions/:publicId/invoices/retry", post(handlers::subscriptions::subs_retry_invoice))
        .route("/api/commerce/subscriptions/:publicId/pause", post(handlers::subscriptions::subs_pause))
        .route("/api/commerce/subscriptions/:publicId/resume", post(handlers::subscriptions::subs_resume))
        .route("/api/commerce/subscriptions/:publicId/cancel", post(handlers::subscriptions::subs_cancel))
        // --- Commerce invoices (auth) ---
        .route("/api/commerce/invoices", post(handlers::commerce::store))
        .route("/api/commerce/invoices/:publicId", get(handlers::commerce::show))
        // --- Public checkout ---
        .route("/api/checkout/invoices/:publicId", get(handlers::checkout::show))
        .route(
            "/api/checkout/invoices/:publicId/kpr1-intent",
            get(handlers::checkout::kpr1_intent),
        )
        .route("/api/checkout/invoices/:publicId/kpr1-finalize", post(handlers::checkout::finalize_kpr1_covenant))
        .route("/api/checkout/invoices/:publicId/kpr1-release/prepare", post(handlers::checkout::prepare_kpr1_release))
        .route("/api/checkout/invoices/:publicId/kpr1-release", post(handlers::checkout::submit_kpr1_release))
        .route("/api/checkout/invoices/:publicId/kpr1-refund/prepare", post(handlers::checkout::prepare_kpr1_refund))
        .route("/api/checkout/invoices/:publicId/kpr1-refund", post(handlers::checkout::submit_kpr1_refund))
        // Tier 1 bilateral mutual settlement (customer + merchant co-sign a split).
        .route("/api/checkout/invoices/:publicId/kpr1-settle/prepare", post(handlers::checkout::prepare_kpr1_settle))
        .route("/api/checkout/invoices/:publicId/kpr1-settle", post(handlers::checkout::submit_kpr1_settle))
        .route("/api/checkout/invoices/:publicId/kpr1-payments", post(handlers::checkout::submit_kpr1_payment))
        .route("/api/checkout/links/:publicId", get(handlers::checkout::link_show))
        .route(
            "/api/checkout/links/:publicId/invoices",
            post(handlers::checkout::link_create_invoice),
        )
        // --- Public checkout: per-cycle subscription invoices ---
        .route("/api/checkout/subscriptions/:publicId", get(handlers::checkout_subscriptions::show))
        .route("/api/checkout/subscriptions/:publicId/kpr1-intent", get(handlers::checkout_subscriptions::intent))
        .route("/api/checkout/subscriptions/:publicId/cancel", post(handlers::checkout_subscriptions::cancel))
        // --- Setup (default store) ---
        .route(
            "/api/setup",
            get(handlers::setups::index)
                .post(handlers::setups::store)
                .put(handlers::setups::update),
        )
        // --- Stores ---
        .route(
            "/api/stores",
            get(handlers::stores::index).post(handlers::stores::store),
        )
        .route(
            "/api/stores/:id",
            get(handlers::stores::show).put(handlers::stores::update),
        )
        .route("/api/stores/:id/default", post(handlers::stores::set_default))
        // --- Per-store setup ---
        .route(
            "/api/stores/:id/setup",
            get(handlers::setups::store_show)
                .post(handlers::setups::store_store)
                .put(handlers::setups::store_update),
        )
        .route("/api/stores/:id/setup/clone", post(handlers::setups::store_clone))
        .route("/api/stores/:id/setup/copy", post(handlers::setups::store_copy))
        // --- Webhook endpoints (resource + controls) ---
        .route(
            "/api/webhook-endpoints",
            get(handlers::webhooks::endpoints_index).post(handlers::webhooks::endpoints_store),
        )
        .route(
            "/api/webhook-endpoints/:id",
            get(handlers::webhooks::endpoints_show)
                .put(handlers::webhooks::endpoints_update)
                .delete(handlers::webhooks::endpoints_destroy),
        )
        .route("/api/webhook-endpoints/:id/test-send", post(handlers::webhooks::endpoints_test_send))
        .route("/api/webhook-endpoints/:id/pause", post(handlers::webhooks::endpoints_pause))
        .route("/api/webhook-endpoints/:id/resume", post(handlers::webhooks::endpoints_resume))
        .route("/api/webhook-endpoints/:id/rotate-secret", post(handlers::webhooks::endpoints_rotate_secret))
        // --- Webhook deliveries ---
        .route("/api/webhook-deliveries", get(handlers::webhooks::deliveries_index))
        .route("/api/webhook-deliveries/:id", get(handlers::webhooks::deliveries_show))
        .route("/api/webhook-deliveries/:id/replay", post(handlers::webhooks::deliveries_replay))
        // --- Webhook events ---
        .route("/api/webhook-events", get(handlers::webhooks::events_index))
        .route("/api/webhook-events/:id", get(handlers::webhooks::events_show))
        .route("/api/webhook-events/:id/replay", post(handlers::webhooks::events_replay))
        // Global request timeout + body size cap. Applied after (outside) the
        // per-route media limit so that inner override still wins for uploads.
        .layer(DefaultBodyLimit::max(GLOBAL_BODY_LIMIT))
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS),
        ))
        // Rate limit the whole surface. The public checkout routes are the ones
        // that need it (unauthenticated, keyed only by an invoice id), and there
        // is no reason for an authenticated caller to exceed the budget either.
        .layer(axum::middleware::from_fn(rate_limit::limit))
        .layer(cors)
        // Access log. Outermost, so every request is accounted for — including
        // the ones rejected by CORS or timed out, which are exactly the ones a
        // confused user reports. Without this the server was silent between
        // startup and a crash: a payment could fail end-to-end and leave no
        // trace of the request that failed.
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO))
                .on_failure(DefaultOnFailure::new().level(Level::WARN)),
        )
        .with_state(state)
}
