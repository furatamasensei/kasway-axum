//! Kasway API — Axum port of the AdonisJS `kasway-v2-api` HTTP surface.
//!
//! `build_router` assembles the full route tree (mirroring `start/routes.ts`),
//! grouped by the same auth tiers. Endpoints are ported tier by tier; see
//! `ENDPOINTS.md` for the live coverage map.

pub mod auth;
pub mod auth_token;
pub mod error;
pub mod handlers;
pub mod kpr1;
pub mod password;
pub mod state;
pub mod store_context;
pub mod util;

use axum::routing::{delete, get, post};
use axum::Router;
use state::AppState;

/// Build the application router. Shared by the binary and the integration tests.
pub fn build_router(state: AppState) -> Router {
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
        // --- Internal programmable-settlement sandbox (retired → 410) ---
        .route("/internal/payment-ops/tocatta/sandbox/overview", get(handlers::internal_settlement_sandbox::overview))
        .route("/internal/payment-ops/tocatta/sandbox/splits/preview", post(handlers::internal_settlement_sandbox::split_preview))
        .route("/internal/payment-ops/tocatta/sandbox/holds/preview", post(handlers::internal_settlement_sandbox::hold_preview))
        .route("/internal/payment-ops/tocatta/sandbox/promotion-gates", get(handlers::internal_settlement_sandbox::promotion_gates))
        // --- Internal programmable-settlement records (DB) ---
        .route(
            "/internal/payment-ops/tocatta/covenants/templates",
            get(handlers::internal_settlement_records::templates).post(handlers::internal_settlement_records::store_template),
        )
        .route("/internal/payment-ops/tocatta/covenants/templates/:id/status", get(handlers::internal_settlement_records::status))
        .route("/internal/payment-ops/tocatta/covenants/templates/:id/evidence", get(handlers::internal_settlement_records::evidence))
        .route("/internal/payment-ops/tocatta/covenants/templates/:id/approvals", post(handlers::internal_settlement_records::approve))
        .route("/internal/payment-ops/tocatta/covenants/templates/:id/disable", post(handlers::internal_settlement_records::disable))
        .route("/internal/payment-ops/tocatta/covenants/artifacts", post(handlers::internal_settlement_records::store_artifact))
        .route("/internal/payment-ops/tocatta/covenants/executions", post(handlers::internal_settlement_records::store_execution))
        // --- Internal observability (DB-derived) + tn10 disabled status ---
        .route("/internal/payment-ops/overview", get(handlers::internal_observability::overview))
        .route("/internal/payment-ops/merchants", get(handlers::internal_observability::merchants))
        .route("/internal/payment-ops/merchants/:id", get(handlers::internal_observability::merchant))
        .route("/internal/payment-ops/failures", get(handlers::internal_observability::failures))
        .route("/internal/payment-ops/tn10/status", get(handlers::internal_observability::tn10_status))
        // --- Internal SLO (DB-derived) ---
        .route("/internal/payment-ops/slo", get(handlers::internal_slo::slo))
        .route("/internal/payment-ops/slo/queues", get(handlers::internal_slo::queues))
        .route("/internal/payment-ops/slo/incidents", get(handlers::internal_slo::incidents))
        // --- Internal static contracts ---
        .route("/internal/payment-ops/tocatta/silverscript/templates", get(handlers::internal_silverscript::index))
        .route("/internal/payment-ops/security/launch-gate", get(handlers::internal_security_gate::show))
        .route("/internal/payment-ops/tocatta/production/status", get(handlers::internal_tocatta_production::status))
        .route("/internal/payment-ops/tocatta/production/cutover-runbook", get(handlers::internal_tocatta_production::cutover_runbook_handler))
        .route("/internal/payment-ops/tocatta/production/reconciliation", get(handlers::internal_tocatta_production::reconciliation))
        .route("/internal/payment-ops/tocatta/production/incidents", get(handlers::internal_tocatta_production::incidents))
        .route("/internal/payment-ops/tocatta/production/communications", get(handlers::internal_tocatta_production::communications))
        .route("/internal/payment-ops/tocatta/beta/status", get(handlers::internal_tocatta_beta::status))
        .route("/internal/payment-ops/tocatta/beta/eligibility", post(handlers::internal_tocatta_beta::eligibility))
        .route("/internal/payment-ops/tocatta/beta/reporting", get(handlers::internal_tocatta_beta::reporting))
        .route("/internal/payment-ops/tocatta/beta/contracts", get(handlers::internal_tocatta_beta::contract))
        // --- Internal KPR-1 ops (DB evidence) ---
        .route("/internal/payment-ops/kpr1/intents/:intentId/evidence", get(handlers::internal_kpr1_ops::evidence))
        // --- Media (merchant) ---
        .route("/api/media", post(handlers::medias::store))
        .route("/api/media/:id", delete(handlers::medias::destroy))
        // --- Public bug reports ---
        .route("/api/bug-reports", post(handlers::bug_reports::store))
        // --- Public docs (static) ---
        .route("/openapi.json", get(handlers::docs::openapi))
        .route("/docs", get(handlers::docs::docs))
        // --- Public KPR-1 explorer ---
        .route("/api/explorer/kpr1/intents/:intentId", get(handlers::explorer_kpr1::show_intent))
        .route("/api/explorer/kpr1/intents/:intentId/wallet-verification", get(handlers::explorer_kpr1::wallet_verification))
        .route("/api/explorer/kpr1/payment-requests/:canonicalHash", get(handlers::explorer_kpr1::show_payment_request))
        .route("/api/explorer/kpr1/transactions/:txId", get(handlers::explorer_kpr1::show_transaction))
        .route("/api/explorer/kpr1/invoices/:publicId", get(handlers::explorer_kpr1::show_invoice))
        // --- Public auth (/api/auth) ---
        .route("/api/auth/login", post(handlers::auth::login))
        .route("/api/auth/register", post(handlers::auth::register))
        .route("/api/auth/profile", get(handlers::auth::profile))
        .route("/api/auth/google/redirect", get(handlers::auth::redirect_google))
        .route("/auth/google/callback", get(handlers::auth::callback_google))
        .route("/api/auth/logout", post(handlers::auth::logout))
        // --- Merchant API (auth) ---
        .route("/api/currencies", get(handlers::currencies::index))
        // --- Metrics ---
        .route("/api/metrics/overview", get(handlers::metrics::overview))
        .route("/api/metrics/revenue", get(handlers::metrics::revenue))
        .route("/api/metrics/payments", get(handlers::metrics::payments))
        .route("/api/metrics/payment-observations", get(handlers::metrics::payment_observations))
        .route("/api/metrics/payment-credits", get(handlers::metrics::payment_credits))
        .route("/api/metrics/webhooks", get(handlers::metrics::webhooks))
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
        // --- Payment-ops close-periods (auth) ---
        .route(
            "/api/payments/ops/close-periods",
            get(handlers::payment_close_periods::index).post(handlers::payment_close_periods::store),
        )
        .route("/api/payments/ops/close-periods/:id", get(handlers::payment_close_periods::show))
        .route("/api/payments/ops/close-periods/:id/reopen", post(handlers::payment_close_periods::reopen))
        // --- Payment-ops exceptions (auth) ---
        .route("/api/payments/ops/exceptions", get(handlers::payment_exceptions::index))
        .route("/api/payments/ops/exceptions/:id/resolution", get(handlers::payment_exceptions::resolution))
        .route("/api/payments/ops/exceptions/:id/resolve", post(handlers::payment_exceptions::resolve))
        .route("/api/payments/ops/exceptions/:id/dismiss", post(handlers::payment_exceptions::dismiss))
        // --- Payment-ops risk (auth) ---
        .route("/api/payments/ops/risk/catalog", get(handlers::payment_risk::catalog))
        .route("/api/payments/ops/risk/rule-hits", get(handlers::payment_risk::index))
        .route("/api/payments/ops/risk/rule-hits/:id", get(handlers::payment_risk::show))
        .route("/api/payments/ops/risk/rule-hits/:id/acknowledge", post(handlers::payment_risk::acknowledge))
        .route("/api/payments/ops/risk/rule-hits/:id/dismiss", post(handlers::payment_risk::dismiss))
        .route("/api/payments/ops/risk/rule-hits/:id/notes", post(handlers::payment_risk::note))
        .route("/api/payments/ops/risk/report", get(handlers::payment_risk::report))
        // --- Payment-ops anomalies (auth) ---
        .route("/api/payments/ops/anomalies", get(handlers::payment_anomalies::index))
        .route("/api/payments/ops/anomalies/:id", get(handlers::payment_anomalies::show))
        .route("/api/payments/ops/anomalies/:id/acknowledge", post(handlers::payment_anomalies::acknowledge))
        .route("/api/payments/ops/anomalies/:id/dismiss", post(handlers::payment_anomalies::dismiss))
        // --- Payment-ops retention policy (auth) ---
        .route(
            "/api/payments/ops/retention-policy",
            get(handlers::payment_retention::policy).put(handlers::payment_retention::update_policy),
        )
        .route("/api/payments/ops/retention-runs", get(handlers::payment_retention::retention_runs))
        // --- Payment-ops notifications (auth) ---
        .route(
            "/api/payments/ops/notification-preferences",
            get(handlers::payment_notifications::preferences).put(handlers::payment_notifications::update_preferences),
        )
        .route("/api/payments/ops/notifications", get(handlers::payment_notifications::index))
        .route("/api/payments/ops/notifications/:id/read", post(handlers::payment_notifications::read))
        // --- Payment-ops operations (read) (auth) ---
        .route("/api/payments/ops/invoices", get(handlers::payment_operations::invoices_index))
        .route("/api/payments/ops/invoices/:id", get(handlers::payment_operations::invoice_detail))
        .route("/api/payments/ops/invoices/:id/timeline", get(handlers::payment_operations::timeline))
        .route("/api/payments/ops/observations", get(handlers::payment_operations::observations))
        // --- Payment sandbox (retired -> 410 Gone) (auth) ---
        .route("/api/payments/sandbox/invoices/:id/observations", post(handlers::payment_sandbox::observations))
        .route("/api/payments/sandbox/invoices/:id/confirm", post(handlers::payment_sandbox::confirm))
        .route("/api/payments/sandbox/invoices/:id/underpay", post(handlers::payment_sandbox::underpay))
        .route("/api/payments/sandbox/invoices/:id/overpay", post(handlers::payment_sandbox::overpay))
        .route("/api/payments/sandbox/webhooks/test-event", post(handlers::payment_sandbox::test_event))
        .route("/api/payments/ops/credits", get(handlers::payment_operations::credits))
        // --- Payment-ops CSV exports + manifests (auth) ---
        .route("/api/payments/ops/exports/invoices.csv", get(handlers::payment_operations_exports::invoices))
        .route("/api/payments/ops/exports/observations.csv", get(handlers::payment_operations_exports::observations))
        .route("/api/payments/ops/exports/credits.csv", get(handlers::payment_operations_exports::credits))
        .route(
            "/api/payments/ops/exports",
            get(handlers::payment_operations_exports::index).post(handlers::payment_operations_exports::store),
        )
        .route("/api/payments/ops/exports/:id", get(handlers::payment_operations_exports::show))
        .route("/api/payments/ops/exports/:id/download", get(handlers::payment_operations_exports::download))
        // --- Payment-ops analytics (auth) ---
        .route("/api/payments/ops/analytics/summary", get(handlers::payment_analytics::summary))
        .route("/api/payments/ops/analytics/timeseries", get(handlers::payment_analytics::timeseries))
        .route("/api/payments/ops/analytics/breakdown", get(handlers::payment_analytics::breakdown))
        // --- Payment-ops financial statements (auth) ---
        .route(
            "/api/payments/ops/statements",
            get(handlers::payment_financial_statements::index).post(handlers::payment_financial_statements::store),
        )
        .route("/api/payments/ops/statements/:id", get(handlers::payment_financial_statements::show))
        .route("/api/payments/ops/statements/:id/download", get(handlers::payment_financial_statements::download))
        // --- Payment-ops evidence packs (auth) ---
        .route("/api/payments/ops/invoices/:id/evidence-packs", post(handlers::payment_evidence_packs::store))
        .route("/api/payments/ops/evidence-packs", get(handlers::payment_evidence_packs::index))
        .route("/api/payments/ops/evidence-packs/:id", get(handlers::payment_evidence_packs::show))
        .route("/api/payments/ops/evidence-packs/:id/download", get(handlers::payment_evidence_packs::download))
        // --- Payment-ops adjustments (auth) ---
        .route(
            "/api/payments/ops/invoices/:id/adjustments",
            get(handlers::payment_adjustments::index).post(handlers::payment_adjustments::store),
        )
        .route("/api/payments/ops/adjustments/:id", get(handlers::payment_adjustments::show))
        // --- Payment-ops audit-access grants (auth) ---
        .route(
            "/api/payments/ops/audit-access",
            get(handlers::payment_audit_access::index).post(handlers::payment_audit_access::store),
        )
        .route("/api/payments/ops/audit-access/:id/revoke", post(handlers::payment_audit_access::revoke))
        // --- Support payments tier (internal token) ---
        .route("/api/support/payments/search", get(handlers::payment_support_operations::search))
        .route("/api/support/payments/invoices/:id", get(handlers::payment_support_operations::invoice_detail))
        .route("/api/support/payments/invoices/:id/timeline", get(handlers::payment_support_operations::invoice_timeline))
        .route("/api/support/payments/exceptions", get(handlers::payment_support_operations::exceptions))
        .route("/api/support/payments/webhook-deliveries/:id", get(handlers::payment_support_operations::get_webhook_delivery))
        .route("/api/support/payments/invoices/:id/notes", post(handlers::payment_support_operations::add_invoice_note))
        .route("/api/support/payments/invoices/:id/evidence-packs/regenerate", post(handlers::payment_support_operations::regenerate_evidence_pack))
        // --- Payment audit token-read endpoints (public; grant token + scope) ---
        .route("/api/payments/audit/:token/statements", get(handlers::payment_audit_access::statements))
        .route("/api/payments/audit/:token/exports", get(handlers::payment_audit_access::exports))
        .route("/api/payments/audit/:token/evidence-packs", get(handlers::payment_audit_access::evidence_packs))
        .route("/api/payments/audit/:token/close-periods", get(handlers::payment_audit_access::close_periods))
        // --- Payment-ops financial reporting (auth) ---
        .route(
            "/api/payments/ops/reporting-categories",
            get(handlers::payment_financial_reporting::categories_index).post(handlers::payment_financial_reporting::categories_store),
        )
        .route(
            "/api/payments/ops/reporting-categories/:id",
            axum::routing::put(handlers::payment_financial_reporting::categories_update).delete(handlers::payment_financial_reporting::categories_destroy),
        )
        .route(
            "/api/payments/ops/accounting-profiles",
            get(handlers::payment_financial_reporting::profiles_index).post(handlers::payment_financial_reporting::profiles_store),
        )
        .route("/api/payments/ops/accounting-profiles/:id", axum::routing::put(handlers::payment_financial_reporting::profiles_update))
        // --- Payment-ops settings cluster (auth) ---
        .route(
            "/api/payments/ops/settings",
            get(handlers::payment_ops_settings::settings).put(handlers::payment_ops_settings::update_settings),
        )
        .route("/api/payments/ops/capabilities", get(handlers::payment_ops_settings::capabilities))
        .route("/api/payments/ops/network-capabilities", get(handlers::payment_ops_settings::network_capabilities_merchant))
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
        .route("/api/checkout/links/:publicId", get(handlers::checkout::link_show))
        .route(
            "/api/checkout/links/:publicId/invoices",
            post(handlers::checkout::link_create_invoice),
        )
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
        .route("/api/stores/:id/setup/sync", post(handlers::setups::store_copy))
        // --- Teams (resource) ---
        .route(
            "/api/teams",
            get(handlers::teams::index).post(handlers::teams::store),
        )
        .route(
            "/api/teams/:id",
            get(handlers::teams::show)
                .put(handlers::teams::update)
                .delete(handlers::teams::destroy),
        )
        .route("/api/teams/:id/add-member", post(handlers::teams::add_member))
        // --- Team members (self routes first; static beats :id) ---
        .route("/api/team-members/set-online", post(handlers::team_members::set_online))
        .route("/api/team-members/set-offline", post(handlers::team_members::set_offline))
        .route("/api/team-members/update-profile", axum::routing::put(handlers::team_members::update_profile))
        .route("/api/team-members/logout", post(handlers::team_members::logout))
        .route("/api/team-members/:id", axum::routing::delete(handlers::team_members::destroy))
        .route(
            "/api/team-members/:id/payment-permissions",
            get(handlers::team_members::payment_permissions)
                .put(handlers::team_members::update_payment_permissions),
        )
        .route("/api/team-members/:id/activate", post(handlers::team_members::activate))
        .route("/api/team-members/:id/deactivate", post(handlers::team_members::deactivate))
        .route("/api/team-members/:id/promote", post(handlers::team_members::promote))
        .route("/api/team-members/:id/resend-invite", post(handlers::team_members::resend_invite))
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
        .with_state(state)
}
