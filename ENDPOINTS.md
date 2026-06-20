# Kasway v2 API — Endpoint Inventory (AdonisJS → Rust/Axum port)

This document maps every HTTP endpoint defined in `start/routes.ts` of the AdonisJS API, with full paths reconstructed from all enclosing group prefixes, controller handlers, route-level middleware (beyond the tier middleware), and porting status. Use it as the authoritative checklist for the Rust/Axum port so no endpoint is missed.

Coverage: 241 / 249 ported

## Framework-provided (transmit SSE)

| # | Method | Full Path | Controller@action | Route middleware | Status |
|---|--------|-----------|-------------------|------------------|--------|
| 1 | (multiple) | transmit.registerRoutes() | framework (transmit SSE: __transmit/events, __transmit/subscribe, __transmit/unsubscribe) | — | ⬜ |

## Internal — healthz (no middleware)

| # | Method | Full Path | Controller@action | Route middleware | Status |
|---|--------|-----------|-------------------|------------------|--------|
| 2 | GET | /internal/healthz | (inline closure → `{ status: 'ok' }`) | — | ✅ |

## Internal — payment-indexer (middleware.internalApiToken)

| # | Method | Full Path | Controller@action | Route middleware | Status |
|---|--------|-----------|-------------------|------------------|--------|
| 3 | GET | /internal/payment-indexer/healthz | internal_payment_indexer_controller.ts@healthz | — | ✅ |
| 4 | GET | /internal/payment-indexer/checkpoints | internal_payment_indexer_controller.ts@checkpoints | — | ✅ |

## Internal — payment-ops (middleware.internalApiToken)

| # | Method | Full Path | Controller@action | Route middleware | Status |
|---|--------|-----------|-------------------|------------------|--------|
| 5 | GET | /internal/payment-ops/slo | internal_payment_ops_slo_controller.ts@slo | internal_slo_obs_test (DB indicators) | ✅ |
| 6 | GET | /internal/payment-ops/slo/queues | internal_payment_ops_slo_controller.ts@queues | internal_slo_obs_test | ✅ |
| 7 | GET | /internal/payment-ops/slo/incidents | internal_payment_ops_slo_controller.ts@incidents | internal_slo_obs_test | ✅ |
| 8 | GET | /internal/payment-ops/status | payment_launch_controller.ts@internalStatus | launch_status_test (queue=SLO, storage=fs, tn10 disabled) | ✅ |
| 9 | GET | /internal/payment-ops/security/launch-gate | internal_security_launch_gate_controller.ts@show | internal_static_test (findings.json absent → static default) | ✅ |
| 10 | GET | /internal/payment-ops/tn10/status | internal_tn10_node_controller.ts@show | internal_slo_obs_test (disabled report; live RPC external) | ✅ |
| 11 | GET | /internal/payment-ops/tocatta/silverscript/status | internal_silverscript_controller.ts@show | tier3_covenant_test (disabled report) | ✅ |
| 12 | GET | /internal/payment-ops/tocatta/silverscript/templates | internal_silverscript_templates_controller.ts@index | internal_static_test (static catalog, sha256 sources) | ✅ |
| 13 | POST | /internal/payment-ops/tocatta/silverscript/templates/:id/compile | internal_silverscript_templates_controller.ts@compile | tier3_covenant_test (validation + compiler unavailable; WASM happy-path external) | ✅ |
| 14 | POST | /internal/payment-ops/tocatta/covenants/transactions/dry-run | internal_covenant_transaction_assembler_controller.ts@dryRun | tier3_covenant_test (validation + SDK-not-configured; WASM assembly external) | ✅ |
| 15 | GET | /internal/payment-ops/tocatta/covenants/tn10/status | internal_tn10_covenant_execution_controller.ts@status | tier3_covenant_test (disabled) | ✅ |
| 16 | POST | /internal/payment-ops/tocatta/covenants/tn10/split-executions | internal_tn10_covenant_execution_controller.ts@executeSplit | tier3_covenant_test (not ready; live TN10 exec external) | ✅ |
| 17 | POST | /internal/payment-ops/tocatta/covenants/tn10/hold-release-executions | internal_tn10_covenant_execution_controller.ts@executeHoldRelease | tier3_covenant_test (not ready; live TN10 exec external) | ✅ |
| 18 | GET | /internal/payment-ops/tocatta/covenants/templates | internal_programmable_settlement_records_controller.ts@templates | settlement_records_test | ✅ |
| 19 | POST | /internal/payment-ops/tocatta/covenants/templates | internal_programmable_settlement_records_controller.ts@storeTemplate | settlement_records_test (audit no-op; +422 required-field) | ✅ |
| 20 | GET | /internal/payment-ops/tocatta/covenants/templates/:id/status | internal_programmable_settlement_records_controller.ts@status | settlement_records_test (policy gate replicated) | ✅ |
| 21 | GET | /internal/payment-ops/tocatta/covenants/templates/:id/evidence | internal_programmable_settlement_records_controller.ts@evidence | settlement_records_test | ✅ |
| 22 | POST | /internal/payment-ops/tocatta/covenants/templates/:id/approvals | internal_programmable_settlement_records_controller.ts@approve | settlement_records_test (updateOrCreate by domain) | ✅ |
| 23 | POST | /internal/payment-ops/tocatta/covenants/templates/:id/disable | internal_programmable_settlement_records_controller.ts@disable | settlement_records_test (404 Row not found) | ✅ |
| 24 | POST | /internal/payment-ops/tocatta/covenants/artifacts | internal_programmable_settlement_records_controller.ts@storeArtifact | settlement_records_test | ✅ |
| 25 | POST | /internal/payment-ops/tocatta/covenants/executions | internal_programmable_settlement_records_controller.ts@storeExecution | settlement_records_test | ✅ |
| 26 | GET | /internal/payment-ops/overview | internal_payment_ops_observability_controller.ts@overview | internal_slo_obs_test (tn10NodeStatus=disabled) | ✅ |
| 27 | GET | /internal/payment-ops/tocatta/sandbox/overview | internal_programmable_settlement_sandbox_controller.ts@overview | internal_misc_test | ✅ |
| 28 | POST | /internal/payment-ops/tocatta/sandbox/splits/preview | internal_programmable_settlement_sandbox_controller.ts@splitPreview | internal_misc_test | ✅ |
| 29 | POST | /internal/payment-ops/tocatta/sandbox/holds/preview | internal_programmable_settlement_sandbox_controller.ts@holdPreview | internal_misc_test | ✅ |
| 30 | GET | /internal/payment-ops/tocatta/sandbox/promotion-gates | internal_programmable_settlement_sandbox_controller.ts@promotionGates | internal_misc_test | ✅ |
| 31 | GET | /internal/payment-ops/tocatta/beta/status | internal_tocatta_beta_controller.ts@status | internal_static_test | ✅ |
| 32 | POST | /internal/payment-ops/tocatta/beta/eligibility | internal_tocatta_beta_controller.ts@eligibility | internal_static_test (computed from body) | ✅ |
| 33 | GET | /internal/payment-ops/tocatta/beta/reporting | internal_tocatta_beta_controller.ts@reporting | internal_static_test | ✅ |
| 34 | GET | /internal/payment-ops/tocatta/beta/contracts | internal_tocatta_beta_controller.ts@contract | internal_static_test | ✅ |
| 35 | GET | /internal/payment-ops/tocatta/production/status | internal_tocatta_production_controller.ts@status | internal_static_test | ✅ |
| 36 | GET | /internal/payment-ops/tocatta/production/cutover-runbook | internal_tocatta_production_controller.ts@cutoverRunbook | internal_static_test | ✅ |
| 37 | GET | /internal/payment-ops/tocatta/production/reconciliation | internal_tocatta_production_controller.ts@reconciliation | internal_static_test | ✅ |
| 38 | GET | /internal/payment-ops/tocatta/production/incidents | internal_tocatta_production_controller.ts@incidents | internal_static_test | ✅ |
| 39 | GET | /internal/payment-ops/tocatta/production/communications | internal_tocatta_production_controller.ts@communications | internal_static_test | ✅ |
| 40 | GET | /internal/payment-ops/kpr1/status | internal_kpr1_payment_ops_controller.ts@status | tier3_covenant_test (DB intents + conformance + silverscript) | ✅ |
| 41 | GET | /internal/payment-ops/kpr1/conformance | internal_kpr1_payment_ops_controller.ts@conformance | internal_misc_test (fixture+ed25519 verifier, all checks pass) | ✅ |
| 42 | GET | /internal/payment-ops/kpr1/intents/:intentId/evidence | internal_kpr1_payment_ops_controller.ts@evidence | internal_misc_test | ✅ |
| 43 | GET | /internal/payment-ops/merchants | internal_payment_ops_observability_controller.ts@merchants | internal_slo_obs_test | ✅ |
| 44 | GET | /internal/payment-ops/merchants/:id | internal_payment_ops_observability_controller.ts@merchant | internal_slo_obs_test (404 merchant not found, 400 bad id) | ✅ |
| 45 | GET | /internal/payment-ops/failures | internal_payment_ops_observability_controller.ts@failures | internal_slo_obs_test | ✅ |

## Public — docs & OAuth callback (no middleware)

| # | Method | Full Path | Controller@action | Route middleware | Status |
|---|--------|-----------|-------------------|------------------|--------|
| 46 | GET | /openapi.json | (inline closure → openApiSpec JSON, cache-control 300s) | tier1_public_test (embedded spec) | ✅ |
| 47 | GET | /docs | (inline closure → renderDocsPage HTML) | tier1_public_test (embedded HTML) | ✅ |
| 48 | GET | /auth/google/callback | auth_controller.ts@callbackGoogle | oauth_google_test (OAuth2 code flow, mock) | ✅ |

## Public — /api payments networks (middleware.paymentApiVersioning)

| # | Method | Full Path | Controller@action | Route middleware | Status |
|---|--------|-----------|-------------------|------------------|--------|
| 49 | GET | /api/payments/networks | payment_network_capabilities_controller.ts@networks | — | ✅ |
| 50 | GET | /api/payments/tocatta/beta/templates | merchant_programmable_settlement_beta_controller.ts@templates | — | ⬜ 🔒 covenant beta (external) |
| 51 | GET | /api/payments/networks/:network/assets | payment_network_capabilities_controller.ts@networkAssets | — | ✅ |

## Public — /api checkout, audit & explorer (middleware.paymentApiVersioning; no auth)

| # | Method | Full Path | Controller@action | Route middleware | Status |
|---|--------|-----------|-------------------|------------------|--------|
| 52 | GET | /api/payments/audit/:token/statements | payment_audit_access_controller.ts@statements | audit_access_test | ✅ |
| 53 | GET | /api/payments/audit/:token/exports | payment_audit_access_controller.ts@exports | audit_access_test | ✅ |
| 54 | GET | /api/payments/audit/:token/evidence-packs | payment_audit_access_controller.ts@evidencePacks | audit_access_test | ✅ |
| 55 | GET | /api/payments/audit/:token/close-periods | payment_audit_access_controller.ts@closePeriods | audit_access_test | ✅ |
| 56 | GET | /api/checkout/invoices/:publicId | checkout_invoices_controller.ts@show | — | ✅ |
| 57 | GET | /api/checkout/invoices/:publicId/kpr1-intent | checkout_invoices_controller.ts@kpr1Intent | — | ✅ |
| 58 | POST | /api/checkout/invoices/:publicId/kpr1-payments | checkout_invoices_controller.ts@submitKpr1Payment | — | ⬜ 🔒 chain relay/settlement |
| 59 | GET | /api/checkout/links/:publicId | checkout_links_controller.ts@show | — | ✅ |
| 60 | POST | /api/checkout/links/:publicId/invoices | checkout_links_controller.ts@createInvoice | — | ✅ |
| 61 | POST | /api/bug-reports | bug_reports_controller.ts@store | tier1_public_test (captcha via captcha_ok) | ✅ |
| 62 | GET | /api/explorer/kpr1/intents/:intentId | kpr1_explorer_controller.ts@showIntent | explorer_kpr1_test | ✅ |
| 63 | GET | /api/explorer/kpr1/intents/:intentId/wallet-verification | kpr1_explorer_controller.ts@walletVerification | explorer_kpr1_test | ✅ |
| 64 | GET | /api/explorer/kpr1/payment-requests/:canonicalHash | kpr1_explorer_controller.ts@showPaymentRequest | explorer_kpr1_test | ✅ |
| 65 | GET | /api/explorer/kpr1/transactions/:txId | kpr1_explorer_controller.ts@showTransaction | explorer_kpr1_test (409 ambiguous) | ✅ |
| 66 | GET | /api/explorer/kpr1/invoices/:publicId | kpr1_explorer_controller.ts@showInvoice | explorer_kpr1_test | ✅ |

## Public — /api/auth (middleware.paymentApiVersioning; auth only on profile/logout)

| # | Method | Full Path | Controller@action | Route middleware | Status |
|---|--------|-----------|-------------------|------------------|--------|
| 67 | GET | /api/auth/google/redirect | auth_controller.ts@redirectGoogle | oauth_google_test | ✅ |
| 68 | GET | /api/auth/profile | auth_controller.ts@profile | middleware.auth | ✅ |
| 69 | POST | /api/auth/logout | auth_controller.ts@logout | middleware.auth | ✅ |
| 70 | POST | /api/auth/login | auth_controller.ts@login | — | ✅ |
| 71 | POST | /api/auth/register | auth_controller.ts@register | — | ✅ |

## Authenticated — /api (middleware.paymentApiVersioning + middleware.auth)

| # | Method | Full Path | Controller@action | Route middleware | Status |
|---|--------|-----------|-------------------|------------------|--------|
| 72 | GET | /api/price | prices_controller.ts@index | — | ⬜ 🔒 coingecko (external) |
| 73 | GET | /api/currencies | currencies_controller.ts@index | — | ✅ |
| 74 | GET | /api/api-keys | api_keys_controller.ts@index | — | ✅ |
| 75 | POST | /api/api-keys | api_keys_controller.ts@store | — | ✅ |
| 76 | GET | /api/api-keys/:id | api_keys_controller.ts@show | — | ✅ |
| 77 | POST | /api/api-keys/:id/revoke | api_keys_controller.ts@revoke | — | ✅ |
| 78 | POST | /api/api-keys/:id/rotate | api_keys_controller.ts@rotate | — | ✅ |
| 79 | GET | /api/regional-pricing/countries | regional_pricing_controller.ts@countries | — | ✅ |
| 80 | GET | /api/regional-pricing/settings | regional_pricing_controller.ts@settings | — | ✅ |
| 81 | PUT | /api/regional-pricing/settings | regional_pricing_controller.ts@updateSettings | — | ✅ |
| 82 | GET | /api/invoices | invoices_controller.ts@index | — | ✅ |
| 83 | POST | /api/invoices | invoices_controller.ts@store | — | ✅ (KPR-1 minter; covenant/compiler stubbed) |
| 84 | GET | /api/invoices/:id | invoices_controller.ts@show | — | ✅ |
| 85 | POST | /api/invoices/:id/cancel | invoices_controller.ts@cancel | — | ✅ |
| 86 | GET | /api/payment-links | payment_links_controller.ts@index | — | ✅ |
| 87 | POST | /api/payment-links | payment_links_controller.ts@store | — | ✅ |
| 88 | GET | /api/payment-links/:id | payment_links_controller.ts@show | — | ✅ |
| 89 | POST | /api/payment-links/:id/disable | payment_links_controller.ts@disable | — | ✅ |
| 90 | POST | /api/payment-links/:id/enable | payment_links_controller.ts@enable | — | ✅ |
| 91 | POST | /api/commerce/invoices | commerce_invoices_controller.ts@store | — | ✅ |
| 92 | GET | /api/commerce/invoices/:publicId | commerce_invoices_controller.ts@show | — | ✅ |
| 93 | GET | /api/commerce/subscription-plans | commerce_subscription_plans_controller.ts@index | — | ✅ |
| 94 | POST | /api/commerce/subscription-plans | commerce_subscription_plans_controller.ts@store | — | ✅ |
| 95 | GET | /api/commerce/subscription-plans/:publicId | commerce_subscription_plans_controller.ts@show | — | ✅ |
| 96 | PUT | /api/commerce/subscription-plans/:publicId | commerce_subscription_plans_controller.ts@update | — | ✅ |
| 97 | POST | /api/commerce/subscription-plans/:publicId/archive | commerce_subscription_plans_controller.ts@archive | — | ✅ |
| 98 | GET | /api/commerce/subscription-customers | commerce_subscription_customers_controller.ts@index | — | ✅ |
| 99 | POST | /api/commerce/subscription-customers | commerce_subscription_customers_controller.ts@store | — | ✅ |
| 100 | GET | /api/commerce/subscription-customers/:publicId | commerce_subscription_customers_controller.ts@show | — | ✅ |
| 101 | PUT | /api/commerce/subscription-customers/:publicId | commerce_subscription_customers_controller.ts@update | — | ✅ |
| 102 | GET | /api/commerce/subscriptions | commerce_subscriptions_controller.ts@index | — | ✅ |
| 103 | POST | /api/commerce/subscriptions | commerce_subscriptions_controller.ts@store | — | ✅ |
| 104 | GET | /api/commerce/subscriptions/:publicId/invoices | commerce_subscriptions_controller.ts@invoices | — | ✅ |
| 105 | POST | /api/commerce/subscriptions/:publicId/invoices/retry | commerce_subscriptions_controller.ts@retryInvoice | — | ✅ |
| 106 | POST | /api/commerce/subscriptions/:publicId/pause | commerce_subscriptions_controller.ts@pause | — | ✅ |
| 107 | POST | /api/commerce/subscriptions/:publicId/resume | commerce_subscriptions_controller.ts@resume | — | ✅ |
| 108 | POST | /api/commerce/subscriptions/:publicId/cancel | commerce_subscriptions_controller.ts@cancel | — | ✅ |
| 109 | GET | /api/commerce/subscriptions/:publicId | commerce_subscriptions_controller.ts@show | — | ✅ |
| 110 | GET | /api/metrics/overview | metrics_controller.ts@overview | — | ✅ |
| 111 | GET | /api/metrics/revenue | metrics_controller.ts@revenue | — | ✅ |
| 112 | GET | /api/metrics/payments | metrics_controller.ts@payments | — | ✅ |
| 113 | GET | /api/metrics/payment-observations | metrics_controller.ts@paymentObservations | — | ✅ |
| 114 | GET | /api/metrics/payment-credits | metrics_controller.ts@paymentCredits | — | ✅ |
| 115 | GET | /api/metrics/webhooks | metrics_controller.ts@webhooks | — | ✅ |
| 116 | GET | /api/payments/ops/exports/invoices.csv | payment_operations_exports_controller.ts@invoices | exports_test | ✅ |
| 117 | GET | /api/payments/ops/exports/observations.csv | payment_operations_exports_controller.ts@observations | exports_test | ✅ |
| 118 | GET | /api/payments/ops/exports/credits.csv | payment_operations_exports_controller.ts@credits | exports_test | ✅ |
| 119 | POST | /api/payments/ops/invoices/:id/evidence-packs | payment_evidence_packs_controller.ts@store | evidence_packs_test (queued; build job external) | ✅ |
| 120 | GET | /api/payments/ops/exports | payment_operations_exports_controller.ts@index | exports_test | ✅ |
| 121 | POST | /api/payments/ops/exports | payment_operations_exports_controller.ts@store | exports_test (queued; job dispatch external) | ✅ |
| 122 | GET | /api/payments/ops/exports/:id | payment_operations_exports_controller.ts@show | exports_test | ✅ |
| 123 | GET | /api/payments/ops/exports/:id/download | payment_operations_exports_controller.ts@download | exports_test (drive bytes external; 404/422 paths only) | ✅ |
| 124 | GET | /api/payments/ops/statements | payment_financial_statements_controller.ts@index | statements_test | ✅ |
| 125 | POST | /api/payments/ops/statements | payment_financial_statements_controller.ts@store | statements_test (drive.put skipped; storagePath set) | ✅ |
| 126 | GET | /api/payments/ops/statements/:id | payment_financial_statements_controller.ts@show | statements_test | ✅ |
| 127 | GET | /api/payments/ops/statements/:id/download | payment_financial_statements_controller.ts@download | statements_test (artifact regenerated, no drive) | ✅ |
| 128 | GET | /api/payments/ops/reporting-categories | payment_reporting_categories_controller.ts@index | — | ✅ |
| 129 | POST | /api/payments/ops/reporting-categories | payment_reporting_categories_controller.ts@store | — | ✅ |
| 130 | PUT | /api/payments/ops/reporting-categories/:id | payment_reporting_categories_controller.ts@update | — | ✅ |
| 131 | DELETE | /api/payments/ops/reporting-categories/:id | payment_reporting_categories_controller.ts@destroy | — | ✅ |
| 132 | GET | /api/payments/ops/accounting-profiles | payment_accounting_profiles_controller.ts@index | — | ✅ |
| 133 | POST | /api/payments/ops/accounting-profiles | payment_accounting_profiles_controller.ts@store | — | ✅ |
| 134 | PUT | /api/payments/ops/accounting-profiles/:id | payment_accounting_profiles_controller.ts@update | — | ✅ |
| 135 | GET | /api/payments/ops/close-periods | payment_close_periods_controller.ts@index | — | ✅ |
| 136 | POST | /api/payments/ops/close-periods | payment_close_periods_controller.ts@store | close_periods_test (high-sev exception block is no-op; see module doc) | ✅ |
| 137 | GET | /api/payments/ops/close-periods/:id | payment_close_periods_controller.ts@show | — | ✅ |
| 138 | POST | /api/payments/ops/close-periods/:id/reopen | payment_close_periods_controller.ts@reopen | — | ✅ |
| 139 | GET | /api/payments/ops/audit-access | payment_audit_access_controller.ts@index | — | ✅ |
| 140 | POST | /api/payments/ops/audit-access | payment_audit_access_controller.ts@store | — | ✅ |
| 141 | POST | /api/payments/ops/audit-access/:id/revoke | payment_audit_access_controller.ts@revoke | — | ✅ |
| 142 | GET | /api/payments/ops/evidence-packs | payment_evidence_packs_controller.ts@index | evidence_packs_test | ✅ |
| 143 | GET | /api/payments/ops/evidence-packs/:id | payment_evidence_packs_controller.ts@show | evidence_packs_test | ✅ |
| 144 | GET | /api/payments/ops/evidence-packs/:id/download | payment_evidence_packs_controller.ts@download | evidence_packs_test (drive bytes external; 404/422 only) | ✅ |
| 145 | POST | /api/payments/sandbox/invoices/:id/observations | payment_sandbox_controller.ts@observations | sandbox_timeline_test | ✅ |
| 146 | POST | /api/payments/sandbox/invoices/:id/confirm | payment_sandbox_controller.ts@confirm | sandbox_timeline_test | ✅ |
| 147 | POST | /api/payments/sandbox/invoices/:id/underpay | payment_sandbox_controller.ts@underpay | sandbox_timeline_test | ✅ |
| 148 | POST | /api/payments/sandbox/invoices/:id/overpay | payment_sandbox_controller.ts@overpay | sandbox_timeline_test | ✅ |
| 149 | POST | /api/payments/sandbox/webhooks/test-event | payment_sandbox_controller.ts@testEvent | sandbox_timeline_test | ✅ |
| 150 | GET | /api/payments/ops/exceptions | payment_operations_exceptions_controller.ts@index | — | ✅ |
| 151 | GET | /api/payments/ops/exceptions/:id/resolution | payment_operations_exceptions_controller.ts@resolution | — | ✅ |
| 152 | POST | /api/payments/ops/exceptions/:id/resolve | payment_operations_exceptions_controller.ts@resolve | middleware.paymentOpsRateLimit(bucket: exceptionMutation) | ✅ |
| 153 | POST | /api/payments/ops/exceptions/:id/dismiss | payment_operations_exceptions_controller.ts@dismiss | middleware.paymentOpsRateLimit(bucket: exceptionMutation) | ✅ |
| 154 | POST | /api/payments/ops/exceptions/:id/link-observation | payment_operations_exceptions_controller.ts@linkObservation | middleware.paymentOpsRateLimit(bucket: exceptionMutation) | ⬜ |
| 155 | POST | /api/payments/ops/exceptions/:id/ignore-observation | payment_operations_exceptions_controller.ts@ignoreObservation | middleware.paymentOpsRateLimit(bucket: exceptionMutation) | ⬜ |
| 156 | GET | /api/payments/ops/anomalies | payment_anomalies_controller.ts@index | — | ✅ |
| 157 | GET | /api/payments/ops/anomalies/:id | payment_anomalies_controller.ts@show | — | ✅ |
| 158 | POST | /api/payments/ops/anomalies/:id/acknowledge | payment_anomalies_controller.ts@acknowledge | — | ✅ |
| 159 | POST | /api/payments/ops/anomalies/:id/dismiss | payment_anomalies_controller.ts@dismiss | — | ✅ |
| 160 | GET | /api/payments/ops/risk/catalog | payment_risk_controller.ts@catalog | — | ✅ |
| 161 | POST | /api/payments/ops/risk/evaluate | payment_risk_controller.ts@evaluate | — | ⬜ 🔒 detection engine |
| 162 | GET | /api/payments/ops/risk/rule-hits | payment_risk_controller.ts@index | — | ✅ |
| 163 | GET | /api/payments/ops/risk/rule-hits/:id | payment_risk_controller.ts@show | — | ✅ |
| 164 | POST | /api/payments/ops/risk/rule-hits/:id/acknowledge | payment_risk_controller.ts@acknowledge | — | ✅ |
| 165 | POST | /api/payments/ops/risk/rule-hits/:id/dismiss | payment_risk_controller.ts@dismiss | — | ✅ |
| 166 | POST | /api/payments/ops/risk/rule-hits/:id/notes | payment_risk_controller.ts@note | — | ✅ |
| 167 | GET | /api/payments/ops/risk/report | payment_risk_controller.ts@report | — | ✅ |
| 168 | GET | /api/payments/ops/notification-preferences | payment_notifications_controller.ts@preferences | — | ✅ |
| 169 | PUT | /api/payments/ops/notification-preferences | payment_notifications_controller.ts@updatePreferences | — | ✅ |
| 170 | GET | /api/payments/ops/settings | payment_tenant_settings_controller.ts@settings | — | ✅ |
| 171 | PUT | /api/payments/ops/settings | payment_tenant_settings_controller.ts@update | — | ✅ |
| 172 | GET | /api/payments/ops/capabilities | payment_tenant_settings_controller.ts@capabilities | — | ✅ |
| 173 | GET | /api/payments/ops/confirmation-policy | payment_confirmation_policy_controller.ts@policy | — | ✅ |
| 174 | PUT | /api/payments/ops/confirmation-policy | payment_confirmation_policy_controller.ts@updatePolicy | — | ✅ |
| 175 | GET | /api/payments/ops/network-capabilities | payment_network_capabilities_controller.ts@networkCapabilities | — | ✅ |
| 176 | GET | /api/payments/ops/analytics/summary | payment_analytics_controller.ts@summary | analytics_test (payments aggregate empty—no confirmed_at col) | ✅ |
| 177 | GET | /api/payments/ops/analytics/timeseries | payment_analytics_controller.ts@timeseries | analytics_test | ✅ |
| 178 | GET | /api/payments/ops/analytics/breakdown | payment_analytics_controller.ts@breakdown | analytics_test | ✅ |
| 179 | GET | /api/payments/ops/notifications | payment_notifications_controller.ts@index | — | ✅ |
| 180 | POST | /api/payments/ops/notifications/:id/read | payment_notifications_controller.ts@read | — | ✅ |
| 181 | GET | /api/payments/ops/retention-policy | payment_retention_policies_controller.ts@policy | — | ✅ |
| 182 | PUT | /api/payments/ops/retention-policy | payment_retention_policies_controller.ts@updatePolicy | — | ✅ |
| 183 | GET | /api/payments/ops/retention-runs | payment_retention_policies_controller.ts@retentionRuns | — | ✅ |
| 184 | GET | /api/payments/ops/status | payment_launch_controller.ts@status | launch_status_test | ✅ |
| 185 | GET | /api/payments/ops/invoices | payment_operations_controller.ts@invoices | — | ✅ |
| 186 | GET | /api/payments/ops/invoices/:id | payment_operations_controller.ts@invoiceDetail | — | ✅ |
| 187 | GET | /api/payments/ops/invoices/:id/adjustments | payment_adjustments_controller.ts@index | — | ✅ |
| 188 | POST | /api/payments/ops/invoices/:id/adjustments | payment_adjustments_controller.ts@store | middleware.paymentOpsRateLimit(bucket: adjustmentMutation) | ✅ |
| 189 | GET | /api/payments/ops/invoices/:id/timeline | payment_operations_controller.ts@timeline | sandbox_timeline_test | ✅ |
| 190 | GET | /api/payments/ops/adjustments/:id | payment_adjustments_controller.ts@show | — | ✅ |
| 191 | GET | /api/payments/ops/observations | payment_operations_controller.ts@observations | — | ✅ |
| 192 | GET | /api/payments/ops/credits | payment_operations_controller.ts@credits | — | ✅ |
| 193 | POST | /api/media | medias_controller.ts@store | media_test (fs disk; compression no-op) | ✅ |
| 194 | DELETE | /api/media/:id | medias_controller.ts@destroy | media_test | ✅ |
| 195 | GET | /api/teams | teams_controller.ts@index (resource apiOnly) | — | ✅ |
| 196 | POST | /api/teams | teams_controller.ts@store (resource apiOnly) | — | ✅ |
| 197 | GET | /api/teams/:id | teams_controller.ts@show (resource apiOnly) | — | ✅ |
| 198 | PUT | /api/teams/:id | teams_controller.ts@update (resource apiOnly) | — | ✅ |
| 199 | DELETE | /api/teams/:id | teams_controller.ts@destroy (resource apiOnly) | — | ✅ |
| 200 | POST | /api/teams/:id/add-member | teams_controller.ts@addMember | — | ✅ |
| 201 | DELETE | /api/team-members/:id | team_members_controller.ts@destroy | — | ✅ |
| 202 | GET | /api/team-members/:id/payment-permissions | team_members_controller.ts@paymentPermissions | — | ✅ |
| 203 | PUT | /api/team-members/:id/payment-permissions | team_members_controller.ts@updatePaymentPermissions | — | ✅ |
| 204 | POST | /api/team-members/:id/activate | team_members_controller.ts@activate | — | ✅ |
| 205 | POST | /api/team-members/:id/deactivate | team_members_controller.ts@deactivate | — | ✅ |
| 206 | POST | /api/team-members/:id/promote | team_members_controller.ts@promote | — | ✅ |
| 207 | POST | /api/team-members/:id/resend-invite | team_members_controller.ts@resendInvite | — | ✅ |
| 208 | POST | /api/team-members/set-online | team_members_controller.ts@setOnline | — | ✅ |
| 209 | POST | /api/team-members/set-offline | team_members_controller.ts@setOffline | — | ✅ |
| 210 | PUT | /api/team-members/update-profile | team_members_controller.ts@updateProfile | — | ✅ |
| 211 | POST | /api/team-members/logout | team_members_controller.ts@logout | — | ✅ |
| 212 | GET | /api/setup | setups_controller.ts@index | — | ✅ |
| 213 | POST | /api/setup | setups_controller.ts@store | — | ✅ |
| 214 | PUT | /api/setup | setups_controller.ts@update | — | ✅ |
| 215 | GET | /api/stores | stores_controller.ts@index | — | ✅ |
| 216 | POST | /api/stores | stores_controller.ts@store | — | ✅ |
| 217 | GET | /api/stores/:id | stores_controller.ts@show | — | ✅ |
| 218 | PUT | /api/stores/:id | stores_controller.ts@update | — | ✅ |
| 219 | POST | /api/stores/:id/default | stores_controller.ts@setDefault | — | ✅ |
| 220 | GET | /api/stores/:id/setup | store_setups_controller.ts@show | — | ✅ |
| 221 | POST | /api/stores/:id/setup | store_setups_controller.ts@store | — | ✅ |
| 222 | PUT | /api/stores/:id/setup | store_setups_controller.ts@update | — | ✅ |
| 223 | POST | /api/stores/:id/setup/clone | store_setups_controller.ts@clone | — | ✅ |
| 224 | POST | /api/stores/:id/setup/copy | store_setups_controller.ts@copy | — | ✅ |
| 225 | POST | /api/stores/:id/setup/sync | store_setups_controller.ts@sync | — | ✅ |
| 226 | GET | /api/webhook-endpoints | webhook_endpoints_controller.ts@index (resource apiOnly) | — | ✅ |
| 227 | POST | /api/webhook-endpoints | webhook_endpoints_controller.ts@store (resource apiOnly) | — | ✅ |
| 228 | GET | /api/webhook-endpoints/:id | webhook_endpoints_controller.ts@show (resource apiOnly) | — | ✅ |
| 229 | PUT | /api/webhook-endpoints/:id | webhook_endpoints_controller.ts@update (resource apiOnly) | — | ✅ |
| 230 | DELETE | /api/webhook-endpoints/:id | webhook_endpoints_controller.ts@destroy (resource apiOnly) | — | ✅ |
| 231 | POST | /api/webhook-endpoints/:id/test-send | webhook_endpoints_controller.ts@testSend | middleware.paymentOpsRateLimit(bucket: webhookReplay) | ✅ |
| 232 | POST | /api/webhook-endpoints/:id/pause | webhook_delivery_controls_controller.ts@pause | — | ✅ |
| 233 | POST | /api/webhook-endpoints/:id/resume | webhook_delivery_controls_controller.ts@resume | — | ✅ |
| 234 | POST | /api/webhook-endpoints/:id/rotate-secret | webhook_delivery_controls_controller.ts@rotateSecret | — | ✅ |
| 235 | GET | /api/webhook-deliveries | webhook_delivery_controls_controller.ts@listDeliveries | — | ✅ |
| 236 | GET | /api/webhook-deliveries/:id | webhook_delivery_controls_controller.ts@showDelivery | — | ✅ |
| 237 | POST | /api/webhook-deliveries/:id/replay | webhook_delivery_controls_controller.ts@replayDelivery | middleware.paymentOpsRateLimit(bucket: webhookReplay) | ✅ |
| 238 | GET | /api/webhook-events | webhook_events_controller.ts@index | — | ✅ |
| 239 | GET | /api/webhook-events/:id | webhook_events_controller.ts@show | — | ✅ |
| 240 | POST | /api/webhook-events/:id/replay | webhook_events_controller.ts@replay | middleware.paymentOpsRateLimit(bucket: webhookReplay) | ✅ |

## Support — /api (middleware.internalApiToken)

| # | Method | Full Path | Controller@action | Route middleware | Status |
|---|--------|-----------|-------------------|------------------|--------|
| 241 | GET | /api/support/payments/search | support_payment_operations_controller.ts@search | support_payments_test (transactionId/webhookDeliveryId filters deferred) | ✅ |
| 242 | GET | /api/support/payments/invoices/:id | support_payment_operations_controller.ts@invoiceDetail | support_payments_test | ✅ |
| 243 | GET | /api/support/payments/invoices/:id/timeline | support_payment_operations_controller.ts@invoiceTimeline | support_payments_test | ✅ |
| 244 | GET | /api/support/payments/exceptions | support_payment_operations_controller.ts@exceptions | support_payments_test (cross-merchant via payment_exceptions::derive_user_exceptions) | ✅ |
| 245 | GET | /api/support/payments/webhook-deliveries/:id | support_payment_operations_controller.ts@getWebhookDelivery | support_payments_test | ✅ |
| 246 | POST | /api/support/payments/invoices/:id/notes | support_payment_operations_controller.ts@addInvoiceNote | support_payments_test | ✅ |
| 247 | POST | /api/support/payments/webhook-deliveries/:id/replay | support_payment_operations_controller.ts@replayWebhookDelivery | support_payments_test (replay row; delivery job stubbed) | ✅ |
| 248 | POST | /api/support/payments/invoices/:id/evidence-packs/regenerate | support_payment_operations_controller.ts@regenerateEvidencePack | support_payments_test (queued; build job external) | ✅ |

## Admin — queue dashboard (middleware.adminQueueDashboard)

| # | Method | Full Path | Controller@action | Route middleware | Status |
|---|--------|-----------|-------------------|------------------|--------|
| 249 | (multiple) | /admin/queue/* | framework (queueDashUiRoutes() — queue dashboard UI, mounted under /admin/queue) | — | ⬜ |

## Tier summary

| Tier | Middleware | Endpoint count |
|------|-----------|----------------|
| Framework (transmit SSE) | — | 1 |
| Internal — healthz | — | 1 |
| Internal — payment-indexer | internalApiToken | 2 |
| Internal — payment-ops | internalApiToken | 41 |
| Public — docs & OAuth callback | — | 3 |
| Public — /api payments networks | paymentApiVersioning | 3 |
| Public — /api checkout, audit & explorer | paymentApiVersioning | 15 |
| Public — /api/auth | paymentApiVersioning (+auth on 2) | 5 |
| Authenticated — /api | paymentApiVersioning + auth | 169 |
| Support — /api | internalApiToken | 8 |
| Admin — queue dashboard | adminQueueDashboard | 1 |
| **Total** | | **249** |
</content>
</invoke>
