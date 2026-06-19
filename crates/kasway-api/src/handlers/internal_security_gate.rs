//! `/internal/payment-ops/security/launch-gate` — InternalSecurityLaunchGateController.show
//! → SecurityLaunchGateService.report(). No `milestone41/report/findings.json` ships,
//! so the service falls back to the default findings document; the whole report is
//! static (only `generatedAt` varies). Summary/checks computed from the 4 defaults.

use crate::auth::InternalToken;
use crate::util::now_iso;
use axum::Json;
use serde_json::{json, Value};

/// `GET /internal/payment-ops/security/launch-gate`
pub async fn show(_token: InternalToken) -> Json<Value> {
    let findings = json!([
        {
            "id": "sec-20260524-001",
            "title": "Outbound webhook SSRF policy requires implementation or owner acceptance",
            "severity": "high",
            "status": "open",
            "affectedComponent": "webhooks",
            "owaspCategory": "A10:2021 Server-Side Request Forgery",
            "vulnerabilityClass": "ssrf",
            "exploitability": "likely",
            "impact": "Webhook delivery URLs are currently validated as generic URLs; launch requires an HTTPS/private-network/metadata-IP policy and delivery-time enforcement before untrusted merchant endpoints are enabled broadly.",
            "evidence": [
                {
                    "kind": "code",
                    "summary": "Webhook endpoint validator accepts generic URL syntax and delivery uses the stored URL for outbound fetch.",
                    "location": "app/validators/webhook.ts; app/jobs/deliver_webhook_job.ts",
                    "redacted": true
                }
            ],
            "fixRecommendation": "Require HTTPS webhook URLs, reject embedded credentials and private/link-local/metadata destinations, resolve DNS safely, disallow unsafe redirects, and re-check immediately before delivery.",
            "owner": "security-api",
            "dueBeforeLaunch": true,
            "verification": {
                "status": "not_started",
                "checks": [
                    "unit:webhook_url_policy_service",
                    "functional:webhook_create_update_policy",
                    "delivery:no_unsafe_redirects"
                ]
            }
        },
        {
            "id": "sec-20260524-002",
            "title": "VPS network exposure evidence is pending",
            "severity": "high",
            "status": "open",
            "affectedComponent": "vps_infrastructure",
            "vulnerabilityClass": "network_exposure",
            "exploitability": "likely",
            "impact": "Production launch requires operator evidence that only 80/443 and restricted SSH are publicly reachable and that direct API, PostgreSQL, Redis, and docs dev ports are not exposed.",
            "evidence": [
                {
                    "kind": "config",
                    "summary": "Current compose files include development-friendly port publishing; the new hardening runbook requires production-safe bindings or firewall proof.",
                    "location": "compose.yml; compose.production.yml; docs/operations/vps-hardening.md",
                    "redacted": true
                }
            ],
            "fixRecommendation": "Provide firewall/reverse-proxy evidence, bind API to loopback behind TLS proxy, and keep PostgreSQL/Redis private or explicitly accepted by owner with compensating controls.",
            "owner": "platform-ops",
            "dueBeforeLaunch": true,
            "verification": {
                "status": "not_started",
                "checks": [
                    "operator:ss_or_firewall_snapshot",
                    "operator:external_port_review",
                    "operator:postgres_redis_private"
                ]
            }
        },
        {
            "id": "sec-20260524-003",
            "title": "Dependency and supply-chain remediation is pending",
            "severity": "high",
            "status": "open",
            "affectedComponent": "dependency_supply_chain",
            "vulnerabilityClass": "supply_chain",
            "exploitability": "likely",
            "impact": "Audit context identified critical/high advisories and provenance risks across API and sibling frontend/wallet/extension projects; launch requires triage, upgrades, false-positive rationale, or explicit risk acceptance.",
            "evidence": [
                {
                    "kind": "command",
                    "summary": "Local audit summaries reported critical/high findings in API, frontend, and extension dependencies; docs-site audit was clean at the inspected lockfile.",
                    "location": "milestone41/context/supply-chain.md",
                    "redacted": true
                }
            ],
            "fixRecommendation": "Run pnpm audits for each repo, patch direct/transitive dependencies where possible, replace unreviewed URL dependencies, pin floating docs dependencies, and record accepted residual risk.",
            "owner": "engineering",
            "dueBeforeLaunch": true,
            "verification": {
                "status": "not_started",
                "checks": [
                    "command:pnpm_audit_api",
                    "command:pnpm_audit_docs",
                    "command:frontend_wallet_extension_audits",
                    "review:accepted_risks_complete"
                ]
            }
        },
        {
            "id": "sec-20260524-004",
            "title": "Backup and restore drill evidence is pending",
            "severity": "medium",
            "status": "open",
            "affectedComponent": "vps_infrastructure",
            "vulnerabilityClass": "resilience",
            "exploitability": "theoretical",
            "impact": "Operators need pre-launch proof that PostgreSQL and object-storage backups can be restored into non-production without exposing customer data.",
            "evidence": [
                {
                    "kind": "operator_attestation",
                    "summary": "No repo evidence of a completed restore drill was available during Milestone 41 implementation.",
                    "location": "docs/operations/backup-restore.md",
                    "redacted": true
                }
            ],
            "fixRecommendation": "Complete a non-production restore drill, record timestamp, data scope, RPO/RTO, verifier, and sanitized failure notes in operator attestations.",
            "owner": "platform-ops",
            "dueBeforeLaunch": true,
            "verification": {
                "status": "not_started",
                "checks": ["operator:postgres_restore_drill", "operator:r2_restore_or_lifecycle_review"]
            }
        }
    ]);

    Json(json!({
        "scope": "milestone41.security_launch_gate",
        "generatedAt": now_iso(),
        "environment": "documentation",
        "summary": {
            "criticalOpen": 0,
            "highOpen": 3,
            "mediumOpen": 1,
            "acceptedCriticalHigh": 0,
            "fixedCriticalHigh": 0,
            "launchBlocked": true
        },
        "checks": [
            {
                "key": "security.findings.criticalHigh",
                "status": "fail",
                "severity": "high",
                "messageKey": "security.launch_gate.critical_high_blocking",
                "metadata": { "criticalOpen": 0, "highOpen": 3 }
            },
            {
                "key": "security.dependencies.audit",
                "status": "fail",
                "severity": "high",
                "messageKey": "security.launch_gate.dependencies_review",
                "metadata": { "component": "dependency_supply_chain" }
            },
            {
                "key": "security.vps.firewall",
                "status": "fail",
                "severity": "high",
                "messageKey": "security.launch_gate.vps_evidence",
                "metadata": { "component": "vps_infrastructure" }
            },
            {
                "key": "security.redaction.policy",
                "status": "pass",
                "severity": "medium",
                "messageKey": "security.launch_gate.redaction_policy_active",
                "metadata": { "findingsRedacted": true }
            }
        ],
        "findings": findings,
        "redactionPolicy": {
            "secretsExcluded": true,
            "piiExcluded": true,
            "rawPayloadsExcluded": true,
            "forbiddenPatterns": [
                "Bearer <token>",
                "whsec_<webhook-secret>",
                "postgres://<credentials>@<host>/<db>",
                "-----BEGIN PRIVATE KEY-----",
                "seed phrase / mnemonic words",
                "raw signed transaction payloads"
            ]
        }
    }))
}
