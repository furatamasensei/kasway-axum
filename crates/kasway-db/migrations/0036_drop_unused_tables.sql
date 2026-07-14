-- Drop schema that no code queries.
--
-- These tables were ported ahead of handlers that were never written (the
-- AdonisJS back-office surface: teams, accounting, retention, risk review,
-- statements, exports, programmable settlement), plus the Tier-3 jury dispute
-- layer, which was removed along with its routes and covenants.
--
-- Migrations 0001-0035 are left untouched so databases that already applied
-- them still validate; this migration is the one that removes the tables.
--
-- Dependency order matters: children before parents.

-- Tier-3 jury dispute layer (0034) — removed with jury_escrow/juror_bond.
DROP TABLE IF EXISTS kpr1_dispute_votes;
DROP TABLE IF EXISTS kpr1_juror_bonds;
DROP TABLE IF EXISTS kpr1_juror_pool;
DROP TABLE IF EXISTS kpr1_disputes;

-- Teams (0003).
DROP TABLE IF EXISTS team_member_auth_access_tokens;
DROP TABLE IF EXISTS team_members;
DROP TABLE IF EXISTS teams;

-- Financial reporting / audit / adjustments / notifications (0014-0017).
DROP TABLE IF EXISTS payment_reporting_categories;
DROP TABLE IF EXISTS payment_accounting_profiles;
DROP TABLE IF EXISTS payment_audit_access_grants;
DROP TABLE IF EXISTS payment_adjustments;
DROP TABLE IF EXISTS payment_notification_preferences;
DROP TABLE IF EXISTS payment_notifications;

-- Retention / risk / exceptions / close periods (0018-0022).
DROP TABLE IF EXISTS payment_retention_runs;
DROP TABLE IF EXISTS payment_retention_policies;
DROP TABLE IF EXISTS payment_risk_review_events;
DROP TABLE IF EXISTS payment_risk_rule_hits;
DROP TABLE IF EXISTS payment_exception_resolutions;
DROP TABLE IF EXISTS payment_close_periods;

-- Exports / statements / evidence packs / support notes (0023-0026).
-- NOTE: 0023 also ALTERs the live payment_observations and payment_credits
-- tables; only its CREATE TABLE is dead, so just that table is dropped here.
DROP TABLE IF EXISTS payment_operation_exports;
DROP TABLE IF EXISTS payment_statements;
DROP TABLE IF EXISTS payment_evidence_packs;
DROP TABLE IF EXISTS payment_support_notes;

-- Programmable settlement (0027).
DROP TABLE IF EXISTS programmable_settlement_approvals;
DROP TABLE IF EXISTS programmable_settlement_executions;
DROP TABLE IF EXISTS programmable_settlement_artifacts;
DROP TABLE IF EXISTS programmable_settlement_templates;

-- Bug reports (0029), waitlist (0032).
DROP TABLE IF EXISTS bug_reports;
DROP TABLE IF EXISTS waitlist_entries;
