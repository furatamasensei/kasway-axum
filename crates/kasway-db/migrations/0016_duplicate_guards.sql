-- DB-level guards for duplicates the app previously only checked non-atomically.
--
-- Two concurrent requests could each SELECT-then-INSERT and both win the check,
-- producing duplicate rows. These unique indexes make the guarantee atomic.
--
-- Note: invoices(user_id, external_id) WHERE external_id IS NOT NULL is already
-- enforced by `invoices_user_id_external_id_unique` from 0004_invoices.sql, so it
-- is intentionally not re-created here.

-- One subscription cycle per (subscription, period_start). generate_due_invoice
-- checks for an existing cycle before inserting; this closes the race.
CREATE UNIQUE INDEX IF NOT EXISTS subscription_cycles_subscription_period_unique
  ON subscription_cycles(subscription_id, period_start);
