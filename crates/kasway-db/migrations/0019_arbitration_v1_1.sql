-- Evaluator protocol v1.1: signed-envelope replay protection, percentage fees,
-- and the engagement fields the wallet verifies before funding (case id, order
-- id, engagement version). `covenant_state` has no CHECK constraint, so the new
-- `settled_mutual` dispute outcome needs no schema change.

CREATE TABLE arbitration_nonces (
  signer_key TEXT NOT NULL,
  nonce TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (signer_key, nonce)
);

ALTER TABLE evaluator_quotes
  ADD COLUMN fee_bps BIGINT,
  ADD COLUMN fee_cap_sompi BIGINT;

ALTER TABLE evaluator_engagements
  ADD COLUMN engagement_version BIGINT NOT NULL DEFAULT 1,
  ADD COLUMN order_id TEXT,
  ADD COLUMN case_id TEXT UNIQUE,
  ADD COLUMN fee_bps BIGINT,
  ADD COLUMN fee_cap_sompi BIGINT;

-- Server receipt time: reputation response-time uses this, never the
-- sender-signed `created_at` (forgeable, and any RFC3339 offset is accepted).
ALTER TABLE dispute_messages ADD COLUMN received_at TEXT;
