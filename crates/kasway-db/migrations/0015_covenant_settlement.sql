-- Covenant-only settlement.
--
-- Covenant is now the SOLE KPR-1 settlement path (zero legacy: the address-mode
-- `payment_mode` selector is removed everywhere). Each intent funds one P2SH
-- refund-window covenant. The covenant address depends on the customer's refund
-- address, which is only known once the payer finalizes, so it (and the real
-- script hash) are filled in then — hence script_hash becomes nullable.

ALTER TABLE kpr1_payment_intents
  ADD COLUMN covenant_address TEXT,
  ADD COLUMN customer_refund_address TEXT,
  ADD COLUMN gross_amount BIGINT,
  ADD COLUMN expiry_ts BIGINT,
  ADD COLUMN covenant_state TEXT NOT NULL DEFAULT 'pending',
  ADD COLUMN release_tx_id TEXT,
  ADD COLUMN refund_tx_id TEXT,
  -- Snapshot of the EscrowV2 arbiter panel (JSON array of 32-byte pubkey hex)
  -- baked at finalize, so settlement can rebuild the exact covenant even if the
  -- configured panel later changes. NULL -> settlement falls back to config.
  ADD COLUMN arbiter_panel_json TEXT,
  ADD COLUMN arbiter_threshold INTEGER;

ALTER TABLE kpr1_payment_intents ALTER COLUMN script_hash DROP NOT NULL;

CREATE INDEX kpr1_intents_covenant_state_index ON kpr1_payment_intents(covenant_state);
CREATE INDEX kpr1_intents_covenant_address_index ON kpr1_payment_intents(covenant_address);

-- The settlement-mode selector is gone: covenant is the only path.
ALTER TABLE invoices DROP COLUMN IF EXISTS payment_mode;
ALTER TABLE payment_links DROP COLUMN IF EXISTS payment_mode;
