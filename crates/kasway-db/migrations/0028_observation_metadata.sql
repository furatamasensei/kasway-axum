-- KPR-1 explorer reads observation metadata (kpr1.outputs / kpr1.intentId /
-- kpr1.scriptHash); the minimal observation table never modeled it.

ALTER TABLE payment_observations ADD COLUMN metadata TEXT;
