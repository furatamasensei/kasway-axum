-- Permissionless evaluator marketplace and encrypted dispute protocol.
--
-- Every mutable action is authenticated by a BIP-340 signature over a
-- domain-separated canonical payload. Only public profile data, public keys,
-- hashes, signatures, ciphertext, and chain references are stored. No legal
-- identity fields or private/decryption keys exist in this schema.

CREATE TABLE evaluator_profiles (
  profile_id TEXT PRIMARY KEY,
  identity_key TEXT NOT NULL UNIQUE,
  messaging_key TEXT NOT NULL,
  pseudonym TEXT NOT NULL,
  categories TEXT NOT NULL DEFAULT '[]',
  languages TEXT NOT NULL DEFAULT '[]',
  policy_hash TEXT NOT NULL,
  fee_kind TEXT NOT NULL,
  fee_value BIGINT NOT NULL,
  minimum_fee_sompi BIGINT NOT NULL DEFAULT 0,
  maximum_fee_sompi BIGINT,
  response_sla_seconds BIGINT NOT NULL,
  decision_sla_seconds BIGINT NOT NULL,
  bond_reference TEXT,
  profile_version BIGINT NOT NULL,
  expires_at TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  signature TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (fee_kind IN ('fixed', 'bps')),
  CHECK (fee_value >= 0),
  CHECK (minimum_fee_sompi >= 0),
  CHECK (maximum_fee_sompi IS NULL OR maximum_fee_sompi >= minimum_fee_sompi),
  CHECK (response_sla_seconds > 0),
  CHECK (decision_sla_seconds > 0),
  CHECK (status IN ('active', 'withdrawn', 'expired'))
);

CREATE INDEX evaluator_profiles_status_index ON evaluator_profiles(status);
CREATE INDEX evaluator_profiles_fee_index ON evaluator_profiles(fee_kind, fee_value);

CREATE TABLE evaluator_quotes (
  quote_id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL REFERENCES evaluator_profiles(profile_id),
  invoice_public_id TEXT NOT NULL REFERENCES invoices(public_id) ON DELETE CASCADE,
  customer_key TEXT NOT NULL,
  evaluator_key TEXT NOT NULL,
  case_key_commitment TEXT NOT NULL,
  fee_sompi BIGINT NOT NULL,
  fee_payer TEXT NOT NULL,
  reward_address TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  evidence_format_hash TEXT NOT NULL,
  allowed_outcomes TEXT NOT NULL,
  dispute_deadline TEXT NOT NULL,
  decision_sla_seconds BIGINT NOT NULL,
  backup_evaluator_key TEXT,
  quote_version BIGINT NOT NULL,
  expires_at TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  signature TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (fee_sompi > 0),
  CHECK (fee_payer IN ('customer')),
  CHECK (decision_sla_seconds > 0),
  CHECK (status IN ('open', 'accepted', 'expired', 'withdrawn'))
);

CREATE INDEX evaluator_quotes_invoice_index ON evaluator_quotes(invoice_public_id);
CREATE INDEX evaluator_quotes_profile_index ON evaluator_quotes(profile_id);

CREATE TABLE evaluator_engagements (
  engagement_id TEXT PRIMARY KEY,
  invoice_public_id TEXT NOT NULL UNIQUE REFERENCES invoices(public_id) ON DELETE CASCADE,
  quote_id TEXT NOT NULL UNIQUE REFERENCES evaluator_quotes(quote_id),
  profile_id TEXT NOT NULL REFERENCES evaluator_profiles(profile_id),
  customer_key TEXT NOT NULL,
  seller_key TEXT NOT NULL,
  evaluator_key TEXT NOT NULL,
  messaging_keys TEXT NOT NULL,
  case_key_commitment TEXT NOT NULL,
  fee_sompi BIGINT NOT NULL,
  fee_payer TEXT NOT NULL,
  reward_address TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  evidence_format_hash TEXT NOT NULL,
  allowed_outcomes TEXT NOT NULL,
  dispute_deadline TEXT NOT NULL,
  decision_sla_seconds BIGINT NOT NULL,
  backup_evaluator_key TEXT,
  terms_json TEXT NOT NULL,
  engagement_hash TEXT NOT NULL UNIQUE,
  customer_signature TEXT NOT NULL,
  seller_signature TEXT NOT NULL,
  evaluator_signature TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'accepted',
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (fee_sompi > 0),
  CHECK (fee_payer IN ('customer')),
  CHECK (status IN ('accepted', 'funded', 'disputed', 'settled', 'cancelled', 'expired'))
);

CREATE INDEX evaluator_engagements_profile_index ON evaluator_engagements(profile_id);
CREATE INDEX evaluator_engagements_status_index ON evaluator_engagements(status);

CREATE TABLE dispute_cases (
  case_id TEXT PRIMARY KEY,
  engagement_id TEXT NOT NULL UNIQUE REFERENCES evaluator_engagements(engagement_id),
  invoice_public_id TEXT NOT NULL UNIQUE REFERENCES invoices(public_id) ON DELETE CASCADE,
  opener_role TEXT NOT NULL,
  opener_key TEXT NOT NULL,
  opening_reason_hash TEXT NOT NULL,
  opening_payload_hash TEXT NOT NULL,
  opening_signature TEXT NOT NULL,
  dispute_tx_id TEXT,
  dispute_covenant_address TEXT,
  state TEXT NOT NULL DEFAULT 'open',
  decision_commitment TEXT,
  decision_commit_tx_id TEXT,
  decision_outcome TEXT,
  decision_reason_hash TEXT,
  decision_salt TEXT,
  decision_signature TEXT,
  decision_reveal_tx_id TEXT,
  settlement_tx_id TEXT,
  opened_at TEXT NOT NULL,
  decision_due_at TEXT NOT NULL,
  settled_at TEXT,
  updated_at TEXT NOT NULL,
  CHECK (opener_role IN ('customer', 'seller')),
  CHECK (state IN ('open', 'committed', 'revealed', 'settling', 'settled', 'replaced')),
  CHECK (decision_outcome IS NULL OR decision_outcome IN ('release', 'refund'))
);

CREATE INDEX dispute_cases_state_index ON dispute_cases(state);
CREATE INDEX dispute_cases_evaluator_due_index ON dispute_cases(decision_due_at);

CREATE TABLE dispute_messages (
  message_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES dispute_cases(case_id) ON DELETE CASCADE,
  sequence BIGINT NOT NULL,
  previous_message_hash TEXT,
  participant_role TEXT NOT NULL,
  sender_key TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  envelope_hash TEXT NOT NULL UNIQUE,
  signature TEXT NOT NULL,
  chain_tx_id TEXT NOT NULL,
  chain_commitment TEXT NOT NULL,
  anchor_status TEXT NOT NULL DEFAULT 'submitted',
  created_at TEXT NOT NULL,
  expires_at TEXT,
  UNIQUE (case_id, sequence),
  CHECK (participant_role IN ('customer', 'seller', 'evaluator')),
  CHECK (sequence >= 0),
  CHECK (anchor_status IN ('submitted', 'observed', 'failed'))
);

CREATE INDEX dispute_messages_case_index ON dispute_messages(case_id, sequence);
CREATE INDEX dispute_messages_chain_tx_index ON dispute_messages(chain_tx_id);

CREATE TABLE evaluator_feedback (
  feedback_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES dispute_cases(case_id) ON DELETE CASCADE,
  profile_id TEXT NOT NULL REFERENCES evaluator_profiles(profile_id),
  author_role TEXT NOT NULL,
  author_key TEXT NOT NULL,
  score BIGINT NOT NULL,
  tags TEXT NOT NULL DEFAULT '[]',
  feedback_commitment TEXT NOT NULL,
  signature TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (case_id, author_role),
  CHECK (author_role IN ('customer', 'seller')),
  CHECK (score BETWEEN 1 AND 5)
);

CREATE INDEX evaluator_feedback_profile_index ON evaluator_feedback(profile_id);

-- Bind one accepted engagement and its derived covenant facts to each KPR-1
-- intent. Existing intents remain valid legacy escrow_v2 instances.
ALTER TABLE kpr1_payment_intents
  ADD COLUMN engagement_id TEXT REFERENCES evaluator_engagements(engagement_id),
  ADD COLUMN evaluator_fee_sompi BIGINT,
  ADD COLUMN dispute_covenant_address TEXT,
  ADD COLUMN dispute_script_hash TEXT,
  ADD COLUMN covenant_redeem_script TEXT,
  ADD COLUMN dispute_redeem_script TEXT,
  ADD COLUMN covenant_version TEXT NOT NULL DEFAULT 'escrow_v2';

CREATE INDEX kpr1_intents_engagement_index ON kpr1_payment_intents(engagement_id);
