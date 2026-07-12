-- Escrow V2 tiered dispute layer.
--
-- The escrow covenant is now `EscrowV2` (mutual-settle + M-of-N arbiter panel +
-- jury paths). New `covenant_state` values are plain strings in the existing
-- TEXT column (no schema change): 'disputed', 'settling_mutual', 'settled_mutual',
-- 'arbiter_ruling', 'jury_selecting', 'jury_commit', 'jury_reveal',
-- 'jury_settling', 'settled_jury', 'slashing'.
--
-- This migration adds the off-chain records the dispute/jury flows need. All
-- additive; existing covenant settlement is unaffected.

-- One row per opened dispute (Tier 1 mutual settlement, Tier 2 arbiter, Tier 3 jury).
CREATE TABLE kpr1_disputes (
    id                      BIGSERIAL PRIMARY KEY,
    intent_id               BIGINT NOT NULL REFERENCES kpr1_payment_intents(id),
    -- 'mutual' | 'arbiter' | 'jury'
    tier                    TEXT NOT NULL,
    state                   TEXT NOT NULL DEFAULT 'open',
    -- resolution: 'merchant' | 'customer' | NULL (unresolved)
    resolution              TEXT,
    -- evidence hashes (sha256 hex) anchored on-chain, and their root.
    evidence_customer_hash  TEXT,
    evidence_merchant_hash  TEXT,
    evidence_root           TEXT,
    -- Tier 3: committee + windows (DAA scores) + baked verdict digests.
    committee_json          TEXT,
    jury_threshold          INTEGER,
    commit_deadline_daa     BIGINT,
    reveal_open_daa         BIGINT,
    claim_deadline_daa      BIGINT,
    verdict_digest_merchant TEXT,
    verdict_digest_customer TEXT,
    opened_at               TEXT NOT NULL,
    resolved_at             TEXT,
    updated_at              TEXT NOT NULL
);
CREATE INDEX kpr1_disputes_intent_index ON kpr1_disputes(intent_id);
CREATE INDEX kpr1_disputes_state_index ON kpr1_disputes(state);

-- The standing pool of bonded jurors (Tier 3 candidates). Selection weight is
-- proportional to standing bond.
CREATE TABLE kpr1_juror_pool (
    juror_pubkey  TEXT PRIMARY KEY,     -- 32-byte x-only pubkey hex
    bond_utxo     TEXT,                 -- standing bond UTXO ref (txid:index)
    stake_sompi   BIGINT NOT NULL DEFAULT 0,
    payout_pubkey TEXT NOT NULL,        -- where honest payouts go (P2PK pubkey hex)
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    joined_at     TEXT NOT NULL
);

-- Per-(dispute, juror) bond covenant instances (commit-reveal + slashing).
CREATE TABLE kpr1_juror_bonds (
    id                    BIGSERIAL PRIMARY KEY,
    dispute_id            BIGINT NOT NULL REFERENCES kpr1_disputes(id),
    juror_pubkey          TEXT NOT NULL,
    bond_covenant_address TEXT NOT NULL,
    bond_utxo             TEXT,          -- txid:index once funded
    commit_hash           TEXT NOT NULL, -- blake2b(chosen_verdict_digest || salt) hex
    -- claim state: 'committed' | 'claimed_honest' | 'slashed'
    claim_state           TEXT NOT NULL DEFAULT 'committed',
    settle_tx_id          TEXT,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL
);
CREATE INDEX kpr1_juror_bonds_dispute_index ON kpr1_juror_bonds(dispute_id);
CREATE UNIQUE INDEX kpr1_juror_bonds_dispute_juror_index ON kpr1_juror_bonds(dispute_id, juror_pubkey);

-- Published juror votes (off-chain, verifiable): commit then reveal datasigs.
CREATE TABLE kpr1_dispute_votes (
    id            BIGSERIAL PRIMARY KEY,
    dispute_id    BIGINT NOT NULL REFERENCES kpr1_disputes(id),
    juror_pubkey  TEXT NOT NULL,
    committee_idx INTEGER NOT NULL,
    commit_datasig TEXT,               -- 64-byte hex
    reveal_bit    SMALLINT,            -- 1 = customer, 2 = merchant
    reveal_salt   TEXT,                -- 32-byte hex
    reveal_datasig TEXT,              -- 64-byte hex (vote_sig over verdict_digest)
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE INDEX kpr1_dispute_votes_dispute_index ON kpr1_dispute_votes(dispute_id);
CREATE UNIQUE INDEX kpr1_dispute_votes_dispute_juror_index ON kpr1_dispute_votes(dispute_id, juror_pubkey);

-- Snapshot the EscrowV2 arbiter panel used per intent, so settlement can rebuild
-- the exact covenant even if the configured panel later changes.
ALTER TABLE kpr1_payment_intents
  ADD COLUMN arbiter_panel_json TEXT,
  ADD COLUMN arbiter_threshold INTEGER;
