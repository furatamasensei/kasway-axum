-- Evidence pack manifests (PaymentEvidencePackService). The bundle build runs in
-- a background job and writes JSON to a storage disk — both external — so the
-- port persists `queued` manifests and never sets storage_path.

CREATE TABLE payment_evidence_packs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  invoice_id INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'queued',
  checksum TEXT NOT NULL DEFAULT '',
  storage_disk TEXT,
  storage_path TEXT,
  byte_size INTEGER,
  generated_by_user_id INTEGER NOT NULL,
  generated_at TEXT,
  expires_at TEXT,
  error TEXT,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX payment_evidence_packs_user_index ON payment_evidence_packs(user_id, generated_at);
