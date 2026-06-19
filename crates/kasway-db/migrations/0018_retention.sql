-- payment_retention_policies (1779000000014) + payment_retention_runs (1779000000015).
CREATE TABLE payment_retention_policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  exports_retention_days INTEGER NOT NULL DEFAULT 7,
  evidence_packs_retention_days INTEGER NOT NULL DEFAULT 7,
  notifications_retention_days INTEGER NOT NULL DEFAULT 30,
  webhook_response_body_retention_days INTEGER NOT NULL DEFAULT 30,
  support_notes_retention_days INTEGER,
  anomaly_signals_retention_days INTEGER NOT NULL DEFAULT 30,
  created_at TEXT,
  updated_at TEXT,
  UNIQUE (user_id)
);

CREATE TABLE payment_retention_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  status TEXT NOT NULL DEFAULT 'running',
  started_at TEXT NOT NULL,
  finished_at TEXT,
  exports_expired_count INTEGER NOT NULL DEFAULT 0,
  evidence_packs_expired_count INTEGER NOT NULL DEFAULT 0,
  notifications_deleted_count INTEGER NOT NULL DEFAULT 0,
  webhook_response_bodies_redacted_count INTEGER NOT NULL DEFAULT 0,
  support_notes_deleted_count INTEGER NOT NULL DEFAULT 0,
  anomaly_signals_deleted_count INTEGER NOT NULL DEFAULT 0,
  errors TEXT NOT NULL DEFAULT '[]',
  created_at TEXT,
  updated_at TEXT
);
