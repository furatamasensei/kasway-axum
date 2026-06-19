-- payment_audit_access_grants (subset of 1779000000018).
CREATE TABLE payment_audit_access_grants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  scope TEXT NOT NULL DEFAULT '[]',
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX payment_audit_access_grants_user_index ON payment_audit_access_grants(user_id);
