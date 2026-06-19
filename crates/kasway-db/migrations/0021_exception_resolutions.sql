-- payment_exception_resolutions (1779000000004).
CREATE TABLE payment_exception_resolutions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  exception_type TEXT NOT NULL,
  exception_key TEXT NOT NULL,
  invoice_id INTEGER,
  payment_observation_id INTEGER,
  action TEXT NOT NULL,
  status TEXT NOT NULL,
  note TEXT,
  metadata TEXT NOT NULL DEFAULT '{}',
  resolved_by_user_id INTEGER,
  resolved_at TEXT,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX payment_exception_resolutions_user_index ON payment_exception_resolutions(user_id);
CREATE INDEX payment_exception_resolutions_key_index ON payment_exception_resolutions(exception_key);
