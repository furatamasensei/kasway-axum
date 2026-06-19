-- payment_anomaly_signals (1779000000011).
CREATE TABLE payment_anomaly_signals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  signal_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  detected_at TEXT NOT NULL,
  window_start TEXT NOT NULL,
  window_end TEXT NOT NULL,
  score INTEGER,
  reason TEXT NOT NULL,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX payment_anomaly_signals_user_index ON payment_anomaly_signals(user_id);
