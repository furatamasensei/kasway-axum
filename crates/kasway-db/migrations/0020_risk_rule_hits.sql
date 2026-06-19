-- payment_risk_rule_hits + payment_risk_review_events (1779000000021).
CREATE TABLE payment_risk_rule_hits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  rule_key TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL,
  outcome TEXT NOT NULL DEFAULT 'observed',
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  input_snapshot TEXT NOT NULL DEFAULT '{}',
  thresholds TEXT NOT NULL DEFAULT '{}',
  dedupe_key TEXT NOT NULL UNIQUE,
  evaluator_version TEXT NOT NULL,
  detected_at TEXT NOT NULL,
  window_start TEXT NOT NULL,
  window_end TEXT NOT NULL,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX payment_risk_rule_hits_user_index ON payment_risk_rule_hits(user_id);

CREATE TABLE payment_risk_review_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  risk_rule_hit_id INTEGER NOT NULL REFERENCES payment_risk_rule_hits(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reviewer_user_id INTEGER REFERENCES users(id),
  action TEXT NOT NULL,
  previous_status TEXT NOT NULL,
  next_status TEXT NOT NULL,
  reason TEXT,
  note TEXT,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX payment_risk_review_events_hit_index ON payment_risk_review_events(risk_rule_hit_id);
