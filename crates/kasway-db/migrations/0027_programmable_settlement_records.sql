-- Programmable settlement beta records (internal payment-ops tier):
-- templates + their approvals / compiled artifacts / execution evidence.

CREATE TABLE programmable_settlement_templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  template_id TEXT NOT NULL,
  template_version TEXT NOT NULL DEFAULT 'v1',
  status TEXT NOT NULL DEFAULT 'sandbox',
  source_hash TEXT NOT NULL,
  compiler_commit TEXT,
  kill_switch_enabled INTEGER NOT NULL DEFAULT 1,
  created_by_user_id INTEGER,
  approved_by_user_id INTEGER,
  approved_at TEXT,
  disabled_by_user_id INTEGER,
  disabled_at TEXT,
  disable_reason TEXT,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at TEXT,
  updated_at TEXT
);

CREATE TABLE programmable_settlement_approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  template_record_id INTEGER NOT NULL REFERENCES programmable_settlement_templates(id) ON DELETE CASCADE,
  domain TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  approved_by_user_id INTEGER,
  approved_at TEXT,
  notes TEXT,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at TEXT,
  updated_at TEXT,
  UNIQUE (template_record_id, domain)
);

CREATE TABLE programmable_settlement_artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  template_record_id INTEGER NOT NULL REFERENCES programmable_settlement_templates(id) ON DELETE CASCADE,
  artifact_id TEXT NOT NULL,
  source_hash TEXT NOT NULL,
  compiler_commit TEXT NOT NULL,
  compiler_output_hash TEXT NOT NULL,
  script_hash TEXT NOT NULL,
  network_target TEXT NOT NULL,
  argument_schema TEXT NOT NULL DEFAULT '[]',
  warnings TEXT NOT NULL DEFAULT '[]',
  metadata TEXT NOT NULL DEFAULT '{}',
  generated_at TEXT,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX programmable_settlement_artifacts_template_index ON programmable_settlement_artifacts(template_record_id);

CREATE TABLE programmable_settlement_executions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  template_record_id INTEGER NOT NULL REFERENCES programmable_settlement_templates(id) ON DELETE CASCADE,
  artifact_record_id INTEGER,
  status TEXT NOT NULL DEFAULT 'simulated',
  network TEXT NOT NULL DEFAULT 'tn10',
  dry_run_payload_hash TEXT,
  tx_id TEXT,
  evidence_reference TEXT,
  sandbox_outcome TEXT,
  metadata TEXT NOT NULL DEFAULT '{}',
  executed_at TEXT,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX programmable_settlement_executions_template_index ON programmable_settlement_executions(template_record_id);
