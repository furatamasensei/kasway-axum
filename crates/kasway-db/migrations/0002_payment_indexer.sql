-- payment_indexer_checkpoints (from 1779000000000_create_payment_ledger_tables)
CREATE TABLE payment_indexer_checkpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  network TEXT NOT NULL,
  asset_id TEXT NOT NULL,
  source TEXT NOT NULL,
  checkpoint TEXT,
  metadata TEXT,
  created_at TEXT,
  updated_at TEXT,
  UNIQUE (network, asset_id, source)
);
