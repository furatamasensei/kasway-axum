-- payment_adjustments (1779000000005 + reporting/accounting fields).
CREATE TABLE payment_adjustments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  invoice_id INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  direction TEXT NOT NULL,
  amount INTEGER NOT NULL,
  currency TEXT NOT NULL,
  network TEXT,
  asset_id TEXT,
  external_reference TEXT,
  reporting_category_code TEXT,
  accounting_date TEXT,
  reason TEXT NOT NULL,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_by_user_id INTEGER NOT NULL,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX payment_adjustments_user_index ON payment_adjustments(user_id);
CREATE INDEX payment_adjustments_invoice_index ON payment_adjustments(invoice_id);
