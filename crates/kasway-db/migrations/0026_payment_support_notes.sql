-- Support operator notes attached to invoices (PaymentSupportNote), written via
-- the internal-token support tier.

CREATE TABLE payment_support_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  invoice_id INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  note TEXT NOT NULL,
  metadata TEXT NOT NULL DEFAULT '{}',
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX payment_support_notes_invoice_index ON payment_support_notes(invoice_id, created_at);
