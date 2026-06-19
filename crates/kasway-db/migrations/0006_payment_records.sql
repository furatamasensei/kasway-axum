-- Minimal payment/credit/observation tables consumed by derivePaymentStatus.
-- Columns cover what PaymentOperationsService.derivePaymentStatus reads; the
-- full schemas (from the payment-ledger migration) are fleshed out when the
-- payments slice lands.

CREATE TABLE payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invoice_id INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  amount INTEGER NOT NULL DEFAULT 0,
  metadata TEXT,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX payments_invoice_id_index ON payments(invoice_id);

CREATE TABLE payment_credits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invoice_id INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  amount INTEGER NOT NULL DEFAULT 0,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX payment_credits_invoice_id_index ON payment_credits(invoice_id);

CREATE TABLE payment_observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invoice_id INTEGER REFERENCES invoices(id) ON DELETE SET NULL,
  status TEXT NOT NULL,
  amount INTEGER NOT NULL DEFAULT 0,
  confirmations INTEGER NOT NULL DEFAULT 0,
  accepted_at TEXT,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX payment_observations_invoice_id_index ON payment_observations(invoice_id);
