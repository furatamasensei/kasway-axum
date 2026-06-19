-- payment_links (1792000000000). A reusable link template; each checkout spawns
-- a fresh invoice (invoices.payment_link_id already exists from migration 0004).
CREATE TABLE payment_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  store_id INTEGER REFERENCES stores(id),
  public_id TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active',
  title TEXT NOT NULL,
  amount INTEGER NOT NULL,
  currency TEXT NOT NULL DEFAULT 'KAS',
  payment_network TEXT NOT NULL,
  payment_asset TEXT NOT NULL,
  fee_delegation TEXT NOT NULL DEFAULT 'merchant_subsidized',
  payment_mode TEXT,
  pricing_country_code TEXT,
  metadata TEXT,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX payment_links_user_status_index ON payment_links(user_id, status);
CREATE INDEX payment_links_store_index ON payment_links(store_id);
CREATE INDEX payment_links_public_id_index ON payment_links(public_id);
