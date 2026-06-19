-- setups (1761462409412 + store_id from stores migration). Holds merchant
-- payout/tax/split config consumed by the KPR-1 intent minter.
CREATE TABLE setups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  store_id INTEGER REFERENCES stores(id) ON DELETE SET NULL,
  tos_agreed INTEGER DEFAULT 1,
  kaspa_main_address TEXT,
  kaspa_tax_enabled INTEGER DEFAULT 0,
  kaspa_tax_address TEXT,
  kaspa_tax_percentage TEXT,
  kaspa_split_enabled INTEGER DEFAULT 0,
  kaspa_split_addresses TEXT,
  igra_main_address TEXT,
  igra_tax_enabled INTEGER DEFAULT 0,
  igra_tax_address TEXT,
  igra_tax_percentage TEXT,
  igra_split_enabled INTEGER DEFAULT 0,
  igra_split_addresses TEXT,
  kasplex_main_address TEXT,
  kasplex_tax_enabled INTEGER DEFAULT 0,
  kasplex_tax_address TEXT,
  kasplex_tax_percentage TEXT,
  kasplex_split_enabled INTEGER DEFAULT 0,
  kasplex_split_addresses TEXT,
  redirect_url TEXT,
  webhook_url TEXT,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX setups_user_store_index ON setups(user_id, store_id);
