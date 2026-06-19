-- subscription_plans + subscription_customers (from 1779000000022_create_subscription_tables).
CREATE TABLE subscription_plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_id TEXT NOT NULL UNIQUE,
  external_id TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  name TEXT NOT NULL,
  description TEXT,
  amount INTEGER NOT NULL,
  currency TEXT NOT NULL,
  payment_network TEXT NOT NULL,
  payment_asset TEXT NOT NULL,
  interval_unit TEXT NOT NULL,
  interval_count INTEGER NOT NULL,
  invoice_expires_after_seconds INTEGER,
  metadata TEXT,
  archived_at TEXT,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX subscription_plans_user_index ON subscription_plans(user_id);

CREATE TABLE subscription_customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_id TEXT NOT NULL UNIQUE,
  external_id TEXT,
  email TEXT,
  name TEXT,
  metadata TEXT,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX subscription_customers_user_index ON subscription_customers(user_id);
