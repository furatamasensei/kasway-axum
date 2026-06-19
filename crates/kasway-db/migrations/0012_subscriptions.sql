-- subscriptions + subscription_cycles (from 1779000000022_create_subscription_tables).
CREATE TABLE subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subscription_plan_id INTEGER NOT NULL REFERENCES subscription_plans(id) ON DELETE CASCADE,
  subscription_customer_id INTEGER REFERENCES subscription_customers(id) ON DELETE SET NULL,
  public_id TEXT NOT NULL UNIQUE,
  external_id TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  payment_mode TEXT NOT NULL,
  plan_snapshot TEXT NOT NULL,
  current_period_start TEXT,
  current_period_end TEXT,
  next_billing_at TEXT,
  metadata TEXT,
  paused_at TEXT,
  cancelled_at TEXT,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX subscriptions_user_index ON subscriptions(user_id);

CREATE TABLE subscription_cycles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subscription_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
  invoice_id INTEGER REFERENCES invoices(id) ON DELETE SET NULL,
  public_id TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending',
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  metadata TEXT,
  invoiced_at TEXT,
  paid_at TEXT,
  past_due_at TEXT,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX subscription_cycles_subscription_index ON subscription_cycles(subscription_id);
