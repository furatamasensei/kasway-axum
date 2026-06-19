-- supported_countries (seeded subset of ISO 3166-1 alpha-2) + regional pricing.
CREATE TABLE supported_countries (
  code TEXT PRIMARY KEY,
  name TEXT NOT NULL
);
INSERT INTO supported_countries (code, name) VALUES
  ('US','United States'), ('GB','United Kingdom'), ('ID','Indonesia'),
  ('DE','Germany'), ('JP','Japan'), ('FR','France'), ('CA','Canada'),
  ('AU','Australia'), ('SG','Singapore'), ('IN','India'), ('BR','Brazil'),
  ('NL','Netherlands'), ('ES','Spain'), ('IT','Italy'), ('MY','Malaysia');

CREATE TABLE store_regional_pricing_settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  store_id INTEGER NOT NULL REFERENCES stores(id) ON DELETE CASCADE,
  fallback_policy TEXT NOT NULL DEFAULT 'fail_closed',
  created_at TEXT,
  updated_at TEXT,
  UNIQUE (store_id)
);

CREATE TABLE store_sellable_countries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  store_id INTEGER NOT NULL REFERENCES stores(id) ON DELETE CASCADE,
  country_code TEXT NOT NULL,
  created_at TEXT,
  updated_at TEXT,
  UNIQUE (store_id, country_code)
);
