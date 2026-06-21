-- Uploaded media (MediasController). Bytes live on a storage disk (R2/S3 in prod);
-- the port writes to a local filesystem disk. Row contract is identical.

CREATE TABLE media (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  media_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  size INTEGER NOT NULL DEFAULT 0,
  width INTEGER,
  height INTEGER,
  duration INTEGER,
  created_at TEXT,
  updated_at TEXT
);
CREATE INDEX media_user_index ON media(user_id);
