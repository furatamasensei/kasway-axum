-- Case-insensitive auth: login, the Google OAuth firstOrCreate, and the
-- register duplicate check all look up users by LOWER(email). The plain
-- UNIQUE constraint on email cannot serve those, so add a functional index
-- on LOWER(email) to keep the lookups index-backed.

CREATE INDEX users_lower_email_index ON users(LOWER(email));
