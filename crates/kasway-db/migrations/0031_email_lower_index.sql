-- Case-insensitive auth: login, the Google OAuth firstOrCreate, and the
-- register duplicate check all look up users/team_members by LOWER(email).
-- The plain UNIQUE constraint on email cannot serve those, so add functional
-- indexes on LOWER(email) to keep the lookups index-backed.

CREATE INDEX users_lower_email_index ON users(LOWER(email));
CREATE INDEX team_members_lower_email_index ON team_members(LOWER(email));
