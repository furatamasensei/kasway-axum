-- 1779000000013_add_payment_permissions_to_team_members
ALTER TABLE team_members ADD COLUMN payment_permissions TEXT NOT NULL DEFAULT '[]';
