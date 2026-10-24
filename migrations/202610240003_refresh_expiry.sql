-- Optional provider-reported deadline. NULL means unknown, not non-expiring.
ALTER TABLE credentials ADD COLUMN refresh_expires_at INTEGER;
