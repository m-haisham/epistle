-- A missing mailbox is a folder failure, not an account-wide authentication error.
ALTER TABLE folders ADD COLUMN last_error TEXT;
