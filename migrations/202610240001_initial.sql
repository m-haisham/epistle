CREATE TABLE service_epoch (singleton INTEGER PRIMARY KEY CHECK(singleton=1), epoch INTEGER NOT NULL);
INSERT INTO service_epoch VALUES(1,0);
CREATE TABLE accounts (
 id TEXT PRIMARY KEY, external_ref TEXT NOT NULL UNIQUE, auth_kind TEXT NOT NULL, email TEXT NOT NULL,
 config TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'connecting', status_seq INTEGER NOT NULL DEFAULT 0,
 status_since INTEGER NOT NULL, status_reason TEXT, consecutive_failures INTEGER NOT NULL DEFAULT 0,
 first_failure_at INTEGER, last_success_at INTEGER, last_error TEXT, created_at INTEGER NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1, revision INTEGER NOT NULL DEFAULT 1, worker_state TEXT NOT NULL DEFAULT 'connecting'
);
CREATE TABLE credentials(account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
 ciphertext TEXT NOT NULL, access_expires_at INTEGER, scopes TEXT NOT NULL DEFAULT '[]', updated_at INTEGER NOT NULL);
CREATE TABLE oauth_states(state_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 encrypted_verifier TEXT NOT NULL, expires_at INTEGER NOT NULL, revision INTEGER NOT NULL);
CREATE TABLE folders(id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 name TEXT NOT NULL, role TEXT, uidvalidity INTEGER NOT NULL, uidnext INTEGER NOT NULL DEFAULT 1,
 highestmodseq INTEGER, cursor_uid INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'syncing', last_synced_at INTEGER,
 UNIQUE(account_id,name));
CREATE TABLE seen(account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, message_id_hash TEXT NOT NULL,
 message_key TEXT NOT NULL, first_seen_at INTEGER NOT NULL, PRIMARY KEY(account_id,message_id_hash));
CREATE TABLE message_index(message_key TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE, uidvalidity INTEGER NOT NULL, uid INTEGER NOT NULL,
 rfc_message_id TEXT, pointer TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE backfill_jobs(id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 since INTEGER NOT NULL, until INTEGER, folders_json TEXT, unread_only INTEGER NOT NULL DEFAULT 0, redeliver INTEGER NOT NULL DEFAULT 0,
 state TEXT NOT NULL DEFAULT 'pending', matched INTEGER NOT NULL DEFAULT 0, enqueued INTEGER NOT NULL DEFAULT 0,
 delivered INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, completed_at INTEGER, last_error TEXT);
CREATE TABLE backfill_matches(job_id TEXT NOT NULL REFERENCES backfill_jobs(id) ON DELETE CASCADE,
 identity TEXT NOT NULL, pointer TEXT NOT NULL, enqueued INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(job_id,identity));
CREATE TABLE backfill_folders(job_id TEXT NOT NULL REFERENCES backfill_jobs(id) ON DELETE CASCADE,
 folder_id TEXT NOT NULL REFERENCES folders(id) ON DELETE CASCADE, PRIMARY KEY(job_id,folder_id));
CREATE TABLE fetch_queue(id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
 account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, message_key TEXT NOT NULL,
 pointer TEXT NOT NULL, origin TEXT NOT NULL, backfill_id TEXT REFERENCES backfill_jobs(id) ON DELETE CASCADE,
 state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL DEFAULT 0,
 last_error TEXT, created_at INTEGER NOT NULL);
CREATE TABLE messages(id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 payload_path TEXT NOT NULL, created_at INTEGER NOT NULL, delivered_at INTEGER, expires_at INTEGER, expired INTEGER NOT NULL DEFAULT 0);
CREATE TABLE outbox(seq INTEGER PRIMARY KEY AUTOINCREMENT, idempotency_key TEXT NOT NULL UNIQUE,
 message_key TEXT NOT NULL, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 kind TEXT NOT NULL, payload TEXT, payload_path TEXT, backfill_id TEXT,
 size_bytes INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt_at INTEGER NOT NULL DEFAULT 0, last_error TEXT, created_at INTEGER NOT NULL);
CREATE TABLE message_files(message_key TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE, file_id TEXT PRIMARY KEY,
 role TEXT NOT NULL, filename TEXT NOT NULL, content_type TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
 content_id TEXT, path TEXT NOT NULL, delivered_at INTEGER, expires_at INTEGER, expired INTEGER NOT NULL DEFAULT 0);
CREATE TABLE commands(id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 message_key TEXT NOT NULL, kind TEXT NOT NULL, read_value INTEGER NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL DEFAULT 0,
 last_error TEXT, created_at INTEGER NOT NULL, completed_at INTEGER);
CREATE TABLE connection_events(id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 seq INTEGER NOT NULL, from_status TEXT NOT NULL, to_status TEXT NOT NULL, reason TEXT, detail TEXT,
 created_at INTEGER NOT NULL, UNIQUE(account_id,seq));
CREATE INDEX fetch_ready ON fetch_queue(account_id,state,next_attempt_at);
CREATE INDEX outbox_ready ON outbox(state,next_attempt_at,seq);
CREATE INDEX outbox_ordering ON outbox(message_key,state,seq);
CREATE INDEX files_expiry ON message_files(expired,expires_at);
CREATE INDEX commands_ready ON commands(account_id,state,next_attempt_at);
