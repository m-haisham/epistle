CREATE TABLE send_jobs (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    idempotency_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    message_id TEXT NOT NULL,
    envelope TEXT NOT NULL,
    message BLOB NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK(state IN ('pending','preparing','sending','sent','failed','unknown','cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    accepted_at INTEGER,
    UNIQUE(account_id, idempotency_key)
);

CREATE INDEX send_jobs_ready ON send_jobs(state, next_attempt, created_at);
CREATE UNIQUE INDEX send_jobs_one_active_account ON send_jobs(account_id)
    WHERE state IN ('preparing','sending');
