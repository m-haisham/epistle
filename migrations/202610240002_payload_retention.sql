-- Track every immutable payload generation, including redeliveries. File tombstones
-- remain available after removal, while bodies are removed after acknowledgment.
CREATE TABLE message_payloads (
 path TEXT PRIMARY KEY,
 message_key TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
 expires_at INTEGER,
 expired INTEGER NOT NULL DEFAULT 0
);
INSERT INTO message_payloads(path,message_key,expires_at,expired)
 SELECT payload_path,id,expires_at,expired FROM messages;
INSERT OR IGNORE INTO message_payloads(path,message_key)
 SELECT payload_path,message_key FROM outbox WHERE payload_path IS NOT NULL;
CREATE INDEX payloads_expiry ON message_payloads(expired,expires_at);
