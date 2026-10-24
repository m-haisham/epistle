# Operations and integration

## Configuration

`config` loads built-in defaults, an optional `epistle.toml` in the working directory, and then environment overrides. Environment names are the uppercase field names from `epistle.example.toml`. Additional fields:

| Environment variable | Purpose |
| --- | --- |
| `API_KEY` | At least 32 characters; bearer authentication |
| `MASTER_KEY` | Exactly 32 random bytes encoded as 64 hex characters |
| `WEBHOOK_SECRET` | At least 32 characters; webhook and OAuth state authentication |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Google authorization-code and refresh flow |
| `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET` | Entra authorization-code and refresh flow |
| `TOKEN_ENDPOINT_OVERRIDE` | Local test-only OAuth endpoint |
| `RUST_LOG` | Tracing filter, default `info` |

Keep SQLite and the file store on one local persistent volume. An OS lock prevents two processes owning the same data directory. An epoch checked inside every write transaction fences stale writers. The SQLx read pool is read-only; a bounded channel feeds one dedicated write connection. Migration checksums detect changed historical migrations.

Stop the old instance before deploying a replacement. SIGTERM stops workers; restart resumes durable cursors and queues. Queue claims are in memory, so there are no persisted leases to clear. On startup, unreferenced file generations are removed. Database transactions and filesystem `fsync` make the file-to-outbox handoff recoverable.

## Authentication providers

Set the provider's redirect URI to `${PUBLIC_URL}/oauth/callback`. Create an account with `auth_kind: google_oauth` or `microsoft_oauth`, email, external reference and optional config. The response contains `redirect_url`; opening it completes authorization code + PKCE. `POST /email/accounts/{id}/credentials` with `{}` starts a new consent flow. A refresh token can also be supplied explicitly as `credentials.refresh_token`.

Google requests `https://mail.google.com/`, which covers IMAP and SMTP. Public applications using this scope must satisfy Google's verification requirements. Workspace service-account accounts use `auth_kind: google_service_account` and `credentials: { client_email, private_key }`; the key is a PEM RSA private key and the Workspace administrator must grant domain-wide delegation for `https://mail.google.com/`. The service mints an RS256 assertion with the mailbox as `sub`. [Google's IMAP OAuth documentation](https://developers.google.com/workspace/gmail/imap/xoauth2-protocol) describes the scopes and delegation requirements.

Microsoft requests `offline_access`, `https://outlook.office.com/IMAP.AccessAsUser.All`, and `https://outlook.office.com/SMTP.Send`. Set `config.tenant` to a tenant identifier if appropriate; it defaults to `common`. The tenant must permit IMAP and grant the required consent. [Microsoft's IMAP OAuth documentation](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth) documents these delegated scopes.

Granted scopes are stored. Refresh uses a per-account mutex and persists rotated refresh tokens before returning an access token. Passwords, refresh tokens, access tokens, and service-account keys are encrypted with individual random data keys wrapped by the configured master key. Account IDs are authenticated as associated data. Authentication errors contain allow-listed reason codes, never provider response bodies.

Google/Microsoft consent, real-account throttling, Gmail labels and thread extensions, and organization-specific restrictions require verification with your provider accounts. Dovecot validates the actual XOAUTH2 exchange against the local mock introspection endpoint; it cannot emulate those provider policies.

## Messages and webhooks

Events use `kind: email.message.received` or `account.status_changed` and `channel: email`. A received event contains `message`, including its opaque ID, envelope, raw header list, flags, Gmail thread/labels, text, HTML, origin, backfill ID, and file manifest. Grouped addresses have `name` and `members`; individual mailboxes have `name` and `address`. Text/HTML parts are combined in MIME order. Each body's cap is applied after combining; oversized bodies are downloadable `text` or `html` files. `raw` always identifies the original `.eml`. Malformed messages still deliver the raw file with `parse_error` set.

The service signs the exact HTTP body:

```text
X-Epistle-Timestamp: <Unix seconds>
X-Epistle-Signature: v1=<hex HMAC-SHA256(secret, timestamp + "." + body)>
Idempotency-Key: <stable opaque event key>
X-Epistle-Delivery-Id: <outbox row ID>
```

Validate the signature in constant time, allow a small timestamp window (for example five minutes), and deduplicate by idempotency key. Do not re-serialize JSON before verification. A delivery retry keeps its event key but uses a new timestamp/signature. Acknowledgment is any HTTP 2xx. Network errors, 408, 429 and 5xx retry with backoff; other failure statuses become dead. A numeric `Retry-After` is honored. Per-message and per-account status ordering is preserved while different groups deliver concurrently. Once a delivery becomes dead, later events may continue. Account `status_seq` lets the receiver reconcile stale events.

Download and mirror files promptly. `GET /email/messages/{id}/files/{file_id}` supports a single byte range, suffix ranges, conditional ETags, content length and attachment disposition. Unknown IDs return 404. Expired or pressure-evicted files return 410, with tombstones retained. Unacknowledged and dead deliveries protect their files. Acknowledgment starts the configured retention window, including every payload generation from redelivery. Under disk pressure, only eligible retained/delivered generations are evicted.

`GET /email/messages/{id}` returns the message inside the webhook. Its body expires with the files and then returns 410; this is a temporary store. Message lookup pointers remain available for read commands for 30 days. The `seen` ledger keeps cross-folder and epoch-reset deduplication identities beyond file expiry.

## Account and queue operations

- `PATCH /email/accounts/{id}` with `{ "enabled": false }` disables synchronization and emits a status event. Use `true` to reconnect.
- `POST /email/messages/{id}/read` accepts `{ "read": true }` or `false` and returns a command ID. Poll `GET /commands/{id}?wait=5s`. Pending commands for one message execute in creation order; retries cannot overwrite a newer command.
- `POST /email/accounts/{id}/backfills` accepts RFC3339 `since` and optional `until`, `folders`, `unread_only`, `redeliver`. `until` is exclusive. The live cursor is untouched. Default discovery uses INBOX and an advertised Sent mailbox; Gmail defaults to All Mail, found through the special-use attribute.
- `GET /backfills/{id}` reports matched, enqueued and delivered counts. `done` means all enqueued deliveries were acknowledged or discarded; `failed` means a fetch exhausted its retry policy. A dead outbox delivery keeps the job open until replay/discard. DELETE cancels remaining discovery/fetch work; messages already handed to delivery may still arrive.
- `GET /outbox` lists up to 500 rows, with IDs, attempts and sanitized errors. `POST /outbox/{id}/replay` retries a dead row. `DELETE /outbox/{id}` explicitly discards a dead delivery and releases its retention protection.
- `GET /health` reports account lag, last successful round trip, pending outbox age, depths and dead counts. Dead deliveries also produce error-level logs for external alerting.
- Deleting an account removes its credentials, queues, metadata, and message directories. This ends synchronization; it does not delete mail from the provider.

IDLE is bounded by an absolute timer, with reconciliation every three minutes by default and re-issue no later than twenty minutes. CONDSTORE is enabled when advertised alongside ENABLE, and the mailbox's highest mod-sequence is recorded. New-message correctness uses UIDVALIDITY plus UID catch-up; QRESYNC and flag/delete tracking are not required for this v1. Metadata ranges filter UIDs client-side because `n:*` can include an older highest UID. Fetchers and commands search Message-ID after an epoch reset; an absent message becomes `gone`.

## Backup and recovery

Back up the master key separately. Use SQLite's online backup API (or `sqlite3 .backup`) while the service runs, or stop the service and copy the database together with its WAL state. A plain copy of a live SQLite main file alone is not a consistent backup. Prioritize credentials, then the database and retained file store together. Never place the database on NFS or another network filesystem.

To recover, restore the database, its matching file directory and the same master key to a local volume, then start one instance. For missing historical mail, create a date backfill. Use `redeliver: true` only when explicit repeat delivery is desired. Inspect `needs_reauth` accounts after provider token revocation and update credentials to reconnect.

Do not use the local Compose test passwords, all-zero-style example keys, or insecure endpoint setting in a production deployment.
