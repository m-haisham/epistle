# Email Communication Microservice: Design

Oct 24, 2026 · @Haisham

## Overview and scope

V1 is a single-tenant Rust service that syncs mail from clients' mailboxes over IMAP with OAuth, and tells one main app about new mail through a signed webhook. The service never stores mail long term: the IMAP server is the durable store, and the main app mirrors every file it needs soon after delivery.

**In v1**

- Accounts authenticated with Google OAuth or service account, Microsoft OAuth, or a password
- Live detection of new mail, with an hourly connection recycle driven by access-token expiry
- On-demand fetching and parsing of full messages, with attachments served over HTTP for a short retention window
- Mark read/unread, and backfill by date (with `unread_only` and `redeliver` options)
- `account.status_changed` events for connection problems (revoked access, changed password, unreachable server)

**Deferred**

- Flag-change and delete events, and an outbox size cap
- Outbound email
- SMS and WhatsApp, which will get their own design and their own API surface

**Principles**

- One instance only, with SQLite as the only database
- Boring technology: proven crates, no distributed coordination
- The email API is transport-neutral. No UIDs, folders or `UIDVALIDITY` appear in any path or payload, so IMAP could later be swapped for the Gmail API or Microsoft Graph without breaking the app
- One webhook URL, with namespaced `kind` values

## Architecture

One process runs everything: three kinds of IMAP worker, two queues in SQLite, a webhook delivery loop and the HTTP API.

&#91;embedded content: architecture · 3 IMAP workers, 2 queues, 1 webhook\]

Mail flows from the IMAP server through the watcher to `fetch_queue`, then through the fetcher to the outbox, and out to the main app by webhook. The app pulls files and sends commands back through the API.

**Process model**

- **One instance only.** Two instances syncing the same mailbox is a correctness bug. An OS file lock (`flock`) on the data directory enforces it: the kernel releases it when the process dies, so there is no stale lock to wait out. A rolling deploy must stop the old instance before the new one syncs
- **Epoch fencing.** An `epoch` counter in SQLite is incremented at startup and checked on every write, so a zombie process cannot corrupt state
- **One supervisor task per account** (tokio), each running a persisted state machine: connecting, authenticating, syncing, idle, backoff
- **SQLite in WAL mode** with one dedicated writer task and a small read pool, on a local volume
- **Failover is restart and resume.** Cursors, queues and credentials survive in SQLite and on disk, so a restart loses no mail

## Authentication and token lifecycle

Every account has an auth strategy, and the sync code only ever calls `get_access_token(account)`. It never knows which strategy is behind it.

| Strategy | Use | Notes |
| --- | --- | --- |
| `google_service_account` | Workspace clients | Admin grants domain-wide delegation once; tokens minted per mailbox, no per-user consent or refresh token. Likely the best fit for client domains |
| `google_oauth` | Gmail users | Needs the restricted `mail.google.com` scope, which brings Google verification and a security assessment for public apps. Check current Google limits and test-mode token expiry before relying on it |
| `microsoft_oauth` | Microsoft 365 | Entra multi-tenant app, `offline_access` plus IMAP scope; tenant admin consent may be required |
| `password` | Fallback | App passwords for providers without OAuth |

**Token provider**

- Refreshes when the access token expires within about 5 minutes
- Single-flight per account through an async mutex. Microsoft rotates refresh tokens, so two concurrent refreshes could invalidate each other
- Persists a rotated refresh token before the new access token is used
- Classifies failures: `invalid_grant` becomes `needs_reauth` and retries stop; network errors and 5xx back off
- Tokens are encrypted at rest (per-row data key wrapped by a master key from env or KMS), never logged, and scrubbed from error traces

**OAuth flow**

- Authorization code flow with PKCE and a signed, short-lived `state` carrying the account
- Request offline access, and store the scopes actually granted, since users can untick scopes
- Account creation for OAuth accounts returns a redirect URL; key-based accounts activate immediately

**Scopes:** request the SMTP scopes up front so adding outbound email later does not force re-consent (verify per provider).

## Sync correctness and workers

Each account has up to three connections, each with one job, which keeps the IDLE connection read-only and stays well under Gmail's per-account connection cap.

| Worker | Lifetime | Mode | Job |
| --- | --- | --- | --- |
| Watcher | Persistent | `EXAMINE` + IDLE | Detect new mail; fetch only metadata; enqueue stubs in `fetch_queue`; advance the cursor |
| Fetcher | On demand, lingers \~30 s after the last item | `BODY.PEEK[]` | Fetch full message, parse, write files to disk, hand off to `outbox` |
| Command worker | On demand | `SELECT` + `UID STORE` | Run mark read/unread commands |

**Watcher**

- Per folder it persists `uidvalidity`, `uidnext`, `highestmodseq` and a discovery cursor. Default folders are INBOX, Sent and, on Gmail, All Mail, configurable per account
- On every connect it compares `UIDVALIDITY` and runs a catch-up (`UID > cursor`). `n:*` always returns the highest message, so results are filtered client-side
- IDLE is re-issued about every 20 minutes. A reconcile poll runs every few minutes, because IDLE can silently miss events. A watchdog kills connections that have not completed a round trip within a threshold
- **Hourly recycle:** it reconnects at `access_expires_at` minus a margin and jitter, using `DONE`, `LOGOUT`, then reconnect. This is planned, never counted as a failure, and the catch-up makes it lossless
- Unplanned drops reconnect with jittered backoff. An auth failure with a fresh token refreshes once and retries before marking `needs_reauth`
- On Gmail it reads `X-GM-MSGID` and `X-GM-THRID` and syncs All Mail instead of every label folder, to avoid duplicates

**Fetcher**

- Works in UID batches capped by count and bytes. Parsing runs in `spawn_blocking`
- Checks `UIDVALIDITY` at fetch time. If it changed, it searches by `Message-ID` in the new epoch, and marks the stub `gone` if nothing is found. An empty fetch result also becomes `gone`, with no webhook
- A parse failure does not dead-letter: the raw message is delivered with a `parse_error` flag
- If the token expires mid-batch it reconnects and continues; per-item state is committed as it goes

**Command worker**

- `STORE +FLAGS (\Seen)` is idempotent, so retries are safe
- It resolves the message through `message_index` and applies the same `UIDVALIDITY` fallback as the fetcher
- `message_index` (message id to folder, uidvalidity, uid, `Message-ID`) is kept 30 days, much longer than the files

Note that mark read ends the read-only guarantee for the service as a whole, but only the command worker ever writes.

## Queues, delivery and file store

The fetch queue and the outbox are separate tables with separate retry policies, because they fail for different reasons.

|  | `fetch_queue` | `outbox` |
| --- | --- | --- |
| Holds | Stubs: pointer plus metadata, a few hundred bytes | Small JSON notifications (the finished message, with a file manifest) |
| Consumer | Fetcher (IMAP) | Delivery loop (HTTP to the app) |
| Fails because of | Token, IMAP errors, deleted mail, `UIDVALIDITY` | App down, 4xx/5xx, timeouts |
| Dead means | Unfetchable | Undeliverable (kept for replay) |

**Flow**

1. Watcher: one transaction inserts the `fetch_queue` stub and a `seen` row, and advances the cursor
2. Fetcher: fetches and parses, writes files to disk, then in one transaction inserts the `message_files` rows and the `outbox` row and deletes the stub
3. Delivery: POST the JSON; on 2xx, one transaction deletes the outbox row and sets `expires_at` on the message's files

A crash at any point leaves either the previous state or the next one. Unique idempotency keys (`email:account:folder:uidvalidity:uid`) make a repeated handoff harmless, and orphan files are swept at startup. In-progress state lives in memory and resets on startup, so no extra writes per transition.

**Webhook delivery**

- At-least-once, signed with HMAC over timestamp plus body; the receiver checks the timestamp to block replays
- Ordered per message through an ordering group (`message_key`), parallel across messages. A later event for a message waits behind its `email.message.received`
- Retryable: 5xx, 408, 429, network errors, with backoff through `next_attempt_at`. Permanent: other 4xx, after N attempts the row goes `dead`, an alert fires, later rows continue
- Dead rows and their files are kept until replayed or discarded, through a replay endpoint

**Payload and files**

- The webhook carries envelope, headers, flags, Gmail thread and labels, `text` and `html` bodies (each capped at 256 KB by default, above which the body becomes a file), and a file manifest with ids, names, types, sizes and sha256
- Attachments never travel in the webhook. The app pulls them from the download endpoint and mirrors them eagerly
- Files live in a directory per message. The raw `.eml` is also a file (`raw`), for replay and parser fixes
- Retention starts at delivery ack, not at fetch: files expire 2 hours after ack (configurable). Files for undelivered messages never expire
- A `410 Gone` means the file existed but expired, which should be rare and worth alerting on, since it means the app is lagging
- Under disk pressure, evict delivered-and-retained files first. Only undelivered bytes can pause the fetcher, and that cap is deferred

## Account status and connection issues

Every connection status change is sent to the app by webhook the moment it happens, including routine and transient ones. Nothing is hidden behind a threshold or suppressed as planned, so the app always knows what state each account is in and can decide what to show.

| Status | Meaning | Emitted when |
| --- | --- | --- |
| `connecting` | First connection attempt in progress | Account created or credentials updated |
| `active` | Syncing normally | Connect and catch-up succeed |
| `reconnecting` | Connection closed, reconnecting | Planned token recycle or an unplanned drop |
| `degraded` | A reconnect attempt failed, retrying with backoff | Each failure after the first reconnect, with the failure count |
| `needs_reauth` | A human must act | Permanent auth failure |
| `error` | Permanent non-auth failure | Classified as non-retryable |
| `disabled` | Turned off through the API | On request |

**Reason codes**

| `reason` | Typical cause | Result |
| --- | --- | --- |
| `token_recycle` | Planned reconnect before the access token expires | `reconnecting`, then `active` |
| `connection_lost` | Dropped socket, IDLE timeout, watchdog kill | `reconnecting` |
| `token_revoked` | OAuth `invalid_grant`, access removed, tokens revoked after a password change (verify per provider) | `needs_reauth` immediately |
| `credentials_rejected` | Password auth fails with `AUTHENTICATIONFAILED` | `degraded` on the first failure, `needs_reauth` after 2 to 3 failures over several minutes |
| `consent_required` | Microsoft `interaction_required` or admin consent needed | `needs_reauth` |
| `scope_missing` | User unticked the mail scope | `needs_reauth` |
| `imap_disabled` | Admin or user turned IMAP off | `error`, action `check_provider_settings` |
| `account_locked` | Suspended account, or web-login-required alerts | `error` |
| `mailbox_missing` | Folder deleted | `error` for that folder |
| `server_unreachable`, `tls_error` | DNS, timeout, certificate | `degraded` |
| `rate_limited` | Connection caps, throttling | `degraded` |
| `provider_outage` | Provider unavailable, token endpoint 5xx | `degraded` |

**Mechanics**

- Events are edge-triggered: one per status or reason transition, sent immediately. Each failed reconnect attempt is its own `degraded` event, carrying the running failure count
- The planned hourly recycle is reported too (`reconnecting` with reason `token_recycle`, then `active`), so expect two events per account per hour. The app can ignore them, but they are always sent
- The status change and its outbox row are written in one transaction
- Each transition increments a per-account `status_seq`, so the app can ignore stale or reordered events
- The full history is delivered in order. Superseded status events are not coalesced or dropped
- No periodic reminders for `needs_reauth` by default; the app handles that. A config option can add them
- `detail` is sanitized: provider codes and short messages only, never tokens or raw server text that could echo credentials
- State is also pullable through `GET /email/accounts/{id}`, so the app can reconcile after missed webhooks
- A `connection_events` table keeps an audit trail after outbox rows are deleted

**While an account is broken:** the watcher parks on permanent failures instead of retrying; the fetcher and command worker leave their queues untouched; the cursor does not move, so the catch-up on recovery fetches everything missed. Updating credentials or finishing reauth triggers an immediate reconnect.

## HTTP API and webhook events

The API speaks in accounts and messages. Service-to-service auth is a static API key or mTLS. Message ids are opaque, so a `UIDVALIDITY` reset can never invalidate an id the app stored.

| Endpoint | Purpose |
| --- | --- |
| `POST /email/accounts` | Create an account (`external_ref`, auth type, `config`). OAuth returns a redirect URL; key-based accounts activate immediately |
| `GET /email/accounts/{id}` | Status, reason, `status_seq`, `last_success_at` |
| `POST /email/accounts/{id}/credentials` | Update credentials or start reauth; triggers an immediate reconnect |
| `DELETE /email/accounts/{id}` | Remove an account |
| `GET /email/messages/{id}` | One message, as delivered in the webhook |
| `GET /email/messages/{id}/files/{file_id}` | Stream a file with `Content-Length`, `ETag` (sha256), `Content-Disposition` and `Range` support. `404` unknown, `410` expired |
| `POST /email/messages/{id}/read` | Body `{ "read": true }`; returns `202` with a `command_id` |
| `GET /commands/{id}` | `pending`, `done`, `gone` or `failed`; optional `?wait=5s` |
| `POST /email/accounts/{id}/backfills` | Body `{ since, until?, folders?, unread_only, redeliver }`; returns `202` |
| `GET /backfills/{id}`, `DELETE /backfills/{id}` | Progress (matched, enqueued, delivered) and cancel |
| `POST /outbox/{id}/replay` | Replay a dead delivery from the stored files |
| `GET /health` | Per-account lag, `last_success_at`, outbox depth and oldest pending age, dead counts |

**Backfill**

- It goes through `fetch_queue`, not straight to the outbox, because bodies and attachments still have to be fetched and parsed. The path is backfill, then `fetch_queue`, then fetcher, then `outbox`; the live cursor is untouched
- IMAP `SINCE` has date granularity only, so the search starts one day earlier and filters client-side on `INTERNALDATE`
- The matched UIDs are stored on the job and enqueued in batches (for example 500), so a restart resumes where it stopped
- `unread_only` adds `UNSEEN` to the search and defaults to off
- By default already-delivered messages are skipped. With `redeliver: true` the idempotency key gets a `:backfill_id` suffix, so the app processes them again
- The initial sync on connect is just a backfill job with `since` set to now minus N days
- Webhook payloads carry `origin: "live"` or `"backfill"` plus the `backfill_id`

**Webhook events**

One webhook URL. Routing is by namespaced `kind`, and every event carries `channel`.

| `kind` | Sent when |
| --- | --- |
| `email.message.received` | A new message is fetched and parsed, live or from a backfill |
| `account.status_changed` | An account changes status, with `status`, `previous_status`, `status_seq`, `reason`, `action_required`, `retryable`, `since`, `consecutive_failures` |

Mark-read results are pulled through `GET /commands/{id}`, not pushed. A flag echo from the server after a mark-read is suppressed when flag events arrive later.

## SQLite schema sketch

SQLite runs in WAL mode with one dedicated writer task fed by a channel and a small read pool, which avoids `SQLITE_BUSY`. Message bodies and files stay out of the database. Every write checks an `epoch` counter incremented at startup, so a zombie process that outlived the lock cannot write.

```sql
accounts(id, external_ref, auth_kind, email, status, status_seq, status_since,
         status_reason, consecutive_failures, first_failure_at,
         last_success_at, last_error, created_at)
credentials(account_id PK, ciphertext, nonce, key_id, access_expires_at, scopes, updated_at)
folders(id, account_id, name, role, uidvalidity, uidnext, highestmodseq,
        cursor_uid, state, last_synced_at)
seen(account_id, message_id_hash, first_seen_at)      -- cross-folder and UIDVALIDITY-reset dedupe
message_index(message_key PK, account_id, folder_id, uidvalidity, uid,
              rfc_message_id, created_at)              -- kept ~30 days
fetch_queue(id, idempotency_key UNIQUE, account_id, folder_id, uidvalidity, uid,
            rfc_message_id, flags, size_bytes, state, attempts,
            next_attempt_at, last_error, created_at)
outbox(seq PK AUTOINCREMENT, idempotency_key UNIQUE, message_key, account_id, kind,
       size_bytes, state, attempts, next_attempt_at, last_error, created_at)
message_files(message_key, file_id, role, filename, content_type, size, sha256,
              content_id, path, delivered_at, expires_at)
commands(id, account_id, message_key, kind, state, attempts,
         next_attempt_at, last_error, created_at, completed_at)
backfill_jobs(id, account_id, since, until, folders_json, unread_only, redeliver,
              state, matched, enqueued, created_at, completed_at, last_error)
connection_events(id, account_id, seq, from_status, to_status, reason, detail, created_at)
```

**Backups:** credentials are the only data that is painful to lose, since clients would have to re-consent, so back them up first. Everything else is recoverable by resyncing from the backfill window while the app dedupes on idempotency keys. SQLite must live on a local volume, never a network filesystem.

## Configuration, testing and deferred work

**Configuration defaults**

| Setting | Default |
| --- | --- |
| File retention after delivery ack | 2 hours (`FILE_RETENTION_SECS`) |
| Inline body cap (text and html, each) | 256 KB |
| `message_index` retention | 30 days |
| Status events | Every transition sent immediately, no threshold, no coalescing |
| `needs_reauth` reminders | Off |
| Backfill: skip already delivered | On (`redeliver: false`) |
| Backfill: `unread_only` | Off |
| IDLE re-issue interval | About 20 minutes |
| Fetcher linger after last item | About 30 seconds |

**Crates**

| Crate | Use |
| --- | --- |
| `async-imap` | IMAP client: IDLE, XOAUTH2 authenticator, fetch and store. Check its CONDSTORE and QRESYNC support early, and issue raw commands if it is thin |
| `axum` | HTTP server for the API and file downloads |
| `aide` | OpenAPI generation for the axum routes (with `schemars`), served as `/openapi.json` so the app's client can be generated from it |
| `thiserror` | Typed error enums in every crate |
| `serde`, `serde_json` | Serialization for config, API bodies, webhook payloads and stored JSON columns |
| `tokio`, `reqwest`, `tracing` | Runtime, HTTP client for token endpoints and webhooks, logging |
| `mail-parser` | Message parsing |
| `rusqlite` or `sqlx` | SQLite access behind the single writer task |
| `secrecy`, `zeroize`, `chacha20poly1305` | Token handling and encryption at rest |
| `fs2` | Data-directory file lock |

**Dependency policy**

- Prefer widely used, well-maintained crates over clever or new ones. Where a crate is thin or young, call the protocol directly rather than depend on it
- Start on the latest stable release of each crate and keep them current. Check crates.io for versions when scaffolding rather than copying numbers from old examples
- Automate updates with Renovate or Dependabot, gated by CI (build, clippy, tests against Dovecot)
- `cargo audit` and `cargo deny` run in CI for advisories, licences and duplicate versions
- Commit `Cargo.lock`, pin the toolchain in `rust-toolchain.toml`, and declare shared versions once in `[workspace.dependencies]` so every crate uses the same version

**Workspace layout.** Each concern is its own crate, with dependencies pointing one way (the server depends on everything, `core` on nothing internal). SMS and WhatsApp later become new crates without touching the email ones.

| Crate | Responsibility |
| --- | --- |
| `core` | Domain types, ids, status and reason enums, error traits, config types |
| `store` | SQLite, migrations, the writer task, queue and outbox operations |
| `auth` | Auth strategies and the single-flight token provider |
| `imap` | Thin wrapper over `async-imap`: connect, XOAUTH2, IDLE, fetch, store, with typed errors |
| `email` | Watcher, fetcher, command worker, backfill, message parsing |
| `delivery` | Outbox delivery loop, webhook signing, file store and retention sweeper |
| `api` | `axum` routes documented with `aide`, request and response types |
| `server` | Binary: config, lockfile, wiring of workers and routes |

**Error handling and no unwraps**

- Every crate defines its own error enum with `thiserror` and converts across crate boundaries with `#[from]`. No `anyhow` in library crates
- Errors carry their classification (retryable, permanent, needs reauth), so the status machine maps a failure to a reason code without parsing strings
- Workspace lints deny `unwrap_used`, `expect_used`, `panic`, `todo` and `indexing_slicing`, enforced by clippy in CI. Tests may opt out explicitly
- Use `?`, `get()`, `ok_or`, and `let ... else` instead. Invariants that cannot fail are encoded in types rather than asserted
- A panicking task must not take the service down: each account supervisor runs in its own task, and a join error is logged and turned into an `error` status event
- HTTP handlers return a typed API error that implements `IntoResponse` and appears in the OpenAPI schema, so error responses are documented too

**Testing**

- **Dovecot in Docker Compose.** A `docker-compose.yml` runs Dovecot next to the service, with test users, so one `docker compose up` gives a repeatable environment locally and in CI. Tests inject mail with `IMAP APPEND` or `doveadm`, and assert what the service delivers to a mock webhook receiver. Dovecot supports IDLE, CONDSTORE and QRESYNC, which are the paths the sync correctness depends on
- **OAuth path.** Dovecot's `oauth2` password database accepts XOAUTH2 and validates tokens against a configurable introspection or userinfo URL, so it can point at the mock token endpoint and exercise the real XOAUTH2 flow, including expired and revoked tokens. Verify this configuration early
- **Model-based test.** Drive a Dovecot mailbox through arrivals, expunges, moves and dropped connections, then assert local state converges to the server's. This is where full correctness is proven
- **`UIDVALIDITY` resets** are forced by recreating the mailbox or its index files in the test container, which covers the fetcher's `Message-ID` fallback
- **Crash injection** at each transaction boundary: stub insert, handoff to outbox, delivery ack
- **Token tests** against the mock token endpoint: concurrent refresh, rotating refresh tokens, `invalid_grant`, expiry mid-batch
- **Status events:** assert that every transition (connect, recycle, drop, failed reconnect, revoked credentials) produces exactly one webhook, in order, with increasing `status_seq`
- **Provider quirks** (Gmail's `X-GM-*` extensions, Microsoft throttling) cannot be reproduced by Dovecot, so they need a small manual or scheduled test against real accounts

**Deferred**

- Flag-change and delete events
- Outbox cap on undelivered file bytes (the fetcher would pause, never the cursor)
- Outbound email, which adds a send queue, caller-supplied idempotency keys and delivery status
- SMS and WhatsApp

**Operational risks to verify before building**

- Google verification path and token lifetimes for the clients' accounts, and whether service-account delegation covers all Gmail clients
- Microsoft tenants that disable IMAP or require admin consent
- `async-imap` support for XOAUTH2 error challenges, CONDSTORE and QRESYNC
