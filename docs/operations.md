# Operations and integration

## Configuration

`config` loads typed defaults, an optional `epistle.toml` in the working directory, and then environment overrides. Settings are grouped by subsystem; see [`epistle.example.toml`](../epistle.example.toml). Environment names use the `EPISTLE_` prefix and double underscores between sections. For example, `[mail.fetch] batch_count` becomes `EPISTLE_MAIL__FETCH__BATCH_COUNT`. Unrelated environment variables are ignored; unknown configuration keys fail startup instead of silently using defaults.

| TOML section | Purpose |
| --- | --- |
| `[server]` | Listener, public URL and API key |
| `[storage]` | Data directory, retention and disk reserve |
| `[mail]`, `[mail.fetch]` | IMAP watchdog/reconciliation, body limits and batch size |
| `[delivery]` | Webhook destination, signing secret and retries |
| `[auth]` | Master key and reauthorization reminders |
| `[auth.google]`, `[auth.microsoft]` | OAuth client credentials |
| `[testing]` | Explicit insecure endpoint opt-ins |

Secrets and provider credentials:

| Environment variable | Purpose |
| --- | --- |
| `EPISTLE_SERVER__API_KEY` | At least 32 characters; bearer authentication |
| `EPISTLE_AUTH__MASTER_KEY` | Exactly 32 random bytes encoded as 64 hex characters |
| `EPISTLE_DELIVERY__WEBHOOK_SECRET` | At least 32 characters; webhook and OAuth state authentication |
| `EPISTLE_AUTH__GOOGLE__CLIENT_ID`, `EPISTLE_AUTH__GOOGLE__CLIENT_SECRET` | Google authorization-code and refresh flow |
| `EPISTLE_AUTH__MICROSOFT__CLIENT_ID`, `EPISTLE_AUTH__MICROSOFT__CLIENT_SECRET` | Entra authorization-code and refresh flow |
| `EPISTLE_TESTING__TOKEN_ENDPOINT_OVERRIDE` | Local test-only OAuth endpoint |
| `RUST_LOG` | Tracing filter, default `info` |

Keep SQLite and the file store on one local persistent volume. An OS lock prevents two processes owning the same data directory. An epoch checked inside every write transaction fences stale writers. The SQLx read pool is read-only; a bounded channel feeds one dedicated write connection. Migration checksums detect changed historical migrations.

Stop the old instance before deploying a replacement. SIGTERM or SIGINT stops accepting HTTP connections and new worker work. Existing HTTP handlers, OAuth exchanges, message handoffs, read commands and webhook batches finish before the database writer drains and closes. The instance lock remains held until this completes. Idle sessions and backoff waits stop promptly; network operations retain their watchdogs. Shutdown does not forcibly abort work after a fixed timeout.

Give the process enough time to drain: Compose allows five minutes, and manual container stops should use `docker stop --time 300`. Large file writes or slow clients can need longer. SIGKILL or an external stop deadline still bypasses graceful shutdown. Restart resumes durable cursors and queues; a remotely accepted webhook whose acknowledgment was not committed may be redelivered with the same idempotency key. Queue claims are in memory, so there are no persisted leases to clear. On startup, unreferenced file generations are removed. Database transactions and filesystem `fsync` make the file-to-outbox handoff recoverable.

The server installs `tracing-subscriber` once. Set `RUST_LOG=info,epistle_email=debug,epistle_auth=debug` for account and token diagnostics. Structured spans correlate account IDs, worker roles, delivery IDs and HTTP request IDs. HTTP traces record route templates, status and latency, excluding query strings, headers and bodies. Application instrumentation skips credentials and message contents. The `shutdown complete` event confirms that workers and database writes drained.

## Configuration migration

Old flat TOML keys and unprefixed environment variables remain accepted. Migrate files by moving keys under the sections shown in the example. For instance, `data_dir` becomes `[storage] data_dir`, `fetch_batch_count` becomes `[mail.fetch] batch_count`, and `google_client_id` becomes `[auth.google] client_id`.

Layer precedence is **defaults → file → legacy environment → `EPISTLE_` environment**. Within a file, an explicit nested key wins over its flat alias. Environment overrides merge individual fields, preserving sibling values from the file. If both `API_KEY` and `EPISTLE_SERVER__API_KEY` are present, the latter wins. Digit-only secrets and leading zeros are preserved.

The container retains its legacy `DATA_DIR` and `BIND_ADDR` defaults so existing deployment overrides still work. Compose and new examples use the nested environment names. `RUST_LOG` remains the tracing subscriber's own setting and is not renamed. No database migration is needed; per-account IMAP settings in the API keep their existing shape.

## Authentication providers

Set the provider's redirect URI to `${EPISTLE_SERVER__PUBLIC_URL}/oauth/callback`. Create an account with `auth_kind: google_oauth` or `microsoft_oauth`, email, external reference and optional config. The response contains `redirect_url`; opening it completes authorization code + PKCE. `POST /email/accounts/{id}/credentials` with `{}` starts a new consent flow. A refresh token can also be supplied explicitly as `credentials.refresh_token`.

Google requests `https://mail.google.com/`, which covers IMAP and SMTP. Public applications using this scope must satisfy Google's verification requirements. Workspace service-account accounts use `auth_kind: google_service_account` and `credentials: { client_email, private_key }`; the key is a PEM RSA private key and the Workspace administrator must grant domain-wide delegation for `https://mail.google.com/`. The service mints an RS256 assertion with the mailbox as `sub`. [Google's IMAP OAuth documentation](https://developers.google.com/workspace/gmail/imap/xoauth2-protocol) describes the scopes and delegation requirements.

Microsoft requests `offline_access`, `https://outlook.office.com/IMAP.AccessAsUser.All`, and `https://outlook.office.com/SMTP.Send`. Set `config.tenant` to a tenant identifier if appropriate; it defaults to `common`. The tenant must permit IMAP and grant the required consent. [Microsoft's IMAP OAuth documentation](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth) documents these delegated scopes.

Granted scopes are stored. Refresh uses a per-account mutex and persists rotated refresh tokens before returning an access token. Passwords, refresh tokens, access tokens, and service-account keys are encrypted with individual random data keys wrapped by the configured master key. Account IDs are authenticated as associated data. Authentication errors contain allow-listed reason codes, never provider response bodies.

Google/Microsoft consent, real-account throttling, Gmail labels and thread extensions, and organization-specific restrictions require verification with your provider accounts. Dovecot validates the actual XOAUTH2 exchange against the local mock introspection endpoint; it cannot emulate those provider policies.

## IMAP greetings and token expiration

An initial server greeting is required by IMAP, not only by Gmail. Hark consumed it only for its Gmail flavor; Epistle consumes and validates it for every connection before sending LOGIN or AUTHENTICATE. A `BYE` greeting retries as a provider outage. Unsupported `PREAUTH` tunnels and malformed greetings are rejected without sending credentials. The connect watchdog also bounds a missing greeting. Protocol tests cover delayed/fragmented Gmail, Exchange and Dovecot banners with both password and XOAUTH2 authentication. See [RFC 9051](https://www.rfc-editor.org/rfc/rfc9051.html#section-7.1) and [Exchange's Banner setting](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-imapsettings#-banner).

[Gmail documents](https://developers.google.com/workspace/gmail/imap/imap-smtp#session_length_limits) that OAuth IMAP sessions last approximately as long as the access token and close when the session expires. Epistle recycles its watcher before expiry, re-authenticates, and catches up from its durable cursor. Unexpected disconnects use the same recovery path. For normal hour-long tokens, refresh begins within five minutes of expiration and connections recycle 60–89 seconds before expiration. For shorter tokens, the refresh margin shrinks to 10% of the token lifetime (minimum one second), and recycling waits until refresh is due; this prevents an immediate refresh/reconnect loop. Token issuance and expiry times are stored with encrypted credentials. Legacy records without issuance times retain the five-minute refresh margin.

Tests use a real Dovecot server plus a strict local OAuth issuer. Both Google and Microsoft strategies survive several 12-second token lifetimes, an expired-token process restart, a forced IMAP disconnect and a temporary OAuth outage. The issuer rejects expired access tokens and previously used refresh tokens, so restarting with stale credentials fails the test. Successful rotated refresh tokens are saved before use. Revoked refresh tokens still require re-consent; a temporary outage does not. These controlled tests do not substitute for tenant-specific provider acceptance tests.

## Refresh-token rotation, expiry and crash recovery

The provider rules below were checked against current primary documentation on 2026-10-24. This service uses a confidential web-server OAuth client; Microsoft redirect URIs must be registered as **Web**, not SPA.

| Provider | Refresh and recovery contract | Expiration constraints |
| --- | --- | --- |
| Google | Its documented web-server flow reuses the stored refresh token; a normal refresh response supplies a new access token without replacing the refresh token. After a lost response or a crash before saving, retry the durable refresh token. There is no documented fixed rotation grace period for this flow. | Tokens can fail after six months of inactivity, Gmail password changes, revocation, token-count limits, admin restrictions or time-limited consent. External apps in **Testing** receive seven-day refresh tokens for Gmail scopes. Regular use prevents inactivity expiry but does not remove fixed grant deadlines or revocation. |
| Microsoft | It issues replacements but explicitly does **not** revoke the previous token merely because it was used. If the replacement was lost before persistence, the stored previous token can be retried while still valid. This is not a documented short grace timer. Replace the stored token after a successful commit; no historical-token archive is needed. | Default server-client refresh validity is 90 days; active renewal normally sustains access. Tokens can still be revoked or require interaction under sign-in policies. SPA refresh-token families instead have an inherited 24-hour deadline that rotation does not extend. |

Sources: [Google refresh flow](https://developers.google.com/identity/protocols/oauth2/web-server#offline), [Google expiration rules](https://developers.google.com/identity/protocols/oauth2#expiration), [Microsoft refresh tokens](https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens), and [Microsoft's current inactivity/max-age defaults](https://learn.microsoft.com/en-us/entra/identity-platform/configurable-token-lifetimes#refresh-and-session-token-defaults-not-configurable).

Epistle stores a returned `refresh_token_expires_in` as an absolute `refresh_token_expires_at`, encrypted with the credentials. SQLx migration 3 adds a nullable metadata column surfaced by authenticated `/health` for each account. An omitted value means **unknown**, not unlimited. Subsequent access-token refreshes or token replacements without an explicit new lifetime preserve the known deadline. New consent with a new refresh token can reset it. The service never guesses a Google seven-day or Microsoft ninety-day deadline from an opaque token. A known-expired token produces `needs_reauth` with reason `refresh_token_expired` when another refresh is needed; the provider remains authoritative for undisclosed expiry/revocation. Existing valid access tokens can continue until renewal is needed.

A truncated successful token response is an ambiguous remote success, so it is retryable through the existing backoff, not an invalid-configuration failure. On restart, the encrypted token on disk is retried. Tests launch a separate process and kill it **after receiving and applying the provider response but before the credential write**; they verify that SQLite still contains the original token, then reopen the store and recover under Google's reusable-token and Microsoft's retained-old-token contracts. Further tests cover a lost response, provider expiry/revocation, preserving reported deadlines across rotation/restart, and a strict single-use provider that cannot recover a lost replacement. The crash gate exists only in the unit-test binary; production has no fault-injection switch.

A true `invalid_grant` is not treated as an invitation to retry indefinitely. Re-consent is required if the persisted token has expired or been revoked. These recovery tests model documented contracts; they are not live-account acceptance tests. Google service accounts do not use refresh tokens: they mint another signed assertion for a new access token.

The container expiry suite also verifies a fixed refresh-token deadline through multiple rotations, its `/health` representation, transition to `needs_reauth` without repeated token requests, and recovery after importing fresh credentials.

## Container deployment

The Dockerfile uses the same pinned Rust toolchain and native GNU target for cargo-chef's cook and build stages. Dependency layers survive application-source edits. It builds natively for the selected Docker platform; amd64 and arm64 use their corresponding GNU targets and link dynamically to glibc. Build checks require a dynamic loader and `libc.so.6`, reject a musl interpreter, and verify that shared libraries resolve in the builder. The final image is [Chainguard `glibc-dynamic`](https://images.chainguard.dev/directory/image/glibc-dynamic/overview), which supplies glibc, libgcc and CA certificates without a shell/package manager. Container integration tests verify runtime library compatibility. IMAP TLS uses embedded WebPKI roots; outbound HTTPS uses the system trust store.

The runtime is pinned in `Dockerfile` to an immutable multi-platform index digest covering amd64 and arm64. The `latest` tag is descriptive; the digest selects the image, so upstream tag changes do not silently change builds. To update it, run `docker buildx imagetools inspect cgr.dev/chainguard/glibc-dynamic:latest`, replace the index digest (not an architecture-specific manifest digest), rebuild, and run the container suites in README before committing. Refresh the pin regularly to receive runtime security updates.

The process runs as `10001:10001`; `/home/epistle/data` is pre-created with that ownership so existing Compose volumes keep working. A host bind mount must also be writable by UID 10001. Keep that path on a persistent local volume. A read-only root filesystem is supported with a writable data volume; the expiry container tests also drop all Linux capabilities and enable `no-new-privileges`. Use the authenticated HTTP `/health` endpoint from outside the container instead of a shell-based health command. Send SIGTERM for a graceful stop.

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

Cleanup commits the expired marker before removing a file. If the database write fails, the file remains available; if the process crashes after the commit, startup orphan cleanup removes the leftover file.

`GET /email/messages/{id}` returns the message inside the webhook. Its body expires with the files and then returns 410; this is a temporary store. Message lookup pointers remain available for read commands for 30 days. The `seen` ledger keeps cross-folder and epoch-reset deduplication identities beyond file expiry.

## Account and queue operations

- `PATCH /email/accounts/{id}` with `{ "enabled": false }` disables synchronization and emits a status event. Use `true` to reconnect.
- `POST /email/messages/{id}/read` accepts `{ "read": true }` or `false` and returns a command ID. Poll `GET /commands/{id}?wait=5s`. Pending commands for one message execute in creation order; retries cannot overwrite a newer command.
- `POST /email/accounts/{id}/backfills` accepts RFC3339 `since` and optional `until`, `folders`, `unread_only`, `redeliver`. `until` is exclusive. The live cursor is untouched. Default discovery uses INBOX and an advertised Sent mailbox; Gmail defaults to All Mail, found through the special-use attribute.
- `GET /backfills/{id}` reports matched, enqueued and delivered counts. `done` means all enqueued deliveries were acknowledged or discarded; `failed` means an item is permanently unfetchable or a requested backfill folder is missing. Account-wide outages leave pending fetches and commands untouched. A dead outbox delivery keeps the job open until replay/discard. DELETE cancels remaining discovery/fetch work; messages already handed to delivery may still arrive.
- `GET /outbox` lists up to 500 rows, with IDs, attempts and sanitized errors. `POST /outbox/{id}/replay` retries a dead row. `DELETE /outbox/{id}` explicitly discards a dead delivery and releases its retention protection.
- `GET /health` includes `folder_errors` (opaque IDs and sanitized reasons). Missing folders recover on reconciliation without stopping healthy folders. It also reports account lag, last successful round trip, pending outbox age, depths and dead counts. Dead deliveries also produce error-level logs for external alerting.
- Deleting an account removes its credentials, queues, metadata, and message directories. This ends synchronization; it does not delete mail from the provider.

IDLE is bounded by an absolute timer, with reconciliation every three minutes by default and re-issue no later than twenty minutes. CONDSTORE is enabled when advertised alongside ENABLE, and the mailbox's highest mod-sequence is recorded. New-message correctness uses UIDVALIDITY plus UID catch-up; QRESYNC and flag/delete tracking are not required for this v1. Metadata ranges filter UIDs client-side because `n:*` can include an older highest UID. Fetchers and commands search Message-ID after an epoch reset; an absent message becomes `gone`.

## Backup and recovery

Back up the master key separately. Use SQLite's online backup API (or `sqlite3 .backup`) while the service runs, or stop the service and copy the database together with its WAL state. A plain copy of a live SQLite main file alone is not a consistent backup. Prioritize credentials, then the database and retained file store together. Never place the database on NFS or another network filesystem.

To recover, restore the database, its matching file directory and the same master key to a local volume, then start one instance. For missing historical mail, create a date backfill. Use `redeliver: true` only when explicit repeat delivery is desired. Inspect `needs_reauth` accounts after provider token revocation and update credentials to reconnect.

Do not use the local Compose test passwords, all-zero-style example keys, or insecure endpoint setting in a production deployment.

## API reference and protocol failure recovery

Open `/scalar` for the interactive API reference or `/openapi.json` for client generation. Both documentation endpoints are public; business operations require the bearer API key entered in Scalar's authentication control. The pinned Scalar 1.76.0 browser bundle is loaded from jsDelivr with an integrity hash. Requests use the current service origin with no third-party proxy and authentication persistence disabled.

IMAP metadata, search and flag results are accepted only after a tagged OK completion. NO/BAD responses, including errors following partial results, preserve pending work instead of advancing cursors, marking messages gone or reporting commands done. A UIDVALIDITY fallback verifies exact Message-ID equality because IMAP HEADER searches are substring matches.

Missing webhook payloads become dead with `payload_missing`; remaining files stay retained. Restore the payload before replay, or discard and request a redelivery backfill. Independent webhook deliveries continue even when another delivery's acknowledgment transaction fails. See `spec-review.md` for the complete review and its test coverage.
