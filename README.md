# Epistle

Epistle is a single-tenant Rust service that ingests email over IMAP and delivers normalized messages through signed webhooks. It keeps synchronization cursors, pending work and delivery retries in SQLite, with message bodies and attachments on local disk.

```text
IMAP → discovery + durable fetch queue → MIME parsing + files → webhook outbox → your application
```

It supports password authentication, Google OAuth, Microsoft OAuth and Google Workspace service accounts. Features include initial synchronization, live discovery, date-based backfills, read/unread commands, attachment downloads and recovery after disconnects or restarts.

- [API reference](http://localhost:8080/scalar): `/scalar`, backed by `/openapi.json`.
- [Operations guide](docs/operations.md): provider setup, configuration, delivery contracts and recovery.
- [Original specification](docs/spec.md) and [implementation review](docs/spec-review.md).
- [Contributor instructions](AGENTS.md).

## Quick start with Docker

Run from the repository root with Docker and Compose installed:

```sh
docker compose up -d --build
```

This starts Epistle, a local Dovecot IMAP server and a webhook/OAuth mock. The supplied credentials and plaintext IMAP settings are for local testing only.

| Service | Address |
| --- | --- |
| Epistle API and Scalar | `http://localhost:8080` |
| Webhook recorder | `http://localhost:8090/events` |
| Test IMAP server | `localhost:1143` |

Create an account:

```sh
curl http://localhost:8080/email/accounts \
  -H 'Authorization: Bearer local-test-api-key-0000000000000000' \
  -H 'Content-Type: application/json' \
  -d '{
    "external_ref": "client-1",
    "email": "client@example.test",
    "auth_kind": "password",
    "config": {
      "host": "dovecot",
      "port": 143,
      "tls": false,
      "folders": ["INBOX"]
    },
    "credentials": {"password": "test-password"}
  }'
```

Dovecot accepts test usernames with `test-password`. Append an email to INBOX through port 1143 to see an `email.message.received` event in the recorder. The API response contains the account ID used for subsequent operations.

Inspect logs or stop the stack without removing its data volume:

```sh
docker compose logs -f epistle
docker compose stop
```

## Run the Rust server

Use the toolchain pinned in [rust-toolchain.toml](rust-toolchain.toml); Rustup selects it automatically. Copy [epistle.example.toml](epistle.example.toml) to `epistle.toml` and configure your URLs and limits.

```sh
cp epistle.example.toml epistle.toml

# Generate these once, then retain them in your deployment's secret storage.
export EPISTLE_SERVER__API_KEY="$(openssl rand -hex 32)"
export EPISTLE_AUTH__MASTER_KEY="$(openssl rand -hex 32)"
export EPISTLE_DELIVERY__WEBHOOK_SECRET="$(openssl rand -hex 32)"
export EPISTLE_DELIVERY__WEBHOOK_URL="https://your-app.example/webhooks/email"
export EPISTLE_SERVER__PUBLIC_URL="https://email.example"

cargo run --locked -p epistle-server
```

Keep `EPISTLE_AUTH__MASTER_KEY` stable across restarts and back it up separately. Replacing it makes existing encrypted credentials unreadable. The server defaults to `127.0.0.1:8080`; use a reverse proxy for public HTTPS.

Application settings are grouped into `[server]`, `[storage]`, `[mail]`, `[mail.fetch]`, `[delivery]`, `[auth]`, `[auth.google]`, `[auth.microsoft]` and `[testing]`. The Rust types use the same hierarchy in `crates/core/src/config.rs`.

Configuration precedence is **defaults → optional `epistle.toml` → environment** through the `config` crate. Environment names start with `EPISTLE_`, with `__` between sections: `mail.fetch.batch_count` becomes `EPISTLE_MAIL__FETCH__BATCH_COUNT`. Secrets stay strings during parsing. Existing flat file keys and unprefixed environment names remain supported; see [configuration migration](docs/operations.md#configuration-migration). SQLx migrations run automatically at startup.

| Setting | Purpose / default |
| --- | --- |
| `EPISTLE_SERVER__API_KEY` | Required bearer key, at least 32 characters |
| `EPISTLE_AUTH__MASTER_KEY` | Required encryption key, 32 bytes encoded as 64 hex characters |
| `EPISTLE_DELIVERY__WEBHOOK_SECRET` | Required signing secret, at least 32 characters |
| `EPISTLE_DELIVERY__WEBHOOK_URL` | Required HTTPS destination |
| `EPISTLE_SERVER__PUBLIC_URL` | Public API origin; OAuth callback is `/oauth/callback` |
| `EPISTLE_STORAGE__DATA_DIR` | SQLite and message files; defaults to `./data` |
| `EPISTLE_SERVER__BIND_ADDR` | Listen address; defaults to `127.0.0.1:8080` |
| `RUST_LOG` | Tracing filter; defaults to `info` |

OAuth clients use `EPISTLE_AUTH__GOOGLE__CLIENT_ID` / `EPISTLE_AUTH__GOOGLE__CLIENT_SECRET` or `EPISTLE_AUTH__MICROSOFT__CLIENT_ID` / `EPISTLE_AUTH__MICROSOFT__CLIENT_SECRET`. Creating an OAuth account without a refresh token returns a `redirect_url` for consent. See [authentication providers](docs/operations.md#authentication-providers) for scopes, service accounts and tenant configuration.

Verified IMAP TLS is the default. `EPISTLE_TESTING__ALLOW_INSECURE_ENDPOINTS=true` explicitly enables local HTTP/plaintext test endpoints and token endpoint overrides. The example TOML and operations guide cover all limits and retention settings.

## API and delivery contract

Business endpoints, including `/health`, require `Authorization: Bearer <EPISTLE_SERVER__API_KEY>`. `/scalar` and `/openapi.json` are public. The OAuth callback uses signed, expiring, single-use state. Scalar loads a pinned, integrity-checked browser bundle from jsDelivr; API calls stay on the service origin and authentication is not persisted by Scalar.

| Operation | Routes |
| --- | --- |
| Create/list accounts | `POST /email/accounts`, `GET /email/accounts` |
| Inspect, enable/disable or remove an account | `GET`, `PATCH`, `DELETE /email/accounts/{id}` |
| Replace credentials or start consent | `POST /email/accounts/{id}/credentials` |
| Start, inspect or cancel a backfill | `POST /email/accounts/{id}/backfills`, `GET` / `DELETE /backfills/{id}` |
| Read a message or download a file | `GET /email/messages/{id}`, `GET /email/messages/{id}/files/{file_id}` |
| Set read/unread state and inspect the command | `POST /email/messages/{id}/read`, `GET /commands/{id}` |
| Inspect, replay or discard dead delivery | `GET /outbox`, `POST /outbox/{id}/replay`, `DELETE /outbox/{id}` |
| Inspect account and queue health | `GET /health` |

Webhooks carry `email.message.received` or `account.status_changed` events. Verify `X-Epistle-Signature` over the exact request bytes and timestamp, deduplicate with `Idempotency-Key`, and return a 2xx response after accepting the event. Delivery is **at least once**: a crash after remote acceptance but before the local acknowledgment commits can cause a repeat.

Message files are temporary. Their retention window starts after acknowledgment; pending and dead deliveries protect their files. Download needed files promptly. Expired files and message bodies return 410. Read [messages and webhooks](docs/operations.md#messages-and-webhooks) for signature construction, retry rules, file ranges and retention.

## Shutdown, recovery and deployment

SIGTERM or SIGINT stops new work and drains in-flight HTTP handlers, token exchanges, message handoffs, read commands, webhook acknowledgments and database writes. An idle IMAP worker closes promptly; it does **not** wait for another message. The instance lock is released after draining. Restart resumes persisted queues and cursors.

Compose allows five minutes to stop. For a manually managed container, use `docker stop --time 300 <container>`. Allow longer when workloads require it. A forced kill or external deadline bypasses graceful shutdown and uses the documented crash-recovery paths.

Run **one instance per data directory** on a persistent local volume. SQLite uses WAL, a read-only query pool and a dedicated fenced writer. Do not share the data directory between replicas or put it on NFS. Back up the database and retained file store consistently, together with a separately stored master key.

The Dockerfile uses cargo-chef and builds a GNU-target binary linked to glibc. Its runtime is Chainguard `glibc-dynamic`, pinned by multi-platform image digest and running as `10001:10001`, with no shell or package manager. Persist `/home/epistle/data`; host bind mounts must be writable by that UID. See [container deployment](docs/operations.md#container-deployment) for details.

Use `RUST_LOG=info,epistle_email=debug,epistle_auth=debug` for diagnostics. Application traces include opaque account/request/delivery IDs, route templates, status and timing; credentials, HTTP bodies and query strings are omitted.

## Development and verification

| Crate | Responsibility |
| --- | --- |
| `core` | Shared types, configuration and identifiers |
| `store` | SQLx migrations, transactions, epochs and status events |
| `auth` | Credential encryption, OAuth and token refresh |
| `imap` | Greeting/authentication, checked commands and bounded sessions |
| `email` | Supervision, discovery, MIME parsing, backfills and commands |
| `delivery` | Durable files, retention and webhook delivery |
| `api` | HTTP operations, OpenAPI and Scalar |
| `server` | Startup, tracing and graceful shutdown |

Run Rust checks from the repository root:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo doc --locked --workspace --no-deps
cargo build --locked -p epistle-server
```

The integration tests require Docker, Compose and Python 3. Run them **sequentially**: they share the mock and port 18080. They create their own service instance; only Dovecot and the mock need to be running beforehand.

```sh
export COMPOSE_PROJECT_NAME=epistle
docker compose up -d --build dovecot mock
python3 tests/integration.py

docker compose build epistle
python3 tests/token_expiry.py --image epistle-epistle:latest
python3 tests/recovery.py --image epistle-epistle:latest
python3 tests/shutdown.py --image epistle-epistle:latest
```

Omit `--image` to use the host debug binary. The suites cover ingestion and files, token expiry/rotation and outages, folder isolation, and SIGTERM/SIGINT during token exchange and delivery. Rust regressions inject transaction failures and kill a child process in the refresh-token crash window.

CI also runs `cargo audit` and `cargo deny check`; install their Cargo subcommands to run these locally. Controlled OAuth issuers model provider contracts, including an adversarial single-use refresh token. Live Google/Microsoft policies and tenant-specific behavior still require real-account acceptance testing.

## Scope and Hark

Hark's email parser and domain types informed grouped addresses, sender/resent envelopes, reply references, combined text/HTML parts and inline attachment metadata. Epistle uses current `mail-parser` APIs and stores attachments as files; Hark remains a reference project.

Outbound email, flag/delete webhooks, an undelivered-byte cap, SMS and WhatsApp are outside v1. See the [specification review](docs/spec-review.md) for coverage and operational boundaries.
