# Epistle

A single-tenant Rust email ingestion service: IMAP → durable fetch queue → parsed message and temporary files → signed webhook. The original design is preserved verbatim in [docs/spec.md](docs/spec.md).

The workspace contains `core`, `store`, `auth`, `imap`, `email`, `delivery`, `api`, and `server` crates. SQLx migrations run automatically at startup. Configuration uses `config`: defaults, optional `epistle.toml`, then uppercase environment variables. Secrets are never coerced into numbers by environment parsing.

## Run locally

```sh
cargo build --locked -p epistle-server
# Starts Dovecot, a webhook recorder and OAuth mock, and Epistle.
docker compose up --build
```

The Compose environment is explicitly for local testing. It uses test credentials, a plaintext IMAP connection on the private Docker network, and binds exposed ports to loopback. The API is at `http://localhost:8080`; the webhook recorder is at `http://localhost:8090/events`.

The Docker build uses cargo-chef to cache dependencies and compiles a fully static musl binary. The runtime is `gcr.io/distroless/static-debian13:nonroot`, with no shell or package manager. It runs as UID/GID `10001:10001` to preserve compatibility with existing Epistle volumes. See [container deployment](docs/operations.md#container-deployment) for volume permissions and verification.

Create a test account:

```sh
curl http://localhost:8080/email/accounts \
  -H 'Authorization: Bearer local-test-api-key-0000000000000000' \
  -H 'Content-Type: application/json' \
  -d '{
    "external_ref":"client-1",
    "email":"client@example.test",
    "auth_kind":"password",
    "config":{"host":"dovecot","port":143,"tls":false,"folders":["INBOX","Sent"]},
    "credentials":{"password":"test-password"}
  }'
```

Dovecot's local test configuration accepts any test username with `test-password`. Append messages over IMAP on `localhost:1143` or use the integration suite. `GET /openapi.json` serves the generated OpenAPI document. Open [Scalar API Reference](http://localhost:8080/scalar) at `/scalar` to browse and try authenticated operations. Every business endpoint requires `Authorization: Bearer <API_KEY>`; the OAuth callback is protected by a signed, expiring, single-use state instead.

## Run outside Compose

Copy `epistle.example.toml` to `epistle.toml` and configure the webhook and public callback URLs. Supply secrets through your deployment environment:

```sh
export API_KEY="$(openssl rand -hex 32)"
export MASTER_KEY="$(openssl rand -hex 32)"
export WEBHOOK_SECRET="$(openssl rand -hex 32)"
export WEBHOOK_URL="https://your-app.example/webhooks/email"
export PUBLIC_URL="https://email.example"
cargo run --locked -p epistle-server
```

Keep the master key stable and back it up separately from the SQLite database. The service binds to `127.0.0.1:8080` by default. Terminate HTTPS at your reverse proxy. IMAP uses verified TLS by default; plaintext IMAP and token endpoint overrides require the explicit `ALLOW_INSECURE_TEST_ENDPOINTS=true` test setting.

See [docs/operations.md](docs/operations.md) for provider setup, delivery contracts, retention, backups, and recovery.

## Verification

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked -p epistle-server
docker compose up -d --build dovecot mock
python3 tests/integration.py
# Repeat OAuth expiry/restart tests against the actual distroless image.
docker compose build epistle
python3 tests/token_expiry.py --image epistle-epistle:latest
python3 tests/recovery.py --image epistle-epistle:latest
python3 tests/shutdown.py --image epistle-epistle:latest
cargo audit
cargo deny check
```

Rust tests use loopback HTTP servers for token and delivery tests. The integration suite starts its own service on port 18080 with a temporary data directory and uses Dovecot on port 1143 and the mock on port 8090. It covers initial/live sync, attachments, signatures, ranges, read/unread, cross-folder dedupe, backfills, restart catch-up, UIDVALIDITY fallback, dead replay, real XOAUTH2, revoked-token recovery, encryption, retention, and ordered status events. The expiry suite tests both Google and Microsoft account strategies with 12-second tokens, a rotating refresh token that becomes invalid after use, natural reconnects, process crashes, provider disconnects, and temporary token-endpoint failures. It checks catch-up, deduplication, files, and commands after restart. Omit `--image` to test the host debug binary. Run the suites sequentially: they share the mock and port 18080. Auth unit tests also kill a child process precisely after token exchange and before persistence, then verify recovery using Google/Microsoft token-reuse rules. These tests also cover lost responses and refresh-token expiration; the strict single-use issuer is an additional adversarial model, not a claim about Google or Microsoft rotation. SQL transaction failures are injected at discovery, handoff, and delivery acknowledgment boundaries in Rust tests.

The recovery suite covers missing-folder isolation, failed backfill targets, folder recreation, deleted-folder commands and the Scalar endpoint. See [the specification review](docs/spec-review.md) for the review findings, fixes and remaining scope boundaries.

The shutdown suite sends SIGTERM during a paused OAuth exchange and SIGINT during a paused webhook response. It verifies credential persistence, acknowledgment draining and restart catch-up in both the host binary and distroless image. Rust tests also check pending fetches, commands and queued database transactions at shutdown boundaries.

GitHub Actions runs the checks above, and Dependabot proposes weekly dependency updates. Duplicate transitive crate versions are reported by `cargo deny`; advisories, unapproved licenses, wildcard dependencies, and unknown sources fail the checks.

## Relationship to Hark

Hark's `src/imap/body.rs` and domain types informed the parser here: grouped addresses, sender/resent envelopes, reply references, all text/HTML body parts, and inline attachment metadata are preserved. This uses current `mail-parser` APIs and stores attachments as files. Hark's code and data remain unchanged. Its lazy-session approach also informed the fetcher's connection lifecycle.

Outbound email, flag-change/delete webhooks, an undelivered-byte cap, SMS, and WhatsApp remain outside this v1, as specified in the design.
