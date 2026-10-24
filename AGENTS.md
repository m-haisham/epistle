# Working on Epistle

Epistle is a single-tenant Rust IMAP ingestion service. Read [README.md](README.md) for setup, [docs/spec.md](docs/spec.md) for the original v1 requirements, and [docs/operations.md](docs/operations.md) for runtime contracts. [docs/spec-review.md](docs/spec-review.md) records reviewed gaps and scope boundaries. Preserve the original specification unless the user asks to change it.

## Repository map

- `crates/core`: shared types; nested application configuration lives in `src/config.rs`.
- `crates/store`: SQLx persistence, migrations, process epochs and status events.
- `crates/auth`: encrypted credentials, consent and token lifecycle.
- `crates/imap`: protocol handling and bounded sessions.
- `crates/email`: supervision, discovery, parsing, backfills and commands.
- `crates/delivery`: durable files, retention and webhook outbox.
- `crates/api`: Axum routes, OpenAPI and Scalar.
- `crates/server`: startup, tracing and shutdown.
- `migrations`: embedded SQLx migrations; add new migrations instead of editing applied ones.
- `tests` and `infra`: integration suites, Dovecot and local OAuth/webhook fixtures.

The adjacent `../hark` project is an incomplete reference, especially for email parsing. Inspect useful behavior and verify it against Epistle's contracts. Do not modify Hark as part of an Epistle change unless requested.

## Rust conventions

- Use the pinned toolchain and workspace dependencies. Keep `Cargo.lock` committed; use `--locked` for reproducible checks.
- Run rustfmt. Separate logical blocks with blank lines and expand dense closures and query chains.
- Use concise `//!` module documentation and `///` documentation for public behavior. Explain invariants and non-obvious decisions without narrating the code.
- Follow workspace lints: no unsafe code, production panics, unchecked indexing, `unwrap`, `expect` or `todo`. Keep justified test allowances scoped to tests.
- Use typed errors and sanitized operational reason codes. Parameterize SQL and keep writes in the store's serialized transaction path.
- Use typed nested `config` settings for defaults, optional TOML and `EPISTLE_` environment overrides (`__` separates sections). Preserve documented legacy aliases and layering when adding settings. Keep changes documented in the example file and operations guide.
- Use `tracing` for library instrumentation; initialize `tracing-subscriber` only in the server. Use async-safe spans and skip sensitive arguments. Never log credentials, OAuth codes/state, authorization headers, message contents or raw provider responses. HTTP tracing uses matched route templates, not raw URLs.

## Durability and shutdown invariants

- Discovery, deduplication, fetch enqueue and cursor advancement must commit atomically. Do not advance a cursor after partial or rejected IMAP results.
- Validate tagged IMAP completion. Library stream helpers may omit final NO/BAD responses. Preserve the greeting handling and exact Message-ID check during UIDVALIDITY recovery.
- Flush immutable payload/file generations before transactional handoff. Retention commits an expired marker before unlinking; pending/dead deliveries retain their files.
- Keep acknowledgment and outbox state changes transactional. Delivery is at least once; retries retain the same idempotency key. Independent delivery groups must not cancel one another.
- Serialize refreshes per account and persist replacement credentials before exposing the access token. Preserve known refresh deadlines unless the provider or new consent replaces them. Do not assume rotation prevents expiry or that a lost replacement is always recoverable.
- Respect process epochs and account revisions. Provider outages must not exhaust per-message work; missing folders must not stop healthy folders.
- Cancellation stops new work at durable boundaries. Drain in-flight refreshes, fetch/handoff, commands, webhook acknowledgments and accepted database writes. Interrupt idle/backoff waits promptly; retain watchdogs on network operations.
- Await workers and close the store before releasing the instance lock. Do not reintroduce blanket task abortion or a fixed internal shutdown cutoff.

## Documentation lookup: Context7

Use Context7 for library, framework, SDK, API, CLI and cloud-service documentation, including setup, syntax, migration and library-specific debugging. Do not rely only on remembered APIs. Prefer Context7 over web search for library docs.

1. Call `resolve-library-id` with the library name and a focused question, unless given an exact `/org/project` ID.
2. Select by name/relevance, source reputation, snippet coverage and benchmark score. Use a version-specific ID when applicable; refine an unsuitable search.
3. Call `query-docs` for one concept at a time. Split distinct concepts into separate queries unless their interaction is the question.
4. Base implementation and explanations on the fetched documentation. Use primary provider documentation for OAuth policies and state any limits of modeled tests.

Context7 is not needed for plain refactoring, repository-only review, business-logic debugging or general programming concepts that do not depend on a library API.

## Verification

Match checks to the change. Documentation-only edits need link, example and diff checks; do not rebuild containers solely for prose. For Rust changes, run relevant regressions, formatting and strict Clippy; broaden testing when affected behavior warrants it.

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo doc --locked --workspace --no-deps
cargo build --locked -p epistle-server
```

Use the integration commands in README for protocol, authentication, delivery, shutdown or container changes. Run suites sequentially: they share the mock, Docker network and port 18080. Set `COMPOSE_PROJECT_NAME=epistle` for the expected image/network names. Rebuild the server or image before testing changed code.

Add regressions for changed failure boundaries, not just happy paths. Relevant scenarios include rejected/partial IMAP responses, disconnects, token response/persistence gaps, database rollback, lost acknowledgments, file retention, cancellation and restart. Use synthetic accounts and local fixtures; never real credentials in tests. Distinguish modeled provider behavior from live acceptance tests.

Keep the cargo-chef GNU/glibc build and nonroot distroless CC runtime working; do not switch back to musl. Preserve the writable data-volume contract and allow enough container stop time for graceful draining. CI additionally runs `cargo audit` and `cargo deny check`.

## Change discipline

Inspect Git status before editing. Preserve unrelated user edits and stage only task-owned changes. Commit small, coherent increments after appropriate verification. Keep API schemas, README and operations guidance consistent with behavior changes. Report what changed, checks performed and any remaining limitations. Do not expand deferred v1 scope without a user request.
