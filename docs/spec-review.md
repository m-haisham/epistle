# Implementation review against the v1 specification

Reviewed on 2026-10-25 against `docs/spec.md`. The original specification remains unchanged. This review covers source paths, SQLx migrations, existing tests and the new regressions below; provider-specific acceptance still requires live accounts.

## Corrections made

| Finding | Correction and regression evidence |
| --- | --- |
| `async-imap` 0.12 streaming helpers discard tagged completion status. A failed metadata fetch could advance the cursor, a body fetch could become `gone`, and a rejected STORE could become `done`. | The IMAP wrapper now explicitly checks tagged completion for CAPABILITY, LIST, SEARCH, FETCH, STORE and ENABLE. Partial results are withheld until OK; NO/BAD, BYE, EOF and watchdog expiry fail the operation. Wire tests reject each command after partial data; queue tests verify recovery after repeated failures. Gmail metadata, including thread IDs, is fetched together through this checked path. |
| An outage during fetch/STORE consumed item retry attempts and could permanently lose pending work. | Account-wide errors leave queue state, attempts and scheduling unchanged. A deterministic IMAP fixture fails more times than the retry limit, then reopens SQLite and successfully fetches/delivers and executes the same command. Invalid per-message identifiers fail only their own item. |
| A missing folder parked the entire account; a backfill targeting a missing folder also stopped live sync. | Folder errors are persisted separately and exposed in authenticated health results. Healthy folders continue; missing folders are retried on reconciliation and recover automatically. A missing backfill target fails that job. Real Dovecot tests cover initial absence, creation, deletion, `gone` read commands and continuing delivery. Dovecot's legacy missing-mailbox response is recognized without exposing server text. |
| UIDVALIDITY recovery accepted the first substring match from IMAP HEADER search. | Candidate envelopes must have the exact Message-ID before fetch/STORE. A wire regression returns a misleading first candidate and verifies only the exact second candidate is modified. |
| A command completing against an old pointer could overwrite a newer pointer learned by the watcher. | Command completion compares the current pointer transactionally. If discovery moved the message during the round trip, the command stays pending and retries its current location. |
| OAuth callback credentials and activation used separate transactions; disabling during token exchange could be undone. | Credential replacement, revision change and status event commit together, with revision checked at commit. Tests inject an activation failure and a concurrent disable. Authorization codes remain single-use; a failed code exchange/commit requires a fresh consent flow. |
| A login-time UNAVAILABLE response was classified as rejected credentials. | Explicit provider outages remain retryable and do not force reauthorization. A wire regression covers this response. |
| A missing webhook payload retried every tick, and one delivery error aborted unrelated concurrent deliveries. | Missing payloads become dead with `payload_missing`, retaining remaining files for repair/replay or discard. Other read errors use bounded retries. Each delivery batch drains every independent task, even if another acknowledgment transaction fails. Tests cover a missing payload and a failed ack alongside a slower successful delivery. |
| A supervisor panic could be immediately restarted from a stale account snapshot; parser task failures were retried indefinitely. | Panicked supervisors are excluded from the current restart pass; task panics park the account with an error event. Credential decryption failures also park as configuration errors. |
| Restart reset password failure history and skipped opt-in reminders for already parked accounts. | Supervisors retain the persisted failure count and first-failure window. Configured reauthorization reminders resume without reconnecting or retrying revoked credentials; focused restart tests cover both paths. |
| Long fetch/command batches could start another operation after their connection recycle deadline. | The workers check the deadline and current account revision between items, preserving pending work for the next connection. |
| OpenAPI had no interactive reference and health/callback results were untyped JSON. | `/scalar` renders the generated `/openapi.json`. Health and callback outputs have named schemas. Route tests verify public documentation, schema fields, and bearer authentication on operations. |

## Coverage by specification area

| Specification area | Implementation and verification |
| --- | --- |
| Single instance, SQLite WAL, epochs and atomic writes | OS directory lock, read-only SQLx pool, writer actor, migration checksums; lock, rollback and stale-epoch tests. |
| Authentication and token lifecycle | Four strategies, PKCE/signed one-use state, granted scopes, single-flight refresh, encrypted credentials, rotation-before-use, deadline retention; OAuth/service-account tests and actual crash-before-save subprocess tests. |
| Watcher, catch-up and dedupe | EXAMINE/IDLE, absolute reconciliation timers, metadata cursor transactions, Gmail identity, persisted discovery and UIDVALIDITY resets; protocol regressions and Dovecot arrival/move/expunge/restart tests. |
| Fetching and commands | Checked IMAP completions, per-item persistence, PEEK bodies, MIME parse fallback, exact epoch recovery, ordered idempotent commands, outage-preserved queues and token recycling. |
| Backfills | Stored matches and folder completion markers, chunked enqueue, date filtering, unread/redeliver options, cancellation and progress; integration tests plus isolated missing-target failures. |
| Delivery and file lifecycle | Stable idempotency keys, HMAC, ordered groups, independent concurrent delivery, retry/dead/replay/discard, immutable generations, ack-based retention, pressure eviction and startup orphan cleanup; transaction-boundary and HTTP/file tests. |
| Status and operations | Atomic transition/event audit, sequence ordering, reauth parking/reminders, revision fencing, folder errors and health/dead counts; status and integration tests. |
| HTTP and documentation | Required v1 routes, bearer auth, typed errors and response schemas, file range/ETag/410 behavior, generated OpenAPI and Scalar; API and integration tests. |
| Packaging and configuration | `config` defaults/file/environment, SQLx migrations, pinned dependencies/toolchain, cargo-chef build, static distroless nonroot runtime, CI lint/tests/audit/deny. |

## Scope and operational boundaries

- The specification's deferred features remain deferred: outbound mail, flag/delete events, SMS/WhatsApp and a cap on undelivered bytes. Batch byte limits do not impose a maximum size on an individual email.
- UID catch-up and reconciliation provide v1 new-message correctness. CONDSTORE is enabled when available; QRESYNC delta synchronization and flag/delete tracking are not implemented for this scope.
- IMAP supports code-based error classification plus a narrow Dovecot compatibility case. Unrecognized provider failures remain retryable; real provider throttling, Gmail extensions and tenant-specific authentication restrictions require live acceptance tests.
- Missing local payload data cannot be reconstructed without restoring the file or fetching mail again. The row is retained as dead rather than silently acknowledged. After repairing its stored payload, replay it; alternatively discard and request an explicit redelivery backfill.
- A lost authorization-code response is not generally recoverable by retrying the single-use code. Start a new consent flow. Refresh-token crash recovery has separate Google/Microsoft tests and documented provider guarantees in `operations.md`.
- Scalar loads a version-pinned, integrity-checked script from jsDelivr. Browser access to that CDN is needed for the interactive reference; `/openapi.json` remains directly available. API calls go to the current service origin without a third-party proxy, and bearer credentials are not persisted by Scalar.
