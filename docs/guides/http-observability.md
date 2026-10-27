# HTTP observations and bounded resource behavior

The selected Axum authentication boundaries emit fixed-field `tracing` events.
They preserve the existing server-generated `x-request-id` response header,
security headers, Origin policy and 15-second handler timeout. Incoming request
IDs never select the generated ID. No monitoring endpoint, exporter, remote
collector, new dependency or automatic authentication-policy tuning is introduced.

## Event contract

The event target remains `easy_auth_axum::browser::boundary` at INFO level:

| Message | Fields | Meaning |
| --- | --- | --- |
| `http_request_completed` | `request_id`, `status`, `duration_micros`, `completion` | The boundary produced a response; `completion` is `response` or `timed_out` |
| `http_request_cancelled` | `request_id`, `duration_micros`, `completion` | The boundary future was dropped before producing a response; `completion` is `cancelled`, with no invented HTTP status |

`request_id` is a new server UUID for every entered boundary. `status` is the
actual response status. `duration_micros` is monotonic elapsed time, represented
as a nonnegative integer. Completion duration ends when the boundary produces
response headers; it does not include streaming the response body, socket delivery
or client processing. Cancellation includes future drop/unwind and does not prove
a particular client disconnect or report successful transport delivery.

The original subscriber is retained for the request's lifetime so a future dropped
outside its last poll's subscriber scope still records cancellation to that sink.
Completed requests emit one completion event and no cancellation event. Process
termination can prevent either observation; this is operational telemetry, not a
durable audit ledger or authority to decide whether a transaction committed.

No path, query, method supplied by a client, header, cookie, body, source address,
email, user/realm/provider identifier, credential or raw error enters these events.
The executable's existing filtered formatter remains in place. Embedded consumers
may use their trusted `tracing` subscriber; the event contract is structured fields,
not a promise that the default executable emits JSON or installs a metrics backend.

## Aggregation and interpretation

Aggregate completion counts by the fixed event/completion categories and actual
status. Build duration histograms from `duration_micros` with explicitly chosen
buckets in the receiving system. Count cancellations separately; they have no
response status and cannot be counted as successful responses. A 429 refusal is
not successful authentication capacity. Keep the request UUID in logs for bounded
retention/correlation, **never as a metric label**. Do not enrich metric labels
with paths, identities, tokens or request-supplied values.

Logs and their retention/export access remain operator responsibilities. Use a
trusted bounded sink; no unbounded application queue or background sender is added
by this change. Enabling unrelated dependency TRACE output has its own privacy
implications and is not authorized by this fixed-field contract.

## Overload and cancellation boundaries

Existing password admission is database-backed and realm-scoped. A shared
`PasswordService` permits at most two Argon2 jobs and returns 429 rather than
queueing unlimited hash work. Cancelling an HTTP future does not release a permit
while its blocking job remains queued/running. Once those jobs finish, capacity
returns. Hash parameters and database attempt budgets are unchanged; share the
service across process routers as documented in the [password guide](passwords.md).

The new HTTP regression controls a private runtime's blocking queue, drives the
actual password-login handlers and real PostgreSQL admission below their source
budget, observes saturation, cancels outstanding requests, verifies continued
refusal while jobs remain, then verifies ordinary rejection after capacity returns.
Other cases observe actual database lock waits before timeout/drop and require
rollback without a challenge or mail commit. They use in-process HTTP services and
owned databases, not production sockets or real provider accounts.

Cancellation is not a general transaction undo mechanism: already committed
endpoint effects may remain, and an observation grants no session or retry
authority. Do not automatically repeat credential-completion requests because a
response was lost. Deployment-wide ingress protection, distributed abuse,
representative sustained HTTP/TLS load and production capacity remain separate
qualification. The [local library benchmarks](authentication-performance.md) keep
their exact earlier source/build scope and exclude this HTTP instrumentation.
