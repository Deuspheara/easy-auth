# HTTP observation and resource-lifetime qualification — 2026-10-27

This increment extends AUTH-50's local evidence with fixed-field observations and
actual HTTP-handler timeout/drop/KDF-pressure controls. It is not production load
acceptance, a security audit, protocol compliance or completion of AUTH-50's
prerequisites. External review, real provider/OS and production verification remain
separate and unperformed.

## Source and maintained boundaries

The branch is `feat/auth-50-bounded-benchmarks`, continuing pushed benchmark/review
checkpoint `c7e11ee7a3237ed2dd16bc809d2c958377037cc5`. Fixed security headers and the
unchanged CSP assertion were extracted in separate commit `8ec0abc26a68da9fabc54aba55bda2ad9fee453e`.
Existing library and default/all-feature real-PostgreSQL boundary tests passed on
that clean extraction before behavior changes. An initial unpublished extraction
compile failure exposed a missing Origin-header import; corrected before those
passes, with the original failed/cleanup receipt retained.

Behavior source `5b66eb4fe153f6ec87ee2499cb9c9d6be0601fb7` adds a private observation lifetime around the
same boundary. Qualified source `d32fe8eae3a316bd0ae5c9a6f72328fee55b6175` corrects only
the new tests' JSON-field-order assumption; runtime, fields and canary assertions
are unchanged. Source remained clean/frozen during focused and required checks.

The existing event target/message and generated response request ID remain. New
fields are monotonic integer duration and finite response/timeout classification.
Dropped futures emit a separate cancellation event without a fabricated status.
The original subscriber remains owned through drop outside its last poll's scope.
No path/query/header/body/source/identity/credential/raw-error field is accepted.
No route, auth policy, migration, key/hash profile, dependency, telemetry endpoint
or remote exporter was added. Origin exceptions, 15-second timeout, all headers
and protocol-specific error bodies remain as before. See the
[event contract](../guides/http-observability.md).

## Concrete new controls

All four new cases passed in both default and all-feature real-PG HTTP runs:

- Untrusted-input privacy: actual session/email requests carry a canary through
  query, Authorization, Cookie, Origin and body plus a valid-looking client request
  ID. Responses reject as required, no mail is sent, fresh server UUIDs differ and
  match the events. The complete allowed field sets are asserted; no canary/client
  ID may enter captured fields.
- Timeout: an exclusively owned table lock blocks real email admission. Actual
  database wait observation precedes the unchanged handler timeout. One completion
  reports 504 / `timed_out`, the matching request ID and duration. After lock
  release, all transactions drain; no challenge or mail commits.
- Cancellation: the same actual database wait is observed before aborting the
  request future outside its poll's subscriber scope. Exactly one cancellation is
  captured through its original sink, with no status or completed response. After
  releasing the lock, actual transaction drain/no-challenge/no-mail controls pass.
- KDF pressure: a private runtime controls one blocking-worker queue while the
  production service retains its actual two permits/Argon2 profile. Thirty-two
  distinct unknown-account password HTTP requests stay below the shared source
  budget. Saturation produces 429, then all outstanding HTTP tasks are cancelled.
  Another request still receives 429 while queued work owns the permits. Releasing
  the owned blocker allows genuine hash work to finish; ordinary 401 behavior
  returns. Captured events include rejection, cancellation and recovery with valid
  generated UUIDs/durations. No private production permit introspection, reduced
  hash cost, synthetic authentication proof or timer replacement is used.

These are in-process HTTP services with real PostgreSQL and genuine password
work, not TCP/TLS throughput or a supported OS/provider matrix. Completed-response
timing ends before body/socket delivery. Drop observations do not prove a specific
client disconnect, general rollback or cancellation of an already running native
job. They do not authorize replaying credential completion.

The first behavior run passed timeout and pressure but failed two new exact-field
assertions because JSON preserves insertion order in this graph. The correction
sorts the entire captured key set before comparison; it does not remove a field,
canary, outcome, timing-policy or rollback assertion. Failed receipts/logs remain.

## Required checks and resource ownership

On exact clean `d32fe8e`, formatting, strict default/all-feature workspace/all-target Clippy, default workspace tests (171 passes) and all-feature workspace tests (1,197 reported passes: 1,196 primary plus the isolated logging child) all passed, with zero failed/ignored. The real-PostgreSQL lifecycle target remains 676 passes; the four new HTTP cases are separate. The explicit benchmark Rust control and five Python test methods passed as well. Compiled-graph advisory and all-feature cargo-deny checks passed with inactive RSA/RUSTSEC-2023-0071 and existing warnings retained.

Later evidence/guide/manifest edits change no runtime, test, dependency or schema input and retain that exact backend qualification scope. No new hosted run is inferred from local results.

Every focused and full gate phase provisioned separate newly owned disposable
PostgreSQL/Mailpit with random loopback ports, owner labels, no host bind mounts
and exclusive anonymous volumes. Mail assertions here use the maintained in-memory
HTTP test delivery fixture; Mailpit was provisioned by the shared service lifetime
but these cases do not claim SMTP delivery. Cleanup inspected actual IDs/ownership
and verified container/volume absence, including after the initial failed phases.
No retained preview, existing account/passkey, unrelated service or protected
private/research file was executed or used as a fixture.

## Maintainability and remaining acceptance

Private browser headers, observation lifetime and Origin/timeout composition have
separate responsibilities. Tests separate capture, privacy, observed SQL waits and
ordered resource pressure. New modules stay below 200 lines; the longer ordered
pressure test deliberately retains blocker ownership, abort, permit retention,
release and actual recovery together. Visibility stays private; no test-only
production getter, catch-all framework or unrelated structural refactor is added.

The earlier [library benchmark](authentication-benchmark-verification-2026-10-27.md)
retains its exact source/binary/numeric scope and is not relabeled as a new HTTP
performance measurement. Existing database admission tests remain required;
distributed ingress abuse and representative sustained TCP/TLS load/capacity stay
unqualified. Request UUIDs are log correlation values, never metric labels; sink
aggregation/retention is an operator obligation. AUTH-49 remains a native blocker.
The [independent review plan](independent-review-plan.md) is preparation, not a
booked/performed review. SAML waiver limits and the outbound issuer hard release
gate remain unchanged. No PR, merge, release or deployment accompanies this work.
