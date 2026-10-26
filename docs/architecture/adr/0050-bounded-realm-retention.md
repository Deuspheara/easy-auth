# ADR0050: Explicit bounded retention by realm and lifecycle

Date: 2026-10-26. Status: implementation under qualification for AUTH-49;
local acceptance and complete operational/production acceptance remain pending.
The explicit cleanup command is implemented; no scheduler is enabled automatically.

## Context

Expiry denies authority but does not remove a PostgreSQL row. Existing request-time
pruning covers selected replay/cooldown records; the Apple grant component has its
own explicit maintenance operation. Neither bounds all retained authentication
state in an inactive realm. Historical audit foreign keys reference sessions,
issuer authorizations, native families and refresh generations. Parent cascades
can remove many child rows. A generic `DELETE WHERE expires_at < now()` is therefore
neither a complete policy nor a safe bounded implementation.

The [schema38 inventory](../../design/retention-cleanup.md) records all 47 current
auth tables, existing lifecycle checks and the intended eligibility for each.
Its real PostgreSQL catalog observation is design evidence only, not a retention
test or a completed acceptance criterion.

## Implemented boundary under qualification

Use one explicit trusted maintenance use case/port in auth-core and its PostgreSQL
implementation. Core owns validated retention choices, finite operation selection
and bounded orchestration. PostgreSQL owns current database time, candidate
locking, reference checks and writes. Standalone one-shot administration and
embedded consumers compose the same use case; no HTTP management route, caller
SQL/table names, new plugin framework or automatic startup deletion is introduced.
Explicitly reject a nil realm before database work. Maintenance does not provision
a missing realm or derive a realm from a browser request.

Keep protocol expiry/cooldown/replay policies intact. Use stored final caps,
including SAML `retain_until`, rather than inventing earlier cleanup from creation,
consumption, cancellation, idle expiry or revocation alone. Hold refresh-generation
history through its family's absolute expiry, including spent tokens, so cleanup
cannot remove reuse detection while a family can still grant authority. Never
delete public key/configuration records as a side effect of row retention.

Audit deletion and exhausted-notification deletion require separate explicit
operator horizons; preserving either indefinitely is a deliberate supported
selection. No default legal, compliance, recovery-objective or evidence-preservation
period is inferred. Pending/retryable notices and live leases are retained. Expired
recovery claims cannot cascade-delete notice/replacement rows behind the batch
limit or acknowledge delivery. Consumed recovery-code state is retained.

Use finite per-table batches (initial target: 64 selected rows per operation),
deterministic ordering and `FOR UPDATE SKIP LOCKED`. Retain each parent's child rows
until they are independently eligible and pruned; do not rely on unbounded
cascades. Keep audit references intact while those events are retained, rather
than nulling fields, fabricating erasure or relaxing immutable event shapes.
Candidate eligibility and dependencies must remain true at deletion after lock
acquisition. Database constraints remain the final authority against competing
inserts; conflicts/timeouts roll back that operation rather than disabling checks.

Each table operation commits separately, with bounded server lock/statement waits
and cancellation-safe connection lifetime. Do not hold child locks into a later
parent operation: ordinary authentication locks parents before children. A failed
run may have committed earlier batches. Document this explicitly; repeated runs
are safe and counts describe committed operations, never a whole-run atomicity
claim. Skip-locked or retained-reference rows can require later runs; an empty
batch is not proof that the whole realm is clean. Scheduling/backlog monitoring
and per-realm selection remain operator responsibilities.

Explicitly select Read Committed inside each owned transaction, before its first
query. Do not inherit an embedded pool's repeatable-read session default and then
assume the second statement sees new children. PostgreSQL documents fresh command
snapshots under [Read Committed](https://www.postgresql.org/docs/17/transaction-iso.html#XACT-READ-COMMITTED)
and the conflict between [update/key-share row locks](https://www.postgresql.org/docs/17/explicit-locking.html#LOCKING-ROWS).
Its [foreign-key implementation](https://github.com/postgres/postgres/blob/REL_17_STABLE/src/backend/utils/adt/ri_triggers.c)
uses a key-share lookup of the referenced row. This supports the two-statement
design; it does not replace real concurrency/cancellation tests. A regression test
with an actual repeatable-read pool must fail before explicit isolation selection
and pass afterward, with its deletion trigger observing Read Committed.

Apple ciphertext expiry and terminal-metadata cleanup must reuse the owning grant
lifecycle, including feature-disabled operation. Do not copy or weaken its seven-day
job/final-metadata windows, lease/version checks or the distinction between expired
and remotely confirmed revocation. A structural extraction of its maintenance
implementation was first moved byte-for-byte in separately verified structural
commit `4855fa7c75b8fee2ef608d8aeff8dd520fc71c88`, before behavioral wiring.

## Migration and qualification

Migration0039 adds realm/expiry and reference indexes; migrations1–38 remain
immutable. The index-only checkpoint
`9209a2ae495b4fce4bfdfae33d7f65138e9e9119` preserves pre-retention schema39
software separately from current behavior. Update the owned upgrade qualification
for this schema using that pinned actual ancestor.
The existing actual schema38 software-overlap result remains historical evidence,
not proof that an old binary accepts a future schema or that DDL has no writer-drain
requirement. Revalidate failed migration recovery and fresh-connection startup.

Real PostgreSQL tests must cover all categories, live/expired boundaries, explicit
operator choices, exact counts/limits, two-realm isolation, preserved audit foreign
keys, spent-token retention, lease ownership, concurrent maintenance/ordinary
operations, final eligibility after waits, error rollback and idempotent reruns.
Use normal maintained protocol producers for authority/replay tests, not forged
production proofs. Qualify standalone and embedded operation over the same policy,
record exact failures, and run the required workspace/security gates before
accepting this implementation.

Retention is separate from incident revocation and restored-snapshot reconciliation.
It cannot recall SMTP already in flight, downstream sessions or self-contained
tokens. It does not erase external backups/logs, prove forensic tamper resistance,
complete AUTH-49, clear AUTH-47/AUTH-48, independently approve SAML or clear the
outbound OIDC release gate. Real provider/OS/production qualification stays deferred.
