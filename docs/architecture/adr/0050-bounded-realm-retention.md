# ADR0050: Explicit bounded retention by realm and lifecycle

Date: 2026-10-26. Status: proposed for AUTH-49; implementation and qualification
are pending. This decision does not enable a cleanup command or scheduler.

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

## Proposed boundary

Add one explicit trusted maintenance use case/port in auth-core and its PostgreSQL
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

Apple ciphertext expiry and terminal-metadata cleanup must reuse the owning grant
lifecycle, including feature-disabled operation. Do not copy or weaken its seven-day
job/final-metadata windows, lease/version checks or the distinction between expired
and remotely confirmed revocation. A structural extraction of its maintenance
implementation, if needed, is a separate verified commit before behavioral wiring.

## Migration and qualification

Add new migration indexes where actual query plans require them; keep migrations
1–38 immutable. Update the owned upgrade qualification for a new current schema.
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
