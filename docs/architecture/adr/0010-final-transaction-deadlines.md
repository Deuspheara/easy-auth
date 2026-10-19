# ADR 0010: Final database-time validation of transaction authority

Status: accepted, implemented in AUTH-54, 2026-10-19. Eight controlled
PostgreSQL regressions reproduced gaps in older mailbox/session operations; those
cases and an additional final-touch matrix pass with the deadline checks.

Owner, session, proof and credential locks protect authorization state. They do
not stop wall time: a valid proof or fresh session can expire during a later row,
uniqueness, audit or notification write. Statement timestamps can also authorize
an unchanged-row waiter using time from before the wait. AUTH-53 corrected this
for enrollment; the same rule applies to existing mailbox and session operations.

Keep each feature's existing binding, version, policy and lock checks explicit.
After holding the authorizing row locks, capture the earliest database deadline
for the required proof and/or original session. Store it only in a crate-private
value, as an exact signed PostgreSQL epoch-microsecond integer. This adds no public
contract, dependency, schema, clock substitution or general workflow engine.

A final table-free SELECT compares current database wall time against that cap
AFTER all potentially blocking writes and BEFORE commit/returning success. Its
failure returns Unauthorized and rolls back identity/credential/session/proof/
audit/notification writes. A captured deadline is not authorization by itself;
callers must already have validated and locked the exact realm/owner/session/
proof/version and current account policy. Holding those locks prevents another
writer from changing their authority while the transaction retains the cap.

This permits deletion/recovery to erase proof or session rows within the same
transaction while retaining the original deadline for its final check. It never
recreates an identity or extends original freshness when rotating/revoking sessions.
For fresh actions the cap includes original authenticated_at+5min, idle+30min and
absolute expiry. Ordinary validation/inventory use only idle/absolute time.

Session validation locks owner FOR SHARE before session FOR UPDATE, then evaluates
current time in a new statement. Shared owner locks allow independent validations
while serializing policy/deletion changes; the order matches existing mutations.
Inventory uses the same locked caller validation, touches only that caller and
performs its final deadline check after its query. Ordinary logout remains an
idempotent revocation with no freshness requirement.

Tests must observe actual waits and cross a database clock deadline, assert the
wait was reached beforehand, and compare all durable state after rejection.
SQLx 0.8.6 gives all test pools in one binary a shared 20-permit parent. Cargo
defaults to four test workers so gates/actions can acquire their connections; a
separate one-connection observer avoids spending another parent permit. Setup,
observed-lock and clock failures are distinct from exact Unauthorized assertions.
Unavailable results fail explicitly and require database/pool diagnosis; they do
not count as proof of expired-authority rejection. No proof, cookie, address or
snapshot is printed. Preserve successful controls, concurrency/realm isolation,
SMTP and native regressions. See the [verification record](../../security/verification.md).

The final check precedes COMMIT; it cannot bound commit durability/response latency
or later application work. It adds database round trips to session validation and
short owner/session locks; earlier performance measurements are historical and
do not measure this implementation. No production latency claim is made.
