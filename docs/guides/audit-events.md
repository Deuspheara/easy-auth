# Lifecycle audit events

Both server compositions record the same committed lifecycle facts through the shared repository. HTTP responses and OpenAPI are unchanged; there is no public audit read/write endpoint. The core exposes a closed `AuditEvent` type for adapter authors, and PostgreSQL records it only inside the owning lifecycle transaction.

## Version 1 fields

`auth_audit` has nine fixed columns: `id`, `realm_id`, `user_id`, `kind`, `occurred_at`, `schema_version`, `actor_session_id`, `session_id` and `subject_erased`. IDs are opaque identifiers, not authentication credentials. Runtime event time uses the database clock when the fact is recorded, after lock waits; it is not the transaction-start or exact commit timestamp. No free-form metadata column exists.

| Kind | Actor session | Issued/affected session | Meaning |
| --- | --- | --- | --- |
| `email_authenticated` | none | newly issued session | Verified bound mailbox proof committed |
| `password_authenticated` | none | newly issued session | Password verification and exact stored-credential recheck committed |
| `password_enrolled` | fresh initiating session | replacement session | First credential enrollment and rotation committed |
| `password_reset` | none | none | Current recovery proof consumed, credential replaced and sessions/proofs invalidated |
| `session_revoked` | initiating owned session | revoked session | Logout or individual revocation changed an owned record |
| `all_sessions_revoked` | fresh initiating session | none | Owned sessions and pending proofs canceled |
| `email_changed` | fresh initiating session | none | Both mailbox proofs confirmed and one stable user's email changed |
| `account_deleted` | none | none | Subject/session references erased and authentication account deleted |

A live subject's user and session references must share the event's realm and owner. Login facts have no pre-existing session actor. Password recovery does not invent an authenticated-session actor. Logout may revoke an expired owned session without fresh authentication; the session-management mutations require the existing five-minute authentication window. No-op targets and rolled-back/failed attempts do not become success events.

There are no passwords/PHC strings, bearer values/verifiers, mailbox addresses, reset/browser proofs, IP/user agents, arbitrary request context or provider claims in these rows. Rejected HTTP fields do not become audit context. Notifications keep their separately documented delivery recipient and retry state; they are not arbitrary audit payloads.

## Deletion and upgrades

Deleting an account sets its old events' `subject_erased=true` and removes user, actor-session and affected-session references. The original kinds/times remain, followed by a subject-free deletion event. Other users and realms keep their attribution. This deidentifies the live store; timing, backups, previously exported data and delivered mail have separate privacy/retention policies.

Migration `0006_safe_audit.sql` leaves old rows at version 0 with unknown actor/target fields. Valid subject ownership remains; dangling/cross-realm subjects and old deletion records are deidentified. It never attaches an old event to a guessed session. New writes use version 1 with kind-specific shapes. Stop old writers, apply migrations and upgrade all replicas together; mixed-version writing is unsupported for this alpha. Custom adapters must implement equivalent atomicity, ownership, redaction and deletion semantics.

The foreign keys deliberately retain referenced user/session rows until the audit references are handled. Use the normal account-deletion flow, which clears them transactionally. A future session/audit retention job must coordinate pruning; there is no automatic retention policy in this slice. A privileged database writer remains trusted, so these records are not tamper-proof or independently audited evidence.

## Operator reads and linking

Audit access is privileged database access today. Scope operator queries to an authorized realm, select only necessary fields and page by `id` with a fixed limit; do not expose unrestricted SQL through an application route. Request status logs remain redacted and contain no event payload. Failure-attempt auditing, exports, read authorization/retention and monitoring are later operational work.

Provider linking/unlinking remains unavailable until AUTH-25 implements its verified flow. It must prove both current-account control and a separately verified new identity, bind the transaction to its purpose/realm/connection/browser, reject already-owned identities and never merge by email. Its successful audit event must commit with the actual link, using a reviewed schema extension. `identity_linked` and arbitrary event kinds are rejected by the current database. See [ADR 0007](../architecture/adr/0007-safe-audit-and-linking.md).
