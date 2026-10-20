# Lifecycle audit events

Both server compositions record the same committed lifecycle facts through the shared repository. HTTP responses and OpenAPI are unchanged; there is no public audit read/write endpoint. The core exposes a closed `AuditEvent` type for adapter authors, and PostgreSQL records it only inside the owning lifecycle transaction.

## Version 1 fields

`auth_audit` has eleven fixed columns after migration 0014: `id`, `realm_id`, `user_id`, `kind`, `occurred_at`, `schema_version`, `actor_session_id`, `session_id`, `subject_erased` and nullable `passkey_id` and `recovery_claim_id`. IDs are opaque identifiers, not authentication credentials. Runtime event time uses the database clock when the fact is recorded, after lock waits; it is not the transaction-start or exact commit timestamp. No free-form metadata column exists.

| Kind | Actor session | Issued/affected session | Meaning |
| --- | --- | --- | --- |
| `email_authenticated` | none | newly issued session | Verified bound mailbox proof committed |
| `oidc_authenticated` | none | newly issued session | Optional verified provider proof, current policy and scoped identity resolution/session committed together; no claims, email, tokens or raw subject in audit |
| `password_authenticated` | none | newly issued session | Password verification and exact stored-credential recheck committed |
| `password_enrolled` | fresh initiating session | replacement session | First credential enrollment and rotation committed |
| `passkey_enrolled` | fresh initiating session | none | Optional core/PostgreSQL registration verified, state consumed and unique credential inserted; no new authenticated session |
| `passkey_renamed` | fresh passkey-method session | none | Owned key label/version changed; public `passkey_id` retains the target |
| `passkey_removed` | fresh passkey-method session | none | Owned key removed with proven-key guard and session invalidation; `passkey_id` retains the target |
| `passkey_recovery_configured` | fresh passkey-method session | none | Saved-code configuration confirmed/replaced and pending setup consumed; no recovery session or policy activation |
| `passkey_recovery_started` | none | none | One saved code reserved for a browser-bound claim; public `recovery_claim_id` identifies the claim, not a login grant |
| `passkey_recovery_cancelled` | genuine fresh key session, or none for browser/reserved-code denial | none | Current claim invalidated without reviving its code or issuing a session |
| `passkey_authenticated` | none | newly issued session | Experimental verified assertion, exact-state consume, credential update and new session committed atomically |
| `passkey_recovered` | none | newly issued session | Saved-code claim delay/receipt and private replacement assertion verified; prior keys/sessions/proofs invalidated and claim consumed atomically |
| `passkey_signed_up` | none | newly issued session | Optional core/PostgreSQL signup verified separate assertion and atomically created email-free user/key/session and consumed pending state |
| `password_reset` | none | none | Current recovery proof consumed, credential replaced and sessions/proofs invalidated |
| `session_revoked` | initiating owned session | revoked session | Logout or individual revocation changed an owned record |
| `all_sessions_revoked` | fresh initiating session | none | Owned sessions and pending proofs canceled |
| `email_changed` | fresh initiating session | none | Both mailbox proofs confirmed and one stable user's email changed |
| `account_deleted` | none | none | Subject/session references erased and authentication account deleted |

A live subject's user and session references must share the event's realm and owner. Login facts have no pre-existing session actor. Password recovery does not invent an authenticated-session actor. Logout may revoke an expired owned session without fresh authentication; the session-management mutations require the existing five-minute authentication window. No-op targets and rolled-back/failed attempts do not become success events.

There are no passwords/PHC strings, bearer values/verifiers, mailbox addresses, reset/browser proofs, IP/user agents, arbitrary request context or provider claims in these rows. Rejected HTTP fields do not become audit context. Notifications keep their separately documented delivery recipient and retry state; they are not arbitrary audit payloads.

## Deletion and upgrades

Deleting an account sets its old events' `subject_erased=true` and removes user, actor-session affected-session and passkey/claim-target references. The original kinds/times remain, followed by a subject-free deletion event. Other users and realms keep their attribution. This deidentifies the live store; timing, backups, previously exported data and delivered mail have separate privacy/retention policies.

Migration `0006_safe_audit.sql` leaves old rows at version 0 with unknown actor/target fields. Valid subject ownership remains; dangling/cross-realm subjects and old deletion records are deidentified. It never attaches an old event to a guessed session. New writes use version 1 with kind-specific shapes. Stop old writers, apply migrations and upgrade all replicas together; mixed-version writing is unsupported for this alpha. Custom adapters must implement equivalent atomicity, ownership, redaction and deletion semantics.

Migration `0007_passkey_enrollment.sql` adds the closed passkey-enrollment kind
with an owned actor session and no affected session; the nine-column schema stays
unchanged. Normal HTTP composition does not enable enrollment yet. The event is
recorded only by the actual verified credential transaction, and follows the same
rollback and deletion-deidentification rules as other kinds.

Migration `0008_passkey_authentication.sql` adds the owned passkey-authentication
fact with no pre-existing actor and one newly issued session, preserving version 1
and the nine-column shape. Context, signature, backup/counter and binding failures
create no success fact; a failed audit rolls back the session/key/state transaction.

The foreign keys deliberately retain referenced user/session rows until the audit references are handled. Use the normal account-deletion flow, which clears them transactionally. A future session/audit retention job must coordinate pruning; there is no automatic retention policy in this slice. A privileged database writer remains trusted, so these records are not tamper-proof or independently audited evidence.

Migration `0010_passkey_signup.sql` adds the closed signup fact, with no prior
actor and one owned issued session. It keeps version 1/nine columns and is written
only after verified assertion. Registration-stage advancement emits no success
fact or session. Final expiry/one-use consumption follows the audit write; expiry
or audit/persistence failure rolls the account/key/session/fact back together.
Experimental HTTP/native signup now exercises this transaction; ordinary activation remains gated.

Migration `0012_passkey_management.sql` adds the nullable public target UUID and
closed rename/removal facts. Only those live event kinds may carry `passkey_id`;
other current/historical kinds retain NULL. A live key foreign key would prevent
removal, so this historical identifier is instead bound to the exact owned key by
the locked mutation transaction. User/actor/session ownership foreign keys remain.
Subject erasure clears the target with all other attribution. The optional
management boundary also queues a fixed non-secret notice to a verified contact;
email-free users have no fabricated contact. Recovery and ordinary activation
remain unfinished AUTH-20 work.

Migration `0013_passkey_recovery_setup.sql` adds the closed recovery-configuration
fact without new audit columns. Actor ownership is required; `session_id` and
`passkey_id` remain NULL. No code, verifier, pending ID or arbitrary recovery data
enters audit. Configuration replacement, pending consumption and a purpose-specific
verified-contact notice commit atomically after final original-deadline checks.
Email-free users receive no fabricated email. This event proves configuration,
not recovery completion or independent review of the proposed protocol.

Migration `0014_passkey_recovery_claims.sql` adds the public historical claim target
for started/cancelled facts only. Subject erasure clears it alongside every other
reference. There is no live-claim foreign key that would block cancellation or
configuration rotation; the exact owned claim is validated in the locked owning
transaction. Start and non-session cancellation do not invent a session actor or
record passkey authentication. Only genuine fresh-key cancellation records its
owned actor session. A notification receipt is separate database delivery state,
not proof of authentication, user readership or completed recovery. No code,
browser verifier, recipient or arbitrary recovery context enters audit.

## Operator reads and linking

Audit access is privileged database access today. Scope operator queries to an authorized realm, select only necessary fields and page by `id` with a fixed limit; do not expose unrestricted SQL through an application route. Request status logs remain redacted and contain no event payload. Failure-attempt auditing, exports, read authorization/retention and monitoring are later operational work.

Provider linking/unlinking remains unavailable until AUTH-25 implements its verified flow. It must prove both current-account control and a separately verified new identity, bind the transaction to its purpose/realm/connection/browser, reject already-owned identities and never merge by email. Its successful audit event must commit with the actual link, using a reviewed schema extension. `identity_linked` and arbitrary event kinds are rejected by the current database. See [ADR 0007](../architecture/adr/0007-safe-audit-and-linking.md).


Migration `0015_passkey_recovery_replacement.sql` adds `passkey_recovered` without
new audit columns. A live fact requires an owned newly issued session and historical
claim target, with no invented prior-session actor. Private registration/stage
advancement creates no authentication success fact. Expiry, collision, cancellation
or persistence errors create no completion fact; erasure clears its session/user/
claim references. This fact does not assert policy activation or independent review.
