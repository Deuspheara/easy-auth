# Experimental provider account deletion

The optional core/PostgreSQL `oidc-identities` boundary supports deliberate deletion
of a `provider_required` account using a separate verified provider proof. It adds
no public HTTP route, browser proof transport or ordinary server activation.
AUTH-55 remains In Progress until its HTTP/browser boundary and final acceptance
are complete. [ADR 0017](../architecture/adr/0017-provider-account-deletion.md)
records the implemented transaction and proposed transport.

## Prepare a separate provider proof

The trusted host selects the exact persisted connection/policy and obtains the
current user from the initiating session, never from a browser-supplied owner ID.
Begin a new OAuth transaction with
`OAuthPurpose::DeleteProviderAccount { user, session }`, the original independent
browser binding and protected nonce/PKCE transport. Use
`OidcCodeExchange::reauthentication_url` for fixed `max_age=0`/`prompt=login`.
Do not expose arbitrary authorization parameters or copy state/proof from a
different sign-in/link flow. Follow the [OAuth transaction guide](oauth-transactions.md)
for exact callback, one-use state, error and secret handling.

The initiating provider session must remain active under the exact current source,
revision and account policy. Its old or unknown `auth_time` may request new proof,
but never authorizes deletion or becomes fresh through preparation/session touch.
After actual state consumption, code exchange and mandatory signature/claim checks,
retain the opaque verified deletion-purpose identity for the explicit destructive
action. Preparing an intent alone does not delete anything.

## Complete the destructive action

After deliberate user confirmation and full verification, trusted Rust composition
can consume the opaque proof:

```rust
let mapped = policy.map(verified_deletion_identity)?;
OidcAccountDeletion::new(repository.clone()).finish(mapped).await?;
```

`finish` is destructive. The caller must obtain intentional confirmation; do not
call it from a callback GET, automatically after a normal login, or with unverified
callback JSON. The reference HTTP confirmation/transport contract remains under
implementation. Proofs have no public constructor, Clone or Serialize and must
not enter URLs, logs, script storage or a generic session-issuance path.

Both core and PostgreSQL reject a sign-in/linking-purpose or missing-time proof.
The transaction requires the exact issuer/subject of the initiating session's
existing identity, current complete policy/configuration, owner/session binding,
and genuine signed authentication within
`MAX_OIDC_DELETION_AUTH_AGE_SECONDS` (300 seconds). Future authentication time is
rejected by token validation; deletion also checks it against database time.
Token `iat`, local session creation, provider email, `amr`/`acr`, a public UUID or
mere bearer possession cannot replace this proof. No display/profile field or
JIT-Allow setting is required to delete an existing owner.

The final cap is the earliest original OAuth/token deadline, initiating session's
idle/absolute deadline and signed authentication freshness deadline. Touching a
session cannot extend the proof's original cap. Configuration/policy locks precede
optional email, owner, session and identity locks. No lock spans provider I/O or
signature verification. A table-free clock check after all destructive/audit/notice
writes rejects expiry and rolls the transaction back, including during final waits.

Only committed completion returns success. It erases implemented account identity,
credential/session/pending state through the shared account-erasure operation,
deidentifies audit subjects/actors/targets and records a subject-free deletion fact.
It queues the established deletion notice only for an existing genuine verified
contact; an email-free account gets no fabricated recipient. SMTP acceptance and
readership are separate. Signed provider email is not
local contact or permission to select another account.

## Concurrency, failure and limits

Concurrent valid deletions have one winner. A sign-in may commit before a waiting
deletion, after which its new session is also erased. A deletion that wins the
owner lock rejects the waiting old callback without JIT recreation. Source disable
that commits first rejects deletion; an admitted deletion may finish before a
waiting disable. Original deadlines still apply in every ordering.

Deletion preserves the scoped five-minute subject cooldown. Old anonymous proofs
and fresh requests cannot immediately JIT-recreate the deleted owner. Expired
metadata cleanup is opportunistic as described in the [identity guide](oidc-identities.md).
Unavailable storage is not an authorization rejection. Failed deletion restores
account/session/audit/notice/cooldown state but never resurrects already-consumed
OAuth state; retry requires a new valid flow. Expired/revoked initiating sessions
require a genuine new login rather than restoration of their old authority.

Disabled/unavailable provider or lost browser proof can prevent self-service
completion. Preserve the account and fail closed; do not weaken policy, re-enable
a connection implicitly or fabricate a mailbox. No provider vault deletion,
upstream grant revocation, application business-data erasure or total erasure from
backups/mailboxes is promised. Deletion notices temporarily retain their established
recipient under the existing queue policy. AUTH-26 owns Apple grant revocation;
AUTH-25 owns link/unlink and last-credential mutation. Ordinary OIDC web composition
is AUTH-56. None of these boundaries establishes production readiness, independent
review, certified assurance or complete provider lifecycle activation.
