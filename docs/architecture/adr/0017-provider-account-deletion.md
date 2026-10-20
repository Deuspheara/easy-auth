# ADR 0017: Purpose-bound provider account deletion

Date: 2026-10-20. Status: proposed for AUTH-55; provider deletion is not implemented
or activated by this design. AUTH-56 owns ordinary OIDC sign-in composition.

## Context

AUTH-30 creates `provider_required` users without inventing a mailbox. Its sessions
retain exact provider identity/configuration provenance and signed optional
`auth_time`. Existing mailbox deletion intentionally rejects those users, even
when trusted storage contains verified contact. A useful provider integration
needs a deliberate deletion path without making email, password, passkey recovery,
token issuance or local session creation into substitute provider authority.

The existing mailbox deletion transaction's destructive tail is extracted into
private `account/erasure.rs` before adding behavior. Authorization, owner/session
locks, original deadlines and commit remain in the caller. Existing proof cleanup,
audit deidentification, deletion event/notice and rollback behavior are preserved.

## Intended proof boundary

Add a distinct OAuth purpose, `DeleteProviderAccount { user, session }`, bound to
the exact initiating provider session. It cannot be consumed as sign-in or linking.
An additive migration must extend closed purpose/binding constraints; published
migrations remain immutable. The existing state/browser/nonce/S256, exact configured
issuer/client/redirect/revision, original-cap and one-use checks remain mandatory.

An active provider session may initiate this purpose, including one whose provider
authentication time is old or unknown. Initiation grants no deletion authority.
Requiring the old authentication time to be fresh before requesting reauthentication
would strand otherwise active accounts. Initiation, state consumption and exchange
context checks must retain the original session's idle/absolute caps and reject
revocation, policy/source change, wrong owner or another configured connection.

Request provider reauthentication with fixed `max_age=0` and `prompt=login` through
a typed code-exchange API, not arbitrary extra authorization parameters. These
parameters alone prove nothing. Final deletion requires a newly verified,
purpose-bound ID-token proof with nonmissing, nonfuture, genuinely recent signed
`auth_time`, and an issuer/subject matching the exact initiating session's existing
identity. `iat`, local mint time, `amr`/`acr`, provider email, an account UUID and a
bearer alone cannot satisfy it. No selected display name is needed for deletion.
Providers unable to return the required proof remain unsupported for this action;
there is no weaker fallback or remote-availability override.

## Intended transaction and lifecycle

After signature verification and provider I/O finish, lock current configuration
and policy before optional email, owner, session and identity authority. Snapshot
reads only select that lock path; recheck them under locks. Compare the complete
trusted configuration/policy and exact purpose/session/identity binding. Retain
the earliest original OAuth/token, active-session and new signed-authentication
freshness deadline before deleting authorizing rows.

Reuse the account erasure operation, extending it explicitly for absent verified
contact. Erase implemented credential/session/pending state and owned admission,
deidentify audit, record the existing subject-free deletion event, and queue the
existing notice only for a genuine verified contact. Preserve the subject cooldown
trigger against old anonymous JIT. The final table-free database-clock check follows
all potentially blocking writes and precedes commit; failure rolls back the entire
deletion and does not resurrect already-consumed OAuth state.

No database lock spans remote I/O. Deletion never removes provider vault entries,
revokes an upstream grant by inference, deletes application business data or claims
complete erasure from backups/mailboxes. Apple grant revocation remains AUTH-26;
explicit link/unlink and last-credential mutation remain AUTH-25. Disabled/unavailable
provider or lost/expired browser proof can prevent self-service completion; preserve
the account and fail closed. Do not silently re-enable a connection or restore an
old revision to recover availability.

## Intended HTTP boundary

Provide an explicit opt-in deletion composition with trusted aligned services;
do not activate ordinary provider sign-in or accept a client-selected issuer,
connection, realm or owner. Locally initiated start/finish/cancel actions require
the exact Origin, current session, closed bounded inputs and independent HttpOnly
browser/nonce/PKCE transport. Require the explicit destructive confirmation phrase
at initiation and final submission. No raw proof belongs in logs or script storage.

The cross-site callback GET serves only a no-store/no-referrer/CSP-controlled
reference bridge and never deletes or consumes state. Its same-origin script reads
the bounded callback parameters, immediately scrubs the address and retains them
only in transient memory. A deliberate same-origin POST then has the original
Strict session/proof cookies and performs verification/deletion. Review duplicate,
unknown and malformed callback parameters, cancellation and navigation cleanup;
never echo provider error descriptions. No success cookie/response precedes commit.
Refresh or lost response does not justify replay, fallback or identity recreation.

## Required verification before acceptance

Add real PostgreSQL purpose/owner/source/session/realm/revision binding, wrong signed
subject, missing/old/future `auth_time`, original deadline/freshness wait, rollback,
concurrent one-winner, disable and deletion-vs-callback ordering tests. Preserve the
mailbox denial, no-email-merge and last-credential corpus. Upgrade tests must show
no deletion authority is invented by migration. Exact infrastructure failures are
not expected authorization rejections.

Add HTTP contract/Origin/cookie/callback/redaction/confirmation negatives and actual
owned Keycloak browser reauthentication-to-deletion acceptance with normal cleanup.
Keep all existing native/SMTP cases. Record formatting, strict default/all-feature
lint, full default/all-feature real-DB suites, security/license/secret scans and
exact-code hosted CI. Until that evidence exists, this is design, not a completed
capability, interoperability pass, independent review or activation approval.
