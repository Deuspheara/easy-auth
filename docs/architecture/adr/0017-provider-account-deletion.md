# ADR 0017: Purpose-bound provider account deletion

Date: 2026-10-20. Status: accepted for AUTH-55's optional core/PostgreSQL deletion
transaction and opt-in HTTP/browser boundary. Component and owned Keycloak-to-HTTP
acceptance are recorded; exact final-commit CI remains mandatory. Ordinary activation is
not enabled. AUTH-56 owns ordinary OIDC sign-in composition.

The preparation checkpoint implements the distinct OAuth purpose, migration 0019,
current active provider-session/source authorization and fixed reauthentication
URL API. Preparation can request/consume exchange context only. The subsequent
`OidcAccountDeletion` use case now consumes the separately verified mapped proof
in a current-policy, exact-subject, original-session and signed-freshness-authorized
erasure transaction. The [deletion guide](../../guides/oidc-account-deletion.md)
documents the explicit Rust and opt-in HTTP APIs.

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

## Implemented proof boundary

The distinct OAuth purpose, `DeleteProviderAccount { user, session }`, binds to
the exact initiating provider session. It cannot be consumed as sign-in or linking.
Additive migration 0019 extends closed purpose/binding constraints; published
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
The [OIDC authorization request specification](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
describes these parameters and the required authentication-time claim; a fresh
token/request is not itself proof of a new user gesture.

## Implemented transaction and lifecycle

After signature verification and provider I/O finish, lock current configuration
and policy before optional email, owner, session and identity authority. Snapshot
reads only select that lock path; recheck them under locks. Compare the complete
trusted configuration/policy and exact purpose/session/identity binding. Retain
the earliest original OAuth/token, active-session and new signed-authentication
freshness deadline before deleting authorizing rows.

The shared account erasure operation now explicitly supports absent verified
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

## Experimental HTTP boundary

The implementation provides an explicit opt-in deletion composition with trusted aligned services;
it does not activate ordinary provider sign-in or accept a client-selected configured issuer,
connection, realm or owner. Locally initiated start/finish/cancel actions require
the exact Origin, current session, closed bounded inputs and independent HttpOnly
browser/nonce/PKCE transport. Require the explicit destructive confirmation phrase
at initiation and final submission. No raw proof belongs in logs or script storage.

The cross-site callback GET serves only a no-store/no-referrer/CSP-controlled
reference bridge and never deletes or consumes state. Its same-origin script reads
the bounded callback parameters, immediately scrubs the address and retains them
only in transient memory. A deliberate same-origin POST then has the original
HttpOnly Lax session/proof cookies and performs verification/deletion. Review duplicate,
unknown and malformed callback parameters, cancellation and navigation cleanup;
never echo provider error descriptions. No success cookie/response precedes commit.
Refresh or lost response does not justify replay, fallback or identity recreation.

## Verification and remaining acceptance

Real PostgreSQL cases cover purpose/owner/source/session/realm/revision binding, wrong signed
subject, missing/old/future `auth_time`, original deadline/freshness wait, rollback,
concurrent one-winner, disable and deletion-vs-callback ordering tests. Preserve the
mailbox denial, no-email-merge and last-credential corpus. Upgrade tests must show
no deletion authority is invented by migration. Exact infrastructure failures are
not expected authorization rejections.

HTTP contract/Origin/cookie/callback/redaction/confirmation negatives now pass.
Actual owned Keycloak browser reauthentication-to-HTTP-deletion acceptance now
passes six cases with normal cleanup, alongside all 23 existing backend cases.
Keep all existing native/SMTP cases. Record formatting, strict default/all-feature
lint, full default/all-feature real-DB suites, security/license/secret scans and
exact-code hosted CI. Until exact final-source verification and hosted CI are complete,
AUTH-55 stays open; backend/component acceptance is not an independent review or
ordinary activation approval. Exact results and limits are recorded in
[verification evidence](../../security/verification.md).

The transport's four independent canonical proof cookies use the existing Lax
policy, Secure/HttpOnly host prefixes and five-minute transport lifetime. Its
constructor requires exact trusted service configuration, realm and HTTPS callback
alignment. Normal routers are unchanged. Closed query failures are converted to a
fixed error rather than echoing attacker-supplied field names. The reference client
never auto-submits callback proof, stores it persistently or displays provider errors.
Component acceptance consists of 18 real PostgreSQL HTTP cases plus a controlled
Chromium reference-client suite. Actual provider-to-HTTP acceptance is now separately recorded in six native cases;
component results alone do not establish it, independent review or ordinary activation.


## Owned HTTP provider acceptance

A separate server-package example composes the same opt-in Axum router, core
verifier and real PostgreSQL port with the existing production HTTPS sources and
owned certificate/address mapping. Its initial session is obtained from actual
Keycloak signed login and delivered to the owned browser through a one-use
fixture-only capability. It seeds no session or identity and exposes no ordinary
login route. Provider reauthentication and deletion then use the actual reference
pages, cookies and HTTP routes. Finite verified-port observations forward the
opaque proof unchanged and preserve the PostgreSQL result. Wrong-subject denial
therefore cannot be a missing signature/nonce/infrastructure failure in disguise.
The controlled unavailable-token case must return 503, not an expected 401.

The captured old cookies are restored only inside this isolated browser to prove
replay rejection after committed erasure; Chromium's actual fixture DNS/TLS path
performs that request. A fresh signed same-subject login reaches resolution and is
denied with a still-live cooldown. Final evidence has zero users/sessions/identities/
pending/contact/notice rows, two deidentified audit facts and one live cooldown.
No provider-contact SMTP, production-provider, independent audit or ordinary
activation acceptance follows. Reports, source/binary hashes and normal cleanup
are linked from the [deletion guide](../../guides/oidc-account-deletion.md).
