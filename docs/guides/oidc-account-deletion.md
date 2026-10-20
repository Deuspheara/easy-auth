# Experimental provider account deletion

The optional core/PostgreSQL `oidc-identities` boundary supports deliberate deletion
of a `provider_required` account using a separate verified provider proof. It adds
an explicit opt-in Axum HTTP/browser boundary. The combined
[OIDC web composition](oidc-web.md) also supplies trusted server settings and a
shared callback with public sign-in; default composition remains unchanged.
The implementation has component and owned Keycloak-to-HTTP acceptance evidence.
AUTH-56 records owned two-mode public-flow acceptance with final hosted verification
and broader release gates still explicit. [ADR 0017](../architecture/adr/0017-provider-account-deletion.md)
records the transaction and experimental transport.

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
callback JSON. The experimental HTTP contract requires confirmation at both start and finish. Proofs have no public constructor, Clone or Serialize and must
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

## Explicit experimental HTTP composition

Enable `easy-auth-axum/oidc-account-deletion` and construct
`OidcAccountDeletionServices::new(policy, transactions, exchange, deletion)` from
trusted persisted configuration. It rejects mismatched full connection revisions.
Pass those services to `experimental_oidc_account_deletion_router(auth, browser,
services)`. The Auth realm must match and the configured redirect must be exactly
`<HTTPS browser origin>/oidc/account-delete/callback`. HTTP loopback development
origins are deliberately insufficient for this OAuth callback. There is one trusted
connection per router; no request selects an owner, realm, connection or redirect.
This legacy constructor leaves default routers unchanged. AUTH-56's separate
[combined composition](oidc-web.md) uses the same deletion use case with its common
`/oidc/callback`, trusted server settings and owned public-login acceptance.

| POST path | Closed JSON input | Committed success |
| --- | --- | --- |
| `/v1/account/provider-delete/start` | `{confirmation}` | 200 `{authorization_url}` plus four proof cookies |
| `/v1/account/provider-delete/finish` | `{confirmation,state,code,issuer?}` | 204 and cleared authentication/proof cookies |
| `/v1/account/provider-delete/cancel` | `{}` | 204, pending attempt denied, proof cookies cleared |

Both confirmations require exactly `delete my account`. All POSTs require the
single exact Origin, bounded JSON and no query parameters. The current session
resolves the owner; another valid session, including one for that same owner,
cannot finish the original intent. Callback `issuer` is the actual decoded `iss`,
never a value supplied by trusted configuration in place of missing provider data.
The generic [OpenAPI snapshot](../architecture/openapi-oidc-account-deletion.json)
contains the combined opt-in contract; normal OpenAPI omits these operations.

Independent browser/state/nonce/PKCE values use four `__Host-auth-oidc-delete-*`
cookies: Secure, HttpOnly, Path=/, no Domain, SameSite=Lax and Max-Age=300.
Lax matches the existing session-cookie policy; exact-Origin POST checks and the
one-use state/nonce/PKCE binding remain mandatory. Cookies neither grant freshness
nor extend database deadlines. Raw PKCE and session secrets never enter JSON or
redirect URLs. The start response intentionally carries the protocol authorization
URL, including state/nonce and the S256 challenge, for navigation to the provider.
A pending cookie set must be explicitly cancelled before another start.

The fixed `/oidc/account-delete` reference page requests provider reauthentication
after deliberate confirmation. Its callback GET serves fixed bytes and does not
read account authority, consume state or invoke deletion. The same-origin module
bounds and rejects malformed/duplicate/unknown callback parameters, immediately
scrubs the query/fragment, retains usable code/state/issuer only in transient memory,
and requires the second deliberate confirmation before POSTing finish. No provider
error description is displayed. Refresh after scrubbing cannot replay proof.
Navigation aborts page-scoped requests and discards transient state; an interrupted
request or lost finish response is never reported as success. No browser storage,
third-party script or analytics is used. These are experimental reference pages,
not approval of general usability or provider interoperability.

Invalid confirmation/JSON/query input precedes proof consumption. A finish attempt
with invalid authority returns a fixed error and clears its four local proof
cookies. Storage/provider unavailability remains 503 rather than 401; a boundary
timeout is 504. Already-consumed state stays consumed on failure. A failed start
attempts denial-only cancellation before returning without proof cookies; unavailable
storage may leave its bounded pending row until expiry. Cancellation clears local
proof even when its old session cannot authorize remote cleanup. Logout/current
session revocation clears this composition's proof cookies, and database session
binding independently prevents reuse. A cancelled/expired provider flow has no
weaker fallback and cannot create a new account.

The 18 HTTP/PostgreSQL component regressions use real signed ES256 proofs, including
rollback and an observed final-audit lock wait proving no response before commit.
The Chromium reference-client suite uses controlled responses to check seven bad
callback forms, explicit confirmation, URL scrubbing, reload, cancellation and 503
feedback. Those are component/client checks. A separate six-case owned Keycloak run now
exercises this HTTP composition end to end, while all 23 existing native backend
cases pass unchanged on the same frozen source. See the
[HTTP provider record](../../tests/browser/oidc/results/2026-10-20/keycloak-provider-deletion-http.json)
and [backend regression record](../../tests/browser/oidc/results/2026-10-20/keycloak-provider-deletion-http-backend-regression.json).
The initial session comes from actual signed core login and a one-use fixture-only
cookie-delivery capability; it is not ordinary public sign-in acceptance. Real
provider reauthentication then drives the production deletion routes and pages.
The run verifies non-mutating callback GET/cancellation, wrong fresh signed subject,
503 token-service failure, explicit committed deletion, captured old-cookie/state
replay rejection and a fresh signed login denied while cooldown is still live.
This is an email-free owned fixture, not provider-contact SMTP, independent review
or production-provider interoperability evidence.
