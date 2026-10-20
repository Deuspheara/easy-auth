# HTTP contract v1

AUTH-56 adds the trusted PostgreSQL
`load_or_initialize_oidc_identity_policy(&definition)` operation and narrow core
`OidcIdentityPolicy::with_persisted_revision` metadata API. Matching startup loads
preserve revision and authority state; absent configuration initializes with a fresh
revision atomically. Disabled/mismatched/generic/stale policy cannot be auto-adopted.
These methods create no verified proof, user/session or HTTP endpoint. Existing
administrative configure APIs retain revision rotation. See the
[startup guide](../guides/oidc-identities.md#startup-loading-versus-administrative-changes)
and [ADR 0018](adr/0018-oidc-web-composition.md); ordinary OIDC web composition
remains unimplemented.

AUTH-55's optional `oidc-account-deletion` Axum feature now exports an explicit
aligned-services router with three POST operations for start/finish/cancel and static
reference/callback pages. It derives owner/session from current authentication,
requires `delete my account` at start and finish, and uses independent HttpOnly
proof cookies. Normal OpenAPI/routes and ordinary server activation are unchanged.
See the [HTTP contract](../guides/oidc-account-deletion.md#explicit-experimental-http-composition)
and [combined schema](openapi-oidc-account-deletion.json). Owned Keycloak-to-HTTP
acceptance is now recorded separately from the preserved backend cases; ordinary
provider sign-in composition remains gated.

AUTH-55 adds the optional Rust enum variant
`OAuthPurpose::DeleteProviderAccount { user, session }` and the fixed-parameter
`OidcCodeExchange::reauthentication_url` API. Consumers of this experimental enum
must handle the new purpose; it is not a sign-in/linking proof. PostgreSQL requires
the identity feature and exact active original provider source/session. Migration
0019 adds its closed owner/session binding. The optional `OidcAccountDeletion`
use case and `OidcAccountDeletionRepository` port now consume the mapped deletion
proof for atomic erasure with exact subject/source and genuine signed authentication
within `MAX_OIDC_DELETION_AUTH_AGE_SECONDS` (300 seconds). Success returns only
after commit. The Rust caller must obtain deliberate destructive confirmation.
The explicit experimental HTTP composition is described above and in
[ADR 0017](adr/0017-provider-account-deletion.md); ordinary activation is gated.

AUTH-30's explicit core/PostgreSQL `oidc-identities` features add trusted mapping
policy and an opaque proof. The administrative `configure_oidc_identity_policy`
returns a policy bound to a fresh persisted revision, atomically cancelling old
pending state without clearing disable. It is never browser input. HTTP DTOs and
OpenAPI are unchanged; no callback/session endpoint is added. Provider email never
becomes local verified contact. JIT defaults to deny. The library `OidcSignIn::finish`
now returns `(User, Secret)` only after atomic current-policy identity/session/audit
commit. Core `AuthenticationPolicy` adds `ProviderRequired` (`provider_required`),
and the new feature's mapped display candidate is `Option<&str>`: required for new
JIT users, optional for an already-bound subject. Missing auth_time remains unknown
in the existing nullable session inventory field. No HTTP DTO/schema change or
ordinary provider activation is introduced. See
[ADR 0016](adr/0016-oidc-identity-mapping.md).

AUTH-19 adds explicit experimental passkey HTTP sign-in, separately enabled from
the ordinary router/server. Its verified session transaction, mode/selection contract
and remaining stronger-account gates are documented in the
[sign-in guide](../guides/passkey-authentication.md).

Initial same-origin browser contract. Realm is trusted router configuration. JSON bodies are bounded at 8 KiB. Auth responses use Cache-Control: no-store. Errors expose stable codes; internal database/SMTP details never reach the caller. Application session and raw PKCE secrets never appear in query parameters or response JSON. The experimental OAuth redirect boundary deliberately carries protocol state/nonce and the S256 challenge; callback code/state are immediately scrubbed by its reference client.

| Method/path | Input | Output / behavior |
|---|---|---|
| GET /openapi.json | none | generated implemented v1 API specification |
| GET /healthz | none | 200 liveness, no dependency details |
| GET /readyz | none | 200 if database reachable; 503 otherwise |
| POST /v1/email/start | {email} and exact configured Origin | 202 generic accepted; browser-binding HttpOnly cookie; rate limit 429 independent of account existence |
| POST /v1/email/finish | {token} and binding cookie + Origin | 204 plus fresh session cookie; invalid/expired/replayed/misbound 401 |
| POST /v1/password/enroll | {password}, fresh session cookie + Origin | 204 enrolls once, revokes prior sessions, sets replacement cookie; 400 policy rejection, 401 stale/invalid/existing credential; 429 admission/capacity, 503 disabled |
| POST /v1/password/login | {email,password} + Origin | 204 fresh session cookie; generic 401 invalid/unknown/no credential; 429 admission/capacity, 503 disabled |
| POST /v1/password/reset/start | {email} + Origin | generic 202 and reset binding cookie; same mail path for every email; 429 shared admission, 503 disabled/delivery failure |
| POST /v1/password/reset/finish | {token,password}, reset cookie + Origin | 204 changes existing credential, revokes sessions/proofs, queues notification; clears cookies; normal login required; 401 invalid proof, 400 password policy |
| GET /reset | emailed fragment, handled only by browser | reference reset form; GET does not consume proof |
| POST /v1/account/email/start | {email}, fresh session + Origin | 202; separate current/new address proofs and binding cookie |
| POST /v1/account/email/confirm | {token}, same fresh session + change binding + Origin | 202 first proof; 204 second proof changes verified email, revokes sessions/proofs and clears cookies; login required |
| POST /v1/account/delete/start | {confirmation: "delete my account"}, fresh session + Origin | 202; current-mailbox deletion proof and binding; no mutation yet |
| POST /v1/account/delete/finish | {token,confirmation}, same fresh session + deletion binding + Origin | 204; auth account cleanup/deidentified audit, cleared cookies; generic 401 stale/invalid proof |
| GET /email-change and /account-delete | fragment handled only by browser | reference confirmation pages; GET does not consume proof |
| GET /v1/session | session cookie | public user ID/realm, required nullable email/display_name; 401 invalid, expired or method rejected by account policy |
| GET /v1/sessions | session cookie, optional after UUID | at most 50 owned active session metadata entries, next cursor; invalid caller 401 even on empty pages |
| POST /v1/sessions/revoke | {id}, fresh session + Origin | 204 owned target revoked; foreign/unknown/inactive targets are the same no-op; current target clears cookies |
| POST /v1/sessions/revoke-all | {}, fresh session + Origin | 204 all owned sessions and pending proofs canceled atomically, caller included; cookies cleared; new sign-in allowed |
| POST /v1/logout | session cookie + Origin | 204 idempotent server revocation and cookie clearing |
| GET / | none | minimal local reference email client, no third-party assets |

Planned versioned endpoints: passkey registration/authentication/management, connection-specific OIDC/social start/callback/link/unlink and SAML metadata/ACS. These require concrete OpenAPI schemas and negative tests in their milestones; they are not available by virtue of this document.

AUTH-22 adds an optional core/PostgreSQL OAuth transaction API, documented in the
[transaction guide](../guides/oauth-transactions.md). It adds no HTTP/OpenAPI route
or authentication grant. Future OAuth authorization requests carry protocol state,
nonce and S256 challenge; raw PKCE/session/browser secrets must not enter URLs.
The private proof transport and actual callback route/issuer parsing are mandatory
adapter work before exposing provider flows.

Only exact configured Origin is accepted on initial browser POST endpoints, including pre-authentication. Missing/null Origin fails closed, so command-line clients must explicitly send it. No wildcard credentialed CORS. SameSite=Lax, Secure in HTTPS production, HttpOnly, Path=/, no Domain; production session uses __Host- prefix. Dev HTTP is loopback-only and explicitly enabled. Duplicate cookie names/invalid token shapes must be rejected. An Origin guard is appropriate for this constrained same-origin contract; it is not a substitute for OAuth state or SAML correlation.

Outbound issuer (M07) has a distinct protocol contract: registered clients, exact redirects, code + S256, client authentication where applicable, signing keys, discovery, JWKS, audience-bound ID/access tokens, revocation and introspection. First-party alpha session introspection does not constitute OIDC support. Native refresh credentials and cross-origin apps are unavailable until that gate passes.

Password policy and configuration: [guide](../guides/passwords.md); credential enrollment decisions: [ADR 0003](adr/0003-password-enrollment.md).

Recovery proofs, version binding and notification lifecycle: [guide](../guides/password-recovery.md), [ADR 0004](adr/0004-password-recovery.md).

Lifecycle policy, proof ordering, freshness and privacy scope: [guide](../guides/account-lifecycle.md), [ADR 0005](adr/0005-account-lifecycle.md).

Session inventory fields, freshness, pagination, cookie effects and concurrent-login semantics: [guide](../guides/sessions.md), [ADR 0006](adr/0006-session-management.md).

Audit facts are transaction-internal with no public append/read route. HTTP/OpenAPI remain unchanged by AUTH-16. [Audit schema, attribution and linking policy](../guides/audit-events.md), [ADR 0007](adr/0007-safe-audit-and-linking.md).

## Optional mailbox contract

Migration 0009 changes Rust `User.email` to `Option<String>` and adds
`display_name` plus typed account policy. The HTTP user response has required,
nullable `email` and `display_name`; existing verified emails remain strings.
Default and experimental OpenAPI snapshots include this shared contract change.
Passkey-required accounts reject weak-method sessions, email/password login and
password recovery; mail-only lifecycle operations are unavailable pending
AUTH-20. Fresh passkey session controls work without email. The optional core/PostgreSQL signup use case now requires a separate verified
assertion before creating the account/session. Explicit signup HTTP/native browser
evidence now exists; verified contact attachment has experimental core/HTTP tests
and native Chromium/SMTP confirmation evidence. See the
[model/migration guide](../guides/optional-mailbox.md).

## Explicit experimental passkey enrollment

The `easy-auth-axum/passkey-enrollment` feature exposes
`experimental_passkey_enrollment_router`. The ordinary router and standalone
server never enable it automatically. Composition rejects mismatched realms or
origins before mounting. This is registration only: it issues no passkey session
and does not implement sign-in, passkey-first accounts or stronger-account recovery.

| Method/path | Input | Output / behavior |
| --- | --- | --- |
| POST /v1/passkeys/enrollment/start | `{label, discoverable?:bool}`, fresh session cookie and exact Origin | 200 `{transaction_id, options: {publicKey: ...}}`; optional explicit resident request; sets/reuses two-minute HttpOnly browser binding |
| POST /v1/passkeys/enrollment/finish | `{transaction_id, credential}`, same session/binding cookies and exact Origin | 201 `{id}` after verified, atomic single-use registration; no new authenticated session |

Only these two experimental endpoints use a 32 KiB encoded JSON body bound;
ordinary routes retain 8 KiB. Core decoded ceremony buffers are additionally
bounded to 16 KiB. Start/finish outer objects reject unknown fields. `credential`
uses standard browser WebAuthn JSON: canonical base64url `id`, encoded `rawId`,
type `public-key`, `response.attestationObject` and `response.clientDataJSON`,
with optional transport/extensions fields. Only the high-level verifier's attested
credential data is authoritative; browser convenience public-key fields are not.

The private serialized verification state is absent from options, cookies and
response JSON. The binding cookie is `__Host-auth-passkey` under HTTPS, otherwise
`auth-passkey` in explicit localhost development; HttpOnly, SameSite=Lax, Path=/,
no Domain, Max-Age=120, Secure under HTTPS. It is retained after one completion so
other pending ceremonies in the same browser can finish. Current/all-session
revocation clears it when the feature is compiled; logout clears the authenticated
session, and this short-lived binding expires separately.

Errors use the existing redacted codes: 400 invalid input/JSON, 401 invalid,
expired, replayed or misbound authentication/proof, 403 rejected Origin, 413 body
bound, 415 unsupported media, 429 admission/credential/pending limits, 503 unavailable
persistence and 504 request timeout. Rejected and rolled-back operations create no
success audit fact. The experimental router serves the complete combined schema at
`/openapi.json`; its [generated snapshot](openapi-passkey-enrollment.json) is checked
against live output. Default [OpenAPI](../openapi.json) excludes experimental
routes while sharing the optional-mailbox user contract described above.

See the [enrollment guide](../guides/passkey-enrollment.md) and
[browser test instructions](../../tests/browser/passkeys/README.md) for verified
boundaries and remaining M03 release gates.

## Explicit experimental passkey authentication

The additional `passkey-authentication` feature exports `experimental_passkey_router`
and a [full schema](openapi-passkeys.json), combining base, enrollment and sign-in.
Ordinary server composition stays gated on the remaining M03 security policy.

| Method/path | Input | Output / behavior |
| --- | --- | --- |
| POST /v1/passkeys/authentication/start | `{mode:"account_bound",account_id}`, `{mode:"discoverable"}` or `{mode:"conditional"}`, exact Origin | 200 `{transaction_id,options}`; persists private state; sets/reuses host binding cookie |
| POST /v1/passkeys/authentication/finish | `{transaction_id,credential}`, same binding and exact Origin | 204 with fresh session cookie after atomic verified key/state/session/audit commit |

Both use 32 KiB bodies and the same redacted errors and cookie policy as enrollment.
Account selection uses an opaque remembered/private owner hint; email lookup and
extra/unknown mode fields are rejected. Modal discovery has no selected account;
conditional mode preserves the browser autofill hint. Private state and session
secrets are absent from JSON. See the sign-in guide for native JSON conversion,
counter/backup/context policy and the new-browser nonresident selection limitation.

## Explicit experimental anonymous signup

`easy-auth-axum/passkey-signup` exports `experimental_passkey_signup_router`,
combining base, enrollment, sign-in and three signup routes with a [full schema](openapi-passkey-signup.json).
Normal server composition and the earlier experimental constructors do not enable
signup implicitly. Every signup POST requires exact Origin, JSON, no session cookie
and at most 32 KiB; unknown fields are rejected. Even an expired/unknown session
cookie requires explicit logout first. Both completion stages require the original
HttpOnly passkey browser binding.

| POST path | Input | Result |
| --- | --- | --- |
| `/v1/passkeys/signup/start` | `{display_name}` | 200 `{transaction_id,options}` with required-UV resident creation options and binding cookie; no durable account/session |
| `/v1/passkeys/signup/registration` | `{transaction_id,credential}` registration JSON | 200 `{transaction_id,options}` for separate assertion; only the candidate/stage changes |
| `/v1/passkeys/signup/finish` | `{transaction_id,credential}` assertion JSON | 204 fresh session cookie after verified atomic account/key/session/audit completion |

Registration alone never authenticates. The prospective owner is server-selected;
no client owner, email, RP or residence override is accepted. The two-minute database
expiry is not extended at registration completion. New authenticated users have
`email: null` and passkey-required policy. Existing error/cookie/CSRF rules apply.
See the [signup guide](../guides/passkey-signup.md) for limits, one-use scope and
native platform/roaming evidence. The same explicit signup composition also mounts
POST `/v1/account/email/attachment/start` (`{email}`, 202) and `/finish` (`{token}`,
204 rotated session). They require an existing fresh passkey session, exact Origin,
JSON and an independent attachment binding, with an 8 KiB body bound. GET
`/email-attach` consumes nothing. See the [contact attachment contract](../guides/email-attachment.md).
Native Chromium platform/USB cases verify real SMTP confirmation and later passkey
login; AUTH-20 recovery/management remains required before ordinary activation.

Proof consumption and session-authorized mutations recheck the original database
deadline after potentially blocking writes and before commit. Expiry at that check
returns the existing generic 401 and rolls back mutation, proof consumption, session
touch/rotation, audit and notices together. Session validation/inventory lock owner
before caller session and evaluate policy and idle/absolute bounds after those waits;
a touch cannot renew authority that expires during the touch itself. Fresh actions
also retain the initiating authentication's five-minute cap. Logout remains
idempotent. See [ADR 0010](adr/0010-final-transaction-deadlines.md) for the precise
transaction boundary; this does not authorize consuming-application actions.

AUTH-20's optional core/PostgreSQL `PasskeyManagement` provides bounded public key
metadata, expected-version rename and last-proven-key-protected removal. No
ordinary activation is supplied by this checkpoint. Experimental management HTTP
is available only through its additional explicit constructor. Core port
consumers must implement `EmailDelivery::passkeys_changed` for non-secret queued
notices. See the [management guide](../guides/passkey-management.md) and
[ADR 0011](adr/0011-passkey-management-and-recovery.md); recovery and the full
stronger-account management/activation contract remain in progress.

The `passkey-management` feature exports `experimental_passkey_management_router`
and [the complete management OpenAPI](openapi-passkey-management.json). It reuses
all prior route builders and adds GET `/v1/passkeys` (no query selectors, bounded
public metadata), POST `/v1/passkeys/rename` (`{id,version,label}` -> `{version}`)
and POST `/v1/passkeys/remove` (`{id,version}` -> 204 with all auth/action cookies
cleared after commit). All require genuinely fresh passkey-method authority;
mutations require exact Origin and closed JSON within 8 KiB. Stale/foreign/last-
working-key targets use generic 401; storage failure uses generic 503 and returns
no success cookie. Ordinary and earlier experimental constructors remain unchanged.

Additional passkey enrollment now requires genuine fresh passkey-method authority
once the owner has any key in the realm, even for another configured RP. The first
key may bootstrap from a known fresh email/password method; unknown legacy methods
are rejected. All repository stages recheck under owner/session locks and retain
original deadlines through final writes/consumption. Registration does not change
account policy or issue stronger session provenance. Existing generic 401 responses
and wire schemas are unchanged. See the [enrollment guide](../guides/passkey-enrollment.md).


Optional `PasskeyRecoverySetup` requires genuine fresh passkey-method authority
plus an owned proven key in the configured RP, stores only a saved-code verifier
and binds confirmation to the original session/realm/owner/RP/pending ID. The new
explicit `passkey-recovery-setup` HTTP constructor exposes closed prepare `{}` ->
200 `{id,code}` and confirm `{id,code}` -> 204 under
`/v1/passkeys/recovery/code/{prepare,confirm}`. It validates service realm/origin,
rejects queries, retains exact Origin/session and 8 KiB/no-store protections,
returns generic errors and sets no session/action cookie. A code is serialized
only in the successful prepare response after persistence. The full
[recovery-setup schema](openapi-passkey-recovery-setup.json) preserves earlier
schemas/routes, which remain unchanged in their older constructors. No recovery
session or stronger-policy activation is exposed.
`EmailDelivery::passkey_recovery_changed` is required for the new purpose-specific
queued notice. See [ADR 0012](adr/0012-saved-passkey-recovery.md) and the
[management guide](../guides/passkey-management.md#experimental-saved-code-configuration).


Optional `PasskeyRecoveryClaims` adds core/PostgreSQL claim begin/resume/status
and browser, fresh-key or reserved-code cancellation. Its non-secret readiness metadata is never
session/key authority. It reserves a saved code once, binds its exact generation
and browser to the configured realm/owner/RP, preserves same-browser retry timing,
and enforces a 24-hour delay plus seven-day expiry using database time. Verified-
contact delay requires a current unexpired notification-lease acknowledgement;
email-free metadata explicitly reports the absence of an independent alert.
Reserved-code cancellation is deny-only and cannot transfer a browser or revive
proof. The required delivery port adds started/cancelled notices. See
[ADR 0012](adr/0012-saved-passkey-recovery.md) for rate scopes, lost-response handling,
original deadline/receipt rules, the separate replacement service and remaining
native/review/activation gates.


The experimental `PasskeyRecoveryReplacement` Rust service now exposes private
begin/finish-registration/finish operations for a `PasskeyRecoveryTarget` (public
user and claim UUIDs) plus the original browser secret. It returns creation/assertion
options and a transaction UUID; only committed genuine assertion completion returns
a fresh `Secret` session. Repository contracts use private verified transitions and
exact snapshots. The separate HTTP constructor below exposes them; existing
constructors, wire documents and ordinary activation remain unchanged. A repeated completion is
unauthorized; a lost response is resolved by ordinary sign-in with the installed
replacement key, never by returning another recovery grant.


The opt-in `passkey-recovery` feature exports `experimental_passkey_recovery_router`
and [the complete recovery OpenAPI](openapi-passkey-recovery.json). Named
`PasskeyRecoveryServices` supply enrollment/sign-in/signup/management/setup/claims/
replacement; startup validates every realm/origin. Older constructors retain their
schemas/routes. Ten new POST paths under `/v1/passkeys/recovery/` are:

| Suffix | Closed body | Success |
| --- | --- | --- |
| `browser` | `{}` | 204; establish/retain separate recovery browser cookie |
| `claims/start` | `{account_id,code}` | 200 claim metadata; pre-bound browser required |
| `claims/resume` | `{account_id}` | 200 same browser-bound claim after lost response |
| `claims/status` | `{account_id,claim_id}` | 200 timing metadata only |
| `claims/cancel` | `{account_id,claim_id}` | 204; bound-browser denial |
| `claims/cancel-with-code` | `{account_id,code}` | 204; reserved-code denial, no browser transfer |
| `claims/cancel-with-key` | `{}` | 204; current owner/RP selected by genuine fresh session |
| `replacement/start` | `{account_id,claim_id}` | 200 `{transaction_id,options}` |
| `replacement/registration` | `{account_id,claim_id,transaction_id,credential}` | 200 private-candidate assertion options |
| `replacement/finish` | `{account_id,claim_id,transaction_id,credential}` | 204; committed actual assertion sets session |

Claim metadata is exactly `{claim_id,expires_at_ms,not_before_ms,notification_required,
ready}`; nullable not-before remains explicit. All require exact Origin and reject
query selectors; stateful reads are POST only. Ordinary bodies retain 8 KiB, while
the two WebAuthn response paths allow 32 KiB. Anonymous claim/replacement operations
reject any existing session cookie; only fresh-key cancellation uses one. Recovery
has an independent host-bound HttpOnly cookie established before consumption;
other action/session cookies cannot replace it. Only final successful assertion
sets a session, clears stale action cookies and preserves the independent recovery
binding for other claims. Errors never return success cookies/proof values. Cookie
retention is seven days; original database deadlines remain authoritative. See
[ADR 0012](adr/0012-saved-passkey-recovery.md) for cancellation, lost-response and
remaining review/device/activation gates. This adds no ordinary server enablement.


Only `experimental_passkey_recovery_router` serves the reference client GET resources
`/passkey-recovery`, `/passkey-recovery/setup`, `/passkey-recovery/shared.js`,
`/passkey-recovery/recover.js` and `/passkey-recovery/setup.js`. They inherit no-store,
no-referrer/CSP and emit no success cookie or dynamic proof on GET. These static
resources do not add protocol operations to OpenAPI. The client uses the unchanged
closed POST contract with explicit sign-out/retention/consumption/replacement and
cancellation consent, transient proof fields, same-browser resume and normal
replacement-key sign-in after a lost finish response. Other constructors and
ordinary server composition retain their existing routes.

AUTH-28 adds the optional core/server-library document API described in the
[egress guide](../guides/oidc-egress.md). It adds no HTTP/OpenAPI route, provider
callback, token endpoint or authentication grant. Normal `configured_auth`
composition remains unchanged. Documents are backend input to a future reviewed
verifier; callers cannot treat fetch success as authentication or authorization.


AUTH-29's `OidcDocuments::refresh_jwks` is a backend-only bounded document operation
using an opaque observed snapshot. It accepts no endpoint/key-ID selector, exposes
no new HTTP/OpenAPI route and returns no verified identity or session. The token
verification/code-exchange boundary is described below; provider activation
and HTTP callback contracts remain unimplemented.

The opt-in `oidc-verification` library API adds `OidcIdToken`, explicit
`OidcVerificationPolicy`, `OidcTokenVerifier` and an opaque `VerifiedOidcIdentity`.
Its repository port validates consumed exchange context against database time.
It also adds `OidcCodeExchange`, explicit `OidcClientAuthentication`, protected
code/request/response values and the `OidcTokenHttp` backend port implemented by
`OidcHttps`. It exposes no HTTP/OpenAPI callback or authentication route and does
not serialize a verified identity as a browser credential.
See the [verification guide](../guides/oidc-verification.md). Existing ordinary
server composition and wire schemas remain unchanged.


The backend code flow may wait once per first ordinary discovery/key fetch, under
its existing shared capacity, for the remaining admission interval. It
keeps existing fetch rates, fresh/no-store semantics and exchange/verification
bounds; no state/code/failed-request retry occurs. Standalone document/token APIs
and forced-refresh admission remain prompt. A native retry retains the operation
lease through final authority validation. These resource semantics add no wire
route, response schema, clock extension or local authentication grant.

## AUTH-56 opt-in shared OIDC browser routes

The explicit Axum `oidc-web` feature and trusted `oidc_web_router` add
`POST /v1/oidc/sign-in/start` (`{}`), `finish` (`{state,code,issuer?}`) and `cancel`
(`{}`), plus the fixed `/oidc/sign-in` page and nonmutating `/oidc/callback` bridge.
One exact HTTPS source/realm/callback is selected by trusted composition. Start and
finish reject any presented session cookie; logout is explicit. Independent protected
purpose cookies carry browser/state/nonce/PKCE, and only committed success returns a
session cookie. Callback GET does no database/provider work or grant; exact unique
state-cookie matching selects fixed UI only. Scripts scrub URL proof before rendering,
require deliberate finish and drop proof on reload/navigation. Cancel never replaces
or revokes an ambient session. Existing provider-deletion endpoints reuse their
original use case and stronger proof requirements with the same common callback.
See [the concrete schema](openapi-oidc-web.json), [consumer guide](../guides/oidc-web.md)
and [ADR 0018](adr/0018-oidc-web-composition.md) for errors, cookie transport and
request-snapshot concurrency limits. Default OpenAPI/composition is unchanged. Explicit server `oidc-web` settings select
the same routes through `configured_application`; supported-mode native public-login
acceptance remains unfinished.
