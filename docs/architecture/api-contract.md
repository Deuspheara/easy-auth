# HTTP contract v1

## Trusted retention administration

`auth_core::run_retention` and `RetentionRepository::retain_batch` provide explicit
realm maintenance, not an HTTP endpoint or an authentication/application permission.
`RetentionPolicy` requires independent audit/exhausted-notice horizons: `keep`, or
a validated positive whole-second age. The PostgreSQL adapter performs finite
64-row categories using explicit Read Committed, candidate row locks and a fresh
reference/expiry check before deletion. Categories commit independently; failures
can follow earlier commits. Retained audit/proof/grant children pin their parents.
Durable identities, credentials, consumed recovery-code state and issuer/provider
keys/configuration are excluded. Apple expiry/lease/terminal effects remain distinct.

The executable's `easy-auth retention` and server library's `retain_database`
compose that same core policy from protected `DATABASE_URL`, non-nil `AUTH_REALM_ID`
and required `AUTH_RETENTION_AUDIT`/`AUTH_RETENTION_NOTICES`. Exact current schema
verification precedes mutation, with no DDL/provisioning/startup fallback. Output
contains only fixed category names and scalar effects. No listener/SMTP/provider
composition, new wire schema or credential output is introduced. Operational
qualification is in progress; [retention](../guides/retention.md) defines the command,
limits, notification exception and embedding boundary.

## Database administration boundary

`Postgres::migrate` and `Postgres::verify_schema` remain adapter administration
operations, with no HTTP route. The server library's `migrate_database` and executable
`easy-auth migrate` require only a privately supplied `DATABASE_URL`, apply SQLx
migrations and exit. Shared configured runtime composition accepts exact
`AUTH_DATABASE_MIGRATIONS=run|verify`, default `run`; verification never applies DDL
or falls back to migration. Missing/dirty/future/checksum-mismatched history fails
closed. Auth wire schemas, realm scope and public credential handling are unchanged.
See [database roles](../guides/database-roles.md) for privilege and recovery limits.

## Experimental social linking web transport

Explicit Axum `social-linking-web`, `SocialWebServices` and
`experimental_social_web_router` compose one base router with matching existing
Google/Apple web services and separate link authorizations. Same realm, HTTPS,
exact existing callbacks and all source/profile checks remain mandatory. Compiling
the feature does not enable linking in ordinary or separate provider builders.
The [selected schema](openapi-social-web.json) and
[guide](../guides/social-linking.md) specify the integration boundary.

| Exact-Origin JSON POST | Closed body | Success |
| --- | --- | --- |
| `/v1/account/google-link/start`, `/v1/account/apple-link/start` | `expected_owner`, `confirmation="link this account"` | 200 public authorization URL and four independent protected Link cookies |
| `/v1/account/google-link/finish` | actual raw `query`, same confirmation | 204 after atomic link; current session retained |
| `/v1/account/apple-link/finish` | actual raw `response` form, same confirmation | 204 after atomic link; current session retained |
| `/v1/account/google-link/cancel`, `/v1/account/apple-link/cancel` | optional returned public `state`; absent deliberately selects current | 204 original bound cancellation; current session retained |
| `/v1/account/providers/oidc/unlink` | `expected_owner`, `identity`, `confirmation="unlink this account"` | 204 owned identity removal using a fresh retained method; no remote grant revocation |

`expected_owner` is a deny-only check against the trusted current session, never an
owner selector. The original Link purpose binds owner/session through final commit.
Unknown query/body members, absent/duplicate/tampered private cookies, wrong purpose,
changed source/session, stale original caps or conflicting subject ownership fail
closed. A stale returned state cannot clear newer proof cookies. Logout clears all
five Google/Apple sign-in/deletion/link proof sets. No mutation issues a session.

`/social/accounts` is a fixed read/confirmation page using normal session/inventory
reads. Google GET return selects link UI only under trusted explicit composition
and unique matching protected state. Apple cross-site delivery remains cookie/
storage/DB-free. Its same-origin POST `/v1/apple/return-operation` takes only `{state}`
and returns a fixed `sign_in` or explicitly selected `link_identity` presentation
hint, with no database, exchange, consume or mutation. Default Apple composition
can select only sign-in. Unknown/ambiguous state returns401 without clearing proof.
The default Apple schema includes the finite selected-composition enum; this is
not authority or activation. Scripts drop raw returns before finish and on
navigation/restoration; no storage, raw rendering or automatic finish retry.

## Optional Rust Apple grant capture (in progress)

Core/PostgreSQL `apple-grants` adds explicit `AppleGrantAuthorization::sign_in` and
`::linking`, separate from default credential-discarding Apple operations. Link
registration remains web-only. Begin/cancel/callback admission reuse original
purpose/private proof/exact return/one-use state/source/deadline checks.
Completion returns opaque `AppleVerifiedGrant` only after the same response's
Apple signature/nonce/issuer/audience/source checks pass. Unsigned profile never
selects an owner. There is no raw-token upload or public proof constructor.

`grant.map(&policy)` consumes the result into `AppleMappedGrant`.
`AppleGrantSignIn::finish` generates a local session only after final repository
commit; `AppleGrantLinking::finish` retains the original owner/session and issues
no session. `AppleGrantRepository` extends shared identity/link transactions with
atomic encrypted capture. Select explicit protected `AppleGrantVault` on the
PostgreSQL adapter using `with_apple_grant_vault`; missing configuration returns
Unavailable and rolls back all local authority. Compiling the feature changes
neither the normal Apple router nor its selected services.

Axum `apple-grants-web` supplies explicit
`AppleWebServices::new_with_grants(policy,transactions,exchange,sign_in)` using
`AppleGrantSignIn`. Together with `social-linking-web`,
`SocialWebServices::new_with_apple_grants` selects the matching Apple transactions,
exchange and `AppleGrantLinking`, retaining ordinary Google and local unlink
services. Source/policy/realm and web-only registration checks apply at construction.
The existing `new` builders still discard credentials even with capture compiled.
The selected grant services require the same protected PostgreSQL vault at final
commit; absence returns503 without a normal-flow fallback.

No HTTP route, body, public token field or browser script is added. The selected
flows retain original Origin, private cookies, purpose, state-only presentation,
cross-site handoff, explicit confirmation and one-use callback checks. Grant data
stays behind signed proof and atomic encryption; a successful finish never returns
provider credentials. Local unlink queues every captured grant atomically and
returns before provider I/O. Selecting these services schedules no worker or
maintenance; operators must explicitly compose both.

The repository-only `into_parts` boundary exposes a mapped proof and opaque
`AppleGrantCapture`, never a raw credential. Its `seal(binding,vault)` requires
the same realm/source/client. The transaction supplies the identity actually
resolved under existing locks. Authenticated storage binding includes realm/
source/client/identity/grant; the encrypted payload also binds the exact provider
client string. Refresh tokens are preferred. Access-only capture requires a
positive bounded lifetime conservatively anchored before redemption; this is
not authentication freshness or an extended proof/session lifetime.

Migration0038 stores only encrypted credentials. A storage trigger moves every
captured grant into pending revocation atomically on unlink/deletion, including
ordinary account deletion with no vault selected. Existing freshness, audit
erasure and session isolation still apply. Jobs retain opaque binding/source IDs,
not local user/contact/subject columns. Pending eligibility is capped at604800
elapsed seconds, independent of database timezone; this is not automatic erasure
or confirmed remote revocation. Explicit maintenance is required; this timestamp
is not a database TTL.

Trusted `rotate_apple_grant_key(realm,grant_id)` rewraps active/pending/failed rows
under the configured current storage key using a row lock and version CAS. It
skips busy/leased/finished rows, preserves binding/deadlines, changes no provider
token and claims no remote success. Retain explicit old reading keys until
migration completes; missing keys never select fallback. See
[ADR0045](adr/0045-apple-grant-custody-and-revocation.md). Owned genuine Chromium-to-worker qualification now covers both selected capture
paths, local unlink, provider failure, actual backoff/erasure and ordinary account
erasure in a separately compiled capture/linking-disabled probe. This is offline
provider fixture evidence; real-provider/production acceptance remains pending.

`AppleGrantRevoker::new` selects one immutable Apple source, the shared protected
`Arc<AppleClientSecretSigner>`, vault, repository and checked HTTPS adapters.
`run_once()` claims one eligible job before network I/O. The PostgreSQL claim has
an exclusive60-second lease/version and at most8 attempts. An expired lease can
be reclaimed; stale workers cannot acknowledge or reschedule its replacement.
The30-second attempt decrypts against the stored binding, compares the encrypted
provider client, issues a fresh client secret and resolves only
`https://appleid.apple.com/auth/revoke`. Disabling sign-in does not discard pending
revocation or reenable authentication. No user/session lock spans network I/O.

`AppleRevocationHttp` receives a protected, redacted form request, never an uploaded
ID token or a caller-selected endpoint. Server `apple-grants` selects the existing
`OidcHttps` implementation with normal certificate/hostname verification, checked
address pinning and shared bounded operations. It uses no proxy, redirect, cookie,
automatic retry or raw diagnostics. Its dedicated16KiB response profile permits
an absent Content-Type only for actually empty200; ordinary OIDC responses still
require their original JSON profile. Core accepts only empty200 as confirmation;
nonempty200 and400 invalid_grant do not become success. Errors retain finite
transport/provider/configuration/unavailable categories.

Only an opaque worker-created `AppleRevocationConfirmation` can request repository
completion. Exact realm/source/client/job/lease/version and authoritative clock
checks after row/write waits precede commit. Confirmed completion erases ciphertext
and key ID. Failure retains ciphertext and schedules capped exponential backoff
starting at30 seconds; exhausting8 attempts remains a visible failed state. A lost
successful response can be retried idempotently after backoff; no local session is
created, refreshed or revoked by this worker.

Trusted `maintain_apple_grants(realm)` processes at most64 rows per phase with
`SKIP LOCKED`: erase expired pending/leased/failed ciphertext, classify exhausted
expired leases, then remove terminal metadata after another604800 elapsed seconds.
It returns the number expired, not the number confirmed. Claims invoke maintenance
for their realm; an operator must also schedule it for inactive sources/realms and
repeat bounded batches as necessary. Without invocation no automatic purge occurs.
Normal startup does not schedule or select this component.

## Optional Rust social identity mutation

Core/PostgreSQL `oidc-linking` exposes `OidcIdentityLinking` and the
`OidcIdentityLinkRepository` port. Explicit `AppleIdentityLinkAuthorization` and
`GoogleIdentityLinkAuthorization` retain original private web operation proof and
only accept linking purpose; default sign-in/deletion components still reject it.
Google's selected ordinary/session-age profile remains explicit and requests fixed
account selection without inventing freshness. Apple native kind and Google desktop
loopback linking are rejected; OS delivery remains unimplemented.

`finish(mapped,current_session)` consumes the mapped link proof and requires its
original session/owner, current source/policy, uniqueness and original deadlines.
It returns public `LinkedProvider` metadata only; no local session or policy change.
Duplicate/conflicting ownership, including same-owner repeat, is Unauthorized
without exposing another owner. `unlink(realm,current_session,identity_uuid)`
requires fresh retained-method authority and rejects removal of the caller's own
OIDC source. Cross-owner/realm UUIDs are not authority. Identity mutation, scoped
cooldown, finite audit and existing verified-contact notice enqueue are atomic.
The delivery port's additive `providers_changed` hook must be implemented by custom
adapters selecting this feature; its default reports Unavailable and leaves retry
work rather than claiming delivery. Existing SMTP implements a fixed non-secret notice.
See [ADR0044](adr/0044-explicit-social-identity-linking.md).

The optional Rust Apple boundary exposes `AppleClientSecretSigner`,
`AppleCodeExchange` and `AppleAuthorization` behind core/PostgreSQL `apple`.
Preparation returns private proof separately from public web/native request
inputs. Strict form decoding is untrusted; completion requires the retained
operation/private proof and actual trusted dedicated backend return. Success
returns the existing opaque verified identity, with unsigned first-consent profile
separate; mapping/final session commit retain existing contracts. No ordinary
Apple startup or `AUTH_APPLE_*` setting is added. Native OS delivery is unimplemented. See the
[Apple guide](../guides/apple-setup.md) and [ADR0043](adr/0043-apple-code-flow.md).

## Experimental Apple web transport

Axum `apple-web` exposes only explicit `AppleWebServices` and
`experimental_apple_web_router` composition. Persisted realm, web-only client kind
and exact trusted HTTPS origin plus `/apple/callback` must match. The selected
[Apple OpenAPI](openapi-apple-web.json) is served at `/openapi.json`; ordinary
and unrelated provider contracts contain none of these operations.

| Route | Input / result |
| --- | --- |
| POST `/v1/apple/sign-in/start` | Closed JSON `{}`; `200 {authorization_url}` plus four private operation cookies |
| POST `/apple/callback` | Actual form-urlencoded body, at most32KiB; escaped inert HTML handoff only, no cookies/storage/consume/exchange/session |
| POST `/v1/apple/sign-in/finish` | Closed JSON `{response:string}` holding the actual raw form; `204` session cookie only after verified mapping and atomic commit |
| POST `/v1/apple/sign-in/cancel` | Closed JSON `{state?:string}`; callback pages supply returned public state, standalone sign-in page deliberately cancels current pending proof; `204`, existing session retained |
| GET `/apple/sign-in` | Fixed deliberate sign-in page; no query proof import |

Start/finish/cancel require one exact trusted Origin and reject unknown queries or
JSON fields. Start and finish reject any ambient session cookie, including invalid
ones. Four independent `__Host-auth-apple-signin-{browser,state,nonce,pkce}` cookies
are Secure, HttpOnly, Path=/, SameSite=Lax and Max-Age300, with no Domain. The `pkce`
name retains the existing private operation-proof field; it advertises no Apple
S256 wire support. Logout/session-clear responses also clear these proofs.

Delivery is the sole cross-site exception. It validates form syntax but cannot
authenticate Apple. Fixed `/apple/client.js` removes the inert return from DOM,
retains it only in transient memory and requires a deliberate confirmation. Finish
discards the payload before submission; navigation/restoration discards it without
retry. Raw return data never enters URLs, browser storage or diagnostics. Malformed
or mismatched-state finish/cancel cannot clear a newer operation. Successful
state matching still requires all private/core/provider/current-policy checks.
Client IP supplies committed abuse admission, not IP-pinned identity. Unsigned
initial profile is ignored by local mapping. Real registered Apple/device tests,
ordinary activation and provider-grant lifecycle remain gated.

Current SAML activation policy: [ADR0032](adr/0032-saml-maintainer-directed-activation.md) permits explicitly configured
normal SAML by maintainer direction, waiving independent review. Default-off,
trusted persisted configuration and every protocol/security check remain required.
Earlier source-disabled stage descriptions below are superseded only as to
activation policy; their assurance gaps remain unverified, not independently approved.

## Linked-provider inventory

GET `/v1/account/providers` validates the normal current session and returns
`{providers:[{id,kind,issuer}],next:{kind,id}|null}`. Each page contains at most 50
records ordered by `kind` (`oidc` before `saml`) then UUID. Continue with both
`after_kind` and `after_id` from `next`, or omit both. Unknown/duplicate fields,
unsupported kinds and partial/malformed cursors return 400. Missing, duplicated,
expired, revoked or current-source-invalid session proof returns 401. Storage
unavailability remains 503; the normal boundary timeout remains 504.

No request field selects a realm, user or provider source. Subjects, claims,
email, credentials and verifier material are excluded. Issuer metadata describes
the linked identity; it is neither current enabled/trusted status nor permission
to sign in, link, unlink or delete. The response uses the existing no-store,
no-referrer and browser security headers. See
[ADR0041](adr/0041-linked-provider-inventory.md). Existing repository adapters
without this optional read return Unavailable rather than an invented empty list.

## Reference presentation metadata

`/v1/session` additionally returns the existing core `authentication_policy`
string (`mailbox`, `passkey_required` or `provider_required`). This is current
account metadata, not authentication-method or freshness proof. The root reference
page advertises only boolean capabilities for the actually selected router and
password service; URL fields cannot activate a method. Read-only inventory and
all protected mutations retain the same backend authority checks. See
[the reference client](../guides/reference-ui.md) and
[ADR0042](adr/0042-reference-account-ui.md).

## Existing authentication contracts
The opt-in core/PostgreSQL `saml-requests` Rust component adds no HTTP route or
OpenAPI operation. `SamlRegistration::unsigned_redirect` selects the explicit
outgoing profile; `SamlTransactions::start` persists browser-bound request state
and `cancel` removes only that operation under both proofs/current registration.
`prepare_response` additionally consumes bound state and returns original DB timing
for future verification; it accepts no XML or signed protocol claims. None of these
operations grant a user/session. The normal SAML
ACS remains absent. See the [component contract and limits](../guides/saml.md).

The separate opt-in `saml-certificates` component adds operator-pinned public
certificate configuration and atomic revision/rotation invalidation in PostgreSQL.
It adds no HTTP endpoint, response verifier or user/session grant. Exact leaf pins,
X.509/approval windows, namespace checks and remaining integration requirements are
specified in the same [SAML guide](../guides/saml.md#operator-pinned-idp-certificates).

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

AUTH-23 adds explicit `OAuthRedirect` metadata and
`OAuthConnection::with_redirect` for trusted desktop embedding. The existing
constructor remains HTTPS-only. Literal desktop loopback has exact nonzero,
nondefault port and canonical path binding; it does not create a public native or
Google endpoint. See the [desktop contract](../guides/oauth-transactions.md#explicit-desktop-return-metadata).

The opt-in core `google` feature adds `GoogleCodeExchange`, which fixes trusted
Google issuer/egress/signature/scope policy around the existing one-use opaque
sign-in exchange. It accepts no unsolicited token, linking or deletion proof and
issues no local session. Public HTTP/OpenAPI and server startup settings are
unchanged. See the [component contract](../guides/google.md); Google web/native
transport, lifecycle integration and manual evidence remain unfinished.

`GoogleAuthorizationResponse` decodes a bounded Google-specific raw query into
canonical returned state, actual exact issuer and an untrusted redacted code or
finite denial/provider-failure outcome. It does no I/O, consumption, cancellation
or grant. Presentation metadata/error details are discarded. The supported closed
member set, limits and mandatory subsequent private-operation binding are specified
in the [Google callback contract](../guides/google.md#callback-decoding-component).
No generic HTTP callback contract is broadened by this core component.

`GoogleAuthorization` composes exact matching transaction/code-service snapshots
for sign-in-only start/finish/cancel. Callback completion compares original retained
state and actual issuer/route before one-use consume/exchange or proof-bound
cancellation. It returns a verified proof or finite canceled-provider outcome;
neither issues a session. Failed cleanup and storage/provider/verification errors
remain observable. Request network source is admission metadata, while provider
configuration/browser/state/purpose/nonce/PKCE remain authentication bindings.
See the [shared-use-case contract](../guides/google.md#shared-authorization-use-case).

The optional server-library `google-desktop` transport owns a literal IPv4/IPv6
loopback listener before exposing its exact ephemeral-port redirect. Bounded GET
delivery creates an opaque `GoogleDesktopCallback`; its completion supplies the
captured URI plus original retained state/private proof to the shared core use case.
No public constructor or pasted callback-URL API exists for that delivery value.
Transport cancellation/expiry closes sockets without cancelling database state or
issuing authority. Fixed browser responses scrub URL proof and issue no cookie.
See the [desktop contract](../guides/google.md#owned-desktop-loopback-delivery) for
resource bounds and remaining registered-provider/platform/lifecycle gates. This
adds no ordinary startup flag, generic web route or remote application token API.

`GoogleCodeExchange::with_session_age_claims` produces the explicit eligible-client
`GoogleSessionAgeCodeExchange`. Its fixed authorization request selects essential
signed `auth_time` without reauthentication parameters or arbitrary claims. Separate
sign-in/deletion exchange methods preserve purpose before token I/O; actual signed
claim absence is Unavailable, invalid claims Unauthorized, and old time stays old.
`GoogleAuthorization::new_session_age` retains shared callback/cancellation bindings
for this sign-in profile. The returned existing opaque deletion proof still needs
mapping and the original deliberate-confirmation/freshness-checked deletion use
case. No endpoint/OpenAPI or ordinary activation changes. See the
[eligible-profile contract](../guides/google.md#eligible-session-age-claims-profile).

`GoogleAccountDeletionAuthorization` is the separate deletion-purpose counterpart
to the shared sign-in service. Construction requires matching transaction and
explicit session-age exchange snapshots. Bound start/finish/cancel reuse original
state/private proof/actual route/issuer checks for codes and provider errors.
Sign-in/linking intents fail before I/O; both sign-in constructors remain sign-in
only. Completion yields proof, denial or provider failure, never account erasure
or a session. Current-policy mapping and `OidcAccountDeletion` retain original
owner/source/subject/session/freshness/cap and atomic erasure checks. No HTTP schema
or ordinary composition changes follow from this core API.

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
the same routes through `configured_application`; owned supported-mode public-login
acceptance is described in the guide with its private-TLS/source-copy limits.


The optional Axum `google-web` composition has its own
[generated contract](openapi-google-web.json) and
[HTTPS route/cookie/confirmation contract](../guides/google.md#experimental-https-browser-composition).
`GoogleWebServices` requires the explicit eligible-client session-age profile;
`experimental_google_web_router` requires HTTPS, the exact `/google/callback` and
matching realm/source snapshots. It adds fixed `/google/sign-in` and
`/google/account-delete` pages and separate Google sign-in/deletion start/finish/
cancel endpoints. Finish accepts the actual raw query under all original private
bindings, including provider-error cancellation. GET grants nothing. No base or
generic OIDC path/schema is broadened and no ordinary startup flag is introduced.


The optional server-library `google-desktop-launch` API adds `GoogleDesktopSignIn`
(`begin`, one-attempt `run`, consuming operation `cancel`) and finite launcher/core/
transport error classification. It adds no HTTP/OpenAPI route. Proof remains private;
verified completion still needs mapping and atomic sign-in. Transport cancellation
is distinct from committed pending-state cancellation. See the
[native operation contract](../guides/google.md#owned-native-sign-in-operation)
for original caps, child cleanup, drop semantics and source-revision limitations.


Optional native composition adds `OAuthRedirectPolicy`, the explicit trusted
`OAuthConnection::with_desktop_loopback_returns` profile builder,
`OAuthTransactions::for_desktop_return` and readonly operation `redirect()` getters.
`OAuthStart`/`OAuthRequest` fields and existing repository methods stay unchanged.
New `save_oauth_return`/`consume_oauth_return`/`cancel_oauth_return` methods bind exact
operation URIs; their defaults reject alternate returns on unextended backends.
The default profile remains exact. This adds no HTTP/OpenAPI route or remote token
contract. See the [stable native contract](../guides/google.md#stable-native-registration-and-per-attempt-return).


The opt-in Rust-only `saml-verification` component consumes prepared browser-bound
request state and a bounded POST field through concrete `SamlResponseVerifier`.
`VerifiedSamlAssertion` contains authenticated persistent-subject/time/source/pin
facts and hashed replay reservations, without raw XML or local session authority.
It has no public constructor or clone/serialization contract. The PostgreSQL
configuration/clock port requires exact current enabled registration. The separate
identity component owns final replay and local authority; normal HTTP APIs expose
no SAML ACS. See the [SAML component guide](../guides/saml.md).


The opt-in `saml-identities` Rust API binds `SamlIdentityPolicy` to exact full
registration and defaults JIT to Deny. It consumes actual verified assertions into
opaque `SamlMappedIdentity`, without local authority or durable replay commit.
PostgreSQL configures registration, explicit pins and mapping policy atomically;
current-policy reads require enabled exact registration. `SamlSignIn::finish`
consumes the mapped proof through `SamlIdentityRepository::finish_saml_identity`
and returns `(User, Secret)` only after atomic replay/identity/session/audit commit.
`AuditEvent::SamlAuthenticated` records the committed user/session fact. Existing
authentication, inventory, revocation and logout APIs enforce SAML source policy.
Attribute selection remains unsupported; the separate purpose-bound SAML deletion
backend and explicit HTTP extension are described below. The
separate gated Axum composition below supplies engineering-only HTTP routes.
See [ADR 0023](adr/0023-saml-identity-session-commit.md).


The explicit Axum `saml-web` API adds `SamlWebServices`,
`experimental_saml_web_router` and `saml_web_openapi` for sign-in. That contract
contains closed start/cancel JSON, POST delivery/finish forms with exactly
`SAMLResponse` and `RelayState`, trusted metadata and a reference page. ACS delivery
is non-authoritative; only same-origin finish can issue the shared session cookie
after concrete verification and final commit. HTTPS, exact realm/ACS and private
pending cookies are mandatory; no browser-selected source or return URL exists.
Normal OpenAPI/router/server configuration has no SAML provider activation.
[ADR 0024](adr/0024-saml-web-delivery.md) records the cross-site exception and limits.


The explicit SAML deletion extension constructs `SamlAccountDeletionWebServices`
from the same full persisted policy and calls `SamlWebServices::with_account_deletion`.
The original constructor leaves it absent. Only that selection registers
`/v1/saml/account-delete/start`, `/finish`, `/cancel` and the reference deletion
page. Both initiation and final form submission require the exact case-sensitive
phrase `delete my account`, the current SAML session and same-origin boundary.
Three independent Secure/HttpOnly/host-only/Lax deletion cookies preserve request,
RelayState and private-browser binding; no owner/realm/provider selector is accepted.

The shared ACS still consumes/grants/erases nothing and reads no cookie or SQL.
Its script first calls the same-origin cookie-only `/v1/saml/operation` endpoint
with the returned RelayState. That endpoint neither consumes nor verifies: only a
unique private-cookie match selects fixed sign-in versus deletion UI. Ambiguous,
foreign or unavailable operation profiles reject. Sign-in still checks absence
of an ambient session at actual same-origin finish. Deletion requires another
deliberate confirmation before its separate finish verifies and atomically erases;
its proof cannot mint a sign-in session. Callback data is transient memory only,
removed from the DOM and discarded on navigation/restoration; no provider field
selects a return URL. A stale deletion RelayState cannot clear newer proof cookies.

The selected [deletion contract](openapi-saml-account-deletion.json) is generated by
`export_saml_account_deletion_web_openapi`; `saml_web_openapi` retains the sign-in
composition and adds only the non-authoritative operation selector. Normal public
OpenAPI/router/server configuration still activates no SAML provider. Component
HTTP/real-PG checks and the existing owned browser sign-in regression are recorded;
actual IdP deletion/browser acceptance and independent approval remain separate.

## Outbound issuer client metadata component

The opt-in core/PostgreSQL `issuer-clients` feature exposes trusted
`IssuerClientRegistration` public/confidential HTTPS web configuration and
Postgres configure/disable/enable/check/subject metadata methods. It adds no HTTP
route or OpenAPI endpoint. Exact redirect allowlisting and stable realm/hostname-
sector owner subjects are metadata boundaries, not client authentication, consent
or authorization. Existing session/inbound federation contracts are unchanged.
See [the guide](../guides/issuer-clients.md); actual authorize/token/consent and
interoperability remain required before an outbound issuer can be enabled.

The same feature now adds explicit public native loopback registration through
`IssuerClientRegistration::public_native_loopback`, a closed `IssuerRedirectProfile`
and typed `IssuerClientAuthentication` inputs. Web defaults remain exact HTTPS.
Native port admission fixes literal address/path and grants no listener ownership;
eventual code redemption must retain the exact actual redirect. The PostgreSQL
credential-validation method checks current enabled configuration and method/secret
without issuing authority or an authenticated-client proof. No HTTP/OpenAPI shape
changes. `load_issuer_client` restores validated enabled metadata and its revision
without requiring a raw secret or mutating configuration; subsequent authority still
requires current transactional checks. See
[ADR0034](adr/0034-issuer-native-registration-and-authentication.md).


## Gated SAML verified attribute facts

`VerifiedSamlAssertion::attributes()` returns ordered, debug-redacted, zeroizing
`SamlAttribute` records with exact Name, optional NameFormat and scalar value
groups. This adds no HTTP/OpenAPI field, user contact, owner key, role or session
grant. Missing attributes are empty; incomplete XML-valued/nil projection rejects
the current profile. Core consumes the maintained typed complete-record view,
never raw XML or the legacy name-keyed aggregate. Public constructors cannot
fabricate this verified proof. Signed authentication time also remains separate
from response issuance; ordinary new-response/old-authentication cases retain
all admission,24-hour session-age and five-minute deletion caps.
See [ADR 0028](adr/0028-saml-attribute-and-authentication-facts.md). Normal SAML is now explicit opt-in under ADR0032; independent review is waived,
not completed.

Normal SAML server preparation uses the optional `saml-web` feature and the shared
standalone/embedded `configured_application` factory. Disabled startup exposes
no SAML paths/schemas. Complete opt-in startup loads only a matching enabled
persisted policy and active trusted pins; missing/mismatched trust fails closed. The additive
`experimental_oidc_saml_web_router` composes the existing OIDC and SAML components
with one base and combined contract for engineering tests. It preserves their
exact HTTPS callbacks, realm checks, Origin boundaries and private proof cookies.
[ADR 0029](adr/0029-gated-saml-server-composition.md) records trusted provisioning and
read-only restart semantics; ADR0032 supersedes its separate approval requirement.

### Optional issuer authorization-code component

With `issuer-codes`, `IssuerAuthorization` composes a trusted `IssuerAuthority` and
`IssuerAuthorizationRepository`. `prepare` takes the actual session/browser Secrets
and `IssuerAuthorizationInput` (client, code response type, exact actual URI, openid,
state, nonce and S256 challenge). Its start exposes a private handle and public
preview UUID, client/destination and original expiry. Neither creates authority.
`approve`/`cancel` require the initiating session, private browser/handle and that
exact preview UUID. Only validated registered destinations receive code/state/iss
or access_denied/state/iss. HTTP must independently enforce private cookie/Origin/
explicit confirmation and never select owner/realm from these wire fields.

`redeem` takes typed public/Basic client input, canonical code Secret, actual exact
URI, `IssuerPkceVerifier` and a trusted network-source string. Source is an abuse key,
never a body-selected credential. The repository atomically checks current client/
source/session, PKCE and original code binding, consumes once and records audit.
`IssuerTokenError` separates InvalidClient, InvalidGrant, RateLimited and Unavailable.
The opaque `IssuerRedeemedCode` contains internal identity/caps for a later signing
layer, grants no new local session and is not a wire token. Internal owner/session
IDs must never be serialized as `sub`. No HTTP endpoint or startup feature is
introduced by this core/PostgreSQL increment. See
[ADR0035](adr/0035-issuer-consent-and-authorization-codes.md).

### Optional issuer HTTPS consent delivery

`issuer-consent-web` adds only the explicit HTTPS root-origin
`experimental_issuer_consent_router` and `issuer_consent_openapi` composition.
Default routes and standalone startup do not mount it. Fixed GET `/oidc/authorize`
and `/oidc/authorize.js` are non-authoritative. Origin-bound closed JSON POSTs:

| Path | Input | Result |
| --- | --- | --- |
| `/v1/oidc/consent/prepare` | Exact code request members, `client_id` | Public preview UUID/client/actual URI/original expiry; private proof cookies |
| `/v1/oidc/consent/resume` | Empty object | Revalidated existing pending preview; no grant or expiry extension |
| `/v1/oidc/consent/approve` | `authorization` preview UUID | Validated callback with one code/state/iss |
| `/v1/oidc/consent/cancel` | `authorization` preview UUID | Validated callback with access_denied/state/iss only |

Every operation requires the actual fresh source-aware initiating session. Resume/
decisions additionally require exact private browser/handle and public operation
selector cookies; decision JSON must match that selector. Invalid/expired authority
returns401; malformed input400, Origin403, oversized body413, media415, admission429,
storage503 and timeout504 remain distinct. No unvalidated redirect receives a
protocol error. Resume clears permanently unusable proofs on401, preserving them
on503; failed decisions cannot clear another preview's cookies. There is no token
endpoint or unsigned token response. See [ADR0036](adr/0036-issuer-https-consent-delivery.md).

### Optional signed issuer transport

`issuer-web` adds `IssuerWebServices` and `experimental_issuer_web_router`, extending
the consent composition above. Supply the identical realm and exact HTTPS root
issuer/browser origin, separate token/metadata repository ports and explicit protected
keys. Default routes and standalone startup do not activate an issuer.

| Method/path | Contract |
| --- | --- |
| GET `/.well-known/openid-configuration` | Exact issuer/endpoints; code/query, openid, S256, pairwise, RS256, none/Basic only |
| GET `/oidc/jwks` | At most four enabled retained public RSA verification keys; no private/certificate/key URL members |
| POST `/oidc/token` | Closed form authorization_code/code/redirect_uri/code_verifier and optional client_id; maximum8192bytes |

Metadata accepts no query-selected realm/issuer. Token POST requires one form content
type (optional UTF-8 charset), no encoding/query, strict percent/UTF-8 decoding and
no decoded duplicate or unknown members. Public client_id is explicit; confidential
clients use one Basic header with separately form-encoded identifier/secret. Header
and optional body identities must agree. No client_secret_post, refresh, userinfo,
client assertion, cookie authentication or anonymous fallback is supported.

Mount the router using actual socket `ConnectInfo<SocketAddr>`. Missing peer data
returns503; Forwarded/X-Forwarded-For cannot change the bounded admission source.
The token endpoint accepts native/server POSTs without Origin or local cookies;
existing consent/session endpoints retain their original Origin checks.

Success returns access_token, token_type=Bearer, expires_in, id_token and scope=openid
only after final committed issuance. The opaque access credential grants no local
session or application permission and has no userinfo/introspection API in this
increment. ID tokens contain exact iss/aud/sub/nonce/iat/exp/auth_time; original
code/session/key caps bound expiry to at most60seconds in the current profile.
Responses use no-store/no-cache and set no session cookies. Finite errors are
invalid_request (400/413/415), invalid_client (401 with Basic challenge), invalid_grant
(400), unsupported_grant_type (400), or temporarily_unavailable (429/503/504).
See [ADR0037](adr/0037-issuer-signing-and-final-issuance.md) and
[the component guide](../guides/issuer-signing.md) for trust and evidence limits.

### Optional token status and revocation

`issuer-token-management-web` and `experimental_issuer_token_management_web_router`
explicitly add POST `/oidc/introspect` and `/oidc/revoke` to the same trusted HTTPS
root issuer/realm. `issuer_token_management_openapi` merges their concrete schemas.
Default issuer/server routes remain unchanged; native families use separate library operations described below and are not
advertised by this access-only router.

Closed4096byte form bodies accept token and optional client_id/token_type_hint,
with the same strict percent/media/duplicate/query rules as token issuance. Presented
opaque input is bounded to1024printable ASCII bytes; unknown valid formats still
require actual current-client authentication before an inactive result. Hints are
ignored and confer no type/namespace authority. Actual socket ConnectInfo is required;
no Cookie/Origin/forwarded-header authority is accepted. Public possession can revoke
its matching token, but introspection requires current confidential Basic and the
exact same audience. Header/body client IDs must agree; client_secret_post rejects.

Introspection200 is either only active=false or active=true with iss/aud/client_id/
pairwise-sub/iat/exp/token_type/scope. It contains no owner/session/nonce/raw credential
or hash. Unknown/foreign/revoked/inactive tokens disclose no claims; client failure401
and infrastructure failure503 remain errors. Revocation200 has no body and reveals
no existence/replay distinction. Shared no-store/no-cache,401Basic challenge and
400/413/415/429/503/504 finite failures apply. Neither operation grants a local session
or application permissions. See [ADR0038](adr/0038-native-token-lifecycle.md) and
[the guide](../guides/issuer-token-management.md) for exact lifecycle and pending scope.

### Native offline policy configuration

`issuer-native-refresh` in core/PostgreSQL exposes trusted provisioning: `public_native_refresh_loopback`, `IssuerNativeRefreshPolicy`, and
`configure_issuer_native_refresh_policy`, `enable_issuer_native_refresh_policy`,
`disable_issuer_native_refresh_policy`, `load_issuer_native_refresh_policy` and
`check_issuer_native_refresh_policy`. New saved policy is disabled; enable needs
the exact current full policy and enabled client. Replacement rotates revision and
preserves disable. Load/check return configuration facts, never authentication or
consent. Absolute1second–7days and idle1second–24hours/at most absolute are enforced.
Policy provisioning alone introduces no HTTP endpoint or startup activation. Default
online authorization still accepts only openid. Separate native consent and native
wire components below supply offline_access and token/refresh delivery explicitly.
`supports_online_authorization` is a configuration capability query, not a proof.
It is false for the new offline profile: default request/SQL code operations and
core grant validation refuse that profile, including future rows written by a newer
native implementation. Existing ordinary web/native code behavior is preserved.

Separate core/PostgreSQL `IssuerNativeAuthorization` now supplies explicit native
`prepare`/`preview`/`approve`/`cancel` operations through
`IssuerNativeAuthorizationRepository`. `IssuerNativeAuthorizationInput` wraps the
usual fields plus exact prompt=consent and requires exact openid offline_access.
Actual session/browser/handle bindings remain mandatory. Safe preview exposes
client/return/consent deadline/original proposed grant expiry/idle seconds; it grants
nothing. Approval returns only the existing code/state/iss callback after atomic
consent/code/actual-owner-session audit. Native cancellation can clean pending state
after policy disable. Default online APIs and signer refuse native operation rows.
Migration0034 adds only a native marker and full-tuple immutable proposed-consent
sidecar; old rows remain online. Separate components below supply native consent
HTTP/UI and wire responses/discovery. Default standalone activation stays gated.
An untrusted prompt string is never explicit owner-confirmation proof.

## Native family library operations

`IssuerNativeTokenIssuer::exchange` uses separate approved native consent and returns
initial short ID/access plus opaque refresh credentials after atomic commit.
`IssuerNativeRefresh::refresh` returns only newly rotated opaque access/refresh
credentials; no ID token or local session. `revoke` reduces the matching native
family. Exact current client/source/owner/session, immutable consent caps, typed
credential audit and final clock apply. Migration0035 preserves online rows. Public
native IDs cannot authenticate introspection. Library operations alone mount no HTTP
route; explicit native wire composition and owned browser acceptance are described
below. See [ADR0038](adr/0038-native-token-lifecycle.md) and the
[native guide](../guides/issuer-native.md) for lifetime/quota/replay semantics.

## Native consent HTTP component

The explicit issuer-native-consent-web router adds GET /oidc/native/authorize and
POST /v1/oidc/native/consent/{prepare,resume,approve,cancel}, preserving ordinary
consent routes. Native input is closed and requires exact prompt=consent/openid
offline_access. Preview adds original grant_expires_at_us and idle_seconds. Exact
same-Origin/current session/private operation bindings,16KiB JSON bound, shared
cookie hygiene and existing core/PG final transaction checks apply. Distinct
operation IDs and closed schemas are generated by issuer_native_consent_openapi. No
token/refresh/revocation/discovery is mounted by this component. See the
issuer-token-management guide and ADR0038.

## Native token and cleanup HTTP

Optional issuer-native-web adds explicit mixed-profile code/refresh/revocation
composition. Native token input is the closed union of existing authorization-code
fields and grant_type=refresh_token/refresh_token/client_id?/scope?. Refresh scope is
absent or exactly the original openid offline_access. Initial native response has the
existing ID/access plus refresh_token/refresh_expires_in/scope; refresh has no
id_token. Online responses keep five fields. All three concrete response schemas are
closed. One admitted configuration snapshot selects one core operation, never a retry
after failure. Scope mismatch returns invalid_scope400. Actual peer/strict bounded
form/query/auth/no-store rules remain. Only this discovery adds
refresh_token/offline_access; default metadata stays unchanged. Native revocation
selects matching current registered-method reduction and ignores hint as authority.
Explicit native resource-consumer introspection uses the separate policy/endpoint
below; public native IDs/cookies/tokens cannot authenticate it. See the
[native guide](../guides/issuer-native.md) and
[ADR0038](adr/0038-native-token-lifecycle.md).

## Native audience consumers

`IssuerNativeConsumerPolicy` binds exact same-realm confidential consumer and native
public audience definitions to one trusted issuer. Configure/enable/disable/load
use `configure_issuer_native_consumer`, `enable_issuer_native_consumer`,
`disable_issuer_native_consumer` and `load_issuer_native_consumer`. Initial policy
is disabled; current full definitions and exact saved revision are mandatory.
Migration0036 adds only consumer configuration and preserves previous token rows.

`IssuerNativeIntrospection::introspect_access` uses
`IssuerNativeIntrospectionRepository`, actual Basic authentication, committed source
admission and separate native source/family lifetime checks. Only sealed
`IssuerNativeActiveAccess` projects validated metadata; it grants no local session.
Call `IssuerNativeWebServices::with_native_introspection(repository)` to add POST
`/oidc/native/introspect`; otherwise route/schema are absent. Explicit live contract
is `issuer_native_consumer_openapi`. Existing online introspection is unchanged.
Closed4KiB status forms/current Basic/body ID/actual peer/no-cookie fallback and
finite no-store failures are shared. Output uses the existing closed active/inactive
shape, native aud/client_id and openid offline_access scope. Invalid credentials401;
unknown/foreign/inactive/unauthorized only active=false; storage faults503.
See [ADR0039](adr/0039-native-introspection-consumers.md) and the
[native guide](../guides/issuer-native.md) for ordering and lifetime semantics.

## Independent Rust relying-party client

The optional core `oidc-client` API exposes `OidcClientConfiguration`, `OidcClient`,
one-use `OidcClientAuthorization`, finite `OidcClientError`, verified
`OidcClientIdentity`, `OidcClientTokens` and opaque `OidcClientCredential`/
`OidcClientCredentials`. `authorize`/`complete` retain private S256/state/nonce
correlation and verify actual discovery and RS256 tokens. Native `refresh` consumes
one credential and returns credentials only. These are library contracts, not
new local HTTP endpoints or session proofs. Bounded configured standalone/embedded parity and remaining assurance limits
are documented separately. See [the SDK guide](../guides/oidc-client.md) and
[ADR0040](adr/0040-independent-oidc-client-and-standalone.md).

## Explicit configured issuer delivery

Server `issuer-web` plus complete `AUTH_ISSUER_ENABLED=true` HTTPS/protected matching
key settings selects the existing mixed web/native issuer handlers in the shared
configured application. Default-off and unsupported/partial settings fail closed.
Startup reads the current enabled realm/issuer/public-key registration and performs
no issuer enable or provisioning writes. Optional native inspection requires
`AUTH_ISSUER_NATIVE_INTROSPECTION_ENABLED=true` and the existing exact persisted
consumer policy. Selected inbound providers extend the same router/contract and
retain their own realm/source/proof-cleanup rules. No new token schema, grant or
local-session authority is introduced. [Setup and acceptance limits](../guides/issuer-standalone.md).
