# ADR 0018: Shared OIDC browser composition

Date: 2026-10-20. Status: stable startup metadata loading and opt-in Axum browser
composition and shared server configuration are implemented for AUTH-56;
owned supported-mode public-login acceptance is implemented with explicit private
TLS/source-copy limits. Dated local and exact-head hosted checks are tracked in
the [verification history](../../security/verification.md); broader release gates
remain open.
AUTH-30 and AUTH-55 acceptance are prerequisites, not ordinary sign-in activation.
No new schema or default activation is introduced. Public routes require the
explicit `oidc-web` feature and trusted `oidc_web_router` composition, selected
by complete explicit settings in the shared server application factory.

## Context and scope

Core/PostgreSQL already own one-use OAuth state, reviewed document/token transport,
signature/claim verification, mapping/JIT, current-source provider sessions and
purpose-bound account deletion. A private fixture's session bootstrap is not a
supported login boundary. Embedded and standalone consumers need the same browser
sign-in and deletion composition without repeating policy or persisting credentials
in a script, URL or public configuration response.

One `OAuthConnection` binds one exact redirect URI and a realm/connection/local-client
identity namespace. Giving sign-in and deletion different local clients would change
that namespace and would not authorize deletion of the original provider identity.
The existing experimental deletion constructor requires its dedicated callback;
preserve that API while adding a coherent combined composition.

The existing administrative configure methods deliberately rotate revisions, cancel
old state and invalidate old provider-session snapshots. Calling them automatically
on every restart would make ordinary availability depend on new sign-ins. Startup
loading and explicit administrative policy change need distinct semantics.

Keep the four crates and existing inward dependencies. Core owns policy/proof types,
PostgreSQL persistence/locking, Axum closed transport and server configuration/lifetime.
No linking, dynamic tenant templates, arbitrary claim paths, provider management API,
business permissions, native provider adapter, SAML or outbound issuer is introduced.
[ADR 0013](0013-oauth-state-transactions.md),
[ADR 0014](0014-oidc-egress.md), [ADR 0015](0015-oidc-token-verification.md),
[ADR 0016](0016-oidc-identity-mapping.md) and
[ADR 0017](0017-provider-account-deletion.md) retain their proof/security invariants.

## Trusted composition and callback

Provide one explicitly configured provider connection per combined router and public
origin initially. Trusted configuration selects realm, stable connection/local-client
UUIDs, exact issuer/provider client, allowed egress origins, explicit registered client
authentication, claim selection and JIT policy. Browsers select none of those values.
JIT remains denied unless explicitly enabled. Do not infer local contact or ownership
from matching provider email. Use the existing bounded `OidcHttps` adapter in ordinary
server composition; configuration exposes no private-root/address override.

The new combined composition uses one fixed HTTPS callback at `/oidc/callback` for
both sign-in and deletion purposes. The configured complete URI must exactly match
the browser origin and this path. Existing global callback uniqueness remains
mandatory, including across disabled connections/realms. This initial delivery does
not promise multiple provider connections or realms under the same callback/origin.
Preserve the legacy experimental deletion router and its existing callback. A
future expansion needs explicit unique trusted routes, not browser-selected issuers
or weakening callback uniqueness.

Callback GET is nonmutating. It may select a fixed sign-in or deletion reference
bridge only when the actual returned canonical state uniquely matches that purpose's
HttpOnly state cookie. This comparison is a routing hint, never authentication,
state consumption or deletion authority. Missing, duplicate, malformed or ambiguous
matches yield fixed failure content. No database or provider operation, cookie grant
or identity transition occurs in GET. No untrusted Host/forwarded header or query
parameter selects a configured provider/realm/redirect.

Every bridge immediately scrubs query/fragment material, renders no provider error
text and retains usable callback code/state/actual `iss` only in transient memory.
A deliberate same-origin POST performs the selected operation and all core bindings.
No automatic finish, arbitrary URL proof import, browser storage, analytics, inline
script or third-party resource is introduced. Unknown/duplicate/oversized callback
inputs and navigation/reload/late-result behavior must be tested. A fixed error bridge
also scrubs its address; it must not echo attacker-controlled keys or values.

Code/query callbacks only are in scope. Cross-site `form_post` must not gain a global
Origin exemption or weaker ordinary session cookies; unsupported response modes
fail closed. A present wrong issuer is always rejected. `RequireIssuer` remains the
normal explicit configuration; `DedicatedRedirect` requires deliberate selection
and the existing globally unique callback defense, never inferred fallback.

## Browser proof and existing sessions

Use independent canonical browser/state/nonce/PKCE secrets per purpose in Secure,
HttpOnly, host-only `__Host-` cookies, Path=/, SameSite=Lax and bounded lifetime.
Database deadlines remain authoritative. Keep sign-in and deletion namespaces
separate so one purpose cannot overwrite or consume another's proof. New starts
must not silently overwrite an existing pending cookie set; cancellation explicitly
disposes of it. The raw PKCE/session bearer never enters JSON, redirect URLs,
script storage, logs or telemetry. Authorization URLs intentionally carry protocol
state/nonce and the S256 challenge.

Sign-in start and finish require the browser to have no session cookie. An existing,
invalid, duplicated, revoked or expired cookie requires explicit logout first;
neither a provider callback nor a different tab may silently switch an ambient
account. Check at both stages. The eventual PostgreSQL sign-in transaction still
owns one-use identity/session/audit commit and all source/deadline revalidation.
Tests must exercise overlapping requests and session arrival after initiation;
never report an HTTP precheck as a database atomicity guarantee.

The implemented guard examines the request's cookie snapshot. Distinct concurrent
anonymous starts can each create a bounded transaction; they do not share a global
browser/session epoch or serialize other authentication methods. The browser may
retain the last start's cookies. Exact state/proof matching prevents crossing those
attempts, and both contexts cancel independently. A request already in flight is
not undone by a later cookie response in another tab. Explicit callback confirmation,
one-use database completion and checks at both stages remain required; this does
not claim browser-wide atomic account-switch exclusion. Peer address is an abuse-
admission dimension, not an identity binding; forwarding headers do not select it.

All locally initiated POSTs require one exact Origin, closed bounded bodies and
closed query inputs. Sign-in purpose is fixed by its trusted route. Deletion retains
its original current-session/owner binding, exact identity, newly signed recent
`auth_time` and both destructive confirmations. Callback routing or mere sign-in
freshness cannot substitute for any deletion condition. Cancellation is denial only:
it may clear local proof after expiry or a session transition, but never replaces
or revokes a current session implicitly. Logout/revocation hygiene clears applicable
proof cookies while database authority independently prevents reuse.

Only committed sign-in success sets a new session cookie. Failure retains no grant,
clears the attempted transport proof, and preserves an already consumed OAuth state
as consumed. Storage/transport failure is 503, boundary timeout 504, and actual
authorization failure 401; closed input/Origin/admission errors retain their existing
finite distinctions. Never format foreign payloads, causes, headers or URI proofs.
Interrupted completion may have committed remotely/locally; do not auto-replay,
recreate an account or claim success from an optimistic page message.

## Stable persisted configuration

Add a narrow trusted startup load/initial-provision operation for the complete
connection and identity-policy definition. An unchanged restart returns the actual
persisted revision without cancellation or session invalidation. It compares the
full configured definition under configuration-before-policy locks and preserves
an operator disable. Mismatch, missing policy on an existing generic OAuth record,
or unavailable/corrupt storage fails startup; do not overwrite, silently adopt,
restore an old revision or implicitly re-enable it.

Only a genuinely absent connection/policy may be provisioned atomically from the
explicit trusted definition. Concurrent startup must return one consistent persisted
revision or fail without partial rows. Existing generic OAuth contexts cannot gain
new identity/JIT authority by attaching policy under their old revision. Explicit
administrative changes continue to use revision rotation and state cancellation;
loading is not reconfiguration. Any necessary core restoration API constructs only
validated configuration metadata, never verified proof or authority.

The implemented `Postgres::load_or_initialize_oidc_identity_policy` first takes a
shared registry-key lock. Existing rows are read without attempted DML. For an
absent key, it allocates a fresh candidate revision, inserts without conflict
updates, reads the winning revision and writes policy only when its own registry
insert won. A conflicting generic OAuth row never gains policy. Both paths reuse
the existing exact configuration/policy/enable checks before commit. Matching
concurrent initializers converge; competing definitions have one winner and a
non-mutating mismatch. Global callback uniqueness still fails across foreign keys.

`OidcIdentityPolicy::with_persisted_revision` restores validated definition metadata
for trusted persistence; the underlying OAuth mutator is crate-private. It rejects
nil revisions and constructs no verified proof. The adapter maps corrupt stored
revisions to Unavailable and rechecks every field under locks. A metadata revision
cannot rewrite a verified identity's original snapshot. Explicit administrative
configure methods retain their existing rotation/cancellation semantics.

Keep credentials outside database policy/configuration rows and public DTOs. Select
client authentication explicitly; a missing secret never changes a confidential
client into a public client. Treat credential rotation separately from identity
policy changes and preserve the exact registered-client contract. Do not log file
contents or configuration values containing credentials.

## Intended HTTP contract

| Method/path | Closed input | Successful effect |
| --- | --- | --- |
| GET `/oidc/sign-in` | No imported proof | Fixed sign-in reference page |
| POST `/v1/oidc/sign-in/start` | `{}` | 200 authorization URL and protected transaction cookies |
| GET `/oidc/callback` | Bounded protocol query | Fixed selected bridge; no consumption/session/deletion |
| POST `/v1/oidc/sign-in/finish` | `{state,code,issuer?}` | 204 and committed session cookie |
| POST `/v1/oidc/sign-in/cancel` | `{}` | 204 denial-only cancellation and proof cleanup |

The final sign-in POST is a deliberate client action, not an automatic callback
submission. It uses the actual returned `iss` and no browser-selected connection,
redirect, owner or JIT setting. Existing provider-deletion paths and their exact
destructive confirmation remain unchanged. Scope selection is trusted composition,
never browser input; request no additional profile/contact authority by inference.

An existing consumer opting into the new common callback must explicitly update
its provider registration and administrative configuration. Preserve connection/
local-client identity keys; a different local client is not a callback workaround.
The normal administrative revision change invalidates old contexts/sessions without
reassigning account ownership. Startup must not perform that transition implicitly.
The legacy experimental constructor remains available under its original contract.

## Server delivery and maintainability

Preserve the existing `configured_auth` API. Extract cohesive configuration concerns
before extending composition. Add a shared supported application/router factory for
standalone and embedded use; main remains listener/worker/shutdown composition.
Validate settings and supported feature availability before serving. Partial,
unknown, malformed or unsupported OIDC configuration fails closed rather than being
ignored or enabling a fallback. Ordinary production transport remains strict TLS,
reviewed DNS/IP/origin policy, bounded bodies/concurrency and no redirects/proxies.

Reuse the accepted deletion implementation through a private route-composition
boundary rather than copying policy, SQL or use cases. Keep public APIs deliberate
and implementation visibility narrow. Feature tests live in named modules with
shared setup only where genuinely reusable. Structural extraction and behavior
changes are separate commits with relevant regression checks between them.

## Required verification and limits

Before activation, verify concrete OpenAPI and HTTP negatives for state/browser/
nonce/PKCE, wrong purpose/issuer/client/realm, exact callback, unknown/duplicate/
oversized inputs, Origin, confirmation, current-session transitions, cancellation,
provider error and redaction/referrer/cookie cleanup. Add real PostgreSQL startup
idempotence, concurrent initial provision, disable/mismatch/rollback and unchanged
revision tests, preserving existing one-use/final-deadline and identity race coverage.
A transaction rollback must not undo already committed independent admission or
resurrect consumed remote-exchange context.

Owned Keycloak evidence must exercise supported embedded and standalone route/
configuration composition, genuine public sign-in, local session use/logout and
provider deletion. AUTH-55's fixture-only bootstrap is not acceptable as that login
proof. Isolate any owned certificate/address arrangement in the test transport/
producer, never production settings, and state the distinction from public-root
normal-binary or production-provider evidence. Normal configuration must reject
such overrides. No seeded identity/session, invented freshness or weaker proof is
permitted. Retain all existing component/native/SMTP cases and normal cleanup.

Record fmt, strict default/all-feature lint, default/all-feature real-DB suites,
security/license/secret gates and exact final-source hosted CI. Independent review,
manual provider/device matrix, SAML, outbound issuer and broader first-release gates
remain open. This proposal and later local/fixture passes are not production
readiness, an audit, protocol certification or provider interoperability guarantees.
