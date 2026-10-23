# ADR 0038: Native token lifecycle

Date: 2026-10-23. Status: in progress for AUTH-40. Stateful access revocation and
authenticated introspection are implemented. Explicit native policy persistence is
implemented, with separate explicit native consent library operations. Refresh
families, reuse detection, consent HTTP delivery and owned native browser
acceptance remain work. These increments alone do not complete AUTH-40 or M07.

## Existing access authority

Keep the published signed code flow and its original60second code/session/freshness/
key bounds unchanged. `issuer-token-management` extends the existing core/PostgreSQL
issuer modules with status/revocation operations, not a new session or business-role
credential. No new cryptographic primitive/dependency or arbitrary bearer authority
is introduced. A presented opaque token is bounded ASCII, immediately hashed using
the existing Secret SHA-256 representation, and retains no raw text. Unknown valid
opaque formats are not required to parse as a newly minted canonical Secret.

Introspection authenticates the current exact enabled confidential client, including
the actual Basic credential, before returning any active/inactive result. Public
client_id, a local cookie or a known token cannot authenticate an introspection
consumer. This initial profile permits only that client's own audience; separate
resource-server delegation is not inferred. Unknown/foreign/revoked/inactive tokens
return no claims. Authentication/infrastructure failures remain finite errors.

The snapshot selects lock order only. After current client authentication, lock
the exact enabled retained public key/namespace, original provider source, optional
email, owner, session, access row and original code. Recheck current source/account/
session policy, original method/authentication time, current client revision, consumed
grant and all original consent/code/session caps. Ordinary active-key rotation keeps
an unexpired token valid under its retained key; key disable or unpropagated reenable
does not. Current global issuance disable suspends introspection, without removing
retained public JWKS. The final SQL clock follows all waits. Inspection never touches
the session's idle timestamp or extends token/grant time.

Only pairwise subject, configured issuer/client audience, issued/expiry timestamps,
Bearer type and openid scope may leave an active result. No local owner/session,
nonce, token hash, raw credential, email, role or upstream identity is projected.
This is metadata for an authenticated consumer, not a local authentication proof.

## Revocation

Migration0032 adds a nullable durable access-revocation timestamp. Published
migrations0029–0031 remain immutable. Public clients may revoke by possessing the
exact access credential and matching current public registration; confidential
clients also require their actual current Basic credential. Every query is bound
to the exact realm/issuer/client. Unknown/foreign/already-revoked tokens succeed
indistinguishably. Revocation cannot clear/rewrite an earlier timestamp, change the
original code, revoke a local cookie, or restore authority after configuration changes.

No owner/source locks are needed to reduce only that credential's authority; this
allows explicit cleanup after logout/source expiry. The current client lock precedes
the access update. Introspection taking an access share lock linearizes against a
competing revocation update; a committed revoke observed after a wait cannot return
active metadata. Existing ledger timestamps record this access revocation, without
inventing an owner-actor audit event. Typed refresh-family lifecycle audit remains
part of the later family implementation.

Local revocation cannot remotely erase already issued self-contained ID tokens,
cached public keys or downstream app sessions. Their original short expiry and
consumer session policy remain necessary; no immediate offline JWT revocation or
sign-out propagation is claimed.

## HTTP boundary

The explicit `issuer-token-management-web` router extends the existing HTTPS issuer
composition with POST `/oidc/introspect` and `/oidc/revoke`. It requires identical
trusted authority and actual socket ConnectInfo, reusing the token-client boundary:
no ambient-cookie/Origin authentication, no forwarded-header source selection and
no-store/no-cache/sanitized responses. Local cookie routes retain Origin enforcement.
Strict shared form decoding rejects malformed percent/UTF-8, decoded duplicate names,
unknown fields, queries and encoded/non-form bodies. Status forms are bounded to4KiB;
presented tokens to1024ASCII bytes. The optional token_type_hint is non-authoritative
and ignored by this access-only profile. OpenAPI describes active and inactive
envelopes separately; inactive output contains only active=false. Revocation200 has
an empty body. Default issuer/server composition mounts none of these extra routes.

## Explicit native offline configuration

The optional core/PostgreSQL `issuer-native-refresh` feature now supplies trusted
configuration and separate explicit consent operations. `public_native_refresh_loopback` has a distinct persisted
`native_refresh_loopback` profile: identical literal-interface/path/variable-port
and per-client pairwise-sector rules, but older/feature-disabled loaders reject it
instead of interpreting future offline consent as an older online profile.
Existing web/native profiles, registrations and revisions are unchanged.
The configuration-aware build also rejects this profile from existing online
request, SQL preparation/decision/redemption and core grant-validation paths.
An older online-only component must not process future offline consent merely
because it understands that client's configuration. Separate explicit native
consent/issuance operations are still required; no old guard may be removed to
make the new profile enter an online path.

`IssuerNativeRefreshPolicy` binds an exact HTTPS issuer/realm, full public native
client snapshot and independent revision. Absolute lifetime is1second–7days; idle
is1second–24hours and cannot exceed absolute lifetime. The absolute grant bound is
the earlier of original consent preparation time plus configured lifetime and the original
source/session absolute cap captured under fresh-owner locks. Invalid/overflowing
times reject; this calculation does not establish consent or extend cookie idle/
freshness. Existing code, session and access limits remain unchanged.

Migration0033 adds only the profile constraint extension and scoped configuration
table. A new policy starts disabled. Replacement allocates a fresh revision and
preserves operator disable; enable requires the exact full policy and current
enabled full client. Client replacement invalidates the old policy. All mutating/
checking policy transactions lock client before policy. Disable can reduce stale/
disabled-client policy without creating user authority. Loading is read-only and
returns configuration facts; future authority operations must recheck them under
the same ordered locks. No startup/HTTP/discovery activation, consent, token family,
refresh secret, local session or owner audit event follows from this table.

## Explicit native consent library

`IssuerNativeAuthorization` is a separate opt-in use case/port, not an extension of
the default online approval path. `IssuerNativeAuthorizationInput` requires exact
`openid offline_access` and `prompt=consent`, reusing existing actual-return,
S256/state/nonce validation. Preparation still needs the genuine fresh initiating
session and private browser binding, and uses shared bounded pending admission.

Migration0034 marks only new explicit native operations and adds an immutable
proposed-consent sidecar bound to the complete realm/issuer/client/revision/owner/
session/authorization tuple. Existing rows default to online; no historical approval
is upgraded. Under current client/policy then existing source/owner/fresh-session
locks, capture the original source/session absolute expiry and fixed proposed
grant expiry. Preview exposes only actual client/return, consent deadline,
grant expiry and idle bound, without allocating authority or sliding the proposal.

Approval rechecks current full policy/client, original fresh owner/session/method/
authentication time, pending private bindings, immutable sidecar and original caps.
Current narrowed source/session absolute expiry cannot be exceeded. Existing
subject/code allocation and typed IssuerAuthorized audit retain the actual owner
session and authorization target; the sidecar records its same approval timestamp.
The existing60second code and original fresh/consent deadlines still bound code
delivery, with a final database clock after every write/wait. No refresh credential
or long-lived access follows yet. The default online repository/signer cannot
prepare, preview, approve, cancel or redeem this new offline operation.

Native cancellation reduces only the bound pending operation, keeps existing fresh
owner/private proof rules and cascades its sidecar. Policy disable/reconfiguration
cannot prevent cancellation, but cannot approve/preview old proposals. Client
replacement invalidates old pending state. Account erasure removes native consent
alongside the original aggregate and deidentifies its existing audit facts.

Schema migration runs before serving requests on fresh database connections. The
upgrade evidence reconnects after DDL, avoiding pre-upgrade SELECT * prepared-result
reuse, and proves existing online code redemption and new native consent after
restart. No live in-place DDL/old-query concurrency guarantee is claimed.

Native consent HTTP/confirmation UI is not mounted or advertised yet. The core
approval API requires a trusted application to implement explicit owner confirmation;
an input prompt string alone is not evidence that a human reviewed a page. Actual
browser delivery and owned native acceptance remain mandatory full-ticket work.

## Remaining full-ticket work

Long-lived refresh authority cannot be obtained by extending the old code/freshness
cap or treating an existing openid-only approval as offline consent. The native
increment still needs actual owner-confirmation HTTP/browser delivery, a distinct
bounded original grant, hash-only one-use rotation with reuse-detected family
revocation, current source/owner/client and revoke-all lifecycle checks, original
absolute/idle caps, typed audit and real PostgreSQL race/rollback/isolation evidence.
Secure client storage and actual owned system-browser/PKCE delivery remain required.
Explicit policy is now implemented, but these consent/grant/family operations are
not implied by configuration or current access APIs.

No independent audit, external interoperability certification, production readiness
or normal outbound activation follows. Production operations remain supervised.
ADR0032's SAML independent-review prerequisite was waived, not performed; every
existing SAML protocol/trust/lifecycle check remains required. No new adversarial
XML/cryptographic producer or custom signature-concurrency experiment is authorized.
