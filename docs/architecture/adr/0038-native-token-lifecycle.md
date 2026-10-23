# ADR 0038: Native token lifecycle

Date: 2026-10-23. Status: in progress for AUTH-40. Stateful access revocation and
authenticated introspection are implemented. Explicit native policy persistence is
implemented, with separate explicit native consent library operations. Native signed issuance, bounded families, one-use rotation and reuse revocation
are implemented in core/PostgreSQL. Consent HTTP delivery and owned native browser
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
inventing an owner-actor audit event. Native family lifecycle uses separate typed credential-actor audit, described below.

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
delivery, with a final database clock after every write/wait. Consent approval itself emits only a short code; separate native issuance is required. The default online repository/signer cannot
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

## Native family library

Migration0035 preserves online credentials and approved native consent. It adds
hash-only refresh generations, an exact full-tuple consent/source/owner-bound family,
native access generations and closed credential-actor audit references. Schema must
be applied before serving requests on fresh connections. A database erasure trigger
clears new references when the unchanged feature-independent account erasure SQL
sets subject_erased; it only removes identifying facts.

`IssuerNativeTokenIssuer` shares the existing concrete RS256 engine and capacity
with `IssuerTokenIssuer`. Only its opaque staged proof reaches native completion.
Preparation and completion each recheck actual current client authentication, exact
enabled native policy, signing namespace/key, original source/owner/fresh session,
approved code and immutable consent snapshots. Initial ID/access expiry retains the
original short code/freshness/key caps; the family retains the separate original
proposed offline expiry. Code consumption, family, generation0 hashes/access and
both code/credential audits commit atomically before credentials leave core.
Maximum active families is10 per realm/issuer/owner/client, checked under owner lock.

`IssuerNativeRefresh` authenticates the current matching native client and exact
credential possession. Active rotation locks current saved policy/key namespace,
original provider source, optional mailbox, owner, original session, family and
refresh generation. Original account method/authentication time, current source
policy, session revocation and original source/session absolute expiry remain
mandatory. This explicit offline grant uses its own idle bound rather than cookie
idle/five-minute freshness, and never updates cookie timestamps or auth_time.
Actual revoke-all prevents further refresh. Native access is at most300seconds,
capped by current key, new idle and original absolute expiry. Refresh returns only
opaque access/refresh credentials; it creates no ID token or local session.

One transaction spends the old hash, increments generation, inserts new hashes,
rolls idle within the original absolute cap and records typed refresh-actor audit.
The final database clock follows all writes/waits and checks the pre-rotation idle
deadline as well as new credential deadlines. No grace/retry window exists. Reusing
any retained spent hash commits permanent family/all-descendant access revocation
before reporting invalid_grant. Generation10000 exhausts this family and requires
fresh explicit consent. Old hashes remain for detection, bounded per family.

Possession of any matching family refresh/access credential can permanently revoke
the whole family, including after policy/source/session disable. Reduction still
requires actual current matching client authentication and exact scoped rows; it
never invents owner authentication. Owner serialization precedes family locks so
audit foreign keys do not invert erasure order. Unknown/repeated revoke succeeds
indistinguishably and cannot alter a previous revocation timestamp. Audit failure
rolls back the mutation and returns unavailable; no revoked/granted success is
claimed. Typed events distinguish code, refresh and access actors without fabricating
a local actor session. Public native client IDs remain insufficient for introspection.

## Remaining full-ticket work

Actual owner-confirmation HTTP/UI, native token/refresh/revocation transport,
secure platform storage integration and owned system-browser/PKCE acceptance remain
required. Library tests and prompt input do not prove human confirmation or native
client interoperability. Default HTTP/startup/discovery remain unchanged. Source
OIDC/SAML lifecycle acceptance of this new delegation boundary remains to be added;
existing source checks are reused and cannot be relaxed to obtain coverage.

No independent audit, external interoperability certification, production readiness
or normal outbound activation follows. Production operations remain supervised.
ADR0032's SAML independent-review prerequisite was waived, not performed; every
existing SAML protocol/trust/lifecycle check remains required. No new adversarial
XML/cryptographic producer or custom signature-concurrency experiment is authorized.
