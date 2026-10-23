# ADR 0038: Native token lifecycle

Date: 2026-10-23. Status: in progress for AUTH-40. Stateful access revocation and
authenticated introspection are implemented; full verification is running. Native
refresh consent/families, reuse detection, storage guidance and owned native browser
acceptance remain work. This increment alone does not complete AUTH-40 or M07.

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

## Remaining full-ticket work

Long-lived refresh authority cannot be obtained by extending the old code/freshness
cap or treating an existing openid-only approval as offline consent. The native
increment still needs explicit trusted policy and owner-reviewed consent, a distinct
bounded original grant, hash-only one-use rotation with reuse-detected family
revocation, current source/owner/client and revoke-all lifecycle checks, original
absolute/idle caps, typed audit and real PostgreSQL race/rollback/isolation evidence.
Secure client storage and actual owned system-browser/PKCE delivery remain required.
These are pending design/implementation decisions, not implied by current access APIs.

No independent audit, external interoperability certification, production readiness
or normal outbound activation follows. Production operations remain supervised.
ADR0032's SAML independent-review prerequisite was waived, not performed; every
existing SAML protocol/trust/lifecycle check remains required. No new adversarial
XML/cryptographic producer or custom signature-concurrency experiment is authorized.
