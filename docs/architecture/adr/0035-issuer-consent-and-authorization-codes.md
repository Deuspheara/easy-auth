# ADR 0035: Explicit issuer consent and one-time authorization codes

Date: 2026-10-23. Status: accepted optional crate implementation; HTTP/token
issuance, signing and interoperability acceptance remain open.

## Policy and authority

Add `issuer-codes` to core/PostgreSQL, extending the existing issuer registration
feature. Inbound federation, local sessions and application authorization remain
separate. A trusted `IssuerAuthority` selects one stable HTTPS issuer and realm;
wire input cannot select an owner or source policy. The initial profile accepts
exactly `response_type=code`, `scope=openid`, nonempty bounded state and nonce,
and S256 for every public/confidential client. Unsupported scopes are refused,
never silently reduced. PKCE accepts the complete RFC7636 43–128 ASCII unreserved
verifier range and uses existing SHA-256/base64 dependencies.

Preparation requires the actual fresh local session, including current originating
OIDC/SAML policy when applicable. It persists no code or subject and grants no
local authority. Explicit approval requires that exact initiating owner/session,
private browser/handle digests and the public UUID of the preview being confirmed.
The selector prevents an old consent tab approving a newer cookie-selected request;
it is not itself a credential. Cancellation requires the same proofs and emits
only `access_denied`. A future HTTP adapter must enforce these bindings through
Origin-bound POSTs and private cookies, never GET auto-consent or request owner IDs.

Approved codes use existing random canonical `Secret` values; PostgreSQL stores
only the verifier. Bind each code to issuer/realm, complete current client revision,
actual exact redirect (including a native loopback port), S256 digest, nonce,
initiating session and its actual method/authentication time. Emit `iss` alongside
state/code or denial, preserving original callback spelling and fixed queries.
Reserved response query names cannot collide with pre-registered query members.
No bearer, owner identifier, upstream assertion or provider subject is returned as
an outbound subject: approval allocates the existing random sector mapping.

## Transaction and lifetime decision

Preparation orders realm admission, current client, provider source, optional
mailbox, owner, session, then that owner's operation rows. Approval/cancellation
and redemption order current client, originating source, optional mailbox, owner,
session and operation. Snapshot reads only select this order; full current policy
is checked again under locks. No new authentication rule is copied from source
adapters and no cryptographic verification runs under database locks.

Pending consent lasts at most300seconds; codes last at most60seconds and never
outlive the original consent, original session/freshness/idle cap or current session
cap. Actual signed authentication time is retained; new issuance never invents
freshness. A final database-clock statement after all subject/state/audit writes
rejects expired transactions with complete rollback. Changing a persisted original
snapshot while a request waits also rejects. There is no replay restoration.

Registered client authentication is checked inside redemption while holding the
full current definition lock, even for unknown codes or wrong redirects. Public
identification does not authenticate an app; PKCE and one-use code ownership remain
required. Confidential wrong/missing credentials yield `InvalidClient`; wrong code,
PKCE/URI, source/session or consumed state yield `InvalidGrant`. Storage failures
remain `Unavailable`, admission refusal `RateLimited`. Do not infer an HTTP status
or endpoint from the crate's finite error enum.

Source abuse admission commits independently before client lookup:30attempts per
60second fixed database window and at most1024source keys per realm/window. It is
not authentication authority. Pending plus approved live operations are limited to
3per owner and256per realm; cancellation/consumption frees capacity. Preparation
cleans only its own expired records while holding that owner, avoiding cross-owner
lock inversions. Successful/expired code tombstones retain digests for replay/audit
attribution; no automated long-term retention claim is made here.

## Storage and remaining work

Migration0029 creates separate outbound operation/admission tables, exact composite
owner/session/sector-subject constraints and typed audit attribution. Consumption
scrubs nonce/state/PKCE. Confirmed account erasure deidentifies issuer audit metadata
before cascading local operation/subject state; other realms remain untouched.
Historical fixtures use version-pinned original audit columns, not current writers
against old schema. Published migrations remain immutable.

The opaque committed result carries internal owner/session IDs, pairwise subject,
nonce, actual authentication method/time and original caps. It has no public
constructor, Clone, serialization or raw credential fields; Debug is redacted and
nonce is cleared on drop. It is a code-redemption component result, **not an ID or
access token**. AUTH-39 must supply reviewed signing, audience/issuer/key policy and
final issuance semantics; HTTP consent/token handling, discovery, refresh/native
families and real interoperability remain required. No unsigned token fallback,
normal issuer activation, independent audit or production approval is implied.
