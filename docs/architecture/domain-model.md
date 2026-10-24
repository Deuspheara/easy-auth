# Domain model

A realm is an authentication security partition; it is not a workspace/business organization. A registered client belongs to a realm and has exact redirects, origin policy and audience. The first slice binds one realm per server/router in trusted configuration; no request body may select it.

User has an opaque random UUID, realm, optional verified email, optional display label and an explicit authentication policy. Migration 0009 preserves existing mailbox identities and allows email-free passkey-required users; see the [optional-mailbox guide](../guides/optional-mailbox.md). A label never identifies or authorizes an account. Email policy initially supports a conservative ASCII mailbox and canonicalizes case consistently; no plus/dot rewriting. This product policy can conflate case-sensitive local parts and must be explicit. Email change now requires a fresh session and separate confirmation of both current and proposed mailboxes, preserves the user ID and revokes sessions. Optional OIDC identity records are unique by (realm, connection, local client, exact issuer, subject), with bytewise issuer/subject equality; matching emails never merge users. Provider-only JIT users have null contact and explicit provider_required policy, with source/revision-bound oidc sessions and optional original provider authentication time. Planned linking must prove the current fresh session and a new provider transaction. Unlinking must preserve a usable credential/recovery path. Merges are disabled until separately reviewed.

Password credentials now store a salted Argon2id PHC string under a realm/user composite key, with single-enrollment uniqueness. Enrollment requires a fresh verified session and replaces existing sessions atomically. Credentials (password, passkey) are distinct from provider accounts and user records. The optional passkey enrollment boundary stores RP-scoped credential/public-key state, counter/backup state, last-use metadata and a user label; ordinary activation and credential management remain unfinished. Planned discoverable enrollment must provision a passkey-first user under a reviewed enrollment transaction. Recovery cannot silently replace stronger assurance with email; explicit policy, delays/notifications and audit required.

AuthenticationTransaction carries realm/client/connection revision, purpose,
browser binding, state/nonce/PKCE verifiers and original expiry. The optional
AUTH-22 boundary atomically consumes state before provider exchange without
creating an identity/session. AUTH-29 implements the optional backend code/S256
exchange and signature/claim verifier, returning only opaque transaction-bound
verified identity proof. Its owned Keycloak/browser/PostgreSQL acceptance is
recorded in [ADR 0015](adr/0015-oidc-token-verification.md); no ordinary provider
callback is enabled. AUTH-30's optional final transaction now resolves/provisions
identity and source-bound session/audit under current configuration/policy and
original caps; ordinary activation and provider acceptance remain gated.
See [ADR 0013](adr/0013-oauth-state-transactions.md) for original authority binding
and mandatory final revalidation. Final sign-in persistence consumes the proof and
rechecks configuration, full mapping/JIT policy and original caps under locks.
Linking-purpose proofs reject until AUTH-25 implements that separate boundary.
AUTH-55 adds a distinct deletion-purpose preparation bound to an active original
provider-required owner/session and exact source revision. It cannot become sign-in
or linking authority and does not refresh authentication time. The purpose's state
is one-use and capped by the original active session. The optional final deletion
use case now rechecks the exact existing subject/source, genuine signed freshness
and all original caps before shared atomic erasure, audit deidentification and a
notice only for stored verified contact. Its HTTP composition remains unimplemented;
[ADR 0017](adr/0017-provider-account-deletion.md) records both boundaries.

VerificationChallenge holds only token/browser verifiers, email/purpose and expiry. Email proof consumption commits atomically with user/session creation; a failed session insert rolls back that consumption. Password-reset proofs use a separate table/cookie and bind the current credential version; consumption, password/version update, session/proof invalidation, audit and non-secret notification enqueue commit atomically. Delivery claims are leased and realm scoped. Parallel consumption yields one winner. PostgreSQL constraints include realm in all identity relations.

Session holds a public opaque ID, user+realm composite FK, SHA-256 verifier of a random 256-bit secret, created/last-seen/absolute expiry and revocation state. Browser receives the secret only in HttpOnly cookie. Lookup validates idle and absolute limits in the same database operation. Revocation takes effect on the next database validation; already-authorized in-flight operations can complete. Sensitive operations use separate authenticated_at provenance; rotation does not reset it. Legacy sessions require fresh sign-in after migration 0004. Application-specific transaction semantics remain the consumer’s responsibility. Active inventory exposes only owned public UUID/time metadata through bounded cursor pages. Fresh-authenticated individual/all-session revocation is implemented; revoke-all serializes with session issuance and cancels outstanding proofs. See [session guide](../guides/sessions.md).

Native refresh/token families are separate optional issuer entities: short access lifetimes, atomic refresh rotation, family replay detection and OS secure storage. JWT expiration is not revocation. SigningKey records public metadata and protected key reference; never put plaintext private keys into logs/config dumps. AuditEvent is a closed set of committed lifecycle facts with bounded kinds and opaque user/actor/affected-session references. Version 1 shapes and composite foreign keys enforce ownership; there is no arbitrary payload, token, verifier or email field. Deletion clears every subject/session reference. Historical version 0 attribution remains explicitly unknown. See the [audit guide](../guides/audit-events.md).

The optional passkey boundary persists RP-scoped verified credential state and
short-lived enrollment and authentication transactions. Experimental HTTP enrollment
is available; optional core/PostgreSQL sign-in now atomically consumes browser-bound
proof state, updates the credential and last-use time, issues an owned session and
audits authentication. See the [enrollment guide](../guides/passkey-enrollment.md)
and [authentication review](../research/passkey-authentication.md). Experimental HTTP sign-in now covers account-bound and modal resident discovery,
with an opaque owner hint and no email-to-credential resolver. Stronger-account
policy, passkey-first enrollment and the remaining M03 work keep ordinary
composition gated.

Migration 0008 records session authentication method separately from time: email,
password, passkey or legacy_unknown. Existing sessions retain unknown method;
password enrollment preserves the initiating method and time during rotation.
Freshness alone does not establish passkey proof. Method metadata is internal. Migration 0009's passkey-required policy now rejects
weaker sessions and mailbox/password fallback, with fresh-method enforcement for
session controls and additional enrollment. Full stronger-account recovery and
lifecycle operations remain required before ordinary activation. No MFA/AAL
certification is inferred.

Planned entities are not implemented tables until their milestone. Account deletion now transactionally removes implemented credentials/sessions/proofs and deidentifies live audit subjects; implemented OIDC identities and source-bound sessions cascade with deletion, with a scoped five-minute subject cooldown preventing old anonymous callbacks from re-provisioning. Provider-only public deletion remains a separate lifecycle gate. A subject-free deletion notice temporarily retains the established recipient for delivery.

AUTH-53's accepted [email-free identity design](adr/0009-passkey-first-identity.md)
separates optional verified contact information from account authentication policy.
The optional-email model, migration 0009, nullable public contract and initial
passkey-required policy gates are implemented. Migration 0010 adds pending-only
registration/assertion signup in core/PostgreSQL: only verified assertion completion
creates the user/key/session and typed signup audit, with final expiry checking
after all writes. [Experimental HTTP/native signup](../guides/passkey-signup.md)
now verifies anonymous platform/roaming enrollment, assertion and later account-bound/
discoverable login. Migration 0011 adds one pending contact attachment per owner,
bound to the initiating session, realm and independent browser proof. Verified
completion preserves UUID, stronger policy and authentication provenance, with
transactional session/proof invalidation and a typed audit fact. Native platform/USB
signup-to-SMTP confirmation and later passkey login now have separate evidence. AUTH-20 still owns full stronger-account
management and recovery closure.


Optional saved-code configuration uses one `auth_passkey_recovery_codes` row per
realm/owner/RP, containing only a verifier and version, plus one expiring
`auth_passkey_recovery_setups` row bound to the exact initiating owned session.
Preparation preserves an existing active verifier; confirmation consumes pending
state and replaces the active version atomically with actor-owned audit and a
non-secret verified-contact notice. User deletion cascades both tables. Neither
record is an ordinary authentication session, new key or policy upgrade; recovery
claim consumption and experimental replacement completion use separate state. See [ADR 0012](adr/0012-saved-passkey-recovery.md).


`auth_passkey_recovery_claims` holds one claim per realm/owner/RP: code generation,
browser verifier, original creation/expiry/delay, notification requirement/receipt,
not-before time and cancellation. Starting consumes the configured code for new
claims. Same-browser resume does not extend it; reserved-code cancellation can only
deny it. A start notice has a composite-owned claim reference and is removed on
claim invalidation. Current leased SMTP acceptance records the first receipt before
starting contact-based delay; stale/failed/late acknowledgements cannot revive state.
Public metadata is not authentication. Account erasure removes claim/code state and
known owned abuse buckets and clears the public historical claim target in audit.


Migration 0015 adds `completed_at` to claims and private
`auth_passkey_recovery_replacements` rows, composite-owned by claim/user/realm.
One row per claim moves from registration state to candidate/assertion state with
closed stage constraints and a two-minute expiry. Candidate bytes never enter
ordinary credential lookup until a genuine assertion commits. Completion revokes
old owner keys/sessions/proofs, consumes the claim and records an owned issued
session/claim-target audit fact atomically. Cancel/rotation/deletion remove private
state. No raw code/browser/session secret is persisted, and policy is unchanged.

AUTH-28's optional `OidcDocuments` binds two in-memory cache slots to one immutable
persisted realm/connection/client/revision and an explicit HTTPS origin policy.
`OidcDiscovery` carries validated endpoint metadata; `OidcJwksDocument` contains a
bounded public-key JSON envelope with redacted Debug and an explicit byte accessor.
Neither is a verified external identity, key, token or session proof. Configuration
is rechecked before reuse/fetch and after network validation. No document table or
new migration is introduced; published migrations 0001–0016 remain unchanged.

AUTH-29's optional `VerifiedOidcIdentity` is created only after a consumed
`OAuthExchange`, real signature verification, mandatory typed claims and final
configuration/session/deadline rechecks. It retains exact connection/purpose/subject
and a commit cap no later than the original OAuth deadline, ID-token expiry or
original token-age window. It retains no nonce/PKCE/raw token and has no public
constructor, Clone or Serialize. Issuance time and optional provider authentication
time remain distinct; email verification is a provider attribute, never a local
contact or linking grant. AUTH-30's final identity/session transaction consumes a
mapped proof, checks current exact policy and original caps under locks, and commits
provider-only ownership/session/audit atomically. Display metadata is required only
for a new owner and never changes stored presentation on repeat login. See
[ADR 0016](adr/0016-oidc-identity-mapping.md).

The experimental provider-deletion HTTP adapter derives owner/session from Auth,
retains independent browser/state/nonce/PKCE proof in host-only HttpOnly cookies,
and requires explicit confirmation at initiation and completion. Its callback GET
serves static content only. These transport values confer no identity, freshness
or erasure authority outside the existing verified core/PostgreSQL transaction.
Owned Keycloak-to-HTTP acceptance is recorded separately; ordinary activation
remains gated.


AUTH-56's startup load/initial-provision operation preserves an unchanged enabled
connection/policy revision and all existing pending/session/audit state. Only an
absent registry key can atomically acquire a new policy, always at a fresh revision;
existing generic/stale/disabled records cannot gain authority through loading.
The restored core policy value is definition metadata only. Actual proof, identity
and session authority retain their existing signature, current-source and deadline
checks. Administrative reconfiguration remains a distinct revision-changing action.

AUTH-56's optional browser delivery reuses those same entities and ports: independent
host-only HttpOnly proof cookies per sign-in/deletion purpose, exact common callback
UI routing, deliberate local completion, and session cookies only after the original
core/PG commit. No browser DTO selects an issuer/realm/local client/owner/JIT policy,
and no callback GET creates authority. Trusted settings and protected credential files
compose the existing services in both modes. Actual public-flow evidence preserves
pending proof and a committed owner/session across factory restarts without revision
rotation. Provider-contact attachment, linking, native refresh families and application
business authorization remain separate domains and release work.

AUTH-23's `OAuthRedirect` is validated configuration metadata, not a credential,
proof or new table. Its explicit desktop-loopback constructor keeps the concrete
literal address/port/path in the existing connection's exact redirect string.
Configuration values have no deserialization or arbitrary field mutation API;
`reconfigured` copies their validated definition with a fresh revision. PostgreSQL
retains global redirect uniqueness, realm/client scope and current-policy locking.
The existing HTTPS constructor and web configuration retain their restrictions.

The optional `GoogleCodeExchange` composes that same configuration and consumed
sign-in context into the existing `VerifiedOidcIdentity`; it defines no alternative
identity, contact, session, token or persistence entity. Fixed provider policy grants
no authority by itself. Email attributes remain distinct from verified local contact,
and linking/provider-deletion purposes cannot use this sign-in-only component.


The opt-in SAML verifier returns an opaque `VerifiedSamlAssertion`, distinct from
consumed request state, local user/provider identity and local session authority.
It retains exact registration revision, persistent subject, actual signed authn
time, original/signed/certificate caps, selected approved pin and authenticated
response/Assertion replay hashes. Replay records are staged, not committed; the
durable ledger and identity/session transaction in the separate identity component remain realm-scoped,
recheck current source and retain replay uniqueness across configuration rotation.
Raw XML, public email claims and mere signature success cannot select a local owner.


`SamlIdentityPolicy` and `SamlMappedIdentity` separate trusted default-deny JIT
configuration, real signature evidence and local identity authority. The
persistent subject's owning namespace includes both configured IdP and SP entities
in addition to realm/connection/client. Presentation is optional metadata; it cannot
select ownership, local contact, roles or fallback credentials. Mapping and stored
policy create no local identities, replay admission, sessions or audit facts.


`SamlSignIn` consumes a mapped proof exactly once through a current-policy final
transaction. Migration 0024 separates exact SAML identity ownership, hash-only
response/Assertion replay, hash-only deleted-subject cooldown and session source
provenance. The signed session limit is distinct from admission expiry. Sessions
retain actual authentication time and source revision; current source policy is
required for authentication/inventory/fresh revocation. The typed
`SamlAuthenticated` audit fact has only committed user/session references.
[ADR 0023](adr/0023-saml-identity-session-commit.md) records lock order and limits.

## Gated outbound client metadata

Separate optional `IssuerClientRegistration` describes trusted HTTPS web clients,
realm/client/revision, exact redirects, hostname sector and public versus
client_secret_basic verifier configuration. It does not represent an inbound
provider or authenticated client. Additive migration0027 persists closed explicit-
consent/pairwise policy plus realm-scoped random sector/owner subjects. A metadata
mapping grants no consent, session or token authority; account erasure cascades it.
[ADR0026](adr/0026-outbound-client-registration.md) and the
[component guide](../guides/issuer-clients.md) describe limits. M07 remains gated.

`IssuerRedirectProfile` distinguishes unchanged exact HTTPS web metadata from
explicit public native loopback metadata. Native sector identifiers are isolated
per realm/client, not shared by local IP, and request-specific ports do not mutate
registration. Migration0028 defaults old clients to `web_exact` and closes native
rows to public authentication and their own sector. `IssuerClientAuthentication`
is request data, not a proof: its Basic constructor hashes a canonical Secret,
while current method/credential/configuration checks stay atomic in PostgreSQL.
No consent, code, token or user authority follows. See
[ADR0034](adr/0034-issuer-native-registration-and-authentication.md).


`SamlAttribute` is optional verified provider data inside the opaque SAML proof,
with exact scalar Name/NameFormat/value records, bounded by input/XML limits,
zeroizing strings and redacted Debug. Absent and empty format, duplicate names,
record/value order and empty values remain distinct. No database contact,
identity key, role or permission is inferred from it. NameID and full trusted
registration remain ownership authority. AuthnInstant is the established event,
not new Response/Assertion issuance; stored sessions and deletion freshness use
that original signed time. [ADR 0028](adr/0028-saml-attribute-and-authentication-facts.md)
records these gated contracts and the unchanged verifier/clock boundary.

The optional outbound issuer authorization has a distinct realm/issuer/client
revision, exact actual callback, private browser/handle hashes, S256 challenge,
nonce/state and initiating source-aware owner/session. Explicit approval allocates
the existing pairwise sector subject and one short-lived hash-only code; one atomic
redemption scrubs correlation data. Original authentication time and all original/
current caps remain authoritative through the final transaction write. These are
not inbound identities, local sessions, application permissions or signed tokens.
Typed issuer audit references bind the exact client/operation/owner/session tuple;
confirmed owner erasure deidentifies them before cascading operation/subject rows.
See [ADR0035](adr/0035-issuer-consent-and-authorization-codes.md).

Read-only issuer consent recovery returns only the original public preview UUID,
client, actual return URI and expiry after the same fresh current source/owner/
session checks. It allocates no subject/code and never extends the operation.
The HTTP operation cookie is a selector, not an owner or authorization proof;
explicit decisions must also match the displayed preview UUID and both private
proofs. Local session replacement clears transport state without claiming to undo
an already committed code decision. See [ADR0036](adr/0036-issuer-https-consent-delivery.md).

Optional signed issuance adds a distinct realm/issuer public-key registry with full
revision, explicit active selection, publication/sign/verification windows and
operator disable. Private operator keys have no persistence/public projection.
`IssuerSigningSnapshot` is configuration data; only the concrete signer constructs
the opaque staged `IssuerSignedCode`. Final current-policy/code/owner checks commit
the ledger before wire credentials exist. Migration0031 binds hash-only access rows
to the full authorization/client/owner/session/pairwise-subject tuple and public key;
owner erasure cascades these rows. Access credentials and ID tokens are neither
local sessions nor application permissions. Original authentication time and all
earliest original caps survive signing. See [ADR0037](adr/0037-issuer-signing-and-final-issuance.md).

Optional `IssuerTokenManagement` inspects/revokes the existing access ledger without
creating a local session or extending any grant. `IssuerPresentedToken` retains only
the existing SHA-256 credential verifier for bounded opaque input. An active result
projects only the consuming confidential client's pairwise/issuer/audience/time
metadata after current source/owner/session/key/client and original-cap checks.
Migration0032 adds permanent nullable access revoked_at_us; repeated/foreign/unknown
revocation cannot restore or widen authority. Public possession can reduce only its
matching credential, but does not authenticate an introspection consumer. Refresh
families/delegation use separate optional authority described in
[ADR0038](adr/0038-native-token-lifecycle.md).

Optional `IssuerNativeRefreshPolicy` is trusted configuration only: exact authority,
full offline-capable native client, independent revision and bounded absolute/idle
seconds. Migration0033 creates initially disabled realm/issuer/client policy rows
and a distinct native profile; older loaders refuse that profile. Full locked
definition checks and revision changes preserve disable and reject stale policy.
An eventual original consent grant is capped by its captured source/session
absolute expiry; configuration cannot create consent, refresh authority or extend
cookie freshness/idle. Native confirmation transport and family library are separate implemented components;
bounded owned native browser/wire acceptance is implemented by the explicit native
composition. SDK/standalone and production acceptance remain separate.

Migration0034 adds a native marker on new explicit operations and a full-tuple
proposed-consent sidecar: original policy/client revisions, preparation time,
source/session absolute cap, fixed grant expiry and idle bound. Actual approval
time is separate and matches the original code approval audit. No historical online
authorization is upgraded. `IssuerNativeAuthorization` validates an explicit
offline request and safe display metadata; its opaque Start has no public proof
constructor. Core/SQL default online paths still refuse native operations. Consent
approval creates no refresh family, local session or extended access credential;
confirmation HTTP/UI is a separate optional transport; the family lifecycle is
described below. The separate explicit native wire component includes bounded owned
browser/real-loopback acceptance.

## Native refresh family

A distinct native family retains the exact approved
realm/issuer/client/revision/policy/owner/original-session/subject tuple, original
method/authentication time, immutable proposed/source absolute cap, bounded rolling
idle and generation. Only hashes of one-use refresh credentials persist; spent
generations remain replay detectors. Native access generations remain separate from
LocalSession. Typed code/refresh/access actor facts carry no fabricated actor-session
authentication. Erasure deidentifies audit before cascades; credential reduction
cannot restore authority. See ADR0038.

## Native audience consumers

`IssuerNativeConsumerPolicy` is trusted operator configuration binding exact
current confidential Basic consumer and distinct public native audience definitions
under one realm/issuer. Its independent revision and disabled initial persistence
create no consent or authentication. Disable/reconfiguration invalidates stale
snapshots; explicit enable requires both current clients and the saved policy.
Migration0036 stores configuration only and preserves previous credentials.

`IssuerNativeIntrospection` combines actual consumer authentication with that exact
permission, current native/source/owner/session/family/generation/key and final
lifetime checks. `IssuerNativeAccessData` is repository input;
`IssuerNativeActiveAccess` is sealed validated pairwise metadata, without local
owner/session/raw credential projection. Its audience remains the native client,
separate from the authenticated consumer. No cookie, local session, authentication
time or application permission is created. Optional transport is described in
[ADR0039](adr/0039-native-introspection-consumers.md).
