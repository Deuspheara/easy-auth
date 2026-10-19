# Domain model

A realm is an authentication security partition; it is not a workspace/business organization. A registered client belongs to a realm and has exact redirects, origin policy and audience. The first slice binds one realm per server/router in trusted configuration; no request body may select it.

User has an opaque random UUID, realm, optional verified email, optional display label and an explicit authentication policy. Migration 0009 preserves existing mailbox identities and allows email-free passkey-required users; see the [optional-mailbox guide](../guides/optional-mailbox.md). A label never identifies or authorizes an account. Email policy initially supports a conservative ASCII mailbox and canonicalizes case consistently; no plus/dot rewriting. This product policy can conflate case-sensitive local parts and must be explicit. Email change now requires a fresh session and separate confirmation of both current and proposed mailboxes, preserves the user ID and revokes sessions. Planned ExternalIdentity records are unique by (realm, connection, trusted issuer, subject); matching emails must never merge users. Planned linking must prove the current fresh session and a new provider transaction. Unlinking must preserve a usable credential/recovery path. Merges are disabled until separately reviewed.

Password credentials now store a salted Argon2id PHC string under a realm/user composite key, with single-enrollment uniqueness. Enrollment requires a fresh verified session and replaces existing sessions atomically. Credentials (password, passkey) are distinct from provider accounts and user records. The optional passkey enrollment boundary stores RP-scoped credential/public-key state, counter/backup state, last-use metadata and a user label; ordinary activation and credential management remain unfinished. Planned discoverable enrollment must provision a passkey-first user under a reviewed enrollment transaction. Recovery cannot silently replace stronger assurance with email; explicit policy, delays/notifications and audit required.

AuthenticationTransaction carries realm/client/connection revision, purpose,
browser binding, state/nonce/PKCE verifiers and original expiry. The optional
AUTH-22 boundary atomically consumes state before provider exchange without
creating an identity/session. AUTH-29 implements the optional backend code/S256
exchange and signature/claim verifier, returning only opaque transaction-bound
verified identity proof. Its owned Keycloak/browser/PostgreSQL acceptance is
recorded in [ADR 0015](adr/0015-oidc-token-verification.md); no ordinary provider
callback, identity/JIT persistence or local session grant is implemented.
See [ADR 0013](adr/0013-oauth-state-transactions.md) for original authority binding
and mandatory final revalidation. Future identity/session persistence must consume
the proof and recheck configuration, original caps and linking authority under locks.

VerificationChallenge holds only token/browser verifiers, email/purpose and expiry. Email proof consumption commits atomically with user/session creation; a failed session insert rolls back that consumption. Password-reset proofs use a separate table/cookie and bind the current credential version; consumption, password/version update, session/proof invalidation, audit and non-secret notification enqueue commit atomically. Delivery claims are leased and realm scoped. Parallel consumption yields one winner. PostgreSQL constraints include realm in all identity relations.

Session holds a public opaque ID, user+realm composite FK, SHA-256 verifier of a random 256-bit secret, created/last-seen/absolute expiry and revocation state. Browser receives the secret only in HttpOnly cookie. Lookup validates idle and absolute limits in the same database operation. Revocation takes effect on the next database validation; already-authorized in-flight operations can complete. Sensitive operations use separate authenticated_at provenance; rotation does not reset it. Legacy sessions require fresh sign-in after migration 0004. Application-specific transaction semantics remain the consumer’s responsibility. Active inventory exposes only owned public UUID/time metadata through bounded cursor pages. Fresh-authenticated individual/all-session revocation is implemented; revoke-all serializes with session issuance and cancels outstanding proofs. See [session guide](../guides/sessions.md).

Refresh/token families are separate future native/OAuth entities: short access lifetimes, atomic refresh rotation, family replay detection and OS secure storage. JWT expiration is not revocation. SigningKey records public metadata and protected key reference; never put plaintext private keys into logs/config dumps. AuditEvent is a closed set of committed lifecycle facts with bounded kinds and opaque user/actor/affected-session references. Version 1 shapes and composite foreign keys enforce ownership; there is no arbitrary payload, token, verifier or email field. Deletion clears every subject/session reference. Historical version 0 attribution remains explicitly unknown. See the [audit guide](../guides/audit-events.md).

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

Planned entities are not implemented tables until their milestone. Account deletion now transactionally removes implemented credentials/sessions/proofs and deidentifies live audit subjects; future external identities must join this same lifecycle. A subject-free deletion notice temporarily retains the established recipient for delivery.

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
contact or linking grant. Final identity/session persistence is still unimplemented
and must recheck this authority under locks.
