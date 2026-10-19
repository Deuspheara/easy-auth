# Domain model

A realm is an authentication security partition; it is not a workspace/business organization. A registered client belongs to a realm and has exact redirects, origin policy and audience. The first slice binds one realm per server/router in trusted configuration; no request body may select it.

User has an opaque random UUID, realm, optional verified email, optional display label and an explicit authentication policy. Migration 0009 preserves existing mailbox identities and allows email-free passkey-required users; see the [optional-mailbox guide](../guides/optional-mailbox.md). A label never identifies or authorizes an account. Email policy initially supports a conservative ASCII mailbox and canonicalizes case consistently; no plus/dot rewriting. This product policy can conflate case-sensitive local parts and must be explicit. Email change now requires a fresh session and separate confirmation of both current and proposed mailboxes, preserves the user ID and revokes sessions. ExternalIdentity is unique by (realm, connection, trusted issuer, subject); matching emails never merge users. Linking proves current fresh session and a new provider transaction. Unlinking cannot remove the last usable credential/recovery path. Merges are disabled until separately reviewed.

Password credentials now store a salted Argon2id PHC string under a realm/user composite key, with single-enrollment uniqueness. Enrollment requires a fresh verified session and replaces existing sessions atomically. Credentials (password, passkey) are distinct from provider accounts and user records. The optional passkey enrollment boundary stores RP-scoped credential/public-key state, counter/backup state, last-use metadata and a user label; ordinary activation and credential management remain unfinished. Planned discoverable enrollment must provision a passkey-first user under a reviewed enrollment transaction. Recovery cannot silently replace stronger assurance with email; explicit policy, delays/notifications and audit required.

AuthenticationTransaction carries realm/client/connection, purpose, browser binding, state/nonce/PKCE verifier and expiry. VerificationChallenge holds only token/browser verifiers, email/purpose and expiry. Consume atomically in the transaction that creates the user and session. A failed session insert rolls back consumption. Password-reset proofs use a separate table/cookie and bind the current credential version; consumption, password/version update, session/proof invalidation, audit and non-secret notification enqueue commit atomically. Delivery claims are leased and realm scoped. Parallel consumption yields one winner. PostgreSQL constraints include realm in all identity relations.

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
consumption is not implemented. See [ADR 0012](adr/0012-saved-passkey-recovery.md).
