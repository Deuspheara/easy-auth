# Domain model

A realm is an authentication security partition; it is not a workspace/business organization. A registered client belongs to a realm and has exact redirects, origin policy and audience. The first slice binds one realm per server/router in trusted configuration; no request body may select it.

User has opaque random UUID, realm, verified email and lifecycle status. Email policy initially supports a conservative ASCII mailbox and canonicalizes case consistently; no plus/dot rewriting. This product policy can conflate case-sensitive local parts and must be explicit. A future email change proves old/fresh identity plus new email and revokes sessions. ExternalIdentity is unique by (realm, connection, trusted issuer, subject); matching emails never merge users. Linking proves current fresh session and a new provider transaction. Unlinking cannot remove the last usable credential/recovery path. Merges are disabled until separately reviewed.

Credentials (password, passkey) are distinct from provider accounts and user records. Passkey stores RP-scoped credential/public-key state, counter, UV/backup metadata and a user label. Discoverable enrollment provisions a passkey-first user under a verified enrollment transaction. Recovery cannot silently replace stronger assurance with email; explicit policy, delays/notifications and audit required.

AuthenticationTransaction carries realm/client/connection, purpose, browser binding, state/nonce/PKCE verifier and expiry. VerificationChallenge holds only token/browser verifiers, email/purpose and expiry. Consume atomically in the transaction that creates the user and session. A failed session insert rolls back consumption. Parallel consumption yields one winner. PostgreSQL constraints include realm in all identity relations.

Session holds a public opaque ID, user+realm composite FK, SHA-256 verifier of a random 256-bit secret, created/last-seen/absolute expiry and revocation state. Browser receives the secret only in HttpOnly cookie. Lookup validates idle and absolute limits in the same database operation. Revocation takes effect on the next database validation; already-authorized in-flight operations can complete. Sensitive operations need fresh authentication and application-specific transaction semantics.

Refresh/token families are separate future native/OAuth entities: short access lifetimes, atomic refresh rotation, family replay detection and OS secure storage. JWT expiration is not revocation. SigningKey records public metadata and protected key reference; never put plaintext private keys into logs/config dumps. AuditEvent contains bounded event kinds and opaque subjects, not payloads, tokens or email addresses.

Planned entities are not implemented tables until their milestone. Account deletion must transactionally delete credentials/external identities/challenges and revoke sessions while preserving only policy-approved deidentified audit records.
