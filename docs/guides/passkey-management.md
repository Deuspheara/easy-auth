# Experimental passkey management

AUTH-20 is in progress. The optional core/PostgreSQL management boundary provides
bounded inventory, rename and removal; it does not yet provide HTTP management,
all-keys-lost recovery, stronger-policy activation or ordinary server enablement.
Those and required physical-device/browser evidence remain acceptance gates.
See [ADR 0011](../architecture/adr/0011-passkey-management-and-recovery.md).

Construct `PasskeyManagement` with a trusted realm, the existing configured
`PasskeyService`, and a `PasskeyManagementRepository`. Both embedding and standalone
composition must use these same use cases. Requests cannot select an account owner.

Every operation requires a live session from genuine passkey authentication within
five minutes. Mailbox/password/legacy sessions, future/stale authentication and
expired/revoked sessions fail with Unauthorized, regardless of whether the owner
has a mailbox or uses passkey-required policy. Rotation does not extend freshness.

Inventory returns at most ten credentials in the configured realm/owner/RP, ordered
by public UUID. Fields are `id`, `version`, `label`, `created_at_ms` and nullable
`last_used_at_ms`. No WebAuthn identifier, stored credential, owner or private
ceremony bytes are exposed. Inventory does not refresh authentication time.

Rename accepts the exact current version and a nonblank, bounded, control-free
label. It returns a new version; concurrent/stale metadata requests cannot silently
overwrite one another. Removal also requires the current version and leaves another
key in that realm/account/RP which has actually authenticated. Register and then
sign in with a replacement before removing the prior working key. Merely creating
a credential is not evidence that its owner can use it. Last-proven-key removal
is denied for both mailbox and passkey-required accounts.

Removal revokes all owned sessions, including its caller, and cancels session-bound
enrollment/contact/lifecycle and account-bound sign-in ceremonies. Sign in again
with a remaining working key. An already verified assertion for a removed key must
still fail its final owner/key/ceremony checks. Account policy, UUID and contact
are unchanged; this operation never enables mailbox/password fallback.

Mutations share the existing per-user/source sensitive-action admission budget;
failed operations still spend admission. Owner-before-session-before-key locks
serialize changes, and final database-time checks follow all potentially blocking
writes. Expiry rolls back key metadata/removal, session/proof changes, audit and
notice together. The final check precedes commit/response latency.

Typed `passkey_renamed`/`passkey_removed` audit facts retain the public target UUID,
owner and actor session. Target UUIDs are historical identifiers without a live-key
foreign key; subject erasure clears them with all other attribution. Fixed non-secret
`passkeys_changed` notices use only an existing verified contact and the durable
leased/retry queue. `EmailDelivery::passkeys_changed` is a required delivery port;
implementations must report unavailable delivery honestly. The real SMTP adapter
implements it. No raw credential, label, recovery secret or sign-in link enters a
notice. Email-free users have no fabricated notification address or implied email
recovery; recovery notification limits remain explicit unfinished AUTH-20 work.

Migration 0012 adds management versions and bounded target/audit/notice schema.
Existing key encodings, metadata, owner IDs and session provenance are preserved;
upgrade does not invent successful key use. Published migrations remain immutable.
