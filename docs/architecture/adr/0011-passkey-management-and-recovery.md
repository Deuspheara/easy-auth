# ADR 0011: Passkey management and recovery authority

Status: experimental management and additional-enrollment boundaries implemented
in AUTH-20, 2026-10-19.
Saved-code configuration is described in [ADR 0012](0012-saved-passkey-recovery.md).
The full recovery protocol and ordinary activation remain incomplete; this is not acceptance
of the full ticket or an assurance/conformance claim.

## Credential management

A credential's public UUID selects an owned management record; its WebAuthn ID,
public-key encoding and private ceremony state never enter inventory responses.
Inventory is bounded by the existing ten-key per-account/RP limit. Mutations bind
the configured realm and RP plus exact owner/session and expected management
version. Labels are presentation data and use the enrollment label policy.

Require a genuine passkey-method session authenticated within five minutes, also
within its original idle/absolute lifetime. A recent mailbox/password session or
registration alone does not grant management authority, for either account policy.
Lock owner, initiating session and credential in that order. Serialize all owned
key mutations through the owner lock. Capture the original deadline and recheck
it after audit/notification and all other writes, following ADR 0010.

Rename changes only label/version. Removal must leave another credential in this
same realm/owner/RP that has actually authenticated (`last_used_at` is present).
Registration alone does not prove that a remaining key is usable. Both competing
last-key removals cannot succeed. Removing a key revokes all owned sessions and
session-bound pending enrollment/contact proofs; account-bound sign-in ceremonies
are canceled. Anonymous assertion completion still rechecks exact credential
ownership and bytes under the owner lock, so a removed key cannot issue a session.
Removal never changes authentication policy or enables mailbox/password recovery.

Record closed typed audit events and queue a fixed non-secret notice to an existing
verified contact in the same transaction. Email-free users have audit/inventory
visibility and no fabricated email delivery. This limited notification capability
must remain explicit; general recovery needs an independently reviewed policy.

## Additional enrollment authority

Core owns the method rule; trusted PostgreSQL stages apply it after locking the
exact owner/session and rereading realm-wide credential presence. Known email or
password proof can bootstrap the first key. Any existing owned key requires genuine
fresh passkey-method proof, including enrollment for another RP. Unknown legacy
provenance never suffices. Context, save, load and commit share this rule; the owner
lock serializes competing initial enrollments and credential mutations. Registration
alone preserves policy/method/time. A retained initial key must perform an actual
assertion before it authorizes adding another key.

Each stage checks original session deadlines after its writes. Final completion
also retains locked ceremony expiry and performs a table-free check after the
conditional consumption itself; a write-trigger wait cannot extend either deadline.

## Remaining recovery and activation work

AUTH-20 retains pre-enrolled independent recovery proof, single-use/expiry,
explicit delay/cancellation, notifications where a verified channel exists, audit,
safe stronger-policy activation and complete
remaining HTTP/native/physical-device evidence. Mere denial of fallback does not fulfill it.
A remaining strong key supports normal authentication and replacement enrollment;
it is not a claim of all-keys-lost recovery.

The [NIST authenticator-event guidance](https://pages.nist.gov/800-63-4/sp800-63b/events/)
distinguishes replacement while another authenticator is available from recovery,
and discusses prearranged recovery secrets and independent notification. It informs
the review, but does not establish this implementation's compliance or approve a
mailbox-only fallback. A saved-proof recovery proposal must specify secure offline
issuance/storage, throttling, rotation, restricted replacement-key bootstrap,
waiting-period cancellation and the honest limits for accounts without an
independent notification channel before it is implemented or activated.

## Compatibility and verification

Add a migration for management versions and bounded audit/notice kinds; never edit
published migrations. Keep the existing four crates and optional passkey feature.
Use a separate concrete repository port and focused management modules; no generic
credential engine. Test genuine assertion controls, weak/legacy/future/stale denial,
version and RP/realm/owner isolation, concurrent removal/rename/sign-in, observed
lock/audit/notice expiry, rollback, upgrade and notification retries. Existing
mailbox/signup/sign-in/native behavior must remain covered. Ordinary composition
stays gated until all AUTH-20 and remaining M03 evidence is satisfied.


The explicit experimental management HTTP constructor composes the existing
base/enrollment/sign-in/signup/contact builders and the management use cases.
Earlier constructors and ordinary server routes remain unchanged. Closed JSON,
configured realm/origin startup checks, 8 KiB bodies, shared browser guards and
post-commit cookie clearing preserve the existing trust boundary. Native platform/
USB cases now cover independent spare-device proof, original exclusion/residence/
UV policy, removal and real queued SMTP notices. Recovery design, physical-device/
other-browser evidence and ordinary activation remain incomplete.
