# Passkey enrollment implementation review

AUTH-18, 2026-10-19. Implementation work is in progress; this document records
source findings and acceptance gates, not working passkey support. AUTH-5's
published comparison passed both hosted jobs at `3d644d4` before this work began.

## High-level verifier and private state

Use the registry release [webauthn-rs 0.5.5 source](https://docs.rs/crate/webauthn-rs/0.5.5/source/src/lib.rs),
reviewed against the locally cached release source. Its high-level
`start_passkey_registration` fixes user verification to required, permits platform
and roaming authenticators, and requests no attestation. Its paired
`finish_passkey_registration` performs protocol verification. Do not replace
those methods with low-level challenge or signature code.

The library explicitly permits its `danger-allow-state-serialisation` feature
for server database storage. That is the intended use here: persist the opaque
registration state in PostgreSQL, with realm, user, initiating session, browser
binding, purpose and expiry. Neither a cookie nor a response may contain that
state. Public creation options are a separate type. The client receives only an
opaque transaction identifier and the options needed by the browser. Keep state
wrappers private and redact debugging; never trace submitted credential payloads.

Enabling serialization does not justify `danger-credential-internals`, user
presence without verification, permissive origins or client-managed replay state.
Dependency introduction still requires compiled advisory and license checks.
The MPL-2.0 dependency and OpenSSL distribution obligations need an explicit
dependency-policy entry and notices; do not silently broaden all license policy.

## Configuration and credential ownership

The server owns RP ID and exact origin, with subdomain and arbitrary-port matching
disabled. Use the origin hostname as the initial RP ID rather than accepting an
arbitrary parent domain. This avoids relying on the library's suffix check as a
public-suffix policy. Require HTTPS outside explicit localhost development. An
embedded application's RP and a centralized service's RP remain distinct; these
credentials cannot authenticate unrelated domains automatically.

The library requires the application to reject an already registered credential
ID. Enforce uniqueness within the RP across account ownership, including realms
sharing that RP, rather than merely checking the requesting user's exclusions.
Bind every lookup and mutation to the trusted realm and user; never let a response
select the enrollment owner. Exclusions improve browser behavior but do not
replace database uniqueness or commit-time authorization.

Credential storage must preserve the library's verified credential object and
its counter/backup state. A user label is untrusted display text, not an identity.
No attestation means no claim about authenticator manufacturer, hardware backing
or device identity. Metadata availability must be reported honestly.

## Transactions and existing assurance

First enrollment requires genuinely fresh authentication. Recheck session
ownership, revocation, idle/absolute expiry and authentication time after acquiring
locks, not only before protocol verification. Preserve the existing email-lock,
user-lock, session-lock ordering where an operation touches those resources.
Consume enrollment state and insert the unique credential in one transaction;
rollback must leave no credential without its associated committed state change.
Concurrent completion must have exactly one winner. Bound pending transactions,
credential count, request sizes and verification work.

An enrolled passkey must not accidentally authorize mailbox recovery as passkey
recovery. Existing sessions carry authentication time but no method/assurance
provenance, and all current users require a verified email. Before exposing usable
passkey accounts, implement explicit authentication provenance and stronger-account
policy. Check every existing mailbox/password login, reset, enrollment, email
change and deletion path against that policy, including transactions racing with
passkey enrollment. Merely checking that a session is less than five minutes old
does not prove that a stronger credential was used.

AUTH-19 owns verified passkey sign-in; AUTH-20 owns management and reviewed
recovery. Enrollment alone must not be advertised as usable passkey authentication
or a completed recovery policy. Keep the incremental registration boundary
unavailable in ordinary server composition until users can authenticate with the
registered credential and the downgrade policy is enforced. Tests may exercise
the actual enrollment use case directly. This is a temporary implementation
sequence, not a substitute for delivering the full M03 boundary.

Passkey-first accounts remain required. They need a reviewed enrollment
transaction and an account model without a fabricated email address; an existing
mailbox session is not a passkey-first implementation. Track that work explicitly
in M03 rather than losing it between enrollment and login tickets.

## Discoverability and evidence

The reviewed ordinary registration method sets `require_resident_key(false)`.
It therefore does not itself establish discoverable enrollment. The separate
Google Password Manager workaround requires platform-specific selection and is
not a general replacement. The library's `conditional-ui` authentication API is
also specifically a conditional mediation flow. Review supported options and
persisted state before promising generic usernameless sign-in. Do not infer a
verified resident credential from an untrusted extension result alone.

Required AUTH-18 tests include real PostgreSQL expiry, wrong browser/session,
revocation while waiting, replay, concurrent completion, uniqueness across users
and realms, failed-insert rollback and cleanup during account deletion. Protocol
negatives include wrong challenge, origin, RP hash, missing user presence or
verification and malformed attestation. Test a corrupted signature using a real
signed attestation fixture from an established authenticator/test implementation:
the normal `none` attestation has no attestation signature to corrupt. Do not label
an unsigned fixture as signature-verification evidence.

Use a real browser's `navigator.credentials.create` with virtual CTAP2 platform
and roaming authenticators, including denied verification. The
[Chrome DevTools WebAuthn domain](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/)
provides virtual authenticators and response override controls. Browser fixtures
must reach the same API and PostgreSQL transaction as applications. Preserve
separate statuses for automated virtual-browser evidence, manual real-device
checks and unsupported cases. Native CUA failures are not protocol test evidence.

Normative baseline: [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/), especially
registration verification, credential scope, user verification and backup state.
No conformance, interoperability or production-readiness claim follows from this
source review.

## Initial implementation checkpoint

The optional `easy-auth-core/passkeys` feature now implements the protocol boundary
in [ADR 0008](../architecture/adr/0008-passkey-verification-boundary.md): validated
configuration, public creation options, private versioned database state and a
verified-credential wrapper. The subsequent optional PostgreSQL boundary now
persists and atomically consumes ceremonies with fresh ownership checks; see the
[implementation guide](../guides/passkey-enrollment.md). Explicit experimental HTTP
routes and eight Chromium virtual-authenticator cases now exercise the same
boundary. No normal server composition enables it. Real-device, other-browser,
discoverable, passkey-first, sign-in and stronger-account recovery gates remain M03
requirements; they are not inferred from these registration checks.

Upstream TRACE logging of state and input is suppressed within synchronous library
calls; a positive-control regression test proves the upstream event exists before
checking our boundary. The [dependency notices](../security/third-party-licenses/webauthn.md)
record exact MPL packages and native OpenSSL distribution requirements.
