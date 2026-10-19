# ADR 0008: High-level passkey verification and private ceremony state

Status: accepted for the initial protocol boundary, AUTH-18, 2026-10-19.
The optional core/PostgreSQL boundary, explicit experimental HTTP composition and
Chromium virtual-authenticator registration checks are implemented. Ordinary server
enrollment stays disabled pending sign-in and stronger-account policy. See the
[enrollment guide](../../guides/passkey-enrollment.md).

Use `webauthn-rs` 0.5.5's high-level registration API. It fixes required user
verification and supports platform/roaming selection without implementing custom
signature or attestation verification. Disable default optional attestation APIs;
ordinary passkey registration still uses the library's verifier. Enable state
serialization for PostgreSQL storage of private ceremony objects. AUTH-19 also
enables conditional UI for its high-level discoverable assertion boundary;
preserve the library's conditional mediation.
No credential-internals or user-presence-only feature is enabled.

The protocol service accepts an exact HTTPS origin and derives RP ID from that
hostname. It has a separate localhost-only development constructor. Neither
subdomains nor arbitrary ports are accepted implicitly. The serialized private
state envelope records its version and origin so a changed configuration cannot
reuse a ceremony started under another origin. Its database encoding is explicit;
the public type has no Serde serialization implementation and redacts Debug.
Browser creation options remain separate. The repository must bind ownership,
session, browser, expiry and purpose; a protocol result alone cannot create an
account credential or consume a durable transaction.

The upstream verifier emits raw state/registration input at TRACE and some parsed
material at DEBUG. Wrap its synchronous ceremony calls in a scoped empty tracing
dispatcher. This suppresses those payload events even when a consuming application
enables TRACE, and restores caller logging immediately after the call. A regression
test first proves that this exact upstream version emits a synthetic marker and
then proves suppression and restoration. Never extend that scope around a future
or task spawn; work could then escape the thread-local scope. Safe audit facts and
operational errors remain the owning use case's responsibility.

An optional `passkeys` feature isolates native OpenSSL dependencies from default
email/password builds. CI lints all features, tests default and all features, and
audits all-platform normal/build/dev graphs with all workspace features. The five
production MPL-2.0 package exceptions, and a separate test-only software-authenticator
exception, are exact-name/version entries, with source availability
and distribution notices documented; no broad MPL allowlist or advisory ignore
is introduced. Linux all-feature builds require `libssl-dev` and `pkg-config`;
macOS requires discoverable OpenSSL development libraries, such as Homebrew's
OpenSSL with its pkg-config metadata. Native-library distribution remains a release
packaging responsibility.

Alternatives rejected: lower-level protocol code, client-held ceremony state,
blanket tracing changes for the entire application, permissive RP/origin matching,
and hiding optional dependencies from security gates. Tradeoffs are a native
dependency, covered-source distribution obligations and reduced upstream debugging
detail during ceremonies. Public errors contain no underlying verifier payloads.

AUTH-19 adds the optional [assertion protocol boundary](../../research/passkey-authentication.md),
including trusted credential decoding, owner/realm/origin checks, immutable backup
eligibility, counter updates and private authentication state. It issues no sessions
and has no durable login transaction or HTTP route yet. This decision does not
establish discoverability, account login, recovery assurance or assertion browser
interoperability. The source reviews record those remaining gates.
Do not enable ordinary server enrollment until
registered credentials are usable and mailbox/password flows cannot bypass the
reviewed stronger-account policy. Passkey-first accounts remain required and need
an account model without fabricated email addresses.
