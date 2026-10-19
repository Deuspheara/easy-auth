# Protocol dependency assessment

AUTH-22 implements only optional core/PostgreSQL state transactions using existing
`Secret`, SHA-256/base64url and URL dependencies. The RFC 7636 S256 vector is tested;
no new JOSE/network dependency or custom cryptography is introduced. Provider token
verification, actual PKCE support, egress and interoperability must still satisfy
the assessment below. [Transaction ADR](../architecture/adr/0013-oauth-state-transactions.md).

AUTH-23 Google exchange now explicitly depends on AUTH-28's constrained discovery/
JWKS network boundary as well as AUTH-22. Provider transports must share the reviewed
egress policy; the milestone labels do not permit a separate permissive Google
client. This dependency is recorded in Huly and synchronized to the planning export.
It does not claim that AUTH-28 or provider verification is already implemented.

Assessment date: 2026-10-18. Candidates require lockfile/advisory and license review when actually introduced; version numbers are observations rather than authorization to upgrade blindly.

| Boundary | Candidate/evidence | Decision and gate |
|---|---|---|
| Passkeys | [webauthn-rs 0.5.5](https://docs.rs/crate/webauthn-rs/0.5.5), native OpenSSL dependency | Prefer high-level safe API; persist private challenge state server-side only; verify UV, origin/RP and discoverable-flow support with browser tests. Do not switch on dangerous credential internals without a reviewed need. MPL-2.0 library license must be recorded; using it does not relicense independent application files. |
| External OIDC | [openidconnect 4.0.1](https://docs.rs/openidconnect/4.0.1/openidconnect/) | Prefer typed claim verification. Disable redirects and restrict DNS/IP/ports at every outbound hop. Validate discovery issuer, audience/azp, nonce and signature; permit only explicit algorithms. Key refresh is bounded; no arbitrary URL fetch on token input. Review transitive RSA advisory reachability. |
| Apple | [Apple Sign in REST API](https://developer.apple.com/documentation/signinwithapplerestapi) | Separate provider adapter: ES256 client-secret JWT from protected key; Apple ID-token algorithm/key policy separate. App/Services IDs and nonce-bound native code exchanges require real account tests. |
| Google | [Google OIDC](https://developers.google.com/identity/openid-connect/openid-connect) | Code + S256 + nonce. Trusted issuer/sub identity; email_verified is an attribute, never auto-link authority. Native uses system browser per RFC 8252. |
| SAML native | [samael 0.0.22](https://docs.rs/crate/samael/0.0.22), [source](https://github.com/njaremko/samael) | Evaluate xmlsec-enabled path, libxml2/entity policy and extraction of verified signed content. Native xmlsec1/OpenSSL/libclang requirements accepted if justified. The docs.rs build failure is an integration risk, not a vulnerability claim. No safe production selection yet. |
| SAML alternatives | [saml-rs 0.6.1](https://github.com/salasebas/saml-rs); current samlet/opensaml are compatibility re-exports; bergshamra resolves to 0.9.2 | [Pinned source assessment and hostile fixture plan](saml-assessment.md). Defaults enable broad crypto features; RustCrypto graph includes RSA advisory. AWS-LC experiment excludes reported advisory packages but does not establish SAML safety. Current evidence does not select a production verifier. |
| Email | lettre SMTP with TLS for production | Local Mailpit only in explicit development mode; no stdout transport in production. Delivery failure cannot consume authentication proof. |
| Passwords | RustCrypto Argon2 0.5.3, MIT OR Apache-2.0; Unicode normalization | AUTH-12 selects Argon2id v19, m=65536 KiB, t=3, p=1 after local release measurements; two blocking workers. NFC, 15–256 code points, local blocklist and bounded admission. [Policy, measurements and limitations](../guides/passwords.md). Recovery is implemented at mailbox assurance; authenticated password change and stronger-factor recovery remain incomplete. |
| Outbound issuer | Dedicated module, reviewed JOSE crate later | openidconnect is a client library, not an authorization-server implementation. M07 blocks interoperable standalone release pending exact redirect, PKCE, consent/client policies, key rotation and conformance evidence. |

**Hard SAML release blocker:** until a specific pinned dependency passes signature-wrapping, duplicate-ID, unsigned-claims, attacker-KeyInfo, DTD/XXE, replay, audience/destination/recipient/issuer/time/InResponseTo tests and a focused security review, ship no SAML ACS. Do not silently accept unsigned responses. Native dependencies are preferable to unreviewed custom verification.

AUTH-18's [passkey enrollment source review](passkey-enrollment.md) records the
private-state serialization boundary, RP ownership, discoverability limitations,
authentication provenance/recovery prerequisites and concrete browser/database
test requirements. Experimental enrollment has real Chromium evidence; optional
assertion verification is described in the [authentication review](passkey-authentication.md).
Optional core/PostgreSQL and experimental HTTP sign-in have native Chromium
assertion/modal-discovery evidence. Ordinary activation and management remain
unfinished. Source review alone
is not interoperability evidence.

Baselines: [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252), [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html), [Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html), [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/), [OASIS SAML specifications](https://www.oasis-open.org/standard/saml/), [OWASP SAML guidance](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html), [NIST 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html).

## Resolved first-slice dependency evidence

The 2026-10-18 full-lockfile cargo-audit run reports RUSTSEC-2023-0071 in rsa 0.9.10, resolved for SQLx's inactive optional MySQL path. `cargo tree -i rsa --target all` and `cargo tree -i sqlx-mysql --target all` show no compiled dependency. Cargo metadata's resolver nodes include optional inactive packages and must not alone be used as build-reachability evidence. `scripts/audit.py` retains the full-lockfile finding and independently derives all-platform normal/build/dev compiled reachability on every CI run; any compiled advisory is fatal. cargo-deny provides a second graph-based check. No global RSA advisory ignore is configured. Adding an OIDC/JOSE feature must rerun and review this gate.

License policy additionally admits [0BSD](https://spdx.org/licenses/0BSD.html) for quoted_printable and [CDLA-Permissive-2.0](https://cdla.dev/permissive-2-0/) for webpki-roots certificate data. Distributions must include applicable third-party notices/license texts, including the CDLA text for redistributed root data. This does not change original-code MIT OR Apache-2.0 licensing.
