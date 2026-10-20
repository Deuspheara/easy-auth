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
AUTH-28 now implements the optional document-fetch boundary described in
[ADR 0014](../architecture/adr/0014-oidc-egress.md). The optional AUTH-29 signature/claim
boundary is assessed below; code exchange and provider acceptance remain unfinished.

Assessment updated: 2026-10-19. Candidates require lockfile/advisory and license review when actually introduced; version numbers are observations rather than authorization to upgrade blindly.

| Boundary | Candidate/evidence | Decision and gate |
|---|---|---|
| Passkeys | [webauthn-rs 0.5.5](https://docs.rs/crate/webauthn-rs/0.5.5), native OpenSSL dependency | Prefer high-level safe API; persist private challenge state server-side only; verify UV, origin/RP and discoverable-flow support with browser tests. Do not switch on dangerous credential internals without a reviewed need. MPL-2.0 library license must be recorded; using it does not relicense independent application files. |
| External OIDC | [openidconnect 4.0.1](https://docs.rs/openidconnect/4.0.1/openidconnect/) | Not selected: an isolated defaults-disabled normal/build graph selects rsa 0.9.10 and fails the compiled advisory gate (RUSTSEC-2023-0071). No ignore or custom verifier is permitted. A reviewed typed verifier must still validate signature, exact issuer, audience/azp and nonce with explicit algorithms; reuse AUTH-28 egress. This selection blocker does not establish Marvin exploitability in public-signature verification. |
| External JWS boundary | [josekit 0.10.3](https://docs.rs/crate/josekit/0.10.3) | Selected for optional AUTH-29 per-key signatures with mandatory typed core claim policy. Native OpenSSL; combined graph passes advisory/license gates. Code exchange, Keycloak and full provider acceptance remain unfinished. |
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


## AUTH-28 selected document transport

The optional feature selects reqwest **0.13.5**, defaults disabled with
`rustls-no-provider`; rustls **0.23.46**, defaults disabled with ring/std/tls12;
webpki-roots **1.0.9**; and ipnet **2.12.2**. Transport/IP/TLS implementation
licenses are MIT OR Apache-2.0; root certificate data uses CDLA-Permissive-2.0,
whose text is already retained under `docs/security/third-party-licenses/`.
Test-only rcgen **0.14.10** and tokio-rustls **0.26.6** use ring with defaults
disabled and MIT OR Apache-2.0 licenses. Fixture private keys remain in memory.
Current Rust 1.95 satisfies reqwest's 1.85 and rcgen's 1.88 minimum versions.

Pinned-source review and a cold-process experiment established that the HTTP
feature must receive an explicit per-client crypto provider. The implementation
uses standard rustls safe defaults, ring and public roots without installing a
global provider. reqwest still selects platform-verifier helper dependencies;
these are included in graph/license checks even though requests use explicit roots.
No existing locked package version is removed or upgraded by this addition.

Compiled advisory checks, all-feature cargo-deny licenses/sources/bans and native
TLS component tests pass. No advisory exception was added; SQLx's inactive MySQL
RSA finding stays visible. The separate openidconnect candidate experiment
does not modify the project graph. AUTH-29 selects the per-verifier signature
dependency below while retaining the existing advisory gate.
See the [document guide](../guides/oidc-egress.md) for runtime bounds, public-network
restrictions and the uncancellable native DNS limitation. This selects a document
transport, not a provider verifier or production interoperability claim.


## AUTH-29 selected signature boundary (2026-10-20)

The optional `oidc-verification` feature selects **josekit 0.10.3**, default features
disabled, MIT OR Apache-2.0, and its existing native OpenSSL family. The actual locked
workspace retains all prior package versions and adds ten packages, including the
crate's compression support; application code invokes only bounded compact JWS
verification, never JWE, unsecured JWT or decompression. No native/crypto plugin,
custom signature primitive or advisory/allowlist exception is added.

Source review and isolated real RS256/PS256/ES256 controls led to a per-verifier API.
The alternative jsonwebtoken 11.1.0 AWS-LC probe passed its isolated graph but its
high-level API selects process-global crypto state. openidconnect 4.0.1 remains
unselected because its default-disabled compiled graph selects RSA0.9.10 and fails
the existing advisory gate. This does not establish Marvin exploitability for
public-signature verification and does not justify an ignore or custom crypto.

The combined workspace compiled advisory check and unchanged cargo-deny license/
source/bans policy pass. No existing lockfile version is upgraded/removed. josekit's
[MIT](../security/third-party-licenses/josekit-0.10.3-MIT.txt) and
[Apache](../security/third-party-licenses/josekit-0.10.3-APACHE.txt) texts are retained
verbatim; distributions still own applicable transitive/native notices and updates.
No independent audit, FIPS, conformance or production interoperability is claimed.

Generic payload validation is insufficient: this implementation checks required
typed original signed claims, duplicate/nullable security members, exact issuer/
audience/nonce/azp, key-use/algorithm bounds and final database context/deadlines.
Only validated public components reach the library. Foreign errors are discarded
without formatting input-derived causes. Native jobs retain bounded leases after
cancellation; dependency temporary allocations prevent an absolute memory-erasure
claim. See [ADR 0015](../architecture/adr/0015-oidc-token-verification.md).
The owned Keycloak/browser fixture now supplies named local code/signature/
rotation/replay evidence through private test TLS/address mapping and shared
production HTTPS sources. AUTH-30 extends the owned-provider evidence through
atomic identity/session persistence. AUTH-55 provides optional provider-only deletion;
AUTH-56 adds configured public browser composition and owned two-mode acceptance,
with the same explicit private-TLS/source-copy limits. Final hosted verification,
broader provider acceptance and independent review remain gates; dependency adoption
alone establishes none of those.


AUTH-30 reuses the same pinned josekit 0.10.3 as a PostgreSQL test dependency for
actual ES256-signed identity/JIT/session integration scenarios. No package version,
production crypto dependency or advisory/license exception is added. The SQL
scoped-subject digest uses PostgreSQL's existing SHA-256 over a JSON tuple for
serialization/cooldown metadata, not custom signature or credential verification.
No raw provider token/key/nonce is persisted by the new identity transaction.

AUTH-23's initial explicit desktop return metadata uses existing standard socket
types and the already selected URL parser. It introduces no dependency/version,
cryptography, license or advisory exception. The HTTPS web constructor and provider
network restrictions remain unchanged. Typed exact loopback metadata is not a
Google exchange adapter, native transport or real-provider acceptance result;
[ADR 0019](../architecture/adr/0019-google-code-flow.md) retains those gates.

The subsequent optional core Google component reuses the selected josekit RS256,
typed claim checks and constrained document/token transport with no package/version
change. Its canonical issuer, S256, response issuer support, RS256 and Basic/Post
wire choices were compared with Google's public
[discovery](https://accounts.google.com/.well-known/openid-configuration) and
[OIDC guide](https://developers.google.com/identity/openid-connect/openid-connect)
on 2026-10-20. This is metadata research and offline actual-signature evidence,
not registered-client or Google web/native interoperability. Installed shared
credentials are not application-authenticity proof; real native registration,
provider freshness/deletion and manual matrix remain gates. No advisory or
license exception is introduced.

The AUTH-23 desktop loopback component makes the already resolved Hyper1.12.0 and
hyper-util0.1.21 optional direct server dependencies for explicit HTTP/1 parsing,
buffer/header/time bounds and Tokio I/O. Both selected packages are MIT licensed;
their versions/source/checksums are unchanged, and Cargo.lock only adds the direct
server edges. No new package, crypto implementation, roots or advisory exception
is introduced. This avoids handwritten HTTP parsing and unbounded detached server
tasks. Owned socket/browser evidence is separate from registered Google/OS/native
acceptance and usable provider lifecycle.

Server desktop/database acceptance reuses the workspace-selected josekit0.10.3 as
a development-only dependency for the shared actual RS256 provider fixture. The
package/version/source and license/advisory policy are unchanged; Cargo.lock adds
only that development edge. No production signature implementation, proof
constructor or provider transport override is added. Native receives are actual
sockets/PostgreSQL; provider GET/token/JWKS responses remain private in-memory
fixtures with actual signatures, without claiming real Google interoperability.
