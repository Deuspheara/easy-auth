# Protocol dependency assessment

AUTH-36's independent standards-client acceptance pins test-only
[openid-client6.8.8](https://github.com/panva/openid-client/tree/v6.8.8), with locked
jose6.2.13 and oauth4webapi3.8.8 (all MIT) in the existing shared browser toolchain.
Exact registry archive integrities are in `tests/browser/passkeys/package-lock.json`;
installation uses `npm ci --ignore-scripts`. The 2026-10-27 whole-browser npm audit
reports zero known findings, not independent security approval or unknown-risk
clearance. The dependency introduces no Rust runtime, native library, crypto
implementation, shipping asset, lockfile/advisory exemption or weaker assertion.

The RP uses the upstream discovery, S256/state/nonce and code-grant implementation.
Its explicit [JWS validation option](https://github.com/panva/openid-client/blob/v6.8.8/docs/functions/enableNonRepudiationChecks.md)
requires JWKS signature verification as well as normal HTTPS/claim checks. The
fixture-only Fetch adapter passes original bytes through the same explicit private
certificate/address trust boundary, with no cookie authority, insecure request or
production override. Existing normal signing producers, original Node/Rust cases,
clock/propagation intervals and SAML waiver limits remain unchanged. This strengthens
bounded independent RP evidence; the outbound OIDC hard release gate, independent
review, real provider/OS and production acceptance remain separate.

AUTH-49 retention reuses the locked SQLx/PostgreSQL, Tokio, UUID and async-trait
boundaries. It adds no dependency/version, cryptographic implementation, verifier,
license rule or advisory exception. Fresh statement snapshots and FK-lock behavior
follow the primary PostgreSQL references in
[ADR0050](../architecture/adr/0050-bounded-realm-retention.md). Default and all-feature
workspace/security qualification remains required; dependency reuse alone does
not establish its safety or clear existing release gates.

AUTH-49's offline backup commands use unchanged upstream age1.3.2 with an explicit
build-only Go module selecting x/crypto0.56.0, checksum-pinned Go1.27.3 and pinned
govulncheck1.9.0. This adds no authentication runtime dependency, crypto producer
or application-policy exemption. Exact source/version/checksum, read-only locks,
source/binary scan inventories, imported-package rejection and BSD-style notice
hashes are recorded by `scripts/prepare_backup_tool.py`. The unimported OpenPGP
module advisory remains visible; scans are not independent assurance. Primary
contracts, the fixed SSH dependency findings, installed CMS issue, native archive
profile and quarantine limits are recorded in
[ADR0048](../architecture/adr/0048-encrypted-backup-quarantine.md).

The [2026-10-26 supply-chain checkpoint](../security/supply-chain-review-2026-10-26.md)
records current source-license inventories, selected versus resolver-only graphs,
standard source/image SBOM coverage and actual native/copyright provenance.
Its separately pinned/audited SBOM tool adds no authentication runtime dependency;
the exact tooling-only MIT-0 decision leaves the root application policy unchanged.
Release prerequisites, residual advisories and independent approval remain open.

AUTH-26's optional protected Apple custody/worker reuses locked
josekit0.10.3/OpenSSL0.10.81 for internal fixed `dir` + `A256GCM` storage envelopes
and existing protected ES256 client secrets. This adds no inbound JWE trust,
custom AEAD/signature implementation, package/version, license rule or advisory
exception; Cargo.lock is unchanged. Native-library/parser copies are not claimed
zeroized beyond owned wrappers. The concrete revocation transport reuses locked
reqwest0.13.5/rustls0.23.46 with existing pinned address, hostname/certificate,
resource, redirect/proxy/retry controls. Dependency reuse still requires current
compiled-graph advisory and all-feature license checks. The explicit profile and
[primary Apple contract](../architecture/adr/0045-apple-grant-custody-and-revocation.md)
remain separate from real provider/OS acceptance and independent security review.
Owned browser/PG/TLS fixtures establish only their recorded implementation scope.

AUTH-25's optional linking boundary reuses existing Google/Apple/OAuth/JOSE and
PostgreSQL primitives; no dependency/version or custom cryptographic primitive is
introduced. Fixed Google `select_account` is a documented account-choice request,
not a fresh-event claim; the explicitly selected session-age profile still rejects
missing signed authentication time. Apple retains its own nonce/code contract,
without an invented prompt or PKCE fallback. Explicit local ownership and purpose
binding replace email-based linking; [ADR0044](../architecture/adr/0044-explicit-social-identity-linking.md)
records primary references and the retained real-provider/lifecycle gates.

AUTH-24's optional Apple component reuses pinned josekit0.10.3/OpenSSL0.10.81:
established P-256 key import/ES256 compact JWS for fixed client secrets and the
existing RS256 verification worker for Apple identity tokens. No dependency or
lockfile version changes, custom cryptographic primitive or generic provider
framework. Native signing jobs retain bounded capacity through cancellation;
operator PEM/output buffers zeroize but dependency copies are not claimed erased.
Apple metadata observed2026-10-25 advertises client_secret_post/RS256, not S256 or
response-issuer support. The explicit dedicated-return/signed-nonce profile is
separate from unchanged Google/generic requirements. The Apple REST index now
links its client-secret guidance to the shared AccountOrganizationalDataSharing
page; identity guidance's algorithm wording conflicts with current discovery, so
no algorithm alias/fallback is inferred. Exact primary links and profile decisions
are in [ADR0043](../architecture/adr/0043-apple-code-flow.md).
Owned signing/PG fixtures establish component behavior, not actual Apple console,
OS, provider rotation or lifecycle qualification. Existing license/advisory/native
risks, outbound release gate and SAML waiver limits remain unchanged.
The explicit Axum `apple-web` transport adds no dependency or version. Owned
Chromium acceptance reuses existing Playwright/TLS/PG lifetime helpers and the
unchanged maintained JOSE producer. It observes a real cross-site form POST and
same-origin final commit; interception of Apple authorization remains offline
fixture evidence, not registered-provider or OS acceptance.

The reference presentation in [ADR0042](../architecture/adr/0042-reference-account-ui.md)
uses native browser modules/WebAuthn and fixed included HTML/CSS. The presentation
now pins Basecoat CSS 1.1.0 and optional Motion mini 14.6.0, prepared with
esbuild 0.28.2. It adds no server frontend runtime, remote font/image or advisory
ignore. Versions, licenses, integrity, sizes and exact regeneration live in the
[modernization record](../design/reference-ui-modernization.md).
The maintainer-requested compact design bundles the unmodified Inter 4.1 variable
font under SIL OFL 1.1 with its notice. Its fixed local route and SHA-256 provenance
are recorded in the [design contract](../design/reference-ui.md). A stdlib-only
script checks generated semantic CSS aliases; it is not a server dependency.
The stylesheet hash check uses the existing OpenSSL/base64 dev dependencies;
the browser still uses existing reviewed protocol implementations and original
native options. Full browser/device/accessibility evidence is recorded separately,
not inferred from dependency reuse or a source/format check.

AUTH-43's read-only linked-provider inventory and password-service presence
projection add no dependency, verifier, network client, cryptographic fixture,
provider activation or migration. Existing source/session validation and SQL
transaction policy remain authoritative. Public inventory is not a verified
identity or current provider trust; [ADR0041](../architecture/adr/0041-linked-provider-inventory.md)
records that boundary. Advisory/license and exact-source CI gates remain unchanged.

AUTH-39's optional outbound signer reuses the pinned josekit0.10.3/OpenSSL0.10.81
graph from ADR0015 with an explicit RS256-only profile. It introduces no new crypto
implementation or advisory exception. This reuse and internal RP evidence are not
an independent audit of outbound issuance. Optional Unix protected-file loading
uses only safe `OpenOptionsExt` with NOFOLLOW/NONBLOCK constants from the already
locked libc0.2.191 (MIT OR Apache-2.0); no unsafe application code or libc syscall
wrapper is introduced. Cargo.lock adds direct feature edges only, with no package
or version change. Current advisory/license results must be rerun for this source.
[ADR0037](../architecture/adr/0037-issuer-signing-and-final-issuance.md) records limits.

Current SAML activation policy: [ADR0032](../architecture/adr/0032-saml-maintainer-directed-activation.md) permits explicitly configured
normal SAML by maintainer direction, waiving independent review. Default-off,
trusted persisted configuration and every protocol/security check remain required.
Earlier source-disabled stage descriptions below are superseded only as to
activation policy; their assurance gaps remain unverified, not independently approved.


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

[ADR 0021](../architecture/adr/0021-saml-verification-and-approval.md) records the
current candidate recommendation, additional alternatives and staged approval.
Ordinary integration is not a production-dependency or independent audit approval.

AUTH-32's [isolated native checkpoint](saml-assessment.md#auth-32-native-checkpoint--2026-10-20)
adds 86 passing upstream samael tests and a separately preserved ignored-positive
failure. It resolves the unexecuted native-build gap only; it does not select a
production verifier or clear the native advisory/license and hostile-parser gates.
The subsequent [direct parser observations](saml-assessment.md#direct-parser-observations--auth-32)
reproduce permissive DTD/malformed-input acceptance with working file/network
observers. No resource access was observed for those bounded inputs; signature/
canonicalization paths and full SAML acceptance remain unestablished.

The resumed [signed Response observations](saml-assessment.md#signed-response-engine-observations--auth-32)
establish strong signed positives and bounded trust/unsigned/tamper/digest rejection
in both reduction modes, while reproducing six XML-policy failures. The explicit
RSA-SHA256/SHA-256 allowlist remains intact. This research adds no runtime dependency
or production verifier and does not clear the SAML release blocker.

The subsequent [Assertion and signature-algorithm follow-up](saml-assessment.md#signed-assertion-and-signature-algorithm-follow-up--auth-32)
adds signed Assertion extraction and a separately generated RSA-SHA1-signature
negative without changing that verification allowlist. All 34 prior outcomes
remain unchanged in the expanded 56-row assessment; the same XML-policy failures
and broader release prerequisites remain open.

The [signature-child resource observation](saml-assessment.md#signature-child-resource-observations--auth-32)
adds working independent file/network controls around 20 signed-input outcomes.
No resource calls were observed for those bounded cases, but six forbidden XML
acceptances and six opaque engine errors remain. This does not clear the strict
XML/resource, native dependency or independent-review gates.

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

AUTH-37's explicit native issuer/client credential extension introduces no new
dependency, cryptographic primitive or inbound protocol engine. Existing URL
canonicalization, Secret/SHA-256 and database verifier comparison are reused.
No secret is retained in registration or request Debug, and no verifier-input
constructor permits treating a stored hash as a presented credential. Native
public port admission follows RFC8252's loopback profile while exact actual-return,
S256, consent and token authority remain obligations of the future code transaction.
This component is not full native/issuer conformance or production approval;
[ADR0034](../architecture/adr/0034-issuer-native-registration-and-authentication.md)
records the explicit profile and limits. Existing advisory/license gates remain
unsuppressed.

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

Google's Security Bundle/OIDC documentation was rechecked on2026-10-20 for the
explicit eligible-client session-age request. The component uses existing URL/
zeroizing storage, josekit RS256 and typed claim validation; no dependency/version,
algorithm, trust root or license/advisory exception is added. Fixed `claims` request
support is distinct from actual application verification/settings and from a new
Google authentication event. Provider reauthentication requests remain unsupported;
ordinary activation still requires genuine registered-client/lifecycle evidence.


The experimental Google HTTPS transport reuses the selected core/PG/Axum verifier,
transaction and browser boundary, without a new protocol or production dependency.
Its development-only Axum base64 edge selects the already locked0.22.1 package to
decode the public S256 challenge in the signed provider fixture; no package/version,
algorithm, trust root or advisory exception changes. The owned browser runner reuses
the pinned Playwright/Chromium setup and private TLS proxy. A context-local private
certificate exception is fixture evidence only, not a production transport fallback
or system trust change. Real Google registration, eligibility, supported OS return
and genuinely usable fresh lifecycle remain unverified acceptance gates.


The optional AUTH-23 native launcher pins `open`5.4.4 (MIT, MSRV1.62), with default
features disabled, solely for `commands` construction. Exact downloaded source was
reviewed for macOS/Linux/Windows/WSL: only the first command is selected; Tokio owns
execution and finite errors, null streams, original-deadline bounds and cleanup.
The `insecure` feature, dependency execution helpers and fallback iteration are
unused. Windows/WSL normally use static PowerShell source and a target environment value;
detected Wine places `winebrowser` first with literal target data;
macOS passes the URL as data after `--`. No protocol value becomes shell source.
Linux adds MIT `is-wsl`0.4.0 and `is-docker`0.2.0, whose reviewed sources read/cache
local platform markers without logging or spawning processes; existing once_cell
and libc versions are retained. Server test base64 uses already locked0.22.1.
No existing package version, trust root, crypto or advisory exception changes.

Review rejected `webbrowser`1.2.4 for this use because its source logs target/command
Debug information and its macOS default selection contains a Safari fallback.
No global logging suppression or local dependency patch was introduced. These are
selection constraints, not an interoperability or vendor-defect claim. The chosen
OS handler is trusted configuration and remains unverified by automated private
process actors. See upstream [open source](https://github.com/Byron/open-rs/tree/v5.4.4)
and the [native contract](../guides/google.md#owned-native-sign-in-operation).


AUTH-23's stable native return profile reuses the existing reviewed URL parser,
S256, SQLx/PostgreSQL and Google verifier. It adds no package/version, crypto, trust
root, advisory or license exception. RFC8252 section7.3 and Google's desktop flow
were rechecked on2026-10-20 for ephemeral literal-loopback ports and IPv4/IPv6.
That protocol research is not registered-client/OS-browser acceptance evidence.
See [ADR0020](../architecture/adr/0020-native-oauth-operation-returns.md).


AUTH-23's credential-free public-provider preflight uses only the already selected
`OidcHttps`, public roots and existing PostgreSQL/core dependencies. It introduces
no dependency, TLS override, alternate verifier or provider credential. Public
Google metadata/JWKS admission and native request preparation are separate evidence
from signed identity, registered client or OS/browser interoperability; raw public
keys establish no authentication. See the
[preflight boundary](../guides/google.md#public-metadata-and-transport-preflight).

The [cross-component root-cause investigation](saml-verifier-options.md) compares
identical corpus bytes against both exact pins. It recommends qualifying the
complete strict message component, conditional on exact algorithm/digest policy,
independent resource evidence and security review. No production selection or
SAML release-gate change follows from the passing bounded controls.

The [exact SHA-256 follow-up](saml-exact-policy.md) validates a reviewable
upstream-compatible profile patch and independent resource observation. It leaves
production dependency selection, independent review and the SAML gate unchanged.

The [selected SAML dependency follow-up](saml-dependency-review.md) records Linux
and macOS AWS-LC graph checks, retained inactive full-lock findings, license/source
inventory and native advisory mapping. Independent review and SAML activation
remain gated.

The [complete-document follow-up](saml-document-completeness.md) fixes a confirmed
EOF-stack admission bug with a minimal upstream patch and repeats signed/resource
qualification. Independent review, upstream adoption and SAML activation stay open.

## AUTH-48 workspace TLS dependency update — 2026-10-21

The standard workspace audit identified compiled
[RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html)
in rustls-webpki 0.103.15 and
[RUSTSEC-2026-0381](https://rustsec.org/advisories/RUSTSEC-2026-0381.html)
in webpki-roots 1.0.9. The workspace lock now selects the documented patched
releases **0.103.16** and **1.0.10**. The direct root-store requirement is at least
1.0.10; the 0.26.11 compatibility package reexports the same patched 1.x store.
Earlier version inventories above remain historical evidence.

These are upstream patches: the verifier rejects the distrusted intermediate keys
and the root bundle removes the affected root. No application verifier, TLS
configuration, origin/address policy, algorithms or feature selection changes.
The rustls-webpki fix is transitive and retained in Cargo.lock; builds must honor
the lock and downstream resolvers must select a patched version too. No new
dependency or license exception is introduced.

`python3 scripts/audit.py` passes for the all-platform/all-feature compiled graph
with cargo-audit 0.22.2 and RustSec revision
`4b587f00996ebe5c05a73eaef105ef241e876414`. It still reports inactive SQLx/MySQL
rsa 0.9.10 / RUSTSEC-2023-0071, without a global ignore. Cargo-deny 0.20.2
`--all-features check` passes advisories, bans, licenses and sources; existing
duplicate-version/unused-license warnings remain. Neither check audits the
separate SAML research dependency graph or clears its independent-review gate.

AUTH-37's optional `issuer-clients` metadata component reuses existing URL, UUID,
Secret and PostgreSQL dependencies. It selects no new JOSE/token implementation,
crypto primitive or remote sector-document client. Stored random sector/owner UUIDs
follow the OIDC Core section8.1 GUID method. Reviewed signing/claims, client-auth
protocol handling, real consent, conformance and M07 prerequisites remain gates;
[ADR0026](../architecture/adr/0026-outbound-client-registration.md) bounds the slice.

AUTH-38's optional `issuer-codes` uses the already-selected URL, UUID, existing
Secret/randomness, SHA-256/base64, zeroize and SQLx dependencies. No version, license,
algorithm, crypto/native verifier or advisory exception changes. S256 uses the
existing digest implementation and the previously used published RFC7636 vector;
no custom signature or XML fixture is introduced. The code component does not
establish an outbound JWT/signing dependency decision, conformance or independent
approval. AUTH-39 and M07 still require their own actual evidence.


## AUTH-26 protected Apple storage envelope (in progress,2026-10-25)

The optional core `apple-grants` storage foundation reuses locked josekit0.10.3 /
OpenSSL `dir` + `A256GCM` compact envelopes. No new package/version, algorithm
implementation, trust root, license or advisory exception is introduced. This is
an internal at-rest format, separate from the inbound signature-only profile
recorded above; inbound JWE authentication remains unsupported. Pinned source
inspection confirms exact header selection occurs before decryption/compression.
Every extra/compression/alternate-profile member is rejected, including validly
encrypted negative fixtures. Associated realm/source/client/identity/grant UUIDs
are authenticated; no raw provider subject/email is added to clear metadata.

Trusted explicit storage keys are bounded and distinct from ES256 signing keys.
Unknown IDs do not trigger key-by-trial/current-key fallback. Owned raw key/plaintext
buffers zeroize, but native/parser internal copies are not claimed erased. Tests
exercise rotation/retirement, tag/context tampering, bounds/redaction and native
work retaining its capacity after async waiter cancellation. This foundation is
not yet a captured grant ledger, revocation worker, ordinary activation or real
Apple acceptance. [ADR0045](../architecture/adr/0045-apple-grant-custody-and-revocation.md)
records the remaining integration, persistence, retry and operational requirements.
