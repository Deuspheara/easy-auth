# Outbound OIDC local acceptance extension — 2026-10-27

AUTH-36 requires independently exercised code/PKCE, signing/rotation and client
isolation, with evidence from all five implementation children. This increment
adds a separately maintained OIDC relying-party implementation to the actual
executable/embedded acceptance. It does not establish independent security review,
full protocol certification, production acceptance or all-method release.
**AUTH-36 remains In Progress; the outbound OIDC hard release gate stays open.**

## Concrete change and preserved authority

Source `538b2bb82cf1615dbb37401a5b37befcdf51bbc5` pins test-only
[openid-client 6.8.8](https://github.com/panva/openid-client/tree/v6.8.8), with locked
jose 6.2.13 and oauth4webapi 3.8.8, all MIT. The existing browser package/lock records
exact registry integrities; license-file hashes and versions are in the
[sanitized receipt](outbound-oidc-acceptance-2026-10-27.json). Installation scripts
are disabled. The current whole-browser npm audit reports zero known findings;
this is dated scanner evidence, not unknown-risk or independent approval.
No authentication runtime, Rust dependency, schema, custom crypto primitive, signing
producer or security/advisory exception changes.

The new [RP operation](../../tests/browser/issuer-standalone/standards/client.cjs)
uses library discovery, code/S256, state/nonce and explicit
[enableNonRepudiationChecks](https://github.com/panva/openid-client/blob/v6.8.8/docs/functions/enableNonRepudiationChecks.md).
That option requires actual JWKS/JWS verification in addition to ordinary HTTPS
and claim checks. A TLS-only code response is not counted as signature evidence.
The profile deliberately uses public client authentication and requires an ID token.
Tokens/callbacks stay private in memory; only fixed booleans leave the fixture.

Its [Fetch boundary](../../tests/browser/issuer-standalone/standards/fetch.cjs)
passes original response bytes to the library. Exact owned HTTPS origin/paths,
explicit fixture CA, ordinary hostname validation, loopback-only fixture address,
finite body/time limits and cancellation remain. Cookies, Authorization/proxy
credentials, redirects and insecure requests reject. This is not a production
transport override or a second application verifier. Three
[guard methods](../../tests/browser/issuer-standalone/standards/fetch.test.cjs)
check forbidden origins/credentials/body/method inputs and pre-aborted requests
before owned network I/O; CI requires them before the maintained parity runner.

All original Node-crypto, Rust SDK, native-loopback, replay, audience, browser and
cleanup assertions remain. Both modes now add third-party healthy code/JWS proof,
wrong-state rejection before any token POST, and successful third-party verification
before/after ordinary rollover, with stable same-client pairwise subject. This is
18 required true facts per mode, not 36 independent test cases or security approvals.

## Requirement review and bounded evidence

| Requirement/child | Source and concrete evidence | Scope |
| --- | --- | --- |
| Client registration/isolation — AUTH-37 | [Redirect policy](../../crates/auth-core/src/issuer/redirects.rs), [current client authentication](../../crates/auth-postgres/src/issuer/authentication.rs), [registration cases](../../crates/auth-postgres/tests/lifecycle/issuer/) and retained independent audience denial | Exact web/native callback and client/realm/credential/revision boundaries, stored pairwise policy and explicit consent. Public subjects remain unsupported by deliberate policy. Metadata alone grants no session/token. |
| One-use code/S256 — AUTH-38 | [Redemption](../../crates/auth-postgres/src/issuer/codes/redemption.rs), [code cases](../../crates/auth-postgres/tests/lifecycle/issuer_codes/) and current actual Node/Rust/third-party code grants | Wrong client/redirect/verifier, original deadlines, replay and existing ordered/concurrent redemption assertions remain. No new custom signature-concurrency experiment is introduced. |
| Claims/key protection/rollover — AUTH-39 | [Final signed commit](../../crates/auth-postgres/src/issuer/signing/issuance/completion.rs), [signing cases](../../crates/auth-postgres/tests/lifecycle/issuer_signing/), current ordinary rollover and third-party JWKS verification | Signing is staged before current-policy/code/source/key/time rechecks and final commit. Current/overlap publication and protected operator keys remain; no old-key fallback or remote JWT erasure claim. |
| Native refresh/revocation — AUTH-40 | [Family rotation](../../crates/auth-postgres/src/issuer/native_refresh/family/rotation.rs), [native cases](../../crates/auth-postgres/tests/lifecycle/issuer_native_refresh/), six actual owned browser/TCP-loopback cases and SDK refresh/logout controls | Replay/theft family reduction, audience/client/realm isolation and source/deadline/revoke race controls retain qualified real-PG evidence. In-memory test credentials do not establish OS-vault integration. |
| Independent RP and delivery parity — AUTH-41 | [Client completion](../../crates/auth-core/src/oidc/verification/client/completion.rs), [actual parity runner](../../tests/browser/issuer-standalone/run.cjs) and newly maintained third-party RP | Real PostgreSQL/SMTP/browser consent, separate cookie-free clients, actual executable/embedded factory, code rejection, normal key restart and public-key overlap. This bounded public-client profile is not universal or certified conformance. |

All five historical implementation child runs were freshly corroborated as
completed/success at their exact recorded source. Commit/run pairs are in the
receipt, including the distinct SAML activation observation. They are historical
child evidence, not a new hosted result for this branch. No CI rerun or standing
merge waiver is inferred.

## Fresh execution and cleanup

On exact clean 538b2bb the existing consent 8, signed-web 3 and native 6 cases pass.
The extended real executable/embedded runner passes the same 18 facts in each mode
and takes 611.737919seconds. Each mode preserves the actual 300second prepublication
interval plus the existing margin, genuinely reauthenticates, verifies healthy
old-key output, activates/restarts with the matching protected replacement and
verifies new output plus retained overlap. The Rust and third-party clients verify
both sides; the original Node client rejects a different trusted audience against
unchanged healthy bytes. No clock/ready-at/authentication-time rewrite, pending
operation across the wait, custom signing fixture, bypass/fuzz/stress experiment
or insecure fallback is introduced.

Each mode removes its random database, exactly two owned recipient messages and
private files. Fixture parents exit without unexpected diagnostics or emergency
cleanup; earlier child teardown semantics do not prove graceful runtime shutdown.
The enclosing checks require zero remaining owned databases/mail, then remove the
new PostgreSQL/Mailpit containers and exclusive volumes. Retained preview accounts,
passkeys, services and the original checkout are not used. All 73 protected hashes,
original change-set paths and the empty original index are checked separately.

The initial baseline at 4aa9688 passed its four domain profiles, including original
15-fact parity, then its enclosing Mailpit check failed with TypeError: the helper
already returns decoded JSON, but the driver attempted another decode. Cleanup
still completed; that overall receipt remains **failed**. The corrected driver
requires the actual dictionary and zero-message condition. It reran every profile
and enclosing check on new owned fixtures with a separate receipt; no assertion
or cleanup condition was removed to obtain the passing result.

Full frozen 538b2bb validation passes: formatting; strict default/all-feature
workspace/all-target Clippy; 171 default and 1,197 reported all-feature tests
(1,196 primary plus the isolated logging child), including 676 real-PostgreSQL
lifecycle cases, zero failed/ignored; compiled advisory and all-feature cargo-deny.
Inactive RSA/RUSTSEC-2023-0071 and existing warnings remain visible. The maintained
SAML source check remains 245 files/11 patches, with 11 existing Python methods
passing. Source integrity is not independent security approval. Exact log digests,
fixture/binary identities, dependency licenses and finite observations are retained.

The final source/history secret scans initially flagged the generated server binary
digest when its artifact path served as a JSON key. Rebuilding the exact qualified
feature profile reproduced both recorded executable hashes. The receipt now uses
explicit `artifact`/`sha256` rows for those public checksums. Failed redacted scans
remain local; default rules and exceptions are unchanged. No credential or added
allowlist entry is represented by that digest.

## Source SBOM refresh

After adding the third-party RP, the existing source inventory/SBOM commands were
replayed at exact `1fcb748c0e822d3dcd05ed34b3e395465b8d9ae8`. Nineteen helper
methods pass. Four source profiles generate thirteen Rust SBOMs; three npm SBOMs
cover website, presentation tooling and browser tools. Every selected normal/build
identity and graph reference is covered. Inventory/output hashes and counts are
in the receipt's `source_sbom_refresh` field.

The [browser-tool CycloneDX 1.7 SBOM](sboms/browser-tests-2026-10-27.cdx.json)
now covers all five dependency identities: Playwright/core 1.64.1 (Apache-2.0) plus
openid-client 6.8.8, jose 6.2.13 and oauth4webapi 3.8.8 (MIT). All dependency-license
fields are present. The scanner's application placeholder for `package-lock.json`
retains its missing own-root license field; it is not counted as another licensed
dependency, silently removed or assigned an invented expression. npm source
inventories contain 529 website locations, 33 presentation-tool packages and 5 browser
packages, with zero missing declared dependency licenses. Twenty-one shipped
notice/asset records remain separately hashed.

Cargo inventories retain 403 workspace/380 selected/23 resolver-only packages and
155 consumer/127 selected/28 resolver-only. Source SBOM normal/build selected versus
observed counts are 213/246 default, 332/354 SAML/OIDC, 368/388 all-feature and 127/155
consumer. These inventories include resolver overapproximation and dev-tool data;
they do not establish successful compilation on every target or actual binary
reachability. The earlier source checkpoint's two browser packages remain dated
historical evidence rather than being rewritten to five.

The previously audited pinned generator was reused after source/lock/policy/
bootstrap/binary checks; the current committed lock also matches its declared pin
and cached source byte-for-byte. No fresh bootstrap or tool audit is claimed.
Trivy runs offline with network disabled on owned copies of committed public
manifests and locks. No private/untracked original source, upload or application
service is involved. All sixteen output hashes/coverage records were checked.
Image/native/advisory inventories and their unresolved release dispositions retain
their existing source scope. AUTH-48's AUTH-47 prerequisite and every release/
independent-approval gate remain open.

## Maintainability and remaining release acceptance

The Fetch adapter, third-party operation and guard tests have separate named
owners; each stays below 100lines, functions below 50. Fetch-specific raw bytes and
abort lifetime remain separate from the older JSON/primitive observation client.
Existing case/rollover modules compose checks and retain original order. No
production policy/SQL/signing responsibility moves into tests, no public proof
constructor or generic framework is added, and no structural refactor or unrelated
cleanup is bundled. The large JSON receipt is generated factual data.

These checks close a local third-party RP evidence gap. The new profile exercises
public web code/S256/RS256, not a complete OP certification suite or third-party
confidential/native compatibility matrix. Public DNS/system-root deployment,
physical devices, OS credential vaults, registered-provider/manual verification,
independent security review and production operations remain unperformed. The
[ADR0040 limits](../architecture/adr/0040-independent-oidc-client-and-standalone.md)
retain independent review and production acceptance as separate gates. ADR0032's
SAML maintainer waiver supplies no independent approval or outbound waiver.
AUTH-36 and the outbound hard release gate therefore remain open; no release,
PR, merge, registry publication, deployment or external contact is performed.
