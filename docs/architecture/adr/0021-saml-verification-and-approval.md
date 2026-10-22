# ADR 0021: SAML message verification and staged approval

Date: 2026-10-21. Status: accepted engineering direction; **production approval pending**.

## Decision

Use the complete `saml-rs` strict message component over Bergshamra/AWS-LC as
the preferred qualification path. Keep exact RSA-SHA256/SHA-256, exclusive
canonicalization, configured certificate trust and verified-object coverage
mandatory. Do not implement XML signatures, reference resolution or
canonicalization in easy-auth. A signature success boolean cannot authenticate
an independently parsed Assertion.

This selects an integration direction, **not an approved production dependency**.
The assessed source is saml-rs 0.6.1 at
`3b289001a7a84d5a7ff7af2671991ab7098090bd`, defaults disabled and only
`crypto-aws-lc`. Its recorded lock selects Bergshamra 0.9.2. The existing three
[qualification patches](../../../tests/provider/saml/rust-policy/README.md)
provide the exact signature/digest profile and complete-document EOF check.
They are neither an upstream release nor an independently approved maintained
fork. Do not silently replace them with the broader unpatched strict profile.
Production adoption requires upstream acceptance or a separately reviewed,
explicitly owned patch-maintenance/distribution decision. No new cryptographic
implementation or unreviewed production fork is authorized by this ADR.

Proceed with ordinary configuration, metadata and request/persistence integration
while that adoption decision is open. Keep such components opt-in and incapable
of converting unverified XML into user/session authority. Default application
composition must expose no SAML ACS. Missing approval cannot select unsigned,
compatibility, inline-key or alternative-algorithm fallback.

## Maintained distribution decision

[ADR 0027](0027-maintained-saml-dependency.md) supersedes the unresolved ownership
choice: easy-auth now maintains and distributes the existing patched source in
this repository. The project owner's acceptance covers maintenance, not security
approval. Upstream merging is no longer a prerequisite. The original three
qualification patches, source pin, AWS-LC-only selection and all production
security gates are retained. ADR0027 also records ordinary producer maintenance
patch0004 and its separate source-specific regression evidence.

## Reproducible gated source integration

For ordinary integration engineering, retain the exact qualified source as a
Cargo package-layout dependency under `third-party/saml-rs`, excluded from the
four-package workspace. This is an explicitly identified local qualification
snapshot, not a claimed maintained upstream release or approved production fork.
Only the three already recorded patches are applied. The package retains source,
MIT licensing and all packaged upstream tests/vectors; it generates no new XML or
key fixtures. Do not refactor its large upstream modules or introduce another XML
verification engine. The source pin/patch diff is the third-party review boundary.

The file/patch inventory is checked by `scripts/check_saml_source.py` before builds
and scanning. Four ordinary integrity scenarios cover exact source, changed docs,
extra files and changed patches. Secret-scan exceptions are bound to exact public
upstream vector values and exact paths, not entire files. Other values at those
paths remain scanned. No upstream advisory ignores are inherited. The original
full package lock's inactive/yanked entries remain visible; the adopting compiled
feature graph needs its own unsuppressed advisory/license/native review.

Requests/certificate components still disable all saml-rs crypto features. Merely
importing the qualified source does not activate a verifier, provider or ACS. Later
runtime integration must deliberately select only AWS-LC and retain verified-object
coverage, exact algorithms, pinned trust, request/replay ownership and lifecycle
policy. Explicit maintained distribution/patch ownership acceptance and independent
review remain mandatory production gates, even after engineering builds pass.

## Evidence and alternatives

Current release/activity metadata was checked against the upstream repositories
and crates.io on this date. Activity is maintenance evidence, not an audit.
Historical observations remain in the linked assessments; no new adversarial
probe or cryptographic bypass experiment is required by this decision.

| Option | Maintenance, integration and deployment | Verification boundary and decision |
| --- | --- | --- |
| [Samael 0.0.22](https://github.com/njaremko/samael) / [xmlsec](https://github.com/lsh123/xmlsec) | MIT Rust wrapper; xmlsec has a longer native deployment history. Requires compatible libxml2/xmlsec/OpenSSL and build tooling. Samael last push July 17; xmlsec October 20. Native distribution versions/licenses/advisories require separate inventory. | Established native C14N/signature engine. The assessed wrapper internally uses recovery-enabled parser defaults and exposes no strict parser policy at that boundary. Existing repository observations retain malformed/DTD acceptance and an ignored-positive failure. Reject the current wrapper for production; a maintained native hardening path remains an alternative, not an implemented two-flag fix. |
| [saml-rs 0.6.1](https://github.com/salasebas/saml-rs) | MIT; Rust 1.88 minimum fits our 1.95 toolchain. Last push October 13; pre-1.0, no external audit established. Defaults pull broad providers/features; explicitly select AWS-LC only. Native AWS-LC build/distribution requirements remain. | Complete message/profile layer delegates C14N/crypto to Bergshamra and binds returned Assertion coverage to verified references. Existing patched qualification provides the narrowest matching policy. Preferred candidate, subject to maintained adoption and independent approval. |
| [Bergshamra](https://github.com/kushaldas/bergshamra) directly | BSD-2-Clause; current published 0.11.0, last push October 16. Backend and XML dependencies are version-specific. Current 0.11 documentation is not evidence for the assessed 0.9.2 graph. | Exposes verified Signature/reference nodes and digest evidence, trusted-key and strict-reference controls. It remains an XML security engine: direct adoption would move more SAML object/profile orchestration into easy-auth. Prefer the complete SAML component; do not infer a verified identity from positional strict mode alone. |
| [Gamlastan 0.10.0](https://github.com/kushaldas/gamlastan) | BSD-2-Clause; active October 20 source at `e1c4680`. Complete SAML types/profiles and documented hardening, including verified-object binding. Its current manifest unconditionally enables Bergshamra and Kryptering RustCrypto/legacy/PQ/PKCS11 support; it exposes no minimal AWS-LC-only feature contract. | Worth tracking as an alternative. Its documented review is not our independent approval. The current backend/feature contract does not match our narrowly qualified dependency graph; no crypto implementation is replaced or silently broadened to adopt it. |
| Java OpenSAML / another runtime service | [Shibboleth OpenSAML](https://shibboleth.atlassian.net/wiki/spaces/OSAML/overview) is an established Java SAML implementation, distinct from the Rust `opensaml` compatibility package. | Introduces another runtime/service and a new authenticated assertion-transfer boundary. That deployment cost is not justified for the current four-crate Rust architecture. |

The Rust `opensaml` and `samlet` packages currently reexport saml-rs; they are not
independent verifier alternatives. A parser-only replacement or parse/serialize
bridge in front of an unchanged verifier does not establish canonicalization or
signed-payload correctness.

The existing [comparison](../../research/saml-verifier-options.md),
[exact-policy record](../../research/saml-exact-policy.md),
[dependency review](../../research/saml-dependency-review.md) and
[document-completeness record](../../research/saml-document-completeness.md)
support this direction. Their bounded results are historical, version-scoped
evidence. A package with no matching advisory entry is not thereby audited;
rerun compiled-graph, license and native-backend checks on the adopted lockfile.

## Ordinary upstream canonicalization checks

On 2026-10-21, the unchanged upstream `bergshamra-c14n` library/tests passed:

| Release and immutable source | Result |
| --- | --- |
| 0.9.2, `747a5a877a2415fc0d58286533ae51b22cc966c3` | 32 passed, 0 failed/ignored |
| 0.11.0, `5548cc7c9095c3932f0c791fe63e417dffe88af3` | 41 passed, 0 failed/ignored |

Both used Rust/Cargo 1.95.0 on aarch64-apple-darwin, their own unchanged lockfiles,
and `CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 cargo test --locked --manifest-path
/path/to/release/Cargo.toml -p bergshamra-c14n --lib --tests`. An initial attempt
stopped during compilation with insufficient disk space; the sequential reruns
completed. No custom XML, cryptographic fixture, fuzzing or load scenario was added.
These are library regression results, not a complete C14N conformance assessment,
reference-binding review, AWS-LC verification test or application interoperability
approval. The newer release's passing suite does not qualify the older graph.

The [0.11.0 changelog](https://github.com/kushaldas/bergshamra/blob/5548cc7c9095c3932f0c791fe63e417dffe88af3/CHANGELOG.md)
records substantial C14N/DOM changes in 0.10.0 and later crypto dependency changes.
Its [advisory configuration](https://github.com/kushaldas/bergshamra/blob/5548cc7c9095c3932f0c791fe63e417dffe88af3/.cargo/audit.toml)
contains advisory ignores. We do not copy those ignores or infer applicability
from upstream commentary; any upgrade needs a fresh inventory and unsuppressed
assessment of our actual compiled feature graph. This evidence does not select
0.11.0 for the assessed saml-rs candidate.

## Application responsibilities

Keep the four workspace crates and inward dependency direction. Core owns typed
trusted connection/profile configuration, opaque operation/verified-identity
proofs and use cases. PostgreSQL owns realm-scoped registration, request/replay
records, current-policy locking and final identity/session transactions. Axum owns
the browser/ACS boundary; server composition owns explicit activation and worker
lifetime. There is no generic protocol plugin or independent embedded policy copy.

The initial profile is SP-initiated POST responses to an exact HTTPS ACS. IdP
entity, SP entity, endpoint, NameID and certificate policy come from trusted
configuration, never callback-selected metadata. No IdP-initiated sign-in,
encrypted Assertion, Artifact, SOAP, SLO or dynamic metadata fetch is implied.
Reject unsupported paths rather than using compatibility modes.

Certificate trust is explicit pinning to a realm/connection revision with bounded
overlap windows. KeyInfo cannot introduce trust. Validate certificate/key material
through the selected library, retain applicable validity/algorithm policy and
record whether the deployment uses pinned leaf certificates or a reviewed PKI
model. Never equate loading an X.509 public key with chain/validity validation.
The opt-in `saml-certificates` configuration slice uses existing OpenSSL 0.10.81
bindings for X.509 parsing/validity comparisons, canonical DER and RSA key policy
(at least 2048 bits). It pins one/two exact leaves and explicit approval windows;
it does not perform PKI chain/revocation/EKU validation, XML signature operations
or backend selection. This is a separate optional configuration dependency edge,
not approval of the proposed AWS-LC signature graph. Native OpenSSL updates and
licenses remain part of deployment inventory. See the [SAML guide](../../guides/saml.md).

Rotation or disable must invalidate pending operations and source-bound sessions
according to the same current-source rules used elsewhere in the library.

Persist an unguessable AuthnRequest ID and independent browser/RelayState proof
with the exact realm, connection/client revision, ACS, purpose and original cap.
Use the database clock and one-use consumption; do not repurpose an OAuth PKCE
transaction or accept an unsolicited correlation value. Retain original deadlines
across verification and final transactional waits.

Consume only the library's verified Assertion projection. Require expected issuer,
SP audience, destination, bearer recipient, response and bearer InResponseTo,
NotBefore/NotOnOrAfter and bounded authentication/issue times. Check NameID format
and qualifiers under trusted policy. Subject/attribute selection must be covered
by verified references; display/email attributes cannot select another local owner.
No matching-email linking, fabricated contact or token-issuance freshness.

Atomically serialize replay ownership and current source/identity policy before
issuing a local session. Replay keys must include realm and connection plus
response/assertion identifiers and retain protection for the full accepted window.
A verification result alone creates no user/session. JIT defaults to deny;
provider-required accounts retain safe lifecycle restrictions. Deletion/linking
cannot reuse a sign-in proof or silently fall back to a weaker credential.

## Evidence required for approval

Current engineering evidence as of 2026-10-22. These states describe the opt-in
components, not normal server activation. [ADR 0023](0023-saml-identity-session-commit.md),
[ADR 0024](0024-saml-web-delivery.md), [ADR 0025](0025-saml-account-deletion.md)
and the [provider guide](../../guides/saml-providers.md) record the implemented
boundaries and scoped results.

| Gate | Implemented | Tested | Reviewed | Independently approved |
| --- | --- | --- | --- | --- |
| Dependency source/features/patch maintenance and distribution | Project-owned source distribution under ADR 0027, four recorded patches and AWS-LC-only graph; security approval pending | Source inventory, upstream canonicalization tests and compiled-graph advisory/license checks; not independent approval | Internal assessment only | Pending |
| XML/C14N/signature/reference/verified-payload binding | Library candidate plus recorded patches; no application XML verifier | Existing bounded vectors/corpus and ordinary integration; parser/reference/backend assurance outstanding | Internal source assessment only | Pending |
| Outgoing metadata, browser-bound request state/preparation and leaf-pin configuration | Opt-in AUTH-33 components; preparation grants no authority | Core and real PostgreSQL configuration, correlation, cancellation, rollover and isolation checks | Internal implementation/maintainability review only | Pending |
| Signed message/condition projection | Concrete AUTH-34 adapter returns an opaque proof | Ordinary signed component controls and the documented actual Keycloak profile; broader profile assurance pending | Internal implementation review only | Pending |
| Exact-source identity policy and opaque mapping | AUTH-35 default-deny configuration and exact persistent-subject mapping; no attribute-selected authority | Core/real PostgreSQL mapping, rollback, migration and isolation; actual Keycloak JIT/ownership checks; qualified NameID/attribute evidence incomplete | Internal implementation review only | Pending |
| Durable Assertion replay and identity/session lifecycle | Atomic replay/identity/session/audit commit, current-source invalidation and separate purpose-bound confirmed deletion | Real PostgreSQL replay, rollback, lock ordering and tenant isolation; scoped HTTP/browser and actual Keycloak deletion evidence | Internal implementation/transaction review only | Pending |
| End-to-end IdP interoperability, identity/session and lifecycle | Explicit gated HTTP composition; normal SAML disabled | Ten Keycloak rollover/realm and eight deletion cases, including retained-SSO challenge/newer signed authentication; older-authentication-time wire, qualified profiles and additional IdPs incomplete | Internal fixture/evidence review only | Pending |
| Independent security review and activation decision | Reviewer/scope/decision record still required | No independent approval established by CI, internal review or owned interoperability | Pending | Pending |

The retained-SSO implementation at `a2a89a96c61e1aa8f18a6dd2564417ad5e73fb7b`
passed [full hosted CI 39771675708](https://github.com/Deuspheara/easy-auth/actions/runs/39771675708).
The later cache-work commit `491aa4beee0ceb11443cb9730150154285116840` passed
[full hosted CI 39773799129](https://github.com/Deuspheara/easy-auth/actions/runs/39773799129),
including workspace, real PostgreSQL, isolated features, browser/provider, source,
secret and dependency-policy checks. These receipts do not clear any pending
maintenance, XML/backend or independent-approval requirement.

Ordinary engineering may run established upstream test vectors and documented
integration scenarios, including expected rejection, replay, rollback and tenant
isolation cases. This session does not create custom adversarial XML/signature
probes, bypass experiments, fuzzing or resource-exhaustion campaigns. Assurance
requiring those activities is recorded separately for an authorized review.

Activation requires every mandatory gate, resolved findings and explicit approval
for the actual shipped source/features/configuration. AUTH-32 remains open;
AUTH-33/34/35 can progress as gated engineering slices without pretending the
production dependency or SAML service is independently approved.

## Concrete opt-in adapter boundary

The `saml-verification` component now selects that exact source with only AWS-LC.
The root lock resolves Bergshamra 0.9.2, uppsala 0.10.1, kryptering 0.6.0/AWS-LC,
aws-lc-rs 1.18.2 and aws-lc-sys 0.46.0. The latter two differ from the candidate's
original standalone lock (1.18.1/0.45.0); historical qualification is not claimed
for the newer native versions. The adopting root lock and fresh ordinary tests,
compiled-graph audit, license/source/feature inventory are separate evidence.
No RustCrypto, legacy, PKCS#11, post-quantum or FIPS feature is selected. AWS-LC
needs its native C/CMake toolchain; existing OpenSSL X.509 configuration still
needs OpenSSL development/runtime support. CI installs those prerequisites.
No advisory ignore or license exception is added. Native backend release/advisory
mapping and ongoing distribution/patch ownership approval remain required.

The adapter requires both authenticated signature coverages, narrow algorithms,
current active leaf pins and strict zero-skew typed protocol checks. It calls the
library's complete typed message boundary, not a signature boolean plus separately
parsed XML. Local generated metadata contains only trusted configuration and one
pin. A required replay callback stages authenticated hash/deadline reservations;
that is not durable replay protection or identity authority. Full fixed profile,
opaque-proof limits, worker cancellation semantics and separate atomic identity/
session commit are documented in the [component guide](../../guides/saml.md).
Independent XML/backend review, maintained dependency acceptance and the remaining
profile/lifecycle assurance requirements stay mandatory before activation.


Persistent NameID additionally enforces the protocol's 256-character bound
(Approved Errata 05 E78), with the original 1024-byte cap retained. Admission and
local-session time caps remain separate: the verified proof carries signed
SessionNotOnOrAfter, when present, limited by the fixed 24-hour age policy from
actual AuthnInstant (E26/E79). Final session creation must honor that upper bound
and the independent short admission cap. This is ordinary profile integration,
not a claim of complete SAML compliance or passed independent security review.
