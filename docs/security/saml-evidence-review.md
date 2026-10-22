# SAML maintained-dependency evidence review

Reviewed 2026-10-22. This is an internal engineering/source review. It is not an
independent security audit or production activation decision. Maintenance ownership
is accepted in [ADR 0027](../architecture/adr/0027-maintained-saml-dependency.md).
No PR, upstream/reviewer contact, new adversarial XML/signature probe or verifier
change is part of this review.

## Source and evidence scope

The maintained source is saml-rs 0.6.1 at upstream revision
`3b289001a7a84d5a7ff7af2671991ab7098090bd`, with three retained patches plus ordinary producer patch 0004
and a 235-file inventory. The application selects only `crypto-aws-lc`. Its lock
contains Bergshamra 0.9.2, uppsala 0.10.1, kryptering 0.6.0, aws-lc-rs 1.18.2
and aws-lc-sys 0.46.0. Earlier standalone tests used different AWS-LC versions;
those results cannot silently qualify the application's newer native graph.

The [exact-policy evidence](../research/saml-exact-policy.md) and
[document-completeness evidence](../research/saml-document-completeness.md) retain
real security testing, including 1,089 passing candidate tests and 118 recorded
outcomes across 59 scenarios. The two native-mode tags do not make those 118
independent scenarios. Traced resource observations have working positive and
failure controls; they are a separate observer, not an independent security review.
These historical records are preserved without rerunning their custom probes.

The new `scripts/qualify_saml_dependency.py` runs unchanged dependency tests and
core SAML tests in a disposable application workspace. It starts from the actual
application lock, requires identical active normal/build package versions and
features for the selected core `saml-verification` profile, then tests locked.
The tracked Cargo configuration/test-worker budget is staged and its hash recorded.
The root lock/source remain unchanged during qualification. The historical
three-patch first successful local run reports
**1,106 passed, zero failed, zero ignored, 46 result groups**. This combined count
includes core and dependency tests; it is not 1,106 separate security experiments.
The [finite local receipt](../../tests/provider/saml/rust-policy/results/2026-10-22-shipped-graph.json)
records the final reproducer hash, compiler, source inventory and exact selected graph.
The finite report records both lock hashes and the source inventory. Different
platforms/deployment features still need their own corresponding verification.

Existing full application receipts include final head `d41b9a9`,
[CI 39782028907](https://github.com/Deuspheara/easy-auth/actions/runs/39782028907):
formatting, strict Clippy, default/all-feature workspace and real PostgreSQL,
isolated features, browser/startup, advisory/license and secret checks passed.
Actual Keycloak evidence covers ten rollover/realm cases and eight deletion cases,
including retained SSO, real password challenge and newer signed authentication.
It does not establish other IdPs or every optional SAML profile.

The prior maintenance-ownership commit's local verification passes formatting, strict default/all-feature
all-target Clippy, nine source/qualification-runner regressions, and the default
111/all-feature 782 workspace checks, including 456 real PostgreSQL lifecycle
tests. Those local workspace reruns used one test worker. The initial default run
under normal scheduling had two existing password/recovery HTTP 504 failures at
the unchanged 15-second request boundary; both suites passed with one worker.
No assertion, request timeout, password policy or signature behavior was changed.
CI retains the repository's normal scheduling. All verification steps of
[CI 39794312897](https://github.com/Deuspheara/easy-auth/actions/runs/39794312897)
passed for maintenance commit 728b15d, including the new qualification runner.

The runner's development failures were confined to its staging/reporting logic:
a standalone graph lacked features unified by the application; staging the real
workspace corrected that mismatch. A reporting refactor then referenced an extracted
local variable; the full report-path regression now covers successful output and
rejection of ignored tests. The final runner and receipt pass with zero failures.

## Ordinary NameID producer maintenance

The existing typed IdP producer dropped qualifiers while converting Subject to
its raw User, before the built-in renderer. A new ordinary signed real-PG test
failed for a mismatched qualifier before patch 0004 and passes after it. The patch
retains typed NameID attributes using the existing XML writer and signer. It
changes no cryptographic verifier, trusted keys, algorithms or application policy.
Custom rendering of qualified successful subjects now fails explicitly; PAOS is
unchanged. Two library tests cover signed round trips in legacy and Follow modes
and refusal of lossy custom rendering. Seven real-PG verifier scenarios cover
absent, exact, IdP-only, SP-only, mismatched and unsupported alias qualifiers.

The [four-patch finite receipt](../../tests/provider/saml/rust-policy/results/2026-10-22-qualified-nameid.json)
reports **1,108 passed, zero failed, zero ignored, 46 groups** on the selected
application graph. The earlier 1,106-test receipt and historical security corpus
remain unchanged and do not claim to qualify the new source. This ordinary producer
fix establishes local qualifier delivery to the unchanged verifier; it does not
establish broader IdP interoperability or independent security approval.

Local application verification for patch0004 passes `cargo fmt --all -- --check`,
strict default/all-feature all-target Clippy, 111 default and 783 all-feature
workspace result counts, including 457 real PostgreSQL lifecycle tests. Both
workspace runs use `RUST_TEST_THREADS=1`; CI retains normal scheduling. The
maintained source's changed Rust files also pass rustfmt. Eleven source/runner
regressions, exact incremental patch reconstruction, the 235-file/four-patch
inventory and the changed-source secret scan pass. The confirmed pre-fix qualifier
regression is the only new failing control; no verifier, timeout or assertion was
weakened. Hosted verification of this new source remains separate from728b15d.

## Internal source review

All paths below are relative to this repository. They identify the reviewed
contracts; a passing source inspection does not establish universal parser or
canonicalization correctness.

| Invariant | Reviewed path and observation | Evidence and remaining limit |
| --- | --- | --- |
| Required signatures/algorithms | `crates/auth-core/src/saml/verification/configuration.rs` requires signed Response and Assertion, audience validation and StrictRsaSha256. `projection.rs` requires both authenticated coverages and RSA-SHA256. | Existing exact-policy and application tests pass. No unsigned/alternate-algorithm fallback is enabled. |
| Trusted key source | `third-party/saml-rs/src/crypto/verify.rs` constructs a KeysManager only from supplied configured certificates, enables trusted-keys-only and requires reference digests. | Existing trust/rollover tests and Keycloak pin retirement pass. Inline KeyInfo does not create a configured key. |
| Reference/digest evidence | `crypto/verify.rs::verified_targets` requires verified digests and resolved same-document ID targets; strict profile policy reads the verifier's authenticated signature node in `crypto/verify/profile.rs`. | Existing tests pass. Independent review must still cover ID/namespace/reference equivalence between local quick-xml and verifier uppsala trees. |
| Consumed payload | `crypto/verify.rs::verified_content` selects covered content. `flow.rs::verify_and_prepare` carries it into extraction; `api/sp.rs::session_from_verified_flow` preserves coverage in the typed session. | Application consumes this typed session, not a signature boolean followed by its own XML parser. The two-parser boundary remains an explicit focused-review item. |
| Identity and presentation | `verification/subject.rs` enforces persistent NameID, exact qualifiers when present, byte/character bounds and no SPProvidedID. `projection.rs` retains exact trusted registration. | Core policy and actual unqualified persistent-profile tests pass. Maintained producer patch 0004 has ordinary signed library round trips and seven real-PG verifier qualifier cases; broader actual IdP qualified-profile acceptance remains open. No email/attribute/role ownership fallback exists. |
| Conditions and correlation | `flow.rs::validate_context` checks response correlation/destination and delegates bearer recipient, audience and time checks to `assertion_acceptance.rs`. Core `verification/flow.rs` supplies trusted pending context and zero skew. | Existing correlation/profile tests and actual provider flow pass. These checks use the required authenticated message path. |
| Signed times and final authority | `verification/timing.rs` keeps admission and signed session/authentication caps separate. PostgreSQL completion/deletion rechecks original/current-source/final DB-clock caps. | Real-PG deadline/rollback/order tests and actual signed timing pass. Newly issued deletion responses carrying older-than-five-minute AuthnInstant remain without wire acceptance evidence. |
| Durable replay and tenant scope | `crates/auth-postgres/src/saml/replay.rs` reserves two hash keys in stable order within the authority transaction, scoped by realm/connection and retained across revisions. Identity/session writes remain in the same transaction. | Existing real-PG replay, rollback and DB-only ordering/realm tests pass. No signature-concurrency experiment is added. |
| XML completeness/resource admission | `third-party/saml-rs/src/xml/dom.rs` retains bounded parsing, DTD rejection and the complete-document patch. Core input and worker admission stay bounded. | Existing regressions pass. The review does not establish a native CPU/memory budget or qualify every namespace/ID construction. No stress/resource probe is run. |
| Attribute projection | `model/extract.rs::attributes_from_extract` reconstructs name-keyed values with NameFormat=None. | Confirmed limitation. Attribute-selected policy remains unavailable; ordinary tests cannot repair missing authenticated data. Any extension needs a lossless maintained-library contract and its own review/tests, without a raw-XML bridge. |
| Production composition | `apps/auth-server/src/application.rs` and `crates/auth-axum/src/router.rs` do not compose SAML. | Experimental components remain explicit; this work adds no normal ACS or startup switch. |

### Pinned leaves and the backend's insecure flag

The maintained library sets `DsigContext::with_insecure(true)` together with
trusted-keys-only. In the selected Bergshamra 0.9.2 `bergshamra-dsig/src/verify.rs`,
trusted-keys-only chooses a preconfigured manager key; the insecure flag skips the
separate X.509 chain-validation branch. It does not skip signature or reference
verification. Easy-auth deliberately uses exact leaf pinning, not PKI chain trust.
`certificates/pin.rs` parses canonical DER, requires RSA >=2048 and constrains the
operator approval interval to certificate validity. `trust.rs` selects active pins
at trusted DB time; final proof authority retains the approval deadline.

This documents the existing trust model rather than changing the flag or relaxing
certificate policy. A deployment requiring chain building/revocation/EKU must not
infer those properties from this leaf-pinning integration. Independent review
must confirm the selected backend and pinning contract, including KeyInfo-reference
handling; the name of a flag alone is neither approval nor a demonstrated bypass.

## Remaining work and activation decision

- Maintenance ownership and the requirement to wait for an upstream merge are
  resolved by the project owner's decision and ADR 0027. Production security
  acceptance remains a different gate.
- The shipped-version regression gap is addressed by the new graph-matching test
  runner. Hosted CI39794312897 passed the new runner and existing application
  checks for the original three-patch maintenance commit.
- Focused independent review still needs the exact source/patches/features, XML
  parser/ID/namespace/reference equivalence, canonicalization and native backend,
  trust configuration and signed-field binding. Record reviewer, report, findings
  resolution and the explicit decision. Internal agent review cannot fill this row.
- Resource-budget/concurrent native-path assurance remains separately pending
  under the current restriction on custom stress/probe experiments.
- Lossless attributes, broader actual IdP qualified-profile acceptance and the older
  authentication-time wire case remain open under AUTH-35. They are not silently
  claimed supported by the working Keycloak profile or the maintenance decision.

Production SAML remains disabled. With external contact prohibited and no
independent report provided, this session can prepare review evidence and finish
ordinary engineering but cannot truthfully manufacture independent approval.
