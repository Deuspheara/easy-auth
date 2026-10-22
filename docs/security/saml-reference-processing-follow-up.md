# SAML reference-processing findings follow-up

Internal engineering follow-up to AUTH-32, 2026-10-22. SAML production activation
remains source-locked. No independent approval, PR or external contact is supplied.

## Source and scope

Baseline application source: `006f9a36374941ab5ceb9d5a29b7889d2f526bbe`.
Patch0008 is incremental against that maintained seven-patch source. The new
inventory has243 files/eight patches; the upstream pin, original seven patches,
Cargo.lock, selected AWS-LC graph, existing tests and fixtures remain unchanged.
The generated inventory and new qualification receipt identify the actual source.
Earlier CI39823724381 qualifies only the baseline, not these corrections.

## Implemented corrections

**SR-2: backend execution scope.** The private maintained
`crypto/verify/execution.rs::preflight_backend_references` traverses all DSig
Signature descendants on the exact uppsala DOM passed to the backend, before
certificate attempts. It checks every direct SignedInfo/Reference URI with the
existing same-document resolver policy. All direct SignedInfo/Transforms
containers are checked, including duplicates, a superset of the backend's
first-container selection. Relative/absolute/network/attachment references cannot
reach backend reference resolution through this preflight. For strict profiles,
every transform element must be DSig enveloped-signature or exclusive C14N,
without comments; XPath/XSLT/other transforms are rejected before execution.
Missing mandatory structure still fails in the established backend.

The authenticated-signature RSA-SHA256/SHA-256, one plain-fragment Reference,
exclusive C14N and coverage checks remain after verification. Preflight does not
turn an unsigned-node scan into proof or apply authenticated acceptance to
unrelated signatures. It delegates all digests, signatures and canonicalization.
The single-signature API also checks/reuses its backend DOM. Explicit compatibility
mode retains provider-supported transforms; production never selects it.

Pinned Bergshamra0.9.2 source trace: `verify_all_document_with_source` enumerates
all DSig descendants; `verify_signature_node` selects direct SignedInfo/Reference
children; `verify_reference` resolves/transforms before signature verification.
Same-document references use the backend ID/DOM paths; external resolution and
its CWD fallback require a URI rejected here. Strict allowed transforms dispatch
only to enveloped-signature/exclusive-C14N implementations. Trusted-keys-only
selects from the configured manager, including same-document KeyInfoReference;
`bergshamra-keys::keyinfo::resolve_key_info` matches manager keys and does not load
RetrievalMethod files. Inline extraction/retrieval belongs to the unselected
non-trusted-key branch. These are reviewed source facts, not a new I/O experiment
or a universal guarantee about every public backend API.

**SR-3: composed admission.** Attaching deletion now shares sign-in's existing
semaphore after exact policy/registration comparison. One composition admits two
operations across both entry points rather than four. Each operation keeps its
repository, opaque purpose-bound proofs, pin/policy validation and final database
clock checks. Blocking closures still retain permits after timeout/cancellation.
The new public deletion method only joins capacity; it grants no proof or authority.
It refuses an occupied previous budget, including work left running after a
cancelled/timed-out caller, rather than detaching outstanding jobs from admission.
Additional independently constructed compositions/processes have additional
budgets. No process-wide registry or hard native-job termination is introduced.

## Evidence applicability and remaining findings

| Finding | Engineering disposition | Still required for activation |
| --- | --- | --- |
| SR-1 | No parser/C14N or cryptographic behavior replaced. Exact backend DOM/NodeId evidence, existing namespace guards and consumed-field validation remain. | Independent exact-profile disposition of quick-xml extraction versus uppsala/C14N/ID/selected-Assertion semantics for every consumed field. Existing vectors are bounded evidence, not universal equivalence. |
| SR-2 | Implementation correction above; source review covers backend enumeration, URI/transform dispatch and trusted-manager key resolution. Existing strict/compatibility regression tests remain unchanged. | Review this exact new patch and its regression receipt; no dedicated new non-candidate-reference fixture or side-effect probe was added under this session's constraints. Independent findings closure is not established. |
| SR-3 | Four-to-two amplification within composed sign-in/deletion corrected. | Approved deployment instance/process budgets and native CPU/RSS/duration/HTTP parsing assurance. Two permits and await timeouts alone do not establish that envelope. |
| SR-4 | Explicit change-impact mapping below; no dependency or native artifact changed from006f9a3. New source receives a new ordinary qualification receipt. | Source-scoped historical-evidence applicability decision and actual target OS/OpenSSL/native inventory/distribution/advisory review. Independent approval remains absent. |

The historical three-patch corpus is retained unchanged. Patches0004–0007 add
NameID qualifier propagation, ordered scalar attributes, established authentication
time and consumed-field namespace checks. Earlier raw/digest/C14N outcomes remain
historical observations, while those changed consumed-field paths need their own
current test/source mapping. Patch0008 narrows strict execution without changing
cryptographic algorithms or accepted authenticated identity fields. Current
unchanged upstream/core tests include exact algorithm policy, unrelated-signature
handling, namespace/transform rejection, signed coverage, projection and ordinary
producer round trips; they establish regressions only for those existing cases.
Capacity composition changes admission, not verification or identity semantics.

### Concrete applicability examples for independent disposition

These map recorded historical case names to maintained current tests/source;
they do not claim that a historical case was rerun on the new source.

| Historical examples | Current unchanged regression/source anchor | Applicability limit |
| --- | --- | --- |
| `profile-response-signature384`, `profile-assertion-digest512`, weak algorithms | `crypto/verify/tests/exact.rs::exact_policy_uses_authenticated_content_not_unrelated_signature_algorithms` and `exact_policy_accepts_only_sha256_pairs_for_both_signature_targets` | Authenticated algorithm policy retained; new preflight limits strict execution independently. |
| `profile-file-reference`, `profile-http-reference`, `profile-path-reference` | Existing candidate URI guard, plus new backend-DOM execution preflight; `signed_cid_reference_is_rejected_before_content_extraction` | Historical candidate cases do not test an off-candidate signature's reference. New closure relies on the reviewed traversal/dispatch correction and existing regressions, with independent disposition still required. |
| `wrong-key`, `untrusted-keyinfo`, `altered-signature`, `rollover` | Existing wrong-certificate/tampered-signature/no-metadata-pin and rolling-certificate tests in `crypto/verify.rs` | Trusted-manager, digest and signature logic unchanged; historical native version still differs. |
| `forged-sibling-before`, `assertion-forged-after`, duplicate IDs | Existing verified-content/coverage/first-invalid-signature and unrelated-signature tests in `crypto/verify.rs` | No claim that all cross-parser/ID/selection combinations are covered. |
| `doctype`, `resource-external-dtd`, file/HTTP entity cases | Existing quick-xml rejection before backend parsing and `tests/namespace_version.rs` namespace/consumed-attribute tests | Prepass source retained; historical bounded no-I/O observations do not establish current universal resource/parser assurance. |
| `multiple-roots`, `structure-trailing-open`, other trailing-structure cases | Unchanged patch0003 complete-document rejection; existing XML/parser tests and `rejects_multi_root_wrapping_attack_before_signature_verification` | Source unchanged in this patch; scope remains tested shapes, not parser equivalence proof. |
| Qualifiers/scalar groups/established auth time added after the corpus | Core `verification/subject_tests.rs`, `verification/tests.rs`; maintained producer/projection tests; real-PG `verification/qualifiers.rs`, `identities/attributes.rs`, `identities/authentication_time.rs` and `identities/account_deletion/authentication_time.rs` | Historical three-patch corpus cannot supply coverage for fields it did not carry. Current tests/source and independent semantic review are separately needed. |

The root lock still selects aws-lc-sys0.46.0 (bundled AWS-LC5.11.0), not the
historical sys0.45.0/AWS-LC5.7.0 native assessment. No old native assurance is
silently transferred. Current compiled advisory/license checks are separate from
independent review or approval of a specific deployment image. A deployment image
has not been selected here, so its OpenSSL/OS inventory cannot be invented.

The Assertion Issuer remains the configured identity issuer. Separate Response
Issuer equality remains an explicit profile-review question; no new contract is
silently imposed without an agreed profile and applicable tests.

## Verification

Final local checks on the maintained source:

- `cargo fmt --check`; vendor Rust2021 formatting; strict locked default/all-feature
  workspace/all-target Clippy; isolated core `saml-verification` strict Clippy: pass.
- `cargo test --locked --workspace`:115 passed/0failed/0ignored. Final frozen-source
  `cargo test --locked --workspace --all-features`:799 passed/0failed/0ignored,
  including466 real PostgreSQL lifecycle cases and131 HTTP integration cases.
- Final focused `cargo test --locked --workspace --all-features saml::`:129 passed,
  including96 real-PG SAML cases; none failed/ignored.
- Unchanged selected-graph upstream/core qualification:1115 passed/0failed/0ignored,
  46 result groups. [New exact inventory/graph receipt](../../tests/provider/saml/rust-policy/results/2026-10-22-backend-reference-policy.json).
- Eleven source/runner checks;243-file/eight-patch integrity; exact incremental
  reconstruction against the unchanged seven-patch HEAD; all existing vendored
  tests/fixtures byte-identical: pass.
- Warning-free all-feature docs; default/composed standalone and embedded builds;
  isolated SAML server check;16 closed-SAML and13 existing OIDC startup cases: pass.
- Relative links, historical30-input manifest against006f9a3, unchanged source
  activation guard, diff checks and scoped redacted Gitleaks: pass.

An initial broad run, overlapping source finalization/other builds, stopped at
707 passed/8 failed in the PostgreSQL target. Seven positive-control failures
surfaced Unauthorized and one accepted-control assertion failed. All eight then
passed in both the focused SAML run and the complete frozen-source repeat with
normal four-worker scheduling. No assertion, timeout, clock policy or verifier
result was relaxed. The initial cause is not established; concurrent load or clock
skew must not be asserted as proven. Preserve this non-reproduced observation in
the review evidence and investigate if it recurs; a green rerun is not its cause
analysis. No local failure remains in the final frozen-source checks.

The final Git commit and its new exact-head hosted CI receipt belong in AUTH-32;
CI39823724381 remains baseline-only. A successful local run is not a claim that
new hosted CI or independent security approval has completed.
An initial regression run failed two existing compatibility cases because the
first draft restricted compatibility transforms. The correction preserves that
explicit API and restricts strict execution only; no assertion or fixture changed.
The first staging attempt was invalidated while the source inventory was being
finalized; it is not a qualification receipt for the delivered source.

No new adversarial XML/cryptographic fixtures, bypass experiments, custom probes,
fuzz/stress or signature-concurrency experiments were performed. Remaining review
requirements do not authorize those activities. Independent reviewer identity,
report, exact-scope findings closure and explicit production approval remain blank.
