# SAML parser/C14N and native/resource follow-up

Internal engineering assessment, 2026-10-22. Production SAML remains disabled.
No PR, upstream/reviewer contact, new adversarial XML/crypto fixture, bypass
experiment, fuzz/stress/resource probe or custom signature-concurrency test.

## Exact scope

Base source58e8d343d65e6926921b288ed5f60648d4764b28 has successful
[CI39842005917](https://github.com/Deuspheara/easy-auth/actions/runs/39842005917).
This follow-up adds maintained patch0009 and concrete-core process admission.
It has a new244-file/nine-patch inventory; the upstream pin, original eight
patches, test sources, Cargo.lock and runtime dependency graph are unchanged.
That earlier run is baseline evidence, not hosted verification of this increment.
[ADR0030](../architecture/adr/0030-saml-parser-binding-and-process-admission.md) records the deliberate interpretation/admission changes and compatibility.

## SR-1: parser interpretation and selected payload

Source inspection confirmed two local interpretation omissions: xmlns declarations
entered the local-name attribute list, and literal text/CDATA EOLs used raw content.
Patch0009 excludes namespace declarations after their resource checks and uses the
existing quick-xml XML1.0 normalization API. Character-reference expansion remains
separate, so a referenced CR is not mistaken for a literal source line ending.
No XML or canonical preimage is rewritten.

`crypto/verify/document.rs` now checks the accepted message's actual parser views
before any backend certificate/signature attempt:

| Fact | Runtime binding |
| --- | --- |
| Element identity and selection | Match the entire ordered tree's original byte ranges/local names; select first bearer Assertion once and bind its range to an actual backend NodeId |
| Element/attribute namespaces | Stream the same source with NsReader; compare expanded names to the backend DOM; normalize raw namespace-binding values with quick-xml's Attribute API |
| Attribute interpretation | Exclude xmlns in both ordinary attribute views; compare every ordered local attribute name/value after XML normalization |
| Text/CDATA interpretation | Compare local concatenated direct text against backend direct Text/CData segments without building another combined text copy |
| DSig dispatch/selectors | Strict preflight and authenticated policy require unqualified Algorithm/URI; InclusiveNamespaces uses the exclusive-C14N namespace, at most one parameter, and unqualified PrefixList |
| Signed-payload evidence | Preserve backend resolved-reference NodeIds and signature policy; classify Assertion coverage for the selected NodeId, preserving all-assertion coverage checks |
| XML version | Strict verification requires XML1.0 or implied1.0; separate compatibility APIs retain their documented profile selection |
| DTD/entity handling | Backend Parser explicitly forbids DTDs/entity declarations independently of the prior local rejection; namespace awareness stays enabled |

The local ID scan remains ID/AssertionID; backend indexing additionally recognizes
Id/id/xml:id. The backend's duplicate-ID rejection remains mandatory. Agreement
checks bind the actual values/tree and selected node; an additional backend ID
alias cannot supply a different extraction tree or selected-Assertion identity.
No account mapping policy, issuer/audience/correlation/time/replay check changes.

Schema validation remains selective. These checks remove an unchecked representation
boundary for accepted input; they do
not prove the backend canonicalizer or digest/node-set implementation correct.
Existing namespace, escaped metadata, text/entity, selection, verified-coverage
and multi-Assertion cases remain bounded regression evidence. No new disagreement
payload or cryptographic experiment was constructed.

## Canonicalization evidence applicability

`scripts/qualify_saml_c14n.py` uses the unchanged, lock-verified
bergshamra-c14n0.9.2 archive (SHA256
f9ea63f9d7b6cceeeef8ad96da61325c6ed6397e342377b552a0bf9917e266a9).
It copies all12 archive files, checks that the selected package points to that
copy, compares selected SAML normal/build versions/features with the shipped graph,
and tests the existing library/core/C14N packages locked. Core verification source
hashes and copied archive bytes are checked before/after; no application source or
lock is rewritten. Only the disposable workspace adds a path patch for the exact
registry source and admits the packages as test members.

The additional32 existing C14N tests cover the upstream inclusive/exclusive modes
and existing exclusive examples, whitespace, character escaping, UTF8, comment
handling, visible namespaces, inclusive prefix lists and sibling/default namespace
restoration. They are actual established regressions on the selected version;
a newer0.11 suite is not substituted. Neither their count nor the per-message
parser guard proves exhaustive XML/C14N conformance or signed-payload correctness.
Canonicalization and trusted signature verification implementations are unchanged.

### Actual reference canonicalization scope

Strict policy requires exclusive C14N without comments for SignedInfo. Reference
transform elements, when present, are limited to enveloped-signature/exclusive
C14N; the existing policy does not require an explicit reference-C14N transform.
Bergshamra0.9.2 `fast_reference_c14n_params` defaults references to inclusive XML1.0
without comments when no explicit C14N transform is present. It checks ordering
and duplicate-C14N eligibility for the fast path; other supported chains use the
generic pipeline. This is existing behavior, not a new algorithm relaxation.

Approval must describe that actual contract and review the applicable fast/generic
node-set paths, or explicitly request a tighter reference-transform contract.
Do not describe both SignedInfo and every reference as necessarily exclusive C14N,
or infer a bypass from the presence of this documented standard default. Current
ordinary IdP fixtures/Keycloak emit explicit approved transforms; broader reference
shapes receive no interoperability claim from those scenarios.

## SR-3: resource controls and their limits

| Control | Current scope |
| --- | --- |
| Encoded/decoded input | Existing256KiB ASCII POST field; explicit192KiB decoded XML ceiling in the core SP configuration |
| Early depth | Local/profile/extraction depth128 before building a tree the backend cannot accept; backend independently capped at128 or a stricter caller limit |
| Other syntax bounds | Existing element/attribute/value/text and in-scope namespace bounds; DTD/entity rejection; all-reference and strict-transform preflight |
| Process admission | Shared two permits for all concrete SamlResponseVerifier constructors in this linked core, including distinct service compositions |
| Local/composed admission | Existing immediate two-operation overload rejection and shared sign-in/deletion capacity; repositories/proof purposes remain separate |
| Admission waiting | Up to15s for process admission while holding a local permit; fresh material/DB clock loaded afterwards; original authority deadlines remain mandatory |
| Cancellation/timeout | Both permits owned by the blocking closure until actual exit; caller cancellation cannot release capacity while native work continues |

These are deterministic source controls, not a measured deployment envelope.
A process can have at most two admitted blocking verification tasks through this
concrete adapter; this is not a count of all OS/native-library threads. Other
processes/raw backend consumers are outside that semaphore. Independent instances
can still retain waiting inputs; local budgets bound each instance, not configured
instance count. HTTP body/form parsing also occurs outside the native gate.

Admission, material lookup and blocking await each have a15s boundary, not one
hard15s lifetime. Timeout does not kill native work. An individual task can perform
multiple pinned-key attempts/references/C14N operations. Byte/depth/task limits
therefore do not establish worst-case CPU/RSS or hard per-job duration. Deployment
instance/process/HTTP budgets and any required native containment remain approval
requirements. No custom resource or signature-concurrency experiment was run.

## SR-4: native/source and historical evidence

The lock still selects aws-lc-rs1.18.2/aws-lc-sys0.46.0 with bundled AWS-LC5.11.0,
FIPS disabled. Earlier sys0.45.0/AWS-LC5.7.0 findings retain that older source scope.
The signature/key provider, OpenSSL Rust bindings0.10.81 and native source have
not changed in this increment. The public source archive and copied registry
identities are checked; source identity is not a native security certification.

The recorded local runtime inventory identifies only the development build and
its linked OpenSSL artifact. It is not a selected production image. Hosted Linux
CI provides separate compiler/platform/interoperability/advisory evidence, not
approval for every OS/OpenSSL packaging combination. Production target/build/runtime
inventory, distribution/advisory scope and accepted resource budgets must still
be identified and reviewed without inventing a deployment target.

Historical three-patch corpus outcomes are not rerun or extended. Patches4–7 added
fields/time projection; patch8 closed backend execution scope; patch9 now changes
parsed-view checks/normalization/selection and explicit XML policies. Existing
current tests and reviewed source support those exact paths. Old corpus outcomes
cannot silently qualify the new boundary or newer native graph. The previous
follow-up provides historical-case applicability examples; this increment adds
actual same-graph C14N evidence and per-message agreement rather than a blanket
claim of equivalence.

## Verification and disposition

Final local verification:

- Existing SAML/core/C14N qualification:1147 passed/0failed/0ignored,48 result groups,
  including the unchanged32 selected-version C14N tests. Twelve archive files and
  fourteen core verification sources match before/after; selected normal/build
  versions/features match. [Full receipt](../../tests/provider/saml/rust-policy/results/2026-10-22-parser-c14n-policy.json).
- Full locked workspace suites:115 default/799 all-feature results,0failed/ignored;
  466 real PostgreSQL lifecycle cases. Final SAML-only workspace rerun:129 passed,
  including96 real-PG SAML cases; no failures/ignores. No worker-count, assertion,
  timing, key or signature-policy change was made to obtain those results.
- fmt; strict default/all-feature all-target and isolated-verifier Clippy;
  warning-free all-feature docs;11 existing source/runner checks;244-file/nine-patch
  integrity; exact incremental reconstruction; unchanged original tests/fixtures.
- Default and combined standalone/embedded builds,16 closed-SAML and13 OIDC
  startup cases, and isolated SAML server compile: pass.
- [Local native inventory](../../tests/provider/saml/rust-policy/results/2026-10-22-parser-native-inventory.json):
  Darwin/arm64 development build; OpenSSL pkg-config and paired executable both3.6.2;
  actual linked SSL/crypto artifacts are hashed; locked sys0.46.0 archive identifies
  AWS-LC5.11.0. Binary hash, declared build, source/inventory/qualification hashes
  are recorded. The working-tree/base-commit label is intentional; these input
  hashes identify the implementation, not an invented production image.

`scripts/record_saml_native.py` records ordinary build metadata and selected linked
artifacts without signatures, payloads, load or security/resource probes. CI records
its own Linux inventory after the combined gated startup build. Development and
CI inventories have distinct artifact/platform scopes; neither approves a future
production target. Final new-source hosted verification belongs to its exact commit,
not to the successful eight-patch baseline run.
An initial agreement draft failed the existing escaped-namespace metadata case:
NsReader returns raw URI spelling. Using its existing Attribute normalization API
fixed the comparison; no assertion/fixture or cryptographic check was changed.
A new runner's initial package identity check compared macOS path aliases literally;
canonical path comparison preserves the same-file check across those aliases.

Implemented controls and internal source review do not supply independent approval.
Remaining review must cover this exact patch/admission policy, underlying C14N and
DSig node-set correctness, deployment CPU/RSS/queue/instance/containment budgets,
actual target-native inventory and historical applicability, plus the existing
issuer/profile clarification. A named independent report, findings disposition
and explicit approval remain absent. The production source gate stays closed.
