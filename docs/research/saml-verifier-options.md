# AUTH-32: verifier architecture decision evidence

2026-10-20. **Production gate closed. No verifier selected or runtime changed.**
This investigation supersedes the selection recommendation, not the historical
measurements, in [the assessment](saml-assessment.md). Independent security review
is still mandatory. Passing this bounded corpus does not establish compliance,
interoperability, exhaustive XXE safety or production readiness.

## Exact-policy follow-up

The [tested source patch and independent resource observation](saml-exact-policy.md)
resolve the exact-policy gap for an experimental patched pin:106 inputs, full
candidate tests and working file/network controls. Upstream adoption, independent
security review and application acceptance remain open. The comparison below
records the original unpatched pins; no production verifier is selected.

## Confirmed cause and ownership

The assessed Samael is **0.0.22**, commit
[`2d27dfe`](https://github.com/njaremko/samael/tree/2d27dfe4930c4632b202f32886a85b2d1f9226c2).
Its unchanged lock resolves libxml **0.3.3**, quick-xml **0.41.0**, OpenSSL **0.10.81**.
The executed native stack is libxml2 **2.9.14**, xmlsec **1.2.37**, OpenSSL **3.0.22**.
The quick-xml schema/deserialization layer is not the initial native signature
parser. In `src/crypto/xmlsec/mod.rs`, reduction parses input at line247 and wrapped
selection fragments at line591 with `XmlParser::default().parse_string(...)`.
Direct verification (line220) and signing (line407) also instantiate defaults.

The libxml 0.3.3 binding defaults to recovery enabled and `no_net=false`.
Recovery explains acceptance of malformed closing tags and multiple roots in the
executed corpus. DTD declarations have no explicit rejection policy. A signature
can remain valid over the recovered/canonicalized element while forbidden source
syntax is discarded. Thus XML-policy failure is confirmed; cryptographic forgery
or authentication bypass is **not** established by DTD acceptance alone.

The [public reduction API](https://github.com/njaremko/samael/blob/2d27dfe4930c4632b202f32886a85b2d1f9226c2/src/crypto/mod.rs#L179-L184)
exposes trust certificates, reduction mode and signature algorithms, but no parser
options. Calling the binding's configurable parser separately cannot configure
these internal parses. This is a dependency/API limitation, not a missed public
Samael parser setting. `no_net` alone would not deny filesystem resources or reject
DOCTYPE. The native signature wrapper constructs a context and optionally ORs
flags; it does not explicitly configure reference URI/transform allowlists.

Our repository has no enabled SAML ACS or runtime dependency. Its probe explicitly
supplies trusted certificates and an exact RSA-SHA256 allowlist; it reproduces the
failure without application integration. A separate future integration hazard is
Samael's SP path: absent signing certificates, it parses the original response as
unverified. An adapter must reject empty trust and consume only authenticated
content, never turn that behavior into an accepted identity. SP correlation,
realm isolation and replay remain application responsibilities.

## Reproduction and comparison

[Recipe and adapters](../../tests/provider/saml/comparison/README.md) reuse all
**76 existing signature/resource rows** unchanged and add eight complete bearer
profile controls (healthy Response, healthy Assertion, SHA-1 digest, SHA-1
signature; two native reduction modes). Both candidates receive identical XML
and certificate bytes in one run. There are 42 scenarios, 84 transport rows;
repeated native mode labels are not independent Rust implementations or tests.
No production parser/verifier patch, regex boundary or XML preprocessing was added.

The Rust alternative is saml-rs **0.6.1** at
[`3b28900`](https://github.com/salasebas/saml-rs/tree/3b289001a7a84d5a7ff7af2671991ab7098090bd),
unchanged lock: quick-xml **0.42.0**, bergshamra **0.9.2**, uppsala **0.10.1**,
kryptering **0.6.0** with AWS-LC. Defaults are disabled; only `crypto-aws-lc` is
selected. Default legacy/RustCrypto/PQ/PKCS#11 features are not qualified.

| Boundary | Executed results | Consequence |
| --- | --- | --- |
| Samael exact RSA-SHA256 probe | 44 accepted, 30 invalid signatures, 4 duplicate-ID errors, 6 opaque engine errors | Accepts 12 forbidden syntax/DTD rows; fails mandatory gate |
| saml-rs public generic `verify_signature` | 32 accepted; rejects all18 forbidden XML rows | Accepts eight SHA-1 signature/digest rows; cannot serve as application policy |
| saml-rs configured strict `flow` | 4 complete healthy rows accepted; all8 SHA-1 and all18 forbidden XML rows rejected | Viable qualification candidate, not a drop-in selection |

Strict flow also rejects 20 older engine-only healthy/rollover rows for missing
bearer expiry, ten for protocol profile, twelve for signature, ten for trust and
two for coverage. These are retained outcomes, not reclassified successes. New
complete profile controls set expiry **before signing**, using the unchanged
native signer; they establish strict-flow reachability for both signature targets.
No accepted row in either candidate returned the forged subject/wrapper marker.

Threat-specific evidence and limits:

| Threat | Observed / source-supported behavior | Still required |
| --- | --- | --- |
| Wrapping and signed identity | Native prunes forged siblings; Rust rejects ambiguity and derives consumed Assertion from verified target coverage | Expanded namespace/ID-location/signature-target matrix; review exact identity extraction path |
| Duplicate IDs | Native rejects corpus duplicates; Rust rejects duplicates before verification | Namespace-qualified ID variants, nested targets and decrypted paths if enabled |
| Expansion / external entities | Native entity references give opaque errors; DTD/external-DTD/parameter declarations can pass. Rust bounded DOM rejects all18 syntax/entity rows | Expansion/resource budgets and independent no-I/O observation on chosen full path |
| Document structure | Native recovery accepts malformed/multiple-root input. Rust rejects tested cases and its profile parser uses namespace-aware `NsReader` | Namespace confusion, limits, truncation and structural ambiguity corpus |
| Signature / digest policy | Native exact256 rejects weak pairs. Rust strict profile permits RSA-SHA256/384/512 and SHA256/384/512 | Preserve exact256 policy; do not silently broaden it |
| Trust and profile | Wrong/absent trust and attacker KeyInfo rejected by both tested boundaries; strict flow checks issuer/audience/request and bearer conditions | Complete ACS/recipient/time/replay/certificate-rollover policy and realm binding |

The earlier native independent resource observation had working file/HTTP controls
and zero aggregate observed sentinel opens/connects/HTTP requests for its bounded
20 rows. Six errors were opaque; it does not prove general XXE safety. This new
cross-component replay has **no independent resource observer**, so it establishes
rejection behavior, not no-I/O, for the Rust candidate.

The unchanged native suite rerun passed **86**, with **one ignored**. Its historical
explicit ignored-positive failure remains recorded. Selected unchanged saml-rs
security suites passed **129**: integration73, DOM20, verification36. Full application
and real PostgreSQL regression results from the preceding checkpoint (97 default,
639 all-feature) are historical; no new SAML application integration is tested here.

## Alternatives

| Option | Guarantees and limitations | Cost / compatibility |
| --- | --- | --- |
| Configure existing Samael | Trust, algorithm and reduction settings available; internal recovery/DTD policy inaccessible | Small change cannot meet strict parser gate; reject as current solution |
| Upstream-compatible native hardening | Retains established xmlsec crypto/canonicalization; could make every parse strict and resource-free | Requires version/binding support, parser and dsig-context changes, platform review; design only, no passing patch claimed |
| Replace only initial parser | Leaves native DOM/reparses; serialization bridge risks parser differentials, namespaces, IDs and canonicalization | Adds two parser authorities without closing root cause; do not pursue |
| Complete saml-rs strict message component | Existing parser, verified-target selection and SAML profile policy pass bounded comparison | Strongest executed replacement evidence; new canonicalization/DOM trust base, exact digest-policy gap, unaudited pre1.0 API |
| Direct bergshamra | Existing signature engine, not a complete application SAML profile | More local orchestration/identity policy than full message component; unnecessary ownership |

A native upstream patch would need one audited strict parsing policy for input,
fragments, metadata and enabled decryption paths: recovery off; reject forbidden
declarations before resource processing; no entity substitution/DTD loading;
bounded bytes/nodes/depth/attributes/text; deny file and network resolution using
context-local, concurrency-safe controls. Configure same-document references and
allowed transforms **before native processing**, preserve canonicalization and
verified-node identity. Do not use global callbacks, string filters or a
parse/serialize/reparse workaround as the security boundary.

The [libxml parser documentation](https://gnome.pages.gitlab.gnome.org/libxml2/html/parser_8h.html)
distinguishes NONET from external-entity controls and documents newer per-context
resource-loader APIs. Their availability cannot be assumed on tested2.9.14.
The [xmlsec context API](https://github.com/lsh123/xmlsec/blob/master/include/xmlsec/xmldsig.h)
has URI/transform controls; availability and behavior on pinned1.2.37 need testing.
A binding upgrade alone does not change Samael's default calls. The
[binding changelog](https://github.com/KWARC/rust-libxml/blob/main/CHANGELOG.md)
contains later namespace/memory fixes, requiring review without inventing a CVE
or assuming this pin exploitable. This is not a proven two-flag patch.

Public GitHub metadata checked2026-10-20 shows all four projects non-archived:
Samael last push July17, saml-rs October13, rust-libxml October7, bergshamra October16.
Activity is not security assurance. [saml-rs](https://github.com/salasebas/saml-rs)
explicitly states pre1.0 and no external audit; a newer API is not covered by this
pin's tests. MIT (Samael/saml-rs), BSD-2-Clause (bergshamra), native AWS-LC and full
transitive licenses/advisories still need distribution-specific clearance.

## Recommendation and precise release criteria

**Qualify the complete strict saml-rs message component next; do not integrate it
for production yet.** It resolves the reproduced parser-policy failures without
owning a custom signature verifier or bridging two DOM authorities. Preserve the
native hardened-upstream design as the alternative if exact-policy support,
maintenance or independent review of the Rust component is unsatisfactory.
This is a conditional architecture recommendation, not approval of this pin.

The first upstream qualification requirement is an exact signature **and reference
digest** allowlist tied to verified signatures. The typed session's
`verified_xml_signatures()` exposes exact signature algorithm and object coverage,
but not digest algorithms; strict flow's `sig_alg` is detached-binding evidence,
not embedded-signature policy. Existing strict RSA-SHA2 checks are broader than
our RSA-SHA256/SHA256 controls. Request upstream policy support/evidence; do not
inspect arbitrary unsigned nodes or relax the policy to avoid this gap.

Before selecting a production dependency:

1. Pin source, unchanged lock, features, native/backend versions and license/advisory
   results; agree supported profile/API and an upstream maintenance path.
2. Require exact RSA-SHA256/SHA256, exclusive canonicalization, same-document
   references and explicit safe transforms, trusted configured keys only; reject
   SHA-1, other unapproved algorithms, missing trust, remote/file references and
   attacker KeyInfo. Test paired real signed positives and negatives.
3. Reject every retained forbidden XML case before resource processing; demonstrate
   bounded expansion/depth/size and no file/network access with independent working
   observer controls, across every enabled parse/verification path and concurrency.
4. Demonstrate namespace-correct single-document/single-consumed-Assertion selection,
   duplicate-ID and wrapping rejection, and that the actual subject/attributes used
   by auth-core are covered by the verified reference. Review parser differentials.
5. Independently review source, dependency/canonicalization/backend trust base,
   error/log secrecy, profile/trust/algorithm/resource policy and hostile corpus.
   Resolve findings; record reviewer, scope and decision. No self-review substitution.
6. Before enabling SAML, complete owning feature adapter and required real PostgreSQL
   request/replay/atomicity/concurrency/realm isolation tests, protocol profile and
   certificate lifecycle tests, fmt, workspace strict Clippy/tests and security checks.

AUTH-32 remains **In Progress**, with release-blocker classification. No SAML gate,
public API, persistence rule or published migration changes in this investigation.
