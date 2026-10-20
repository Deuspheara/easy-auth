# AUTH-32: complete-document parser preflight

2026-10-20. **SAML stays gated.** Continuing structural qualification found a
confirmed parser-wrapper bug in the assessed saml-rs0.6.1 pin, including the two
previous policy patches. This is not a newly implemented SAML route or a claim
of an authenticated identity bypass.

## Root cause and reproduction

`src/xml/dom.rs::parse_roots_inner` tracks completed roots and open elements
separately. The low-level quick-xml reader can return EOF while elements remain
open. The wrapper previously returned its completed roots without checking that
stack. Consequently `dom::parse("<Root/><Open>")` returned the completed Root
and silently discarded the unfinished trailing element. `parse_roots` has the
same defect; it is also the foundation of metadata root collection.

Two regression tests failed before the fix (existing three document tests passed):
the document parser accepted unclosed trailing elements, and the raw POST
AuthnRequest flow accepted a second unclosed protocol root. The root-collection
API delegates to the same routine with the same missing EOF check. The raw test
intentionally disables signature verification to isolate XML admission; this is
not the assertion trust policy used by our mandatory-signature candidate driver.
The red failure records `binding=Post, accepted=true`, without raw request output.

Fresh, genuinely signed Response controls also exercised the existing strict
exact-policy path before the fix. Healthy content passed; malformed trailing
inputs were already rejected later as protocol or opaque cryptographic errors.
**No authenticated SAML identity bypass was demonstrated.** The confirmed defect
is failure of the initial well-formed-document contract, affecting lower/raw APIs
and permitting malformed source to reach later stages in the signed flow.

## Minimal correction

[Patch0003](../../tests/provider/saml/rust-policy/patches/0003-reject-unclosed-document.patch)
adds one missing invariant to the existing DOM wrapper: the open-element stack
must be empty before returning roots. It returns a constant XML error, without
input values. It does not normalize XML, add a parser/verifier, change crypto or
weaken namespace, algorithm, trust or resource policy. Well-formed root collections
remain intentionally supported by `parse_roots`; the existing preservation test
continues to pass. Flow's existing DOM preflight now rejects these inputs before
protocol validation or cryptographic work.

Only five production source lines (including two comments) and two focused tests
are added to the upstream patch. The tests reuse the owning XML-document fixture
and cover both document/root-collection modes, POST/Redirect rejection and valid
controls. Existing assertions are unchanged. This is the existing parser's
responsibility; no new public API, module responsibility or architecture is added.

## Verification

[Finite evidence](../../tests/provider/saml/rust-policy/results/2026-10-20-document-completeness.json)
records exact source/patch/lock/image provenance and the retained before-fix result.

| Check | Result |
| --- | --- |
| Before-fix regression suite | Exit101, two failed / three passed; raw POST acceptance recorded |
| After-fix document suite | Five passed with AWS-LC and five passed without crypto features |
| Full patched Linux candidate suite |1089 passed, zero failed/ignored; unit, integration and doc tests |
| Candidate lint/format | Selected AWS-LC all-target strict Clippy and full formatting pass on macOS |
| Original signed/resource corpus | All106 finite outcomes unchanged in both strict profiles |
| New malformed signed-document rows | All8 rejected as XML errors during initial preflight |
| Healthy controls after malformed rows | All4 passed;8 complete positive rows across whole run |
| Independent observation |118 rows, zero sentinel-file calls/connects/HTTP requests; working file/HTTP controls before and after |
| Observer failure | Missing strace exits2; restoring it reproduces all118 outcomes and healthy controls |

There are59 scenarios with duplicated native-mode tags, not118 independent Rust
implementations. The additional malformed fixtures append bytes to an otherwise
unchanged signed document; they are not claimed valid signed documents. The
candidate receives them verbatim. This fixture construction is not preprocessing
or an XML security boundary. XML, certificates, private keys and raw errors are
absent from published observations.

The existing observer now accepts a named corpus/report producer and positive-case
set, reusing its trace, trap, schema validation and fail-closed reporting. Result
coverage is checked against the complete generated key set; the original generator
still requires exactly106 keys and the extended one exactly118. Original defaults
and all18 reporting tests pass. New owned code remains below300lines and functions
below50lines; the upstream parser remains its existing cohesive ordered parse loop.
No unrelated structural cleanup, source lint exemption or production change.

This is a reviewable third patch against the pinned source, not an upstream merged
release or approved private fork. The earlier dependency graph/lock is unchanged.
Upstream maintenance/API adoption, independent backend/canonicalization/security
review, distribution obligations, resource-budget/concurrency qualification,
additional enabled protocol paths and real application/DB acceptance remain open.
No SAML release gate, manifest, persistence, migration or application API changed;
application/DB suites were not rerun for this isolated dependency fix.
