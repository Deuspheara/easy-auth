# AUTH-32: exact SHA-256 policy and resource observation

2026-10-20. **SAML remains gated.** The exact-policy gap is resolved in a tested,
reviewable patch against the assessed saml-rs0.6.1 pin. It is not an upstream merged
release, production dependency selection or independent security review.

The [patch, reproduction and finite evidence](../../tests/provider/saml/rust-policy/README.md)
follow the [architecture comparison](saml-verifier-options.md). No custom signature
verifier, parser filter, weakened requirement or production SAML implementation
was added. The original corpus and earlier failing observations remain intact.

## Policy boundary

The first patch extracts the existing strict profile into its own cohesive module,
with all36 original verification tests passing. The second adds
`XmlSignatureProfile::StrictRsaSha256`, requiring exact RSA-SHA256 **and** SHA-256
reference digest while retaining exclusive canonicalization, one local `#id`
reference, namespace checks and existing safe-transform restrictions.

The existing cryptographic verifier determines which Signature node authenticated
accepted content. Policy reads that node's SignedInfo from the same verifier DOM;
it does not trust an arbitrary signature, an unsigned digest declaration or a
serialize/reparse bridge. Existing cryptography, digest verification and reference
resolution remain delegated to bergshamra/AWS-LC. The profile is checked before
returning authenticated content. This is not a promise to avoid every unapproved
algorithm attempt inside the backend or proof of computational resource bounds.

The typed SP configuration now preserves its profile enum through SSO and both
logout parsers. The low-level optional explicit profile takes precedence over the
old strict-SHA2 boolean; absent it, existing behavior is preserved. Signature
requirement and configured-key trust are separate settings and remain mandatory
in our driver. The generic verifier and compatibility defaults are not approved
application boundaries. A new public enum variant needs upstream version/API
coordination; the patch is proposed, not maintained as a production private fork.

## Executed evidence

Both broad and exact profiles received identical106 inputs: all76 prior
signature/resource rows, eight complete bearer controls, sixteen genuine
SHA384/512 policy negatives, and six direct resource-reference negatives. Native
mode tags duplicate each Rust input, giving53 scenarios. Signature and digest vary
independently, on both Response and Assertion targets. The existing native signer
constructs valid controls; no new signer or verifier implementation is introduced.

| Check | Verified result |
| --- | --- |
| Strong positive reachability | Exact profile accepts4 complete RSA-SHA256/SHA256 rows, with trusted subject and no forged markers |
| Exact algorithm policy | Broad strict profile accepts all16 SHA384/512 rows; exact profile rejects all16 as algorithm errors, plus all8 SHA-1 rows |
| Forbidden XML/entities | All18 rows rejected by exact profile |
| External references | All6 file/HTTP/path URI negatives rejected as reference errors; these alter SignedInfo and are not claimed valid signed controls |
| Existing negative/strict profile behavior | Remaining54 trust, signature, coverage and profile denials retained; no opaque errors counted as safe rejection |
| Independent resource observation | Zero sentinel-file calls, connect calls or HTTP requests in traced exact-flow child |
| Observer reachability | Before/after controls each demonstrate a real sentinel open and HTTP connect/request |
| Observer fault | Missing strace returns infrastructure failure/exit2; restoring it reproduces106 rows and working controls |
| Patched candidate suite | Linux1087 passed, zero failed/ignored, including unit, integration and doc tests |
| Lint and reporting | Candidate selected-feature all-target strict Clippy passes on macOS; both owned Linux examples pass strict Clippy;14 reporting tests and formatting pass |

The full candidate suite covers the unchanged trust/wrapping/profile tests plus
new exact-policy and public typed-SP regressions. An early mixed-pair fixture failed
because the upstream signer fills empty values only. Test construction now clears
the generated digest/signature values using DOM ranges and signs through that same
provider. All39 verification tests pass. No assertion or policy was relaxed.

The observer is a separate syscall/HTTP observer with independently exercised
controls. This is distinct from the required independent **security review**.
Observations are aggregate for this bounded exact-flow child, not a universal
no-I/O, no-XXE, platform or protocol-compliance claim. Raw assertions, certificates,
keys and errors are absent from public reports; synthetic transport remains in
memory. Source/archive/patch/lock/image hashes and compiler version are recorded.

The subsequent [selected dependency review](saml-dependency-review.md) records
clean target-scoped checks, full-lock failures and native advisory mapping. It
does not clear the independent dependency/security or distribution review gates.

## Remaining acceptance gates

- Obtain upstream policy/API acceptance or an explicitly reviewed maintained
  dependency path; qualify the actual selected release and feature graph.
- Complete dependency/license/advisory and backend/canonicalization review. The
  patch leaves the lock unchanged and does not imply an advisory clearance.
- Complete independent security review, resolve findings and record scope,
  reviewer and decision. Current work cannot self-clear this gate.
- Expand namespace/ID/structure, resource-budget and concurrent-path qualification;
  separately assess any enabled metadata, encryption or detached-binding paths.
- Before activation, implement the owning application adapter and validate actual
  consumed identity, recipient/correlation, trust lifecycle, replay, realm isolation,
  concurrency and atomicity with real PostgreSQL. Required workspace tests, strict
  lint and security checks remain activation criteria.

No application API, manifest, route, persistence rule or migration changed. Workspace
formatting was checked; full application/DB tests were not rerun for this isolated
research patch. Prior application checkpoint97/639 is historical evidence only.
AUTH-32 remains In Progress and SAML remains a hard production release gate.
