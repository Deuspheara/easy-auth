# Maintained SAML dependency source

`saml-rs/` is the Cargo package-layout source of upstream saml-rs at
[`3b289001a7a84d5a7ff7af2671991ab7098090bd`](https://github.com/salasebas/saml-rs/tree/3b289001a7a84d5a7ff7af2671991ab7098090bd),
with the three retained qualification patches and ordinary NameID, attribute
projection and authentication-time maintenance patches recorded in
`tests/provider/saml/rust-policy/patches/`. It is **a project-maintained engineering snapshot,
not an upstream release or independently approved production dependency**.
[ADR 0021](../docs/architecture/adr/0021-saml-verification-and-approval.md) retains
the XML/backend review and independent approval gates.
[ADR 0027](../docs/architecture/adr/0027-maintained-saml-dependency.md) records
the accepted easy-auth maintenance and source-distribution responsibility;
upstream patch acceptance is no longer a prerequisite.

The package retains upstream MIT licensing, published fixture provenance and all
packaged source/tests. Existing upstream public test keys are intentional vectors,
never deployment credentials. No key, adversarial XML or cryptographic test fixture
was generated for this import. No cryptographic engine was replaced or invented;
canonicalization, reference resolution and actual signatures remain upstream code.
Record every maintained source change as a reproducible incremental patch. Do not
refactor vendored files solely to satisfy application module size guidelines:
exact upstream/patch comparison is the review boundary.
Git attributes preserve upstream bytes, including existing CRLF in vectors,
instead of normalizing or rewriting signed/test material for a style check.

`saml-rs-source.json` records every packaged file hash, exact patch hashes, upstream
revision and the original three-patch import archive hash. The archive hash does
not describe subsequent maintenance; the complete file inventory does.
`python3 scripts/check_saml_source.py` checks the complete source inventory before
compilation/secret-scan exceptions.
It is an integrity check, not an audit.
Secret scanning exempts only the exact public vector match at its exact source
path; a different existing public key mounted at an allowed path is still
detected. No complete file, directory or private-key class is excluded. Any source, patch, backend, feature or lock
change requires a renewed review. Never fetch or apply source patches at build time.

To reproduce the source layout, check out the exact upstream revision in an owned
external directory, apply patches 0001/0002/0003 in order with `git apply --check`
then `git apply`, and run:

```sh
cargo package --locked --allow-dirty --no-verify --no-default-features --features crypto-aws-lc
```

After unpacking that original import archive, apply maintenance patches 0004–0011 in order with
`git apply --check` then `git apply` from the package root. Patch0004 preserves typed
NameID qualifiers through the built-in IdP response renderer; it changes no
cryptographic verifier. Qualified successful responses refuse legacy custom
rendering, which cannot preserve those fields. Patch 0005 adds a complete ordered
scalar attribute accessor without changing the legacy aggregate view; patch 0006
adds caller-established authentication time distinct from response issuance.
Both use the existing producer writer/signer and bounded extraction, never a new
XML cryptographic verifier. See ADR 0028 for unavailable projection and template
restrictions. Patch0007 extends the existing unqualified consumed-field list to
NameFormat and the consumed NameID qualifiers before DOM projection. No new
XML/security probe is introduced. Patch0008 checks every backend-visible signature's
references on the verifier DOM before certificate attempts, and restricts executable
transforms in the strict profiles. Explicit compatibility mode keeps its documented
transform support; it is not used by easy-auth's production profile. Single-signature
verification reuses the checked DOM. PAOS qualification is not added.

The package's normalized Cargo manifest and `.cargo_vcs_info.json` intentionally
retain version 0.6.1 and `dirty=true`; this is distinct from registry 0.6.1. The
upstream full lock's inactive advisory/yanked entries remain visible. Actual compiled
features/advisories/licenses must be checked in the adopting workspace; no upstream
ignore list is inherited. Keep build output outside the vendored source directory.

Run `python3 scripts/qualify_saml_dependency.py` for unchanged candidate/core
regressions with verified application dependency versions/features. It stages a
private disposable workspace and preserves the actual source and lock. The finite
result is written under `target/`; source integrity and full application checks
remain separate requirements. No scan result or dependency security approval is
inherited merely from a passing test run.

Easy-auth maintainers own the retained patch set and source distribution under
ADR 0027. Normal SAML provider/ACS activation still requires the separately recorded
security review and approval. See the [current evidence review](../docs/security/saml-evidence-review.md).

Patch0009 corrects namespace-binding/text interpretation and binds extraction to
all verifier-DOM ranges, values, expanded names and selected-Assertion identity.
Backend DTD/entity flags and strict XML1.0 are explicit. Strict DSig selectors and
InclusiveNamespaces parameters reject qualified/ambiguous aliases. This adds no custom
canonicalizer/verifier. ADR0030 records compatibility and remaining assurance.
Run `python3 scripts/qualify_saml_c14n.py` to additionally run the unchanged32
selected-version canonicalization tests with the existing SAML/core suite on an
identical normal/build graph. Only a verified archive copy in a disposable
workspace is patched into that test graph; runtime dependencies remain unchanged.

Patch0011 keeps expected-issuer policy in private `flow/issuer.rs`: configured login
flows require both Response and Assertion issuers to match the expected IdP. The
new `responseIssuer` extraction is envelope-scoped; `issuer` stays Assertion-scoped.
This deliberately requires the otherwise protocol-optional Response Issuer in our
narrow profile. Other message policies and flows without an expected issuer retain
their contract. Existing tests/fixtures and all prior patches remain unchanged;
new unit cases use extracted values without generating XML/cryptographic fixtures.
ADR0031 finalizes this profile and the separately gated reference release image.
