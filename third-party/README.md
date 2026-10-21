# Gated SAML qualification source

`saml-rs/` is the Cargo package-layout source of upstream saml-rs at
[`3b289001a7a84d5a7ff7af2671991ab7098090bd`](https://github.com/salasebas/saml-rs/tree/3b289001a7a84d5a7ff7af2671991ab7098090bd),
with only the three existing qualification patches recorded in
`tests/provider/saml/rust-policy/patches/`. It is **an engineering candidate,
not an upstream release or an independently approved production fork**.
[ADR 0021](../docs/architecture/adr/0021-saml-verification-and-approval.md) retains
the maintained-adoption, XML/backend review and independent approval gates.

The package retains upstream MIT licensing, published fixture provenance and all
packaged source/tests. Existing upstream public test keys are intentional vectors,
never deployment credentials. No key, adversarial XML or cryptographic test fixture
was generated for this import. No cryptographic engine was replaced or invented;
canonicalization, reference resolution and actual signatures remain upstream code.
Do not edit vendored files by hand or refactor them to satisfy application module
size guidelines: exact upstream/patch comparison is the review boundary.
Git attributes preserve upstream bytes, including existing CRLF in vectors,
instead of normalizing or rewriting signed/test material for a style check.

`saml-rs-source.json` records every packaged file hash, exact patch hashes, upstream
revision and the local package archive hash. `python3 scripts/check_saml_source.py`
checks the complete source inventory before compilation/secret-scan exceptions.
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

The package's normalized Cargo manifest and `.cargo_vcs_info.json` intentionally
retain version 0.6.1 and `dirty=true`; this is distinct from registry 0.6.1. The
upstream full lock's inactive advisory/yanked entries remain visible. Actual compiled
features/advisories/licenses must be checked in the adopting workspace; no upstream
ignore list is inherited. Keep build output outside the vendored source directory.

Long-term patch ownership and distribution are still subject to explicit maintainer
review. Shipping this candidate must not enable a normal SAML provider or ACS.
