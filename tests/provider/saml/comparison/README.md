# Cross-component research comparison

AUTH-32 only. No production dependency, XML filter or signature verifier. The
[decision record](../../../../docs/research/saml-verifier-options.md) describes
failures, limits and release criteria. All existing negatives remain unchanged.

Use separate clean checkouts of Samael `2d27dfe4930c4632b202f32886a85b2d1f9226c2`
and saml-rs `3b289001a7a84d5a7ff7af2671991ab7098090bd`. Build the existing
[native resource image](../native/signature-probe/RESOURCES.md) first, preserving
its source/lock provenance. Then, from the repository root:

```sh
docker build -f tests/provider/saml/comparison/export.Dockerfile \
  --build-arg RESOURCE_IMAGE=easy-auth-auth32-signature-resources:assessment \
  -t easy-auth-auth32-corpus:comparison tests/provider/saml
```

Only owned examples are overlaid; upstream implementation and lock stay unchanged.
Copy `rust_candidate.rs` to `examples/auth32_compare.rs` in the external saml-rs
checkout, then build there (first resolve dependencies if not already cached):

```sh
CARGO_TARGET_DIR=/private/tmp/auth32-rust-candidate-target \
CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 \
cargo build --locked --offline -j2 -p saml-rs --no-default-features \
  --features crypto-aws-lc --example auth32_compare
```

From easy-auth run the comparison immediately after fixture generation:

```sh
python3 tests/provider/saml/comparison/run.py \
  --native-image easy-auth-auth32-corpus:comparison \
  --rust-example /private/tmp/auth32-rust-candidate-target/debug/examples/auth32_compare \
  --output /private/tmp/auth32-comparison.json
```

The runner generates 56 original signature rows, 20 original resource rows and
8 complete bearer-profile rows. It passes identical private TSV bytes to native
rooted/predigest and both Rust public APIs. Transport stays in memory, includes
synthetic XML and public certificates, and is never published. No private key
leaves the signer process. Bearer controls expire after five minutes. The resource
URI port38117 is synthetic; this replay has no HTTP/file observer. Use the separate
resource observer recipe for actual no-I/O evidence.

The output contains a transport hash and finite case/mode/API outcomes, never XML,
certificates, raw errors or authentication material. Exit0 means complete transport
and execution, **not security success**. The recorded native policy failures and
generic Rust SHA-1 acceptances are expected findings. Verify all84 rows per API,
healthy complete profile acceptance and forbidden/algorithm rejections explicitly.
Two native mode tags repeat each Rust input; do not double-count Rust scenarios.

`native_export.rs` replaces only the example's output callback. `native_replay.rs`
imports the unchanged original fixture, scenario and engine modules. The Rust
adapter invokes upstream `verify_signature` and `flow` with explicit trusted keys,
signature required, strict profile, issuer, audience and request correlation.
Its local subject-marker inspection is an observation of returned content, not an
application identity parser. `profile_control.rs` sets bearer expiry before using
the existing native signer; it does not alter signed bytes to force acceptance.

Existing upstream checks, in the external saml-rs checkout:

```sh
CARGO_TARGET_DIR=/private/tmp/auth32-rust-candidate-target \
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 \
cargo test --locked --offline -j2 -p saml-rs --no-default-features \
  --features crypto-aws-lc --test xsw --test hardening --test xml_document \
  --test assertion_conditions --test metadata_trust
```

Repeat the same prefix/options with `--lib xml::dom::tests`, then with
`--lib crypto::verify::tests`. Recorded counts are73+20+36. The unchanged native
suite has86 passing and one ignored; preserve the separately recorded historical
ignored-positive failure in the native assessment.

Owned Rust examples pass strict direct `clippy-driver -W clippy::all -D warnings`
with their actual built dependencies (edition2021, `--emit=metadata`, dependency
search path and explicit extern artifacts). Full upstream native Clippy retains
20 earlier diagnostics; no source patch or warning exemptions were added. Rustfmt
uses `--config skip_children=true` for overlay entries; imported original modules
have their own existing formatting checks. The longer ordered profile builder
keeps pre-signing policy and target placement together as a test-fixture function
size exception; all owned source files are under150lines.

[Recorded finite outcomes](results/2026-10-20-comparison.json) include exact source,
lock and adapter hashes. Source/image hashes are provenance, not a reproducible
binary or external audit claim. Remove the copied example when done so the upstream
checkout remains clean. No application/API/migration or SAML gate changes.

The subsequent [exact-policy qualification](../rust-policy/README.md) reuses this
driver and signer. Default comparison inputs remain84rows; the additional signed
algorithm controls require the explicit `--exact-policy` exporter flag. Historical
source hashes remain tied to the recorded commit; newer callback sharing does not
change the default upstream API/options or negative cases.
