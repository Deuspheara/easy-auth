# SAML verifier assessment — AUTH-3

Assessment date: 2026-10-18. **No production verifier is selected. SAML remains a hard release blocker.** This is source and dependency research, not an independent security audit. No SAML runtime dependency or ACS is introduced by this assessment.

## Exact candidates

| Candidate | Inspected source | Dependencies and license | Assessment |
|---|---|---|---|
| samael 0.0.22 | [2d27dfe4930c4632b202f32886a85b2d1f9226c2](https://github.com/njaremko/samael/tree/2d27dfe4930c4632b202f32886a85b2d1f9226c2) | MIT; default xmlsec feature, libxml =0.3.3, OpenSSL, xmlsec1, pkg-config and libclang/bindgen | Retain native candidate. Reviewed crypto backend does not itself prove safe SAML claim extraction. Native build and hostile corpus remain required. |
| saml-rs 0.6.1 | [3b289001a7a84d5a7ff7af2671991ab7098090bd](https://github.com/salasebas/saml-rs/tree/3b289001a7a84d5a7ff7af2671991ab7098090bd) | MIT; bergshamra requirement 0.9.0, lock resolves 0.9.2; quick-xml 0.42; Rust >=1.88 | Retain research candidate, with defaults disabled. Upstream explicitly states no external security audit. |
| samlet / opensaml | Compatibility crates in the same saml-rs tree; registry samlet 0.5.0 also re-exports saml-rs | MIT | These are not independent validators. Do not count alias crates as separate security evidence. |
| Historical opensaml-rs used by RustAuth | [c857a2b85a46e2a3df2dea43d2e5e1fdb1e4f2ff](https://github.com/salasebas/saml-rs/tree/c857a2b85a46e2a3df2dea43d2e5e1fdb1e4f2ff) | Workspace 0.1.4; bergshamra 0.5.1; quick-xml 0.41 | Current tests do not establish the safety of this older pin. No adoption by transitive reputation. |

Bergshamra is BSD-2-Clause. Its registry latest 0.11.0 is a different dependency from the resolved 0.9.2 assessed here. saml-rs defaults enable RustCrypto, legacy algorithms, post-quantum and PKCS#11 features. A smaller experiment uses `--no-default-features --features crypto-aws-lc`; that backend still builds native AWS-LC code. Neither a pure Rust label nor a FIPS feature establishes an audited or certified end-to-end SAML service. Full distribution license inventory and native-library versions must be reviewed for whichever stack is eventually selected.

## Signed-content and parser findings

In samael's `src/service_provider/mod.rs`, `parse_xml_response_with_mode` verifies and reduces XML when IdP signing certificates exist. When they do not exist, it parses the original XML with `verified=false`. Any future adapter must reject empty/untrusted certificate configuration before accepting a response. SP-initiated correlation must remain mandatory; `allow_idp_initiated` must remain false.

The xmlsec path in `src/crypto/xmlsec/mod.rs` consumes verified reference/pre-digest evidence and prunes unsigned content. It has duplicate-ID, ambiguous selection and unsigned-attribute tests. It calls libxml `Parser::default().parse_string`. In libxml 0.3.3, parser options default to `recover=true` and `no_net=false`. This alone is not proof of an exploitable XXE, since entity loading depends on parser flags and native versions. It is insufficient evidence for our strict no-DTD/no-external-resource policy. Require explicit strict parsing, external-resource denial and observed zero file/network access across every parse path, including canonicalization and reduced fragments. Never substitute custom signature verification.

In saml-rs `src/crypto/verify.rs`, verification rejects duplicate SAML IDs, restricts reference URIs, uses configured certificates and requires verified reference digests. Successful verification returns content covered by verified references. Its context enables trusted-keys-only and strict verification. `with_insecure(true)` is documented there as skipping certificate chain/time checks for pinned metadata certificates, while retaining signature/reference checks. Certificate trust, validity and rollover therefore need an explicit connection policy and tests; do not infer a Web PKI policy from signature success.

Its bounded quick-xml DOM rejects DOCTYPE and stylesheet instructions. Limits cover bytes, nodes, depth, attributes and text. The DOM stores local element names, so namespace/profile validation must be assessed through the full consuming API. High-level validation has compatibility options, including unsigned metadata and unsolicited responses. An adapter must pin the strict SP profile and demonstrate that none can bypass configured trust, correlation or replay policy.

These observations identify integration constraints and review targets. They do not establish a vulnerability or prove either library safe.

## Advisory evidence

RustSec database commit `999ec89d5d3f10f20be14750ec8c2d8b44e0ac9b` (updated 2026-10-17), cargo-audit 0.22.2:

| Candidate lockfile | Full-lock findings | Compiled graph observation |
|---|---|---|
| samael | No RustSec findings or warning categories reported | Native OpenSSL/libxml2/xmlsec versions are outside cargo-audit coverage. No native vulnerability clearance is claimed. |
| saml-rs | RUSTSEC-2023-0071 (`rsa` 0.9.10); RUSTSEC-2026-0346 through 0349 (`rustls` 0.23.45); yanked der 0.8.0 and spin 0.9.8 | `crypto-aws-lc` excludes the reported rsa/rustls packages from all-platform normal/build/dev graph. `crypto-rustcrypto` includes rsa 0.9.10; rustls findings are inactive in both inspected configurations. |

The RSA finding concerns private-key timing behavior; presence is not proof that public signature verification leaks a private key. It nevertheless fails our compiled-advisory gate and needs an approved resolution before adoption. No global ignore is proposed. Both yanked entries are inactive in the inspected AWS-LC graph and present in the RustCrypto graph; release-lock resolution is required before adoption. The saml-rs default feature set is not approved by this assessment.

Lockfile SHA-256: samael `f1ff7a214a2cb6d7f98437cd01a02280794a1ab24b564bfe16ff0a4bfd1e05e9`; saml-rs `09c5298f304507da1b652fe54a038c1f24cfea3fcb9c3f1dc3e8e1b7f1de72f4`.

Reproduction in the exact upstream checkout:

```sh
cargo-audit audit --json --file Cargo.lock
cargo tree --locked -p saml-rs --no-default-features --features crypto-aws-lc --target all -e normal,build,dev --prefix none --format '{p}'
cargo tree --locked -p saml-rs --no-default-features --features crypto-rustcrypto --target all -e normal,build,dev --prefix none --format '{p}'
```

## Hostile-input evaluation and remaining gates

Run upstream tests in isolated research checkouts, without copying implementation or fixtures into easy-auth. Record exact commits, feature flags, counts, failures and environment. Upstream fixture success is preliminary evidence; our adapter and persistence remain untested until M06.

Executed on macOS arm64 with Rust 1.95.0 against the saml-rs commit above, unchanged lockfile, AWS-LC feature only: **93 selected tests passed, zero failures/ignored**. Suites: `assertion_conditions` 21, `hardening` 22, `metadata_trust` 17, `xml_document` 3, `xsw` 10, and `xml::dom::tests` 20 (235 other unit tests filtered out). The XSW suite includes signed positive controls, forged siblings, duplicate IDs, reference coverage, tampered/unsigned messages and comment splicing. Parser tests include DOCTYPE rejection and byte/depth/node/attribute/text limits. These are not the entire upstream suite or independent adversarial review.

```sh
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo test --locked -j 2 -p saml-rs --no-default-features --features crypto-aws-lc \
  --test xsw --test hardening --test xml_document --test assertion_conditions --test metadata_trust
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 \
  cargo test --locked -j 2 -p saml-rs --no-default-features --features crypto-aws-lc \
  --lib xml::dom::tests
```

The first build exhausted local disk at linking; a clean compact build with the host deployment target succeeded. Native samael tests were **not run**: xmlsec1 executable/pkg-config metadata is absent on this host. No native libraries were installed globally. A pinned isolated native build, native advisory/license inventory and equivalent hostile corpus remain explicit selection prerequisites. Source inspection and a clean Cargo advisory report do not replace those tests.

For this documentation change, easy-auth's fmt, strict clippy and all 13 workspace tests (including real PostgreSQL) passed again; Markdown local links and whitespace checks passed. Runtime code, migrations and Cargo dependencies are unchanged.

The required easy-auth corpus and harness must cover:

| Boundary | Positive control and hostile variants | Required observation |
|---|---|---|
| Signed-node binding | Valid signed Response and signed Assertion; forged sibling before/after, nested wrapper, duplicated IDs, signature over issuer only, unsigned attributes, comment splice, multiple document roots, namespace substitution | Only verified identity content is consumed, or the whole message is rejected; never authenticate the forged subject. |
| Trust and algorithms | Configured rollover certificates; attacker KeyInfo, missing/disabled connection certificates, external references, unsupported transforms, SHA-1, HMAC confusion, altered digest/signature | Reject without configured trust; fixed allowlist and no external fetch. |
| XML resources | DTD, internal/external entities, file and HTTP entities, parameter entities, malformed/recovered XML, extreme nesting/text/attributes and compressed POST/redirect bombs | Bounded rejection; local file sentinel unread; network trap sees zero requests. Test every parser/transform entry point. |
| SAML profile | Expected issuer/audience/destination/recipient/subject; each absent/wrong/duplicated, future/expired times, invalid status, multiple assertions/audiences | Exact configured SP profile enforced on verified content; bounded explicit clock skew. |
| Correlation and replay | Correct outstanding request; missing/wrong/reused request, assertion/response replay, simultaneous redemption, cross-realm/connection replay | Atomic request consumption and replay reservation in PostgreSQL; at most one successful session, tenant isolation. |
| Operational trust | Certificate rollover/expiry, disabled connection, bounded metadata fetch, DNS redirect/rebinding, signed metadata over wrong node | Explicit administrative trust and SSRF controls; no identity from stale or untrusted connection state. |

Pin a local IdP and perform end-to-end SP-initiated browser interoperability after corpus success. Review native dependencies and images, obtain focused security review, and only then select the verifier in an ADR. No IdP-initiated login, SLO or SAML IdP implementation is authorized by this assessment. M06 / AUTH-32 owns this release gate; unrelated authentication milestones may proceed.
