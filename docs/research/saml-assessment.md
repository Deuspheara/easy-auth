# SAML verifier assessment — AUTH-3

Assessment date: 2026-10-18. **No production verifier is selected. SAML remains a hard release blocker.** This is source and dependency research, not an independent security audit. No SAML runtime dependency or ACS is introduced by this assessment.

## Current selection checkpoint — 2026-10-20

**Do not select the current native candidate for production integration.** The
generated signed Response/Assertion controls establish bounded trust, algorithm
and extraction behavior, but the strict XML gate still fails. Additional passing
signature tests cannot clear a reproduced mandatory parser-policy failure.

| Requirement | Current evidence | Selection consequence |
| --- | --- | --- |
| Exact source and explicit trusted-key/algorithm policy | Pinned native build; [56 signature outcomes](../../tests/provider/saml/native/results/2026-10-20/assertion-signature-observation.json), with healthy controls and unsigned/tamper/trust/SHA-1 negatives | Preliminary engine evidence only |
| Reject forbidden XML | DOCTYPE, malformed closing tag and multiple roots accepted in both reduction modes | Failed; cannot activate SAML |
| Signature-path resource behavior | [20 observed outcomes](../../tests/provider/saml/native/results/2026-10-20/signature-resource-observation.json), working independent I/O controls and zero observed resource calls; six XML-policy failures and six opaque errors | Bounded observations; strict rejection and error review remain unresolved |
| Native dependency review and independent security review | No clearance recorded | Required external review remains open |
| Application and PostgreSQL SAML acceptance | No SAML adapter, ACS or persistence authority enabled | Cannot infer acceptance from the existing application regression suite |

Source reinspection confirms a configuration limitation at this exact pin. The
[public reduction contract](https://github.com/njaremko/samael/blob/2d27dfe4930c4632b202f32886a85b2d1f9226c2/src/crypto/mod.rs#L179-L184)
accepts XML, certificates, reduction mode and an algorithm allowlist, with no parser
policy parameter. Both the
[input parser](https://github.com/njaremko/samael/blob/2d27dfe4930c4632b202f32886a85b2d1f9226c2/src/crypto/xmlsec/mod.rs#L241-L247)
and [reduced-fragment parser](https://github.com/njaremko/samael/blob/2d27dfe4930c4632b202f32886a85b2d1f9226c2/src/crypto/xmlsec/mod.rs#L586-L591)
construct the default parser internally. Directly constructing different libxml
options in application code does not configure those calls. This is a limitation
of the assessed API, not a claim that upstream hardening is impossible.

Unblocking selection requires a reviewed dependency hardening change or another
reviewed pinned verifier, followed by the required hostile corpus, native review
and independent security review. Preserve the failing controls and strong positive
controls when evaluating that change. An unreviewed fork, custom XML-signature
implementation, global parser-policy workaround or relaxed verification is not
selection evidence. Until those prerequisites change, AUTH-32 remains incomplete
and the SAML release gate stays closed.

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

## AUTH-32 native checkpoint — 2026-10-20

The earlier native-build gap now has preliminary evidence. The same pinned samael
revision and unchanged Cargo.lock compiled with Rust 1.95.0 in an isolated Linux
arm64 container, without installing host libraries. Actual native packages include
xmlsec 1.2.37, libxml2 2.9.14 and OpenSSL 3.0.22. The
[recipe and limits](../../tests/provider/saml/native/README.md) verify the entire
source archive before extraction and retain exact observed package/image provenance.
Native packages resolve at build time; no reproducible-binary or advisory clearance
is claimed. An altered archive was rejected before extraction/compilation.

The unchanged upstream library suite passed 86 tests, with one ignored case. Its
ignored positive was also explicitly executed: exit 101, one failed assertion,
with native RSA-SHA1 signature rejection. Independent public-certificate key
extraction shows that this fixture's configured metadata key differs from its
embedded certificate key; the passing companion fixture has matching keys. This
is consistent with the observed rejection, not proof of a library vulnerability.
No assertion, fixture, algorithm or trust policy was changed to make it pass.

The [finite record](../../tests/provider/saml/native/results/2026-10-20/upstream-native.json)
keeps these outcomes separate. Read-only, network-disabled execution with no host
mounts contains the run but does not establish zero attempted resource accesses.
Upstream legacy-algorithm positives are not our required production allowlist.
Strict parser/resource and verified-content controls, the easy-auth adapter and
PostgreSQL corpus, native dependency advisory/license inventory and focused
independent security review remain outstanding. No production verifier, SAML
runtime dependency or ACS is selected by this checkpoint.

### Direct parser observations — AUTH-32

The [bounded parser probe](../../tests/provider/saml/native/parser-probe/README.md)
now exercises the exact `libxml` 0.3.3 default interface used in the candidate.
Inspected source confirms `parse_string` passes default options with `recover=true`
and `no_net=false`. Eight fixed DTD/entity/malformed inputs were accepted as XML.
Independent syscall observation and a loopback HTTP trap saw no sentinel-file
calls, connection calls or HTTP requests during those cases. Real healthy parser,
file-access and HTTP controls succeeded both before and after them.

An actual unavailable `strace` produced a separate infrastructure result, exit 2;
restoring the normal environment reproduced the observations, exit 1 for candidate
parser-policy gaps. Failed observation cannot become a secure XML rejection.
Strict full-upstream Clippy also failed on 20 unchanged library diagnostics; that
failure is preserved. The owned Rust probe separately passed strict Clippy against
the actual compiled dependency artifacts, without exemptions or upstream changes.

The [finite record](../../tests/provider/saml/native/results/2026-10-20/parser-defaults-observation.json)
does not establish signature acceptance, SAML authentication bypass or general XXE
safety. Canonicalization, reduced-fragment and other signature/parser paths still
require their own observers. The default parser's acceptance of these inputs does
not satisfy our strict rejection policy; no production integration is selected.

### Signed Response engine observations — AUTH-32

The resumed [signature probe](../../tests/provider/saml/native/signature-probe/README.md)
uses the existing candidate signer with fresh in-memory RSA-2048 certificates.
The response template's SHA-1 reference digest is replaced with SHA-256 before
signing. Every verification supplies the explicit RSA-SHA256/SHA-256 allowlist;
no upstream fixture, assertion, trust configuration or verifier is weakened.

Both nonlegacy reduction modes pass the six healthy signed controls and two
rollover rows. Both reject unsigned content, altered signatures/subjects, wrong
keys, empty trust, attacker KeyInfo, SHA-1 reference digests and duplicate IDs.
Forged sibling markers before/after the signed Response do not reach returned
verified content. These 34 case/mode observations establish bounded engine
behavior, not the full SAML profile or local authentication.

The [finite result](../../tests/provider/saml/native/results/2026-10-20/signature-observation.json)
preserves exit 1 and six XML-policy failures: DOCTYPE, malformed closing tag and
multiple document roots are accepted in both modes. Returning the trusted signed
subject after recovery does not meet strict input rejection policy. No bypass or
general resource-denial claim follows from this result. Actual executable
unavailability exits 2 as infrastructure failure; a restored run reproduces all
outcomes. Four reporting tests additionally preserve failed-control and unknown-
engine distinctions. Signature/canonicalization resource observation, signed
Assertion-only coverage, broader hostile corpus, native advisory/license inventory
and independent review remain open. No production SAML dependency or ACS is selected.

### Signed Assertion and signature-algorithm follow-up — AUTH-32

The [expanded signature record](../../tests/provider/saml/native/results/2026-10-20/assertion-signature-observation.json)
extends the unchanged upstream candidate to 56 case/mode rows. All earlier 34
outcomes are reproduced unchanged. Four new healthy rows establish signed
Assertion extraction in both modes: only the Assertion is signed inside an
unsigned Response containing an outside-signature marker. The marker and forged
unsigned Assertions inserted before/after the signed Assertion are absent from
returned content. Unsigned/altered Assertions, wrong/missing trust and duplicate
signed Assertion IDs are rejected. This closes only the bounded Assertion engine
coverage gap; it is not profile or application authentication acceptance.

A separate negative uses the existing upstream signer to generate RSA-SHA1 with
a SHA-256 reference digest. Both modes reject it under the unchanged explicit
RSA-SHA256/SHA-256 allowlist. Combined with the prior RSA-SHA256/SHA-1-digest
negative, the controls vary signature and digest independently. No permissive
verification, custom cryptography or policy exception is introduced.

Ten healthy rows and both rollover rows pass; six XML-policy failures remain.
The actual missing-executable control and restored run again distinguish
infrastructure failure from candidate rejection. Owned strict Clippy and four
reporting tests pass; full upstream Clippy retains its 20 diagnostics. Broader
hostile/resource/profile coverage, native dependency review, application/PostgreSQL
SAML acceptance and independent security review remain release gates.

### Signature-child resource observations — AUTH-32

The [signature resource recipe](../../tests/provider/saml/native/signature-probe/RESOURCES.md)
reuses the exact earlier parser observer and independent I/O-control executable,
with fingerprints verified against their original record. A separate signature
child runs 20 case/mode rows: healthy signed Responses/Assertions before/after six
DTD/entity variants, always under the unchanged RSA-SHA256/SHA-256 allowlist.
The observer traces only that child and descendants; the independent HTTP trap
and direct-parser/file/HTTP controls work before and after it.

The [finite result](../../tests/provider/saml/native/results/2026-10-20/signature-resource-observation.json)
records zero sentinel-file calls, connection calls and HTTP requests across the
child, including its fixture generation and verification/reduction calls. These
are aggregate observations without per-case or internal-stage attribution. They
do not establish general XXE safety or resource denial for untested transforms.

The assessment exits 1: DOCTYPE, external DTD and parameter entities are accepted
in both modes (six policy failures); internal/file/HTTP entity references produce
six opaque engine errors. The latter remain unresolved rather than secure
rejections. Actual missing `strace` exits 2 without rejection observations; a
restored run reproduces the counts and outcomes. The new binary also reproduces
all prior 56 signature outcomes. Eight reporting tests and owned strict Clippy
pass; the same 20 upstream Clippy diagnostics remain separate failures.

This adds bounded signature-path resource evidence, not a production integration
or complete canonicalization/fragment/transform coverage. Strict rejection policy,
opaque error review, broader hostile/profile and SAML PostgreSQL acceptance,
native dependency review and independent security review still gate selection.
