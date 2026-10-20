# Exact SHA-256 policy qualification — AUTH-32

**Research patch only; SAML stays gated.** No production dependency or custom
signature verifier is introduced. Base: saml-rs0.6.1 commit
`3b289001a7a84d5a7ff7af2671991ab7098090bd`; lock SHA256
`09c5298f304507da1b652fe54a038c1f24cfea3fcb9c3f1dc3e8e1b7f1de72f4`.
The [upstream MIT notice](UPSTREAM-LICENSE) accompanies the source patch.
Patch-directory Git attributes preserve the required single-space blank context
records in unified diffs; Rust source formatting is checked separately.
No claim of upstream acceptance, audited code or production readiness.

## Change and policy boundary

Apply [0001](patches/0001-extract-verified-profile.patch) before
[0002](patches/0002-exact-sha256-profile.patch). The first extracts the existing
profile code into `crypto/verify/profile.rs` without behavior changes; all36
existing verification tests passed after extraction. The second adds:

- `XmlSignatureProfile::StrictRsaSha256`: the existing strict reference, namespace,
  exclusive-c14n and transform profile, with exact RSA-SHA256 and SHA-256 digest.
- An explicit optional `FlowOptions.xml_signature_profile`. `None` retains the
  existing boolean's compatibility/strict-SHA2 behavior; an explicit profile takes
  precedence. Typed SP configuration preserves the enum through SSO and both
  logout parsers. Signature-required policy remains a separate mandatory setting.
- Policy applied to the exact verifier-authenticated Signature/SignedInfo node in
  the existing verifier DOM before exposing content. No scan of arbitrary unsigned
  signatures, custom crypto, replacement canonicalization or DOM bridge.

The generic signature API and old defaults remain compatibility APIs. Our driver
requires signatures, configured trusted keys, strict profile, issuer, audience and
request correlation. Its two fixture subject markers only observe returned content;
they are not an application identity parser. Cryptography and reference validation
remain with the existing bergshamra/AWS-LC stack. Exact policy is an acceptance
postcondition on verified signatures; this does not promise that unapproved
algorithms are never attempted inside the backend or establish CPU-DoS bounds.

The new enum variant requires upstream API/version coordination for exhaustive
matches. This is an upstream-compatible proposal against one exact pin, not a
published release or a maintained private fork. Dependency adoption/review remains
open. No public easy-auth contract, route, persistence or migration changes.

## Reproduce

First build the existing [comparison image](../comparison/README.md). Assemble an
owned temporary build context; do not add a repository checkout or credentials:

```sh
policy_context=$(mktemp -d)
saml_checkout=/path/to/exact-pinned/saml-rs
git -C "$saml_checkout" archive --format=tar 3b289001a7a84d5a7ff7af2671991ab7098090bd > "$policy_context/source.tar"
cp tests/provider/saml/rust-policy/observer.Dockerfile "$policy_context/Dockerfile"
cp tests/provider/saml/rust-policy/patches/*.patch "$policy_context/"
cp tests/provider/saml/rust-policy/exact_candidate.rs tests/provider/saml/rust-policy/observe.py "$policy_context/"
cp tests/provider/saml/comparison/profile_control.rs tests/provider/saml/comparison/rust_candidate.rs "$policy_context/"
cp tests/provider/saml/comparison/run.py "$policy_context/comparison_run.py"
docker build -t easy-auth-auth32-rust-policy:assessment "$policy_context"
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 128 --cpus 2 --memory 3g \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m easy-auth-auth32-rust-policy:assessment
```

The Dockerfile verifies archive SHA256
`5ac1dc497d608edf2c6b751751a6c86d2b935a6e6e56149c788bfe436198e3e1`,
applies patches with zero fuzz and leaves the lock unchanged. The upstream
`rust-toolchain.toml` selects stable; the recorded build resolved **rustc1.99.1**.
Record actual versions/image IDs on subsequent runs; this is not a reproducible
binary claim. The base is the earlier source-pinned native comparison image;
new packages are CMake and patch. Cargo fetch may download inactive locked
packages; execution/build selects defaults off and only `crypto-aws-lc`.

The build runs the candidate's full selected-feature suite, including doc tests,
with `cargo test --locked --offline --no-default-features --features crypto-aws-lc
-p saml-rs`. `/work/policy-tests.log` retains the test output inside the image.
The examples use the existing shared comparison driver; no second verifier or
fixture signer implementation is added. New policy profiles are opt-in via
`auth32_profile_export --exact-policy`; its default output remains eight rows,
so the earlier84-row recipe retains its original input set and API behavior.

## Independent observation and findings

The observer creates a real sentinel file and loopback HTTP trap. Independent
`strace -f -e trace=%file,%network` surrounds only the exact-flow child. Existing
separate file/HTTP control code proves both observers work before and after; the
trace must contain that child's `execve`. Network-none still permits the controlled
container-loopback trap. No application network policy or authentication bypass
is enabled. XML/certificates stay in memory; private signer keys stay in its process.
Only finite outcome labels, booleans, counts and hashes are published.

The106 transport rows are the original76 signature/resource rows, eight complete
bearer controls, sixteen independently signed non-policy algorithm rows, and six
direct resource-reference negatives. Repeated native mode labels duplicate each
Rust input:53 scenarios, not106 independent designs. The16 new signed rows vary
signature and reference digest independently at SHA384/512 on Response/Assertion.
The old broad strict profile accepts all16, establishing cryptographic validity;
exact policy rejects all16 as algorithm errors. Direct URI negatives alter
SignedInfo in a healthy fixture and are not valid signed positives; they test
preflight rejection before resource use. Their mutation is fixture construction,
never preprocessing input at a security boundary.

[Recorded results](results/2026-10-20-exact-policy.json):

| Outcome | Exact flow |
| --- | ---: |
| Complete RSA-SHA256/SHA256 positive controls accepted | 4 |
| SHA-1 + SHA384/512 policy rows rejected | 24 |
| Forbidden XML/entity rows rejected | 18 |
| File/HTTP/path reference rows rejected | 6 |
| Remaining trust/signature/coverage/profile denials retained | 54 |
| Total rows | 106 |

No accepted foreign subject/wrapper marker. Zero sentinel-file calls, connect
calls and HTTP requests from the traced exact-flow child. The file control opened
the sentinel once and the HTTP control made one connect/request, before and after.
These are aggregate bounded observations, not universal no-I/O or XXE assurance.

Missing tracing is a deliberate infrastructure failure (exit2); it cannot pass as
zero I/O. Reproduction, with the same containment flags and image:

```sh
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=128m \
  --workdir /work --entrypoint python3 easy-auth-auth32-rust-policy:assessment \
  -c 'import policy_observe; policy_observe.STRACE="/observer-unavailable"; policy_observe.main()'
```

Restoring the real observer reproduced all106 rows with healthy controls and zero
observed resource operations. Reporting unit tests additionally reject missing
rows, opaque errors, observed resource calls, forged identity and non-policy
algorithm acceptance. Run them and the existing eight reporting tests:

```sh
python3 -m unittest discover -s tests/provider/saml/rust-policy -p 'test_*.py'
python3 -m unittest discover -s tests/provider/saml/native/signature-probe -p 'test_*observe.py'
```

Validation: full patched candidate suite **1087 passed, zero failed/ignored** on
Linux; macOS full pre-typed-test run1086 plus the added public typed test passed.
Strict all-target Clippy on macOS passed for the selected AWS-LC candidate; strict
Linux owned-example Clippy passed for exact adapter and native profile signer.
Candidate/workspace formatting, no-default-features compilation, secret scans and14
reporting tests passed. Early mixed-pair fixture failure is
retained in evidence: upstream signing fills empty values only; the fixture now
clears generated values using DOM byte ranges and signs through that provider.
All39 verification tests then pass. No assertions or production security controls
were weakened. Historical native parser/lint/ignored-fixture failures remain intact.

Maintainability: the shared research callback has only crate visibility; the old
entry still composes the same options. New modules stay below300lines. The existing
strict profile's ordered policy function remains a size exception: keeping
canonicalization, unique reference, verified algorithms and transforms together
makes the complete acceptance invariant inspectable. Ordered fixture/typed test
matrices retain before-signing setup, cryptographic controls and paired outcomes
as test-function size exceptions. No unrelated production refactor or cleanup.

Production gates remain: upstream adoption/maintenance and API review; full
license/advisory/backend review; independent security review; expanded structural,
resource-budget and concurrency qualification; any enabled metadata/encryption/
detached-binding paths; and real application/DB authority, replay, realm and lifecycle
acceptance. This research changes none of those activation requirements.
