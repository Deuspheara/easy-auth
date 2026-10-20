# AUTH-32: selected SAML dependency review

2026-10-20. **SAML remains gated.** This extends the
[exact-policy qualification](saml-exact-policy.md) with target-scoped automated
advisory, license and source checks. It is not independent security review,
legal approval, production selection or assurance of no unknown vulnerabilities.

## Exact scope and findings

Assessed saml-rs0.6.1 at `3b289001a7a84d5a7ff7af2671991ab7098090bd`, with the two
recorded policy patches and unchanged manifest/lock. Defaults are disabled and
only `crypto-aws-lc` selected. Cargo tree and cargo-deny's license inventory agree:
**115 packages on aarch64-unknown-linux-gnu**, **116 on aarch64-apple-darwin**,
including normal/build/dev edges. Root features are exactly `crypto-aws-lc`.

Cargo-deny0.20.2 checks advisories, licenses and sources using the repository's
unchanged policy, copied only to select an isolated advisory-cache path. RustSec
was freshly fetched at commit `b19b2c83c2493961ccb12f9fc4699a00fb2c6c44`
(commit date2026-10-20). Both target checks exit0 with zero advisory/license/source
errors, zero advisory warnings and no tool error logs. Seven license warnings
remain: six existing WebAuthn-specific exceptions and the permitted CDLA license
are unused in this separate graph. No warning suppression or new exception added.

The independent whole-lock cargo-audit0.22.2 check **exits1**: rsa0.9.10 has
RUSTSEC-2023-0071; rustls0.23.45 has RUSTSEC-2026-0346 through0349; der0.8.0 and
spin0.9.8 are yanked. These entries remain in the lockfile. All are absent from
`cargo tree --target all` for the selected AWS-LC graph; they are not dismissed or
ignored globally. This does not approve default, RustCrypto, FIPS, PQ or PKCS#11
features. Changing selection or the lock requires a fresh review.

[Machine-readable evidence](../../tests/provider/saml/rust-policy/results/2026-10-20-dependencies.json)
includes the116-package union, exact versions, registry checksum provenance,
declared license expressions, license-file hashes, enabled features by target,
policy/database/log hashes, retained full-lock findings and check summaries.
It omits private local paths and raw tool messages. It is a review inventory,
not a complete shipping notice bundle or a standard-format compliance attestation.

## Native backend and primary sources

The selected graph resolves `aws-lc-rs1.18.1` and `aws-lc-sys0.45.0`. Bundled
AWS-LC CMake declares **5.7.0**, matching the
[maintainer's release mapping](https://github.com/aws/aws-lc-rs/releases/tag/v1.18.1).
Crate checksum and native license/CMake hashes are recorded. AWS-LC remains a
native dependency; no end-to-end pure-Rust or FIPS claim follows from this feature.

The five advisories listed on the maintainer's AWS-LC Rust advisory page were
checked against the actual sys-crate version, rather than bypassed on presumed
code reachability:

| Maintainer advisory | Fixed aws-lc-sys version | Assessed0.45.0 |
| --- | --- | --- |
| [X.509 name constraints](https://github.com/aws/aws-lc-rs/security/advisories/GHSA-394x-vwmw-crm3) | 0.39.0 | Outside affected range |
| [CRL distribution scope](https://github.com/aws/aws-lc-rs/security/advisories/GHSA-9f94-5g5w-gf6r) | 0.39.0 | Outside affected range |
| [PKCS7 chain validation](https://github.com/aws/aws-lc-rs/security/advisories/GHSA-vw5v-4f2q-w9xf) | 0.38.0 | Outside affected range |
| [AES-CCM tag timing](https://github.com/aws/aws-lc-rs/security/advisories/GHSA-65p9-r9h6-22vj) | 0.38.0 | Outside affected range |
| [PKCS7 signature validation](https://github.com/aws/aws-lc-rs/security/advisories/GHSA-hfpc-8r3f-gw53) | 0.38.0 | Outside affected range |

This is a dated, bounded advisory mapping, not a full native-code audit. The exact
bundled LICENSE includes AWS-LC, BoringSSL/OpenSSL-derived and other third-party
notices. Declared SPDX alternatives satisfy the existing allowlist, but distribution
still needs actual license/notice retention and independent review. No license
policy relaxation is justified by a passing scanner.

## Infrastructure failure and reproduction

An initial offline check failed on a missing locked package and a read-only
advisory cache. More subtly, a subsequent cargo-deny invocation **logged an ERROR
about dependency fetch while returning0 and passing check summaries**. It was
not accepted as clearance. Fetching the unchanged lock into Cargo's cache and
using an owned, freshly fetched advisory database produced clean reruns.

The [report guard](../../tests/provider/saml/rust-policy/check_dependency_report.py)
rejects any ERROR log, missing/ambiguous summary or malformed counts even if the
tool exits0. Four regression checks retain that failure, actual check errors and
license warnings. No raw authentication data is involved.

From the external patched checkout, first `cargo fetch --locked`. For each target,
produce `cargo metadata --locked --offline --format-version 1 --no-default-features
--features crypto-aws-lc --filter-platform TARGET` and the corresponding
`cargo tree --locked --offline -p saml-rs --no-default-features --features
crypto-aws-lc --target TARGET -e normal,build,dev --prefix none --format '{p}'`.
Use a copy of `deny.toml` with only `[advisories].db-path` changed to an owned path;
`cargo deny --config CONFIG fetch db` populates it. Record its actual git commit.
Run and preserve the tool exit status, stdout and stderr:

```sh
if cargo deny --manifest-path /path/to/saml-rs/Cargo.toml \
  --metadata-path metadata.json --config review-deny.toml \
  --no-default-features --features crypto-aws-lc --locked --offline \
  --target aarch64-unknown-linux-gnu --format json \
  check advisories licenses sources > deny.stdout.jsonl 2> deny.stderr.jsonl; then
  deny_status=0
else
  deny_status=$?
fi
python3 /path/to/easy-auth/tests/provider/saml/rust-policy/check_dependency_report.py \
  deny.stderr.jsonl --tool-exit-code "$deny_status"
```

Repeat with macOS target/metadata. `cargo deny ... list --format json --layout crate`
provides the independently compared inventory. Run full-lock audit separately,
without advisory ignores or disabling yanked checks; do not relabel its exit1 as
an all-lock pass. A previous metadata file is provenance only: regenerate it for
the exact source/feature/target inputs whenever dependencies change.

Remaining gates: upstream maintained policy/API path; distribution notice/license
review; independent backend/canonicalization/security review; structural/resource-
budget/concurrency qualification; and real application/DB acceptance before SAML
activation. No production source, migration, manifest, lock or gate changed here.
