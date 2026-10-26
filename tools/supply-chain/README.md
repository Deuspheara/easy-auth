# Source SBOM tool inputs

This is tooling for AUTH-48 evidence, not another authentication crate or runtime
dependency. The application workspace manifest, lockfile and root license policy
are unchanged.

Use Python 3.12+, Rust 1.95, cargo-audit and cargo-deny. From committed reviewed
source, choose a new private temporary parent and prepare its new child:

```sh
tool_parent=$(mktemp -d "${TMPDIR:-/tmp}/easy-auth-sbom-tool.XXXXXX")
python3 scripts/prepare_sbom_tool.py --destination "$tool_parent/generator"
```

The bootstrap downloads the official Apache-2.0
[cargo-cyclonedx 0.5.9](https://docs.rs/crate/cargo-cyclonedx/0.5.9) archive over normal
HTTPS, checks its registry SHA-256 before bounded safe extraction, applies only the
committed tooling lock, fetches locked dependencies, requires clean audit and
explicit tooling license/source checks, and builds frozen. It refuses an existing
destination. Logs remain private; the receipt records source/lock/policy/binary and
toolchain/auditor identities. No generated artifact alone supplies release approval.

The upstream archive's bundled lock selected vulnerable `time 0.3.36`, unsound
`anyhow`/`rand` versions and a yanked entry. The isolated refreshed lock now selects
`time 0.3.55`, `anyhow 1.0.104` and `rand 0.8.8`; its complete 163-package lock
passes current audit with zero vulnerabilities/warnings. The official tool source
is unchanged. This is a tool dependency refresh, not an application upgrade or
advisory exemption. Retain the failed original audit when reproducing the review.

The refreshed tool graph introduces `borrow-or-share 0.2.4` under MIT-0 through
`fluent-uri`/`cyclonedx-bom`. The root application policy correctly rejects that
undeclared license. The separate tooling policy admits only that exact package/
version after reviewing the retained package text and
[SPDX MIT-0](https://spdx.org/licenses/MIT-0.html), which removes MIT's attribution
paragraph. This is an explicit tooling license decision; it does not widen the
application allowlist, exempt an advisory or constitute independent legal approval.
The original no-new-exception intent changed for this recorded, narrow tool need.

The generated 1,528-line lockfile is a size exception. It provides exact checksums
for the separate tool graph and must be updated deliberately with source, audit,
license/source checks and an actual bootstrap replay. Do not replace it with an
unlocked installation or silently reuse the original vulnerable bundled lock.

For inventory/SBOM commands, image/native evidence, observed scanner limitations
and remaining gates, see the
[supply-chain review](../../docs/security/supply-chain-review-2026-10-26.md).
