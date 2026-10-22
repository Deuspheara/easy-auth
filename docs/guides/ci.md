# CI dependency caches and verification

The Rust job retains every formatting, lint, workspace/feature/real-PostgreSQL,
browser/provider, source-integrity and advisory/license check. Cache hits never
skip those steps. Secret scanning remains a separate unchanged job. Job permissions
remain `contents: read`.

## Cache scope

Only push runs restore/save this cache; pull requests run the full cold checks.
The [official actions/cache action](https://github.com/actions/cache/tree/0057852bfaa89a56745cba8c7296529d2fc39830)
is pinned to the verified v4 commit0057852bfaa89a56745cba8c7296529d2fc39830 (MIT).
It saves a new cache only after successful job completion. GitHub documents
[cache matching and scope](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching).
A cache is a performance input, not test evidence or protocol approval.

The explicit paths are public Cargo download/git objects; dependency fingerprints,
native build outputs and libraries under target/debug; and the isolated
`RUNNER_TEMP/easy-auth-security-tools` install root. The whole Cargo home, registry
credentials, Git checkout/auth configuration, runtime temporary directories,
PostgreSQL data, provider credentials, RustSec advisory DB and check results are not
cached. After every check succeeds, `cargo clean -p` removes all four workspace
packages' build outputs before cache save, retaining dependency artifacts. This
also forces current workspace source/tests to rebuild on subsequent runs.

The key binds runner OS/architecture, exact hosted image identity, `rustc -vV`,
installed OpenSSL/CMake/pkg-config/GCC/G++/libc development versions, Cargo.lock,
all Cargo manifests, workspace Cargo configuration and pinned SAML inventory/patches.
Each commit has a distinct immutable save key; fallback is limited to the same
complete environment/dependency prefix. Cargo still validates dependency/build
fingerprints. Missing image data or failed metadata commands disable the cache
and use normal cold verification. Bump the `rust-v1` namespace when changing the
cache policy; a cold miss remains correct.

Both `cargo install cargo-audit --locked` and `cargo install cargo-deny --locked`
still execute each run, with only an isolated `--root` added. Cargo's installed
metadata can avoid rebuilding a current restored tool; the normal installer still
checks the current upstream package selection. This is not a fixed cached-tool
version or cached advisory result. The tool path is added through GITHUB_PATH;
`scripts/audit.py` and `cargo deny --all-features check` always run normally.

## Evidence and limits

A successful pre-cache run39762944493 recorded67seconds in the first strict Clippy
step,117seconds installing cargo-audit and82seconds installing cargo-deny. Those
are observed step durations, not a promise of warm-cache savings or total runtime.
Full PostgreSQL/browser tests still take their normal time.

Local validation parses the workflow and embedded Python/shell, compares every
previous verification step's order/conditions/inputs (allowing only the new tool
install root), checks the cache-path allowlist, and exercises image/compiler/native
key separation plus missing/failed-metadata cold fallback. No application Rust,
protocol policy, migrations, assertion fixtures or tests change for this work.
The first hosted run must establish cold verification and successful save; a later
natural run must establish warm restore and all checks before reporting a measured
improvement. AUTH-58 remains open until that evidence exists. No SAML or outbound
issuer release/independent-review requirement is cleared by caching.
