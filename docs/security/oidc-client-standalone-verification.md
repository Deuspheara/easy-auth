# Independent OIDC client and configured issuer verification

Local verification date: 2026-10-24. Implementation checkpoints:

- `30c42a768b53af383a9ca6f216ac666ba7781cc8`: independent Rust SDK after three separately verified structural extractions.
- `50c3a4fbae270133a1bae5e07bb87926733c60c2`: default-off configured issuer and executable/embedded client parity.
- `61d1ea155970faf16d0885db4753ad1c6a26c6ca`: actual native SDK loopback, rotation and logout acceptance.

This receipt records local implementation evidence. Hosted success must be checked
on the exact pushed commit; this document does not assert an unobserved hosted
result. The CI workflow includes the new isolated SDK/startup and actual parity
steps. No independent audit, certification, production readiness or universal
provider interoperability is claimed.

## Required local gates

| Command/check | Observed result |
| --- | --- |
| `cargo fmt --all --check` | Pass |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | Pass |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Pass, including final native acceptance source |
| `cargo test --locked --workspace` | 118 passed; no failures or ignored tests |
| `cargo test --locked --workspace --all-features` | Final rerun: 1,009 reported passed, comprising 1,008 primary and one child test; no failures or ignored tests |
| Real PostgreSQL lifecycle target within the full workspace run | 591 passed; actual PostgreSQL and migrations, not an in-memory substitute |
| HTTP integration target within the full workspace run | 174 passed |
| Core target within the full workspace run | 150 passed; the separately reported child belongs to its existing subprocess scenario |
| `RUSTDOCFLAGS='-D warnings' cargo doc --locked --workspace --all-features --no-deps` | Pass |
| Changed documentation's local links | Pass |
| `python3 scripts/audit.py` | Compiled advisory check pass |
| `cargo deny --all-features check` | Advisories, bans, licenses and sources pass |
| `python3 scripts/check_saml_source.py` | 245 maintained files and 11 recorded patches pass; no verifier/source patch added |
| `python3 -m unittest scripts.test_saml_source scripts.test_saml_qualification` | 11 pass |
| Scoped gitleaks scans of each explicitly staged implementation/test/doc set | No leaks found; private worktree material excluded |

Advisory tooling still reports the previously documented inactive optional MySQL
lockfile entry `rsa 0.9.10` / `RUSTSEC-2023-0071` as information. It is not in the
compiled shipped graph. No new dependency or advisory ignore was introduced.

## Feature and acceptance checks

The isolated SDK suite passes 14 tests covering actual validated discovery,
S256/nonce/state, a normal signature from the existing maintained producer, exact
callback/fixed query/issuer admission before POST, finite errors, ambiguity without
code retry, operation ownership, monotonic expiry, strict configuration, no-store
refetching and native replacement-credential handling. Existing core OIDC and 126
PostgreSQL OIDC regressions also pass. Isolated SDK HTTPS adapter tests pass 10;
issuer-plus-OIDC and issuer-plus-SAML build independently. Real-PG startup tests
reject missing/disabled/mismatched/foreign keys without provisioning or enabling;
two provider attachment contract/realm cases pass.

`node tests/browser/issuer-standalone/run.cjs` passes identical behavior against
the real executable and the configured embedded factory. Each uses disposable
PostgreSQL, real local SMTP and explicit browser consent, then separate cookie-free
Node and Rust clients. Both verify real discovery/JWKS and production-issued tokens,
code replay refusal, bound denial without POST, actual native loopback callback,
SDK refresh rotation, logout denial of the next refresh, access/local-session
separation, browser privacy and logout. Both report owned database, exact recipient
mail and private-file cleanup. Existing normal web3/native6 browser regressions
also pass after extending the owned client host allowlist.

The runner reuses existing normal TLS/key/HTTP producers and readers. It creates no
adversarial XML/cryptographic fixture and performs no custom signature-concurrency,
fuzzing, stress or bypass experiment. Private owned TLS replaces only the fixture's
address/roots while retaining hostname/SNI/peer validation and request/response
bounds. This does not test public DNS/system trust. Child processes are forcibly
stopped for teardown; graceful shutdown and platform vault integration are not
proved. No live service or registry image is deployed/published by these checks.

## Corrections and limits

The no-cache SDK regression initially exposed a second-authorization admission
failure. Leased operations now use the existing bounded fetch scheduler; limits
remain unchanged, no-store metadata is fetched again and codes are never retried.
An isolated issuer/OIDC build exposed a missing reexport; its feature gate was
corrected. Initial nested test-path and owned readiness setup failures were fixed.
The final suites above passed without changing protocol assertions, cryptographic
checks, admission policy, timeouts or advisory policy to obtain success.

Implementation modules have named ownership and stay under 300 lines. Longer
ordered completion, process lifetime and integration scenarios keep their security
sequence/resource ownership visible as documented function-size exceptions.
No new crate, proof constructor, migration or generic provider framework was added.
SDK metadata cannot become a local session or provider completion proof. Application
sessions, authorization, protected per-user storage, operator rollover and broader
production/assurance requirements remain separate. SAML independent review remains
waived under ADR0032, not performed; these results do not alter that distinction.

## Independent ordinary rollover extension

A final M07 parent audit identified that initial independent key verification did
not itself prove client interoperability through rotation. The existing normal
key/file owner was extracted in separate verified commit `40a5c7d`; its original
executable/embedded parity and isolated strict Clippy passed before extension.

The extended actual suite now passes both executable and embedded modes with the
same 15 behavior facts, including ordinary rollover, retained old-key overlap,
independent wrong-audience rejection and SDK verification on both sides of rotation.
It prepublishes one replacement through existing operator APIs, waits the actual
300-second policy plus one second in each mode, genuinely reauthenticates and only
then obtains healthy old-key tokens. Explicit activation and restart load the exact
new protected key; both old and new normal signatures verify against current public
JWKS while still unexpired. A different trusted audience expectation is rejected
against unchanged ordinary bytes. No custom/adversarial cryptographic fixture,
timestamp rewriting, policy bypass or signature-concurrency experiment is used.

Both modes remove their owned databases, two exact recipient messages per mode and
private TLS/key files. Strict default/all-feature all-target workspace Clippy and
formatting pass on the extension. Runtime implementation and dependencies are
unchanged from the previously verified baseline; the 118default/1009all-feature
workspace evidence above is not relabeled as a rerun of these added browser cases.
The final exact-commit hosted workflow reruns its full gates and extended suite.
Hosted completion must still be checked before ticket/milestone closure.

## Later HTTP-deletion fixture failure and correction

Exact `dbaf114201d6f5bd9d87191fd9f1333ba06e9443` CI40088449730 attempt1 passed the
workspace, isolated client/startup, real extended issuer parity, release and secret
checks, then failed the existing OIDC HTTP-deletion browser step. Overall CI was
failure, not success. Redacted diagnostics showed one blocked callback-origin
script request during initial bootstrap; cleanup completed normally. A secondary
opaque-page storage check masked the original failure in the final reporter.

A stricter controlled-document wait reproduced the failure locally. The redirected
bootstrap return reached the application confirmation document instead of the
intended capture document. The browser collector had relied on interception of a
redirected navigation; [Playwright documents a redirect routing limitation](https://playwright.dev/docs/api/class-page#page-route).
The fix explicitly selects the existing exact-URI owned TLS capture sink for the
two library bootstrap operations, counts their actual network deliveries, then
clears the selection before every real HTTP deletion operation. No production
code, authentication rule, network allowlist, timeout or crypto fixture changed.
Controlled documents gain no-store/no-referrer/CSP; unexpected requests still fail.
Primary errors survive cleanup validation, and contexts close even on failure.

The final six-case real provider HTTP-deletion suite and all23 existing generic
OIDC browser cases pass with owned database/provider/private-file cleanup. Existing
protocol assertions and exact token-post/signature-mutation/replay counts remain.
No new mutation/crypto/bypass/concurrency experiment was introduced. The earlier
failed CI is retained as evidence; a new exact-source full workflow is required
before ticket closure.
