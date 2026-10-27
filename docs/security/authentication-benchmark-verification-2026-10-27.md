# Bounded authentication benchmark qualification — 2026-10-27

This AUTH-50 increment qualifies reproducible local measurements of the existing
session/PostgreSQL and password-service boundaries. It is not complete AUTH-50
acceptance, production capacity, timing-security assurance or independent review.
Native AUTH-49 remains open; real provider/OS/production acceptance is deferred.

## Source and environment

- Initial implementation: `05f625e6f9b4b9e896f6fa9385f5a6b052b513de`.
- Qualified source: `052a3a527d2838dcb94710783e1c3db9b97e9856`, clean and unchanged
  throughout the three-repetition workload and full required checks.
- Branch: `feat/auth-50-bounded-benchmarks`, based on the completed AUTH-42 audit.
- macOS arm64, Apple M2 Pro, 10 logical CPUs; Rust 1.95.0 / LLVM 22.1.3.
- Frozen optimized application build, thin LTO/stripped release defaults,
  incremental disabled; build-tool debug symbols explicitly enabled.
- Binary SHA-256: `aad5c6db663d6efaade7cab3abbbc20b4a2387aadefcfd14ecabf6688febd92a`.
- Resolved PostgreSQL fixture image:
  `sha256:25a89970a83255ae96484d709005bb35aa71f7455f941bc1634514f31c5d5c62`.
  Mailpit from the reused fixture lifetime was provisioned but not exercised:
  `sha256:32a9262f9b8b7cc97130cddf9d17fb3f467cafa622e4427fb2159fe7282b3cad`.
- Complete private aggregate receipt SHA-256:
  `d8eac9cffb81a9f341529c5073f37708d8b153afbecec252af89d3d913bb9400`.
  Its samples contain no identity, credential, cookie, hash or database URL.

The [workload guide](../guides/authentication-performance.md) defines exact fixed
sizes, closed-loop timing, nearest-rank percentiles, outcomes and RSS scope. Each
repetition uses a new owned database and separate session/Argon2 processes.
Required ownership labels, random loopback ports, no host binds and exclusive
anonymous volumes were inspected. Database absence and container/volume cleanup
were verified. No retained preview/account/passkey or unrelated Docker service was
used. Original private/research files were not benchmark inputs.

## Results

All six profile processes and 72 case observations passed independent receipt
validation. Across three repetitions: 4,752 timed attempts, 2,232 successful
operations, 2,232 expected unauthorized outcomes and 288 capacity refusals.
Sessions accounted for 4,224 attempts; Argon2 for 528. There were no unexpected
errors or missing completions. All unknown/foreign-realm attempts rejected; actual
revocation rejected the old bearer while another owner's genuine session remained
usable.

Argon2 process lifetime peak RSS was 134.94–134.98 MiB; session-process peak was
9.73–9.81 MiB. These include startup/fixture/runtime overhead and exclude database
and Docker memory. A separate fresh-child 64 MiB allocation probe returned raw
`ru_maxrss=82018304`, supporting bytes on this macOS. The guide records the primary
resource-interface sources and the obsolete archived Apple manual discrepancy.

The table reports the range of each repetition's p95 and throughput, not a pooled
percentile. The named outcome is the only rate shown. Each eight-worker Argon2
case had 32 attempts: eight reached its expected verification/enrollment outcome,
24 were immediately rate limited. Those refusals have separate counts/latencies
and do not inflate successful authentication rates. Four/eight successful samples
cannot establish stable tail behavior or timing indistinguishability.

| Profile / workload | Workers | Expected completions per repetition | p95 ms range | Expected completions/sec range |
| --- | ---: | ---: | ---: | ---: |
| sessions / shared_session (success) | 1 | 32 | 3.154–5.258 | 267.93–346.05 |
| sessions / shared_session (success) | 2 | 64 | 3.774–4.649 | 557.52–593.65 |
| sessions / shared_session (success) | 8 | 256 | 35.313–40.956 | 563.89–587.64 |
| sessions / independent_owners (success) | 1 | 32 | 3.088–3.739 | 333.79–362.10 |
| sessions / independent_owners (success) | 2 | 64 | 3.712–3.807 | 604.80–623.96 |
| sessions / independent_owners (success) | 8 | 256 | 8.327–10.013 | 1167.84–1175.09 |
| sessions / unknown_session (unauthorized) | 1 | 32 | 1.029–1.105 | 1119.84–1171.33 |
| sessions / unknown_session (unauthorized) | 2 | 64 | 1.096–1.174 | 1946.80–2130.25 |
| sessions / unknown_session (unauthorized) | 8 | 256 | 2.546–3.440 | 3357.72–3785.39 |
| sessions / foreign_realm (unauthorized) | 1 | 32 | 1.031–1.236 | 971.46–1082.01 |
| sessions / foreign_realm (unauthorized) | 2 | 64 | 1.173–1.266 | 1786.13–1937.42 |
| sessions / foreign_realm (unauthorized) | 8 | 256 | 2.428–2.755 | 3270.68–3844.63 |
| argon2 / enroll (success) | 1 | 4 | 94.518–121.001 | 10.03–10.79 |
| argon2 / enroll (success) | 2 | 8 | 101.432–104.327 | 20.83–21.25 |
| argon2 / enroll (success) | 8 | 8 | 90.103–98.260 | 21.11–22.61 |
| argon2 / verify (success) | 1 | 4 | 92.845–95.900 | 10.66–10.83 |
| argon2 / verify (success) | 2 | 8 | 89.033–95.114 | 21.55–23.20 |
| argon2 / verify (success) | 8 | 8 | 88.183–91.294 | 22.59–23.22 |
| argon2 / wrong_password (unauthorized) | 1 | 4 | 94.618–95.939 | 10.56–10.79 |
| argon2 / wrong_password (unauthorized) | 2 | 8 | 92.116–94.449 | 21.63–22.94 |
| argon2 / wrong_password (unauthorized) | 8 | 8 | 89.569–93.609 | 22.75–22.89 |
| argon2 / unknown_account (unauthorized) | 1 | 4 | 94.673–95.529 | 10.56–10.73 |
| argon2 / unknown_account (unauthorized) | 2 | 8 | 90.851–94.107 | 21.74–23.14 |
| argon2 / unknown_account (unauthorized) | 8 | 8 | 91.489–102.571 | 21.63–22.82 |

These measurements include local scheduling and Docker virtualization. They
exclude HTTP/TLS, full password-login transactions, external arrival schedules,
distributed abuse and sustained production load. No latency/RSS acceptance budget
or deployment sizing recommendation is inferred.

## Failures, controls and validation

The first default optimized macOS build failed before fixture creation: SQLx's
stripped procedural macro could not load because of a misaligned LINKEDIT string
pool. The failed receipt/log remains separate. An explicit build-tool debug-symbol
setting fixed the loader failure; application optimization, KDF parameters and
security assertions are unchanged. This was a source/configuration correction,
not an automatic retry that concealed a failed measurement.

Focused Rust validation checks completion accounting and prevents rate refusals
from being counted as successful capacity. Five Python test methods cover missing
and duplicate workloads, samples, percentile/maximum/throughput corruption,
nonfinite durations/samples, wrong-realm success, unproven revocation and absent
RSS. An actual second invocation against the completed output directory refused
it with exit 1, leaving receipt/build-log hashes unchanged.

On exact clean `052a3a5`, all required commands passed: `cargo fmt --all -- --check`; strict default/all-feature workspace/all-target Clippy; `cargo test --locked --workspace` (167 passes); the all-feature workspace suite (1,193 reported passes: 1,192 primary plus one isolated logging child), including the 676-case real-PostgreSQL lifecycle target. Zero failures or ignored tests. Compiled-graph audit and all-feature cargo-deny passed, retaining the inactive RSA/RUSTSEC-2023-0071 report and existing warnings. The explicit benchmark Rust test and five Python methods also passed. All newly owned gate containers and exclusive volumes were removed.

Later changes add CI invocation of those exact focused commands and documentation only; application, benchmark, manifest/lock and schema inputs retain this exact qualification scope. No new hosted CI result is inferred.

## Maintainability and remaining scope

The server example's entry only composes named load/password/session modules;
synthetic proof enrollment and invariant controls live in the session fixture.
Python separates owned-service/build lifetime, single-child RSS observation and
strict outcome/receipt validation, reusing the existing fixture lifetime rather
than copying Docker ownership rules. Handwritten modules stay below 150 lines;
longer ordered launch/collection and cleanup functions retain capability ownership
and failure handling together. No auth policy, migration, public proof API, runtime
dependency or generic framework was added. No structural production refactor was
mixed into this increment.

The [independent review plan](independent-review-plan.md) prepares exact-source
scope, entry conditions and finding/retest treatment. It is not a booked or
performed review, and no reviewer has been contacted. Safe endpoint telemetry,
actual HTTP overload/cancellation and broader abuse/load qualification remain
AUTH-50 work; current request-ID/status logs are not relabeled as that acceptance.
AUTH-47/48/49 prerequisites, real provider/OS/production acceptance, the SAML waiver
limits and the hard outbound OIDC release gate remain open. No PR, merge, release
or deployment accompanies this qualification.
