# Actual loopback HTTP benchmark qualification — 2026-10-27

This AUTH-50 increment measures the actual default-feature server executable over
fresh loopback TCP connections, with genuine disposable SMTP/credential setup and
real PostgreSQL. It is bounded local development HTTP, not TLS, sustained/open-loop
production capacity, protocol compliance or independent security approval.

## Exact source and reproduction

The shared frozen build policy was extracted separately at `0e50f3585dfd9844de34b1c5b50130e403391d25`;
the existing library benchmark passed afterward with its original behavior and
owned cleanup. Initial HTTP implementation is
`31f2cfd6af64bbeb40c137053a453a06e3ea5dae`. Qualified source is
`b0284809b76b2f94608c193916c2321e793b02f3` on
`feat/auth-50-bounded-benchmarks`. Source and binary stayed unchanged through the
three qualified repetitions.

```sh
python3 scripts/benchmark_authentication_http.py --output /tmp/easy-auth-http-new
```

The directory must be new. Default three sequential repetitions; one through five
may be selected explicitly. Frozen release/default-feature build, thin LTO/strip,
incremental disabled and explicit build-tool symbols match the
[documented build policy](../guides/authentication-performance.md).
The actual executable SHA-256 is
`1f471f06d2c2c12e08938e795a4a9359f9ba978b0e5fdc18e9df719f13cb8a28`.
Qualified private aggregate receipt SHA-256 is
`2fe2a6eca632481e6047bf3dbbfefda59dc12668d6db9123c8e7673b709194a4`.

Local environment: macOS arm64 / 10 logical CPUs, Rust 1.95.0 / LLVM 22.1.3.
PostgreSQL image `sha256:25a89970a83255ae96484d709005bb35aa71f7455f941bc1634514f31c5d5c62`;
Mailpit image `sha256:32a9262f9b8b7cc97130cddf9d17fb3f467cafa622e4427fb2159fe7282b3cad`.
The same owned PostgreSQL/Mailpit containers serve the repetitions; each database,
account set and application process is new. OS/database caches, logging, Docker's
VM and other host scheduling are not controlled or characterized as cold starts.

## Workload and actual observations

Each repetition creates eight accounts through real SMTP email proof, then uses
public password enrollment. No identity, credential or session is seeded by SQL.
Session workloads cover one shared session, independent owners and anonymous
rejection at concurrency one/two/eight, 32 attempts per worker. Password login uses
eight workers/four attempts each with fixed actual credentials. Successful returned
credentials must prove their exact owner outside the timed measurement.

Eight enrollments plus 32 password requests exhaust the actual 40/source budget;
eight separate email buckets each record five attempts. An extra attempt must
return 429 with counters unchanged in the same real database window. Actual logout
must reject replay of the saved original cookie while another owner remains valid.
No hash parameter, two-worker permit, database limit, expiry or policy is changed.

Qualified results comprise 30 workload observations and 3,264 timed HTTP requests:
2,136 successful responses (2,112 session reads  + 24 password logins), 1,056 expected
anonymous 401 responses and 72 immediate password429 refusals. Every password run
has eight 204 and twenty-four 429 results; refusal throughput is not successful
authentication capacity. There are zero transport failures or missing attempts.

The ranges below are each repetition's p95/throughput extrema, not pooled
percentiles or selected best runs. Timing includes connection/send/read but stops
before client JSON/ownership verification. Each request uses a fresh connection;
wall throughput includes closed-loop driver scheduling. This short, small sample
does not establish a stable tail, production rate or timing indistinguishability.

| Workload / HTTP status | Workers | Count per repetition | p95 ms range | Completions/sec range |
| --- | ---: | ---: | ---: | ---: |
| shared_session / 200 | 1 | 32 | 3.603–4.038 | 292.59–327.22 |
| independent_owners / 200 | 1 | 32 | 3.691–6.024 | 263.18–330.31 |
| unknown_session / 401 | 1 | 32 | 0.216–0.294 | 3618.90–6066.30 |
| shared_session / 200 | 2 | 64 | 4.484–5.694 | 486.80–502.08 |
| independent_owners / 200 | 2 | 64 | 3.878–4.868 | 503.12–547.74 |
| unknown_session / 401 | 2 | 64 | 0.261–0.396 | 5611.31–8108.96 |
| shared_session / 200 | 8 | 256 | 32.548–43.666 | 504.95–539.09 |
| independent_owners / 200 | 8 | 256 | 7.528–8.546 | 1144.33–1183.82 |
| unknown_session / 401 | 8 | 256 | 1.470–1.714 | 6899.06–7172.88 |
| password_login / 204 | 8 | 8 | 103.373–123.426 | 18.35–20.89 |
| password_login / 429 | 8 | 24 | 10.929–15.019 | 55.06–62.67 |

The three daemon lifetime peaks are 141.86–143.67 MiB; CPU totals are 1.91–2.00 seconds.
A fresh observer waits for exactly one server child, excluding cargo, Python
driver, Docker and PostgreSQL memory/CPU. The peak includes startup/corpus, SMTP,
all workloads and validation/control requests; it cannot be assigned to one
endpoint. Those observations retain the OS unit contract documented in the guide.

Every repetition records 1,141 HTTP completion events with 1,141 distinct generated
UUIDs, matching all measured, readiness, setup, credential-validation and control
requests exactly. The actual four completion fields are required with no extras;
known passwords, cookies, database credentials and owned identity values must be
absent. Exactly one static server-start and one existing development HTTP/SMTP
warning are required. Raw logs remain private and are removed after checks; only
their hashes and aggregate status counts enter receipts.

All 24 exact owned messages were removed. All three servers exited normally;
actual backend absence preceded each exact database drop. Owner labels, random
loopback listeners, no host binds and exclusive anonymous volumes were inspected;
container/volume absence was verified. No retained preview, account/passkey,
unrelated service or protected private/research file was a fixture.

## Retained failure and validation scope

The initial three-repetition HTTP run passed functional/accounting controls with a
less strict diagnostic projection. Tightening exact field/diagnostic privacy then
correctly failed qualification: the initial closed startup allowlist omitted the
server's existing `development_http_and_smtp_enabled` warning. Failed receipts
and separately scoped diagnostic reproductions are retained; only source locations
and non-secret shape booleans were printed. No failed sample was promoted to a
pass. The correction admits exactly the two expected static messages, each once;
unknown/duplicate diagnostics, extra fields and private values still fail. The
warning itself was preserved, not suppressed. Three new repetitions at the fixed
source then passed all stricter assertions. This was not an automatic build/load
retry or a relaxation of authentication checks.

Eleven current Python test methods pass, including actual owned socket responses,
lost-transport stop/no-retry, missing/corrupt outcomes, percentiles/throughput,
cookie ambiguity, exact log fields, unknown/duplicate diagnostics and private
canaries. Both focused CI commands were replayed; the Rust accounting control
passes. Existing output-directory reuse exits 1 without changed receipt/build-log
bytes. CI YAML parses with unique mapping keys. The original library benchmark
also passes a new owned repetition after the shared builder extension.

Fresh qualified-source fmt, strict default/all-feature workspace/all-target Clippy,
compiled-graph advisory and all-feature cargo-deny checks pass. Inactive
RSA/RUSTSEC-2023-0071 and existing warnings remain reported. No runtime, Cargo,
schema, native build/producer or OpenAPI input changed from the prior exact
`d32fe8eae3a316bd0ae5c9a6f72328fee55b6175` full backend checkpoint: 171 default,
1,197 all-feature reported passes (1,196 primary plus isolated logging child),
including 676 real-PostgreSQL lifecycle cases, zero failures/ignored. Those results
retain that exact source scope; no new execution of unchanged full suites or
hosted success is inferred. Fresh HTTP/SMTP/PG repetitions supplement them.

## Maintainability and remaining acceptance

Named modules separate fixed socket I/O, load accounting, genuine journeys,
single-child resource observation, log validation and resource lifetime. They
reuse existing service/mail ownership and extracted frozen build policy.
Handwritten modules stay below 200 lines. The longer ordered repetition keeps
daemon shutdown, log privacy and exact database cleanup visible together; no
production hook, generic provider framework or new dependency is introduced.

The earlier [library measurements](authentication-benchmark-verification-2026-10-27.md)
and [controlled cancellation cases](http-observation-verification-2026-10-27.md)
keep separate source/evidence scope. Deployment ingress budgets, distributed abuse,
real TLS/representative sustained load, external security review and actual
provider/OS/production acceptance remain unqualified. AUTH-49 remains the native
prerequisite; the independent review plan does not book or perform a review.
SAML waiver limits and the hard outbound issuer release gate remain unchanged.
No PR, merge, release or deployment accompanies this work.
