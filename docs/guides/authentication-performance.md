# Bounded local authentication measurements

AUTH-50's local workload measures existing library boundaries on synthetic data.
It does not establish production capacity, an independent audit, provider/OS
interoperability or completion of the AUTH-49 prerequisite. External review and
production verification remain separate work.

From a clean committed isolated Linux/macOS checkout, with Rust, Python 3.10+ and Docker:

```sh
python3 scripts/benchmark_authentication.py --output /tmp/easy-auth-benchmark-new
```

The output directory must not exist. The runner creates it privately, builds the
example with `cargo build --frozen --release`, records the exact commit, compiler
and binary hash, and runs three sequential repetitions. `--repetitions` accepts
one through five. The runner explicitly retains debug symbols for build tools
(`CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_DEBUG=1`): the initial default macOS build
failed to load SQLx's stripped procedural macro with a misaligned LINKEDIT string
pool. This does not change application release optimization or Argon2 parameters.
The receipt records that setting; other release/target/flag overrides are refused.
Required locked dependencies and the existing
`postgres:17-alpine` / `axllent/mailpit:v1.27` fixture images must already be cached.
Resolved Docker image IDs are recorded. No download or remote provider is part of
the workload. Mailpit comes from the existing owned-service lifetime helper; this
benchmark does not send mail or measure SMTP delivery.

Each repetition creates a new database in a newly owned random-loopback PostgreSQL
container. Containers have unique ownership labels, no host bind mounts, and
exclusive anonymous volumes. Cleanup checks actual ownership, database removal
and container/volume absence. Existing databases, accounts, passkeys and preview
services are never benchmark inputs. Do not point the internal Rust example at
an application database: its loopback/name guard is an accident check, not proof
of ownership. Use the runner that provisions and inspects its own resources.

## Workloads and interpretation

Each profile uses a separate process. PostgreSQL sessions run first, then Argon2,
without simultaneous builds/tests. Process RSS is the OS-reported child lifetime
high-water mark, obtained in a fresh single-child Python observer: bytes on macOS,
KiB converted to bytes on Linux. It includes process setup, pool/fixture work and
allocator/runtime overhead. It excludes PostgreSQL/Docker memory and is not a
per-request allocation measurement. Other OS workloads, CPU scheduling, power
management and Docker's virtual machine remain uncontrolled local factors.

The resource contract follows [Python's child-usage interface](https://docs.python.org/3/library/resource.html),
[Linux's KiB definition](https://man7.org/linux/man-pages/man2/getrusage.2.html)
and [Apple's XNU source](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_resource.c)
which assigns `resident_size_max` directly. Apple's old archived manual describes
kilobytes; an actual 64 MiB allocation probe on the local macOS reports roughly
78 MiB in raw bytes, confirming the selected conversion for this qualification.

The session profile uses an eight-connection pool, eight independently enrolled
synthetic owners and eight untimed warm-up validations. Enrollment calls the
actual repository email-proof begin/finish transactions; it does not measure
mail delivery. Timed operations perform the existing verifier hash and full
repository authentication transaction, including locks and idle-time touch:

- One shared session, exposing its required row-lock serialization.
- Independent owners/sessions, exposing a different contention pattern.
- An unknown session and the same genuine session presented in another realm,
  both required to reject every attempt.

Each case runs at concurrency one, two and eight, with 32 attempts per worker.
Afterward, actual revocation must reject the old session while another owner's
session still works. These controls prevent successful latency observations from
concealing a disabled ownership, realm or revocation check.

The Argon2 profile uses the existing public `PasswordService`: Argon2id v19,
64 MiB, three passes, one lane, two shared workers. It measures enrollment, valid
verification, incorrect-password verification and unknown-account dummy work at
the same concurrency levels, four attempts per worker. Service initialization and
one seed hash are outside the timed attempts but inside process RSS. Saturation
may return the existing immediate rate limit; it must not queue unlimited hash
jobs or weaken parameters. Incorrect and unknown inputs must reject. Small samples
do not prove timing indistinguishability or reveal a safe production rate.

Workers are **closed loop**: each starts its next operation after the previous
one completes. There is no external arrival schedule, so this does not measure
open-loop overload, client queueing or coordinated-omission-free tail latency.
Latency uses monotonic elapsed time and nearest-rank p50/p95/p99. The receipt keeps
every latency sample, fixed workload sizes, wall time and all completion counts.
Success, unauthorized and rate-limited latency/throughput stay separate; fast
refusals must never inflate a claimed successful authentication capacity.

## Existing controls and remaining work

The benchmark changes no runtime policy, public API, schema, hash profile or
security assertion. Existing database admission budgets, request size/time limits,
credential-source policy and cancellation-safe hash permits remain authoritative.
The HTTP boundary currently generates a server UUID request ID and logs that ID
and finite status; benchmark receipts contain aggregate outcomes and timing only.
No cookie, password, hash, email address, token or database URL is printed.

This library workload does not measure HTTP/TLS ingress, real password-login
transactions, distributed abuse, pool exhaustion, cancellation under live HTTP
load, or sustained production behavior. Endpoint metrics and external ingress
budgets need their own bounded-cardinality/privacy and adversarial verification;
no monitoring endpoint or automatic policy tuning follows from these numbers.
The [independent review plan](../security/independent-review-plan.md) records scope
and evidence preparation; no reviewer is booked or contacted. AUTH-50 remains open
for its complete evidence, prerequisite reconciliation and external scheduling.
SAML waiver limits and the outbound OIDC hard release gate are unchanged.
