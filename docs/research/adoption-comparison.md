# Native embedded adoption comparison

AUTH-5, 2026-10-19. This follows the checkpoint in [ADR 0001](../architecture/adr/0001-build-versus-contribute.md). See the [reproducible probes and measurement boundary](../../benchmarks/adoption/README.md). These executables measure native session APIs on real PostgreSQL, not HTTP servers, complete feature sets or security equivalence.

## Sources and setup

The comparison pins [RustAuth](https://github.com/salasebas/rustauth/tree/b55e9ce3c9f375a66d8ae7ef40afe0cbd041ec1e), [lucid-auth](https://github.com/lucid-softworks/auth/tree/d16c16bfa2050e5ac08cf7e18521576f41a214f0) and the easy-auth implementation at `ffe0b3dc1ae95803a4f93fb40e2450d2e6145f6a`. A separate locked probe workspace resolves transitive versions consistently. The root product lockfile is unchanged. No upstream implementation is copied into this repository.

| Integration | Setup exercised | Native validation/revocation boundary |
| --- | --- | --- |
| easy-auth core + PostgreSQL | Pool, explicit migrations, trusted realm, email delivery adapter, password policy, delivered email proof, password enrollment with session rotation | `Auth::authenticate` and `Auth::logout`; typed secret input and stable realm-scoped user output |
| RustAuth core + SQLx PostgreSQL | Pool, adapter, configured context and signing secret, generated schema, default password signup, signed session cookie | `SessionAuth::get_session` and `SessionAuth::sign_out`; public native services rather than the HTTP facade |
| lucid-auth + PostgreSQL, default Axum feature disabled | Pool, store, configured service/signing secret, core/plugin migrations, default email/password signup | `AuthService::session` and `AuthService::sign_out`; native token API |

Provisioning is outside timed validation. The libraries use different password/verification defaults; they are not interchangeable authentication ceremonies. The easy-auth fixture uses an explicitly synthetic development blocklist and in-process email delivery. No production email/provider credentials are needed. The probes retain their default password work factors and create eight distinct users with one active session each.

The initial ecosystem review missed [RustAuth's maintenance notice](https://github.com/salasebas/rustauth/blob/b55e9ce3c9f375a66d8ae7ef40afe0cbd041ec1e/README.md). The pinned commit declares no further releases, bug fixes or security updates planned. It remains a requested historical comparison baseline; adopting it would require explicit maintenance ownership. The ecosystem review and ADR now reflect that evidence.

## Results and limitations

The [sustained-load results, feature graphs, environment and advisory record](../../benchmarks/adoption/results/2026-10-19-under-load) contain three fresh processes per project, each with three trials at each concurrency. Producer commit `34ed2e9e9e2255f6b32b25bf18db99b0cca94565` exactly matches every recorded measurement source hash. Medians below aggregate nine trials per concurrency; RSS is the median of the three sampled post-provisioning process peaks. Binary sizes are stripped executable file sizes. The common measurement harness and normal/build dependencies are included in package counts; multiple feature variants of a package count once. The [original sequential-revocation experiment](../../benchmarks/adoption/results/2026-10-19) is preserved as historical evidence, with its producer files in commit `f43e46f`.

| Native probe | Compiled packages | Binary MiB | Session RSS MiB | 1 worker validations/s | 8 workers validations/s |
| --- | ---: | ---: | ---: | ---: | ---: |
| easy-auth | 144 | 4.68 | 73.48 | 1337 | 4078 |
| RustAuth core + SQLx | 169 | 5.30 | 42.39 | 704 | 2600 |
| lucid-auth | 304 | 8.79 | 30.97 | 735 | 2747 |

Eight-worker throughput ranges across the nine trials were 3583–4245, 2084–2875 and 2480–2965 validations/s respectively. Median trial p95 latencies were 2.78, 3.89 and 3.80 ms. These are observations from this local workload, without a confidence interval or general capacity claim.

During each revocation scenario, seven other users continuously validated sessions until all 64 post-return target checks had rejected. Every process verified that the background workers stayed active, then stopped and drained them and checked another user again. Across each project's three processes, all 192 post-return target checks rejected while the workers completed 1054, 717 and 761 successful background validations respectively, including draining in-flight background calls. Median awaited revoke duration under that load was 7.48, 3.70 and 8.92 ms. The run fails if background load ends early; these checks do not treat an earlier in-flight validation of the revoked target as a violation.

Environment: Rust 1.95.0, arm64 macOS, ten host logical CPUs; PostgreSQL 17.11 arm64 Alpine in Docker with ten CPUs and approximately 7.65 GiB VM memory. Native clients use loopback TCP into the same service. Builds were stopped during the final measurements. The first runner dry run and a failed prototype using lucid-auth's optional username schema were excluded; the reported lucid-auth probe uses default email/password signup with no username plugin.

This was a shared development host, not dedicated benchmark hardware. Each workload uses eight users and one active session per user; easy-auth also retains the revoked enrollment-predecessor rows and their audit facts. The tiny dataset and different library query/retention policies limit extrapolation to larger installations.

All probes use two runtime worker threads, a pool maximum of ten, disabled client-side session caches, the same local PostgreSQL service and a bounded workload at one and eight concurrent workers. Each throughput trial performs 512 successful validations after warmup. The revocation scenario follows those trials under its own sustained background load; it does not prove every in-flight or multi-process race. RSS is sampled every 100 ms and can miss short peaks; allocator retention after credential setup remains part of the observed process.

The workloads preserve each library's semantics. easy-auth updates idle activity during every validation; the other APIs follow their own refresh policies. A faster read path cannot therefore establish equivalent idle-expiry, locking or audit behavior. Probe binaries omit HTTP, SMTP, optional UI and most federation functionality. Their sizes cannot establish a full standalone-server footprint advantage.

The locked comparison graph includes RUSTSEC-2023-0071 (`rsa` 0.9.10). The lucid-auth native feature graph compiles that package through its crypto dependencies; the easy-auth and RustAuth probe graphs do not. This is an advisory finding requiring review, not proof of an exploitable operation in these session loops or a general security ranking. It is not added to or ignored in the production dependency gate. No benchmark binary is distributed as a supported application.

## Adoption decision

The narrow easy-auth integration has fewer compiled dependencies and a smaller executable in this experiment. It also had the highest sampled post-provisioning RSS, and its awaited revocation under load was slower than RustAuth's here. Different password defaults and allocator retention limit causal interpretation; the result does not establish a generally smaller operational footprint. Its validation path was faster in this particular workload, while preserving its idle-activity update. Larger datasets, long-duration load, full HTTP stacks and the required protocol features still need M09 measurements.

Immediate post-return server-side revocation is not unique to this project: all three native integrations passed. Setup is not uniformly simpler either. Our explicit realm, verified mailbox and password-policy composition needs more application code than the two native signup paths. Those paths use different verification policies, so line count alone is not a fair usability score. No five-minute onboarding or conformance advantage is established here.

Continue the requested independent embedded/service alpha around its versioned contract, realm-scoped verifier storage and inspectable transactional policy, with the security and full-protocol release gates intact. Do not market faster sessions or smaller memory as a broad adoption promise. For Better Auth client compatibility, maintained lucid-auth/Better Auth RS remain contribution/adoption candidates; RustAuth requires a maintained fork. Shared protocol crates and reusable negative-test fixtures are better collaboration targets than copying authentication implementations. Reassess the full feature/operational burden before release, rather than turning this small benchmark into a competitor ranking.
