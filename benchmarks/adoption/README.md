# Native embedded adoption probes

These are disposable research executables for AUTH-5, outside the production Cargo workspace. They call public native APIs against real PostgreSQL. They are not a new authentication API, a server load test or a production deployment.

## Reproduce

Historical replay must use an isolated source export of exact producer `34ed2e9e9e2255f6b32b25bf18db99b0cca94565` for the sustained-load dataset, or `f43e46f0874443b27d511e8f3c733d989363a486` for the original sequential experiment. Current `src/easy.rs` has evolved with the product and does not match the historical producer hash. The committed results describe their original runtime and lockfile, not current HEAD. Review the recorded dependency advisories before executing old upstream code. Stored arithmetic/provenance can be checked with `python3 benchmarks/adoption/verify_recorded.py` without running those libraries or opening a database.

Use separately owned disposable PostgreSQL and SMTP fixtures in that isolated checkout. The legacy runner below expects its documented development Compose endpoint; do not point it at a retained application preview, account store or production service.

Use Rust 1.95, Python 3.9+, Docker Compose and `ps` (RSS in KiB on macOS/Linux). Start only the isolated checkout’s disposable loopback development PostgreSQL service. The runner uses only its documented development credentials and creates a separate `easy_auth_compare_<random>` database for each process, then removes that exact database in `finally`. It never truncates the application's database. The Rust probes independently reject other database names and non-loopback hosts.

```sh
docker compose up -d postgres
python3 benchmarks/adoption/run.py all
python3 benchmarks/adoption/summarize.py benchmarks/adoption/results/local
```

Results go to ignored `benchmarks/adoption/results/local/`. `build` and `measure` can run separately. Use `--project easy`, `--project rustauth` or `--project lucid` to investigate one probe. `--output /absolute/path` selects another output directory. Build sequentially and stop other builds/load before collecting reported measurements. The default runs three processes per project in a fixed seeded shuffled order, each with three trials per concurrency level. Build duration is diagnostic and cache dependent, not a performance comparison.

Upstream Git dependencies are pinned to the exact reviewed M00 revisions and the separate Cargo.lock pins transitive resolution. Cargo fetches them; no upstream source is vendored or relicensed. The libraries retain their MIT licenses; the probe source is original project code under the root licenses. RustAuth's pinned README declares it unmaintained. Its inclusion satisfies the requested historical baseline, not an adoption recommendation.

All release executables use thin LTO and stripping. Build-time proc macro libraries remain unstripped because the local macOS linker produced a malformed SQLx macro LINKEDIT pool when stripping them. This override is shared by every probe and does not change executable stripping. Production workspace configuration and lockfile remain independent.

Format and lint the isolated harness separately from the product workspace:

```sh
cargo fmt --manifest-path benchmarks/adoption/Cargo.toml --package easy-auth-adoption-probes -- --check
cargo clippy --config 'profile.dev.build-override.strip="none"' --locked --manifest-path benchmarks/adoption/Cargo.toml --all-targets --all-features -- -D warnings
```

The explicit development [build-dependency profile override](https://doc.rust-lang.org/cargo/reference/profiles.html#build-dependencies) also avoids the local proc-macro loader issue during linting. It does not change the measured release profile. Gitleaks retains its default rules; the root configuration permits only the exact verified public `src/rustauth.rs` checksum at its specific provenance JSON path. A synthetic credential in that same file was still rejected. The checksum is not an issued credential.

## Measured boundary

- Two Tokio runtime worker threads, PostgreSQL pool maximum ten, eight users with one session each, no secondary storage or client-side session cache.
- Provisioning uses the libraries' public flows: easy-auth delivered email proof followed by password enrollment/session rotation; RustAuth default password signup followed by its signed-cookie native `SessionAuth`; lucid-auth default email/password signup followed by `AuthService::session`. All eight users have password credentials, without weakening library hash defaults. Proof delivery for easy-auth is an in-process capture transport and its blocklist is an explicitly synthetic development fixture. Provisioning is deliberately outside the timed session trials.
- Warm each session with sixteen validations. For concurrency one and eight, run three trials of 512 total successful validations, recording elapsed wall time and per-call p50/p95. Each worker uses its own session. Calls include real library behavior: easy-auth updates idle activity, while other implementations have their own refresh policy. This difference is reported, not removed by replacing authentication with raw SELECT statements.
- Start seven background workers, each validating another user's session; a barrier waits for their initial validations. Keep them running while awaiting logout/sign-out and requiring 64 subsequent checks to reject the revoked bearer. Fail if any worker ends before those checks finish, or completes no validation during the scenario. Then stop and drain all workers and check another user again. Each worker is bounded at 4096 calls, and exhausting that bound fails the run. Errors never count as successful rejection. This covers post-return revocation under shared PostgreSQL load; it does not race validation of the target bearer already in flight or prove every multi-process interleaving.
- Sample child RSS every 100 ms. A 500 ms post-provisioning pause provides baseline samples. Report setup and post-provisioning peaks separately. Sampling can miss short peaks; shared libraries, allocator retention and password setup can affect RSS. This is a small local workload, not a capacity forecast.
- Save a normal/build dependency feature listing from `cargo tree` for each separately enabled probe. Counts include the common measurement harness and compile-time dependencies, not every optional package in Cargo.lock. Multiple feature configurations of one package count once. The three integrations share one resolved lockfile, but features are built separately; no all-features binary is measured.

The independent HTTP contracts, SMTP service, router protections, reference UI, passkeys and federation are outside this native session microbenchmark. The size of a stripped probe is not the size of a complete standalone authentication server. These measurements cannot establish security equivalence, production readiness, browser interoperability or the full cost of adopting either project. Review the source-level maintenance, credential-storage, tenant-isolation, migration and API differences alongside the numbers.

The original sequential-revocation experiment remains in `results/2026-10-19/` with its measured source hashes; those producer files are preserved in commit `f43e46f`. The sustained-load implementation is pinned by commit `34ed2e9`, with its separate results in `results/2026-10-19-under-load/`. Each experiment left product runtime code unchanged relative to its recorded baseline. The focused `revocation.rs` coordinator keeps barrier, revoke, post-return checks, stop and task draining visible in one ordered scenario.
