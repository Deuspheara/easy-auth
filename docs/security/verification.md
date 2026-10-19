# Initial execution evidence — 2026-10-18

This is alpha implementation evidence, not an independent security audit or a production release.

## AUTH-18 initial verifier checkpoint — 2026-10-19

The optional core `passkeys` feature now wraps high-level webauthn-rs registration
with strict origin/RP configuration, required user verification, bounded private
database-state encoding and redacted failures. The [ADR](../architecture/adr/0008-passkey-verification-boundary.md)
documents ownership and logging boundaries. This checkpoint does **not** implement
durable enrollment, account authorization, HTTP endpoints or browser interoperability.
AUTH-18 remains In Progress; those acceptance criteria still need implementation.

- `cargo fmt --all -- --check` and strict workspace/all-target/all-feature Clippy passed.
- `cargo test --locked --workspace --all-features`: 64 passed, zero failed/ignored,
  including the existing 11 HTTP/PostgreSQL and 42 PostgreSQL lifecycle tests.
  Five new core tests cover configuration, state bounds/round-trip, fresh challenges,
  origin/port changes, redaction and actual upstream payload-log suppression with a
  positive control. They do not substitute for the remaining protocol attack corpus.
- Default workspace build passed. Its compiled graph excludes webauthn-rs;
  the all-features graph includes it. No server composition enables enrollment.
- All-feature compiled advisory and cargo-deny gates passed. The inactive optional
  SQLx MySQL/RSA finding remains visible. A synthetic advisory for webauthn-rs 0.5.5
  was injected into audit output while using the real feature graph; the gate
  correctly rejected it as compiled. No advisory ignore was introduced.
- Both Gitleaks 8.24.3 and 8.30.1 passed a source-only snapshot including untracked
  feature files. Five package/version-scoped MPL exceptions and redistribution
  notices accompany the dependency. Native OpenSSL packaging remains a release gate.

Local macOS commands used the previously documented unstripped build-dependency
workaround (`profile.dev.build-override.strip="none"`, dev debug information off,
two build jobs). CI now tests default and all features, lints all features and
audits the complete feature graph, with explicit Linux OpenSSL build dependencies.
Hosted verification of this checkpoint is still pending publication.

- Rust 1.95.0: `cargo check --workspace` passed.
- `cargo fmt --all -- --check` and `cargo clippy --locked --workspace --all-targets -- -D warnings` passed.
- `cargo test --locked --workspace`: 13 tests passed, zero failures/ignored. Four unit tests, three Axum HTTP/database tests, six PostgreSQL lifecycle/constraint/concurrency tests. Real PostgreSQL 17 with isolated test databases and actual migrations.
- `python3 scripts/smoke.py` passed through real Mailpit SMTP and the standalone server: email proof, identity, opaque session, replay rejection and logout.
- `python3 scripts/smoke.py --embedded` passed while running the embedded example, including its custom `/private` route. Both compositions use the same core, router, PostgreSQL and SMTP adapter.
- Real Chromium browser: request email, open test link, remove fragment, display verified identity, sign out. Same-tab fragment navigation exposed a client issue; after adding a hashchange handler, a second browser sign-in completed without reloading and logout cleared the identity.
- Generated OpenAPI 3.1 document is served at `/openapi.json`; an integration test compares the live result against `docs/openapi.json` and verifies malformed request details are not reflected in error bodies.
- `cargo deny check`: advisories, bans, licenses and sources passed; duplicate-version warnings remain. 0BSD and certificate-root CDLA notices were reviewed and included.
- Full-lockfile cargo-audit reports RUSTSEC-2023-0071 in inactive optional SQLx MySQL/RSA. `scripts/audit.py` passes the all-platform compiled graph, with the resolver finding visible; no global advisory ignore. See protocol-dependencies.md for limitations.
- Gitleaks source snapshot scan passed. A public example realm UUID is explicitly annotated as non-secret; no blanket secret-rule exclusion. Build artifacts were excluded from the source scan.
- Fresh loopback Docker Compose PostgreSQL/Mailpit deployment passed health checks. `docker build -t easy-auth:alpha .` passed (Linux release build); the Dockerfile includes a non-root runtime and liveness health check. Hosted CI and production container connectivity remain separate evidence; configuration alone is not proof.

## Remaining release gates

Hosted [GitHub Actions run 39162595141](https://github.com/Deuspheara/easy-auth/actions/runs/39162595141) passed for published commit `e49ad9ee99bb169dda19fa9ccd54a6c1459c7e73`: both Rust and secret-scanning jobs succeeded, including fmt, strict clippy, real PostgreSQL tests, the compiled advisory gate and cargo-deny. This verifies M01 foundation acceptance only.

Authenticated password change and production blocklist coverage/review; session listing/individual/revoke-all controls; linking and further audit lifecycle; rate/challenge/audit/notification retention and queue monitoring/redrive; passkeys and real authenticator tests; Google/Apple web/native; enterprise OIDC; a pinned reviewed SAML validator and hostile XML corpus; outbound issuer/client isolation/key rotation/conformance; stronger-factor recovery/lifecycle policy; external security review; operational restore/key/migration drills; accessible polished reference UI and broader SDKs. No production-provider interoperability is claimed.

## AUTH-12 password evidence — 2026-10-18

- `cargo fmt --all -- --check`, strict workspace/all-target clippy and `cargo test --locked --workspace` passed: 20 tests, zero failures/ignored (2 Axum unit, 5 HTTP/database, 4 core, 9 PostgreSQL). Real migration 0002 adds password credentials and bounded audit/admission kinds.
- New coverage: fixed Argon2id parameters/random salts, valid/invalid/dummy verification, malicious costly PHC rejection, NFC/long Unicode/length bounds, blocklist membership and worker saturation; PostgreSQL freshness, realm isolation, concurrent enrollment with one winner, session-insert rollback, old-session rejection, stale credential recheck and shared admission; HTTP generic errors for unknown/email-only/wrong-password accounts and disabled feature.
- `python3 scripts/smoke.py --password` and `--embedded --password` passed against actual loopback SMTP/PostgreSQL, using `AUTH_SMOKE_URL=http://127.0.0.1:58418`. Both preserved the same verified identity through password enrollment/login; embedded mode also validated its custom protected route. No real credentials were printed. Test server processes were stopped afterward.
- Production startup with HTTPS/TLS SMTP configuration and the example corpus rejected startup with the expected minimum-corpus error, without attempting SMTP delivery.
- Release KDF measurement: `cargo run --locked --release -p easy-auth-core --example password_cost`, macOS arm64/Rust 1.95.0, five samples: hash 85–91 ms, verify 85–92 ms at 64 MiB/t=3/p=1. This is not a deployment throughput guarantee.
- Compiled advisory gate and cargo-deny passed with the new graph; inactive SQLx MySQL/RSA finding stays visible. Source-only gitleaks scan passed. A whole working-directory scan also included generated data and reported findings; it is not used as the source acceptance result. No broad secret rule was disabled.
- [Password policy/limits](../guides/passwords.md) and [ADR 0003](../architecture/adr/0003-password-enrollment.md) describe opt-in configuration, the development-only corpus and incomplete recovery/release gates. The default reference page remains email-only; password APIs are headless. Hosted CI for this feature is separate evidence and is not claimed here.

Hosted AUTH-12 [CI run 39164588096](https://github.com/Deuspheara/easy-auth/actions/runs/39164588096) subsequently passed every step for commit `4b89a97b5cd9c1c7ed79c7671d0b42f4a2a473eb`. Its Linux release container also built, runs as user 65532:65532, and rejects insecure production HTTP. Password recovery below adds a small reference completion form; enrollment/sign-in remain headless.

## AUTH-13 recovery evidence — 2026-10-18

- Fmt, strict all-target clippy and workspace tests passed: **25 tests, zero failures/ignored**, including real PostgreSQL migrations. New tests cover wrong realm/browser/purpose, expiry, replay, stale credential versions, proofs issued before enrollment, concurrent resets with one winner, all old sessions/proofs invalidated, old password rejected, and notification-insert failure rolling back credentials/session/proof/audit changes.
- Notification tests cover concurrent claims, cross-realm denial, stale acknowledgments, expired leases, delayed retries and retained exhausted work. HTTP tests verify generic start responses/delivery for known/unknown/email-only accounts, origin/binding checks, blocklist rejection, no automatic sign-in and recovery despite a failed first notification delivery.
- Actual `scripts/smoke.py --recovery` and `--embedded --recovery` passed through SMTP/Mailpit and PostgreSQL on loopback 58418. Both verified new-password sign-in with the same identity, old-password/session rejection and background delivery of a notice without password or proof. Embedded mode also verified its custom protected route. Test processes were stopped afterward.
- JavaScript syntax, Python AST and local document links passed. Python's default bytecode-cache check initially failed on an unwritable cache path; the read-only AST check and actual smoke execution succeeded.
- Compiled advisory, cargo-deny and source-only secret scans passed locally. Record the hosted CI result against the final commit in Huly. Existing inactive optional SQLx MySQL/RSA findings remain visible rather than globally ignored. Notification retention/monitoring, stronger-factor recovery and independent security review remain release gates.

Hosted AUTH-13 [run 39165689782](https://github.com/Deuspheara/easy-auth/actions/runs/39165689782) subsequently passed every job/step for commit `3afadc74e47066e6dfe633e6b7d4cc60112875bc`.

## AUTH-14 account lifecycle evidence — 2026-10-18

- Fmt, strict all-target clippy and **33 workspace tests** passed, zero failures/ignored (2 Axum unit, 7 HTTP/database, 4 core, 20 PostgreSQL). New coverage proves both-address confirmation, same-session/browser/user/realm binding, expiry/wrong-purpose rejection, one-winner address races without merging, old-session rejection, scoped deletion cleanup, audit-subject removal and full rollback when notice insertion fails.
- A real migration-0003-to-0004 test preserves normal legacy session validation while denying sensitive actions until a new login. Password-enrollment rotation preserves original authentication time; creating/touching a session does not refresh it.
- `scripts/smoke.py --lifecycle` and `--embedded --lifecycle` passed against actual PostgreSQL/Mailpit on loopback 58418. Synthetic accounts completed both mailbox confirmations, retained the opaque identity/password through email change, rejected the old session, then completed mailbox/phrase-confirmed deletion. The shared worker delivered non-secret change/deletion notices. Embedded mode verified its protected route after the address changed. Test servers were stopped afterward.
- JavaScript/Python syntax, local documentation links and whitespace checks passed. New schema includes proof/session/user composite ownership constraints and explicit audit/notice policy. Dependency and source-secret gate outcomes are recorded against the published commit in Huly.
- Deletion scope is the live auth store, with an explicit temporary recipient-only deletion-notice exception. Backups, delivered email, in-flight SMTP/application actions and consumer business records have separate policies. No total-erasure, security-audit or production-readiness claim is made. See [lifecycle guide](../guides/account-lifecycle.md) and [ADR 0005](../architecture/adr/0005-account-lifecycle.md).

Hosted AUTH-14 [run 39166904145](https://github.com/Deuspheara/easy-auth/actions/runs/39166904145) subsequently passed both jobs and every step for commit `0180e5f932efcd1fecfbb02929935749b51a8b48`.

## AUTH-52 maintainability evidence — 2026-10-18

- Split the accumulating core, PostgreSQL and Axum implementations and integration suites into feature modules; separated server configuration, SMTP and notification worker composition. No new crate, dependency or migration. The largest Rust source/test file is now the existing 218-line password policy module; crate entry files are 7–40 lines. See [organization and reviewed exceptions](../architecture/code-organization.md).
- Fmt, strict all-target Clippy and all **33 workspace tests** passed (2 Axum unit, 7 HTTP/database, 4 core, 20 PostgreSQL), with no failed or ignored tests. SQLx migration, binding, isolation, concurrent consumption and rollback scenarios run against real PostgreSQL after relocation.
- Compared 35 core/PostgreSQL method bodies with the pre-refactor source, normalizing only SQL whitespace and legal trailing argument commas. Existing test/setup bodies were preserved, with relative includes adjusted for relocation. All four published migrations and seven browser assets remain byte-identical. These mechanical comparisons supplement the runtime suite; they are not an independent security audit.
- The existing contract test detected utoipa's automatic module-path tags after handler extraction. Importing generated path descriptors locally restored the exact published OpenAPI JSON; no contract snapshot was updated to hide the regression.
- Standalone and embedded `scripts/smoke.py --password --recovery --lifecycle` runs passed with actual PostgreSQL/Mailpit on loopback 58418; the embedded run also verified its protected application route. Both disposable test servers were stopped.
- Compiled advisory policy, cargo-deny and source-only Gitleaks passed. The inactive optional SQLx MySQL/RSA lockfile finding remains reported; existing duplicate dependency/license-allowance warnings remain non-fatal. Hosted results are tracked against the final published commit in Huly.

Hosted AUTH-52 [run 39168185029](https://github.com/Deuspheara/easy-auth/actions/runs/39168185029) passed every job/step for commit `c15e4732849fa8998490dd08e0663881a89673d3`.

## AUTH-15 session management evidence — 2026-10-18

- Fmt, strict locked all-target Clippy and **48 workspace tests** passed, with no failed or ignored tests (2 Axum unit, 10 HTTP/database, 4 core, 32 PostgreSQL). The strengthened pending-proof ownership case was then rerun separately and passed. Integration scenarios cover active-only bounded inventory, complete 50/50/3 cursor pages, public metadata/redaction, unchanged other-device last-seen, foreign-user/realm/cursor denial, current-cookie clearing, stale/future/legacy authentication, idle/absolute boundaries and atomic audit rollback.
- Deterministic PostgreSQL advisory/row-lock barriers prove both login/revoke-all orderings and authentication freshness revalidation after waiting. Concurrent revoke-all requests have one successful winner and one audit event. All four pending-proof types are canceled for the actor while another user's proofs in the same realm and a same-email identity in another realm are preserved.
- The explicit schema-0004-to-0005 upgrade test preserves existing sessions/audit and enables the new audit kind. Published migrations 0001–0004 are unchanged. Generated OpenAPI adds exactly three management paths and their schemas; every previously published path/schema remains unchanged. Session arrays declare a maximum of 50 items.
- Standalone and embedded `scripts/smoke.py --password --recovery --sessions --lifecycle` runs passed against real PostgreSQL/Mailpit on loopback 58418 in separate disposable realms. The session scenario verifies old-cookie rejection, a genuine new sign-in after all-session revocation and the embedded protected route. Both test servers were stopped.
- The first combined smoke attempt exceeded the existing ten-attempt account admission budget by placing every scenario on one account. The script now gives session management its own disposable account and verifies the original account remains authenticated. Limits and counters were not relaxed or cleared. The corrected combined runs passed in both modes.
- Compiled advisory, cargo-deny and source-only Gitleaks checks passed. Existing inactive optional SQLx MySQL/RSA and non-fatal dependency/license warnings remain visible. JavaScript syntax, Python AST, local documentation links and whitespace checks passed. Hosted results are recorded against the final published commit in Huly.
- Inventory is an evolving set of browser sessions, not physical-device attestation or a pagination snapshot. A fresh authenticated session is required for management mutations; a genuine login ordered after revoke-all may create a session. Application actions already authorized can finish. Higher-assurance step-up, native refresh families, external-provider/outbound tokens, retention/load tuning and full reference UI remain separate release work. See [session guide](../guides/sessions.md) and [ADR 0006](../architecture/adr/0006-session-management.md).

Hosted AUTH-15 [run 39169492302](https://github.com/Deuspheara/easy-auth/actions/runs/39169492302) passed every job/step for commit `fd10222d33f885707d8304a9af8322daa227e6c5`.

## AUTH-16 safe audit evidence — 2026-10-19

Published commit `ffe0b3dc1ae95803a4f93fb40e2450d2e6145f6a` passed [hosted run 39171239645](https://github.com/Deuspheara/easy-auth/actions/runs/39171239645), including both Rust and secret scanning jobs, all 59 tests, formatting, strict Clippy, the compiled advisory gate and cargo-deny. This closes the scoped M02 accounts/session milestone, not the full authentication release.

- Fmt, strict locked all-target Clippy and **59 workspace tests** passed, with no failed or ignored tests (2 Axum unit, 11 HTTP/database, 4 core, 42 PostgreSQL). The focused HTTP redaction test and ten audit integration scenarios were subsequently rerun after small assertion/mapping cleanups and passed.
- Actual lifecycle operations emit all eight closed event kinds with schema-versioned user/actor/affected-session attribution. Tests inspect persisted rows for mailbox, credential, PHC, bearer, verifier, reset/browser-proof and arbitrary-context canaries. The HTTP test uses real Argon2 password enrollment/recovery and confirms unknown context is rejected before persistence. No public audit append/read endpoint or OpenAPI change was added.
- Composite foreign keys reject other-user/realm subjects and actor/target sessions. Kind/version/shape checks reject unbounded values, incomplete current facts and unsupported linking-success kinds. Account deletion erases every subject/actor/target reference while preserving unrelated ownership; tests exercise rollback of deletion and its audit deidentification.
- Injected audit failures roll back email proof/identity/session creation, password enrollment, recovery, email changes and deletion. Existing session-management rollback tests continue to pass. A deterministic user-lock barrier proves logout waits without holding the session lock, preventing the new ownership checks from inverting lifecycle lock order. Its event timestamp is taken at recording after the wait, not transaction start. Repeated logout emits no duplicate success fact.
- The schema-0005-to-0006 fixture retains valid version-0 subjects with explicitly unknown actor/target provenance and deidentifies stale/cross-realm subjects and old deletion facts. Earlier upgrade tests now seed version-pinned legacy rows rather than calling today's writer against an old schema, then verify the preserved legacy authentication-time/session behavior after all applicable upgrades. Published migrations 0001–0005 remain byte-identical.
- Standalone and embedded real PostgreSQL/Mailpit smoke runs passed with `--password --recovery --sessions --lifecycle` in separate disposable realms on loopback 58418. They exercise mandatory audit writes across credential, recovery, session and deletion transactions; embedded mode also verifies the consuming application's protected route. Both test servers were stopped.
- Compiled advisory, cargo-deny, source-only secret, syntax, local-link, whitespace and file-organization checks passed. Existing inactive optional SQLx MySQL/RSA findings and non-fatal dependency/license warnings remain visible. Hosted results are tracked against the final published commit in Huly.
- Linking policy is explicit, not an implemented provider claim: AUTH-25 must prove fresh current-account control and a separately verified bound identity, reject other-owner identities and never merge by matching email. It must add its typed event/schema with the actual link transaction and negative tests. The current database rejects `identity_linked`; email-change tests remain evidence only for that implemented two-mailbox flow. Historical provenance, retention/session-pruning, privileged read/export policy, tamper resistance and independent security review remain explicit limitations. See [audit guide](../guides/audit-events.md) and [ADR 0007](../architecture/adr/0007-safe-audit-and-linking.md).

## AUTH-5 adoption measurement evidence — 2026-10-19

- The isolated [native probes](../../benchmarks/adoption/README.md) built against exact pinned sources. The [final sustained-load experiment](../../benchmarks/adoption/results/2026-10-19-under-load) passed nine fresh-process PostgreSQL runs: 27,648 timed successful validations, 2532 successful background validations, 576 post-return revocation rejections, and nine checks that another user's session stayed valid. Seven background workers remained live through each revocation/check window; each completed validation work and failed the run if its 4096-call bound exhausted before the window finished. Recorded source hashes match both the current measurement source and committed producer `34ed2e9e9e2255f6b32b25bf18db99b0cca94565`. The [initial sequential experiment](../../benchmarks/adoption/results/2026-10-19) and its hashes are preserved, with its producer files in commit `f43e46f`.
- Both product-workspace and all-feature probe formatting/strict Clippy passed. Local memory-saving builds used `CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_INCREMENTAL=0` and two build jobs; an explicit `profile.dev.build-override.strip="none"` avoided the reproduced macOS proc-macro LINKEDIT loader error. Runtime source, production workspace dependencies and immutable migrations were unchanged.
- All three native executables rejected the application database name before connecting. Measurement databases use a fresh guarded prefix and are removed by the runner; the post-run database count for that prefix was zero. No production credentials or external providers were used.
- Native Gitleaks 8.30.1 was downloaded from its official release, with both release checksum-file and archive digests verified. Hosted CI uses 8.24.3, which ignored the initial global allowlist format and flagged the public source checksum in the first publication. The fix uses a compatible rule-level exception for that exact checksum at the two specific provenance JSON paths. Official-checksum-verified 8.24.3 and 8.30.1 both passed Git-mode scanning with the fixed configuration; both still rejected a synthetic credential in each same provenance path. Default rules remain enabled and neither file nor rule is skipped.
- The isolated comparison lockfile reports RSA RUSTSEC-2023-0071, compiled only by the lucid-auth probe; the separate unmaintained `atomic-polyfill` lockfile warning was not in any of the three compiled graphs. These are recorded findings, not an advisory ignore or approval of those dependencies for the product.
- A product workspace rerun initially stopped in the eleven HTTP/database fixtures because Docker's API became unresponsive and PostgreSQL refused connections (`PoolTimedOut` during database setup). After the user authorized restarting Docker Desktop, graceful stop timed out and the supported forced stop/start restored the existing PostgreSQL/Mailpit services. A fresh full workspace rerun then passed all **59 tests**, with zero failures or ignored tests. The strengthened comparison ran after that recovery, with builds stopped during measurement.
- Hosted run [39219868778](https://github.com/Deuspheara/easy-auth/actions/runs/39219868778) passed its complete Rust job for the initial published snapshot, including 59 tests, formatting, strict Clippy, the compiled advisory gate and cargo-deny. Its secret job failed only on the checksum/version compatibility issue described above. Subsequent corrected-head publication and hosted status are tracked in Huly AUTH-5; this failed job is not represented as green.

The SQL transaction uses database time and conditional updates. Revocation applies on the next validation; requests already authorized may finish. Email-only sign-in assumes mailbox control and is not phishing-resistant. Cross-device link redemption and unrelated-domain app integrations are intentionally unavailable in this slice.
