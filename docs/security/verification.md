# Initial execution evidence — 2026-10-18

This is alpha implementation evidence, not an independent security audit or a production release.

## AUTH-19 experimental sign-in checkpoint — 2026-10-19

The optional HTTP router now reuses atomic core/PostgreSQL sign-in with closed modes,
exact realm/origin startup checks, host binding cookies and concrete merged schemas.
Ordinary composition remains gated. Source review adds explicit signed-client-context
policy because the pinned library assertion path omits crossOrigin/topOrigin checks.
Modal mode adjusts only a public mediation hint, retaining required UP/UV and all
cryptographic checks; explicit resident enrollment changes only browser requirements,
without declaring unsigned residence metadata authoritative.

Final local workspace tests pass sequentially: default 59, all-features 102, with
zero failures/ignored tests. Formatting, strict all-target/all-feature Clippy,
compiled-advisory and cargo-deny checks pass; npm audit reports zero vulnerabilities.
The first full run exposed a logging test positive-control failure under concurrent
scoped dispatchers. Its recorder now advertises dynamic callsite interest and an
explicit TRACE hint; three repeated concurrent core suites and the final workspace
run pass with exposure, suppression and caller-log restoration assertions retained.
Production tracing policy and required checks were not relaxed.

Twenty Chromium 156.0.8078.4 cases pass through real HTTP and PostgreSQL: registration,
native platform/USB account-bound assertions, modal resident discovery, bad UP/UV/
signature, replay, missing binding, signed iframe context, BE upgrade, BS update and
signed zero counters. Thirteen sessions/authentication audits and twenty-three
admitted finish attempts confirm valid commits and admission of the signed negatives.
Twenty credentials/enrollment audits, no pending state, one backed-up/one counterless
used key and exact fixture DB removal are required. The counterless acceptance test
explicitly prepares trusted stored-zero metadata for one unused test credential;
it changes no public key, signature verifier or session code and is not native
counterless-enrollment/hardware evidence. See the [fixture details](../../tests/browser/passkeys/README.md).

The test-only dependency is pinned to Playwright 1.64.1. Chromium 151 silently ignored
the counter property setter, verified in its exact upstream handler; newer Chromium
supports it. HTTP tests also caught ignored extra fields on unit enum variants;
empty struct variants now enforce the closed contract. A context-policy unit test
rejects true/null/duplicate crossOrigin and every topOrigin. The new source files
are grouped by protocol, HTTP contract, browser assertions and fixture responsibility.

This is incremental AUTH-19 evidence. Stronger-account sensitive-action/recovery
policy, passkey-first enrollment, other browsers/real devices and full M03 activation
remain unfinished. Older sections below preserve their checkpoint scope and counts.

## AUTH-18 experimental HTTP/browser checkpoint — 2026-10-19

The explicit experimental Axum composition adds typed enrollment start/finish,
startup realm/origin alignment, a two-minute HttpOnly browser binding and a concrete
combined OpenAPI snapshot. Ordinary server composition stays disabled. The default
API/schema remains unchanged. Enrollment returns a credential UUID, not a new
passkey-authenticated session; stronger-account policy and the remaining M03 work
are still release gates.

- Final default workspace run: 59 passed; all-features: 80 passed; zero failures or
  ignored tests. Strict all-target/all-feature Clippy, formatting, compiled advisory
  and cargo-deny checks passed. The npm lock installs with scripts disabled and
  `npm audit --audit-level=low` reports no vulnerabilities.
- Eight Chromium 151.0.7922.34 virtual-authenticator cases passed through real HTTP
  and PostgreSQL: internal/platform and USB/roaming registration/replay, tampered
  challenge/origin, browser RP scoping, required UV, real cross-origin POST rejection
  and another browser lacking binding. Bad UV reached the server and was rejected.
  Each case completed a valid registration control: eight credentials, eight audit
  facts, zero pending ceremonies. The exact disposable database was removed, and
  an independent PostgreSQL query found zero browser-fixture databases afterward.
- Cross-origin status uses CDP response-extra-info because CORS blocks page access
  and can suppress Playwright response events. The assertion still requires the
  actual POST's HTTP 403. No CORS protection or product behavior was weakened.
- Adding the known binding cookie intentionally makes feature-enabled current/all-session
  revocation clear six cookies. Regression checks now explicitly require that name
  and retain zero-Max-Age checks, while default builds still require five cookies.
- Contract review caught the experimental finish DTO sharing the existing email
  `FinishInput` schema name. Unique passkey DTO names and regression checks now
  preserve every base schema and require the new credential/transaction body.

The runner records sanitized tool versions, source hashes, binary hash, named
outcomes and cleanup, without cookies, protocol payloads, browser storage/traces or
virtual private keys. Its loopback fixture seeds verified sessions through the
existing repository proof transaction; it does not claim SMTP/signup coverage.
See the [browser reproduction instructions](../../tests/browser/passkeys/README.md)
and [enrollment guide](../guides/passkey-enrollment.md). Other browsers, real
devices/providers, discoverable/passkey-first accounts, sign-in and reviewed
stronger-account recovery remain unverified. The [recorded browser run](../guides/interoperability.md#recorded-registration-browser-run--2026-10-19)
uses committed producer `05ed2cd0e8292662a7654ffc847945e554ab6ec3`; all 149 source
hashes were independently checked against it. Hosted execution is pending publication.

## AUTH-18 PostgreSQL enrollment checkpoint — 2026-10-19

The optional core/PostgreSQL use case now persists private, realm/user/session/browser-bound
two-minute enrollment ceremonies, verifies real authenticator responses, and atomically
consumes state, inserts an RP-unique credential and records typed audit. Migration
0007 adds the tables and closed audit kind; published migrations 0001–0006 are unchanged.
Normal HTTP composition remains disabled. See the [implementation guide](../guides/passkey-enrollment.md).

- Default workspace tests: 59 passed. All-feature workspace tests: 78 passed.
  Both final runs were isolated and had zero failures/ignored tests. The fourteen
  new real-PostgreSQL cases cover protocol rejection with positive controls, real
  packed-attestation signature tampering, ownership/binding, replay, rollback,
  concurrency, cross-realm RP uniqueness, bounded state/credential/admission,
  deletion and freshness/expiry after an observed PostgreSQL lock wait.
- Formatting and strict workspace/all-target/all-feature Clippy passed. Compiled
  advisory and cargo-deny all-feature checks passed, retaining the reported inactive
  SQLx MySQL/RSA finding. The exact-version software-authenticator MPL exception
  and source/distribution notice accompany the test-only dependency. Production
  graphs exclude that software token, and default production graphs exclude WebAuthn.
- The first complete run exposed an upgrade fixture stopping at migration 0006
  before invoking current cleanup. It now applies 0007, retaining preservation
  assertions. A separate default run overlapped an all-features run and got HTTP
  failures: SQLx hashes test paths into deterministic database names, confirmed in
  its source. Both variants passed when rerun sequentially; no product check or
  assertion was relaxed. CONTRIBUTING now records this constraint.

These are software-authenticator and persistence results, not browser or real-device
interoperability. HTTP/OpenAPI, browser tests, sign-in, stronger-account policy and
passkey-first accounts remain outstanding. AUTH-18 and the M03 parent stay open;
hosted checks for this local checkpoint are pending publication.

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

## AUTH-53 optional-mailbox checkpoint — 2026-10-19

The model/policy boundary is implemented; anonymous signup and verified-mailbox
attachment remain in progress. Migration 0009 preserves existing mailbox identities,
verification times and historical session provenance while allowing email-free
passkey-required users. The core and generated HTTP contracts now explicitly allow
absent email and display labels. This is an alpha API/schema change, not completed
passkey-first signup or stronger-account recovery.

- Default workspace: **69 tests** passed (2 adapter unit, 12 HTTP/database, 4 core,
  51 PostgreSQL). All-feature workspace: **112 tests** passed (2 adapter unit,
  17 HTTP/database, 10 core, 83 PostgreSQL). No failed or ignored tests in the final
  runs. Feature variants ran sequentially against PostgreSQL 17.11.
- Nine new PostgreSQL cases cover upgrade/constraints, null-contact ownership,
  weak-method and password/email/reset/lifecycle denial, preissued proofs,
  user/source admission, policy changes during observed user-lock waits, and
  NULL-to-email snapshot invalidation before revocation. The new HTTP case verifies
  exact null/display-label JSON, safe mail/password route denial and no-email
  revocation. Storage-seeded method fixtures are explicitly not private-key proof.
- Existing lock-wait observers now accept leading SQL whitespace and the updated
  account-name projection. The first default run exposed two observers that only
  matched a query starting at column zero; their timeout was corrected without
  replacing observed lock waits with sleeps or weakening the freshness assertions.
  The final default and all-feature suites pass, including those original races.
- Formatting, strict locked all-target/all-feature Clippy, compiled-advisory and
  cargo-deny gates pass. Gitleaks 8.24.3 and 8.30.1 pass a snapshot of all tracked
  and nonignored new source files; ignored build/dependency caches are excluded.
  No dependency or lockfile changed. The inactive optional SQLx MySQL/RSA finding
  remains reported, without an advisory ignore.
- A newly built experimental fixture passes all **20 existing Chromium WebAuthn
  cases**, with Chromium 156.0.8078.4/Playwright 1.64.1. Counts remain 20 credentials/
  enrollment audits, 13 passkey sessions/authentication audits, 23 admitted finishes,
  zero pending, one backed-up and one used-zero-counter credential. All 195 source
  fingerprints and the fresh binary hash match the local regression report; exact
  fixture database removal is reported and an independent catalog query finds zero
  browser fixture databases. This is regression evidence for existing registration/
  sign-in, not anonymous signup, native counterless enrollment or real-device proof.

The implementation remains in the four existing packages: typed core user/policy,
private PostgreSQL row decoding, focused account admission and session ownership,
and thin HTTP nullable DTOs. Policy is rechecked under user locks before weaker
session/credential/lifecycle mutations. Owned session controls revalidate the nullable
contact snapshot without acquiring email locks after the owner lock. Published
migrations 0001–0008 and prior browser artifacts remain unchanged. Full M03,
AUTH-20 recovery/management, other-browser/real-device evidence and the later
provider/native/issuer/security release gates remain open. Hosted exact-head
results and commit links are tracked in Huly AUTH-53.

## AUTH-53 two-stage signup core checkpoint — 2026-10-19

Optional core/PostgreSQL signup now keeps registration and a verified candidate
pending until a separate genuine assertion. One transaction creates the email-free
passkey-required account, updated key, session and `passkey_signed_up` fact, then
checks expiry and consumes pending state after all writes. HTTP signup/native
anonymous-browser integration and verified-mailbox attachment remain in progress;
this checkpoint does not complete AUTH-53, AUTH-20 or M03.

- Final default workspace **69 cases** and all-feature workspace **131 cases**
  pass sequentially on PostgreSQL 17.11. All-feature totals are adapter unit 2,
  HTTP/database 17, core 10 and PostgreSQL 102. The logging case's body executes
  in an exact child test process and is counted once in the core total.
- Nineteen new signup cases cover real signed registration/assertion and later
  account-bound login; no user/key/session/fact before assertion; stage/browser/
  realm/RP separation; exact proof/candidate snapshots; bad challenge/origin/RP/UV,
  signature/handle/envelope; replay/concurrency; owner/key collision without merge;
  session/audit rollback; pending/admission bounds; upgrade preservation and invalid
  stage shapes. Observed lock waits prove expiry during registration advancement,
  unchanged pending-row locking, rolled-back key uniqueness and the final audit
  insertion. Final expiry rolls every earlier insert back together.
- The pinned SoftToken initially rejected the resident request with `NotSupported`,
  as its source explicitly documents. The test-only helper asserts that the server
  requests residence, then adjusts only the software client's residence hints;
  challenge/RP/required-UV/private state and production verification stay unchanged.
  These are signed nonresident proof/transaction cases. The UV negative uses the
  same unsigned attestation as its valid control with only UV cleared. Native
  resident signup/discovery remains required and must use original options.
- An earlier full run exposed another concurrent tracing-cache positive-control
  failure. Separate commit `c448156` isolates that exact security test in a child
  copy of its existing unit-test executable. Actual upstream marker exposure,
  suppression and caller-event restoration assertions remain intact; production
  suppression is unchanged, with no global logging switch or suite serialization.
  Three repeated concurrent core suites and the final full suite pass.
- Strict all-target/all-feature Clippy, fmt, compiled-advisory and cargo-deny pass.
  Gitleaks 8.24.3 and 8.30.1 pass a source snapshot including new nonignored files.
  No dependency/lockfile changes, new cryptography or advisory ignore. Existing
  inactive optional SQLx MySQL/RSA reporting remains visible.
- The freshly built existing native fixture passes all **20 Chromium 156.0.8078.4 /
  Playwright 1.64.1** regression cases. Counts remain 20 credentials/enrollment
  audits, 13 passkey sessions/authentication audits, 23 admitted finishes, zero
  pending and one backed-up/one used-zero-counter credential. All 212 source hashes
  and the fresh executable hash match the local report. Exact fixture DB removal
  is reported and independently confirmed by a zero browser-DB catalog count.
  These existing-flow regressions are not anonymous signup or real-device evidence.

Published migrations 0001–0009 and earlier committed browser evidence are unchanged.
Core signup owns the flow/typed proof/port; PostgreSQL signup modules own admission,
stage advancement and one visible atomic completion transaction. The deliberate
transaction size exceptions are documented in code-organization.md. Default HTTP
composition/OpenAPI remain unchanged by this core checkpoint. Hosted exact-head
results and publication are tracked in Huly; release gates remain open.

## AUTH-53 experimental HTTP/native signup — 2026-10-19

Producer `d217189ac92c0bc599ff304ab072551835ad1ee9` adds explicit
`passkey-signup` composition, three strict anonymous signup routes and the fourth
full OpenAPI snapshot. Separate refactor `9009e74` passed the existing adapter
tests, strict lint and 20 native regressions before behavior changes. Neither
the ordinary server/router nor earlier experimental constructors enable signup
implicitly. Verified-mailbox attachment and AUTH-20 recovery/management remain open.

- Final default workspace **69** and all-feature workspace **134** unique cases
  pass sequentially (all features: adapter unit 2, HTTP/database 20, core 10,
  PostgreSQL 102). The logging body runs in its isolated child and counts once.
  Three new HTTP cases cover exact Origin, malformed/unknown/duplicate session
  cookies, closed inputs, no client owner/email/RP/residence override, distinct
  32 KiB transport/256-byte label bounds, no pre-proof identity/session/fact,
  stage/binding rejection, concrete live/published schema and startup binding.
  The final focused boundary rerun and full all-feature rerun both pass.
- The canonical [native signup record](../../tests/browser/passkeys/results/2026-10-19/chromium-signup.json)
  has **31 passing Chromium 156.0.8078.4 / Playwright 1.64.1 cases**. Its 224 source
  hashes match producer d217189, and its binary hash matches the newly checked
  example build. Eleven new cases begin with NO seeded session and retain original
  resident/required-UV options. Platform/internal and roaming/USB authenticators
  prove signup, protected null-email retrieval and later bound/modal-discovery
  login. The returned user UUID equals the server-selected creation handle.
- New native negatives include registration challenge/origin/RP/UV, actual signed
  assertion UP/UV/signature, replay after clearing the session, other-browser binding,
  existing live-session confusion and genuine signed cross-origin iframe context.
  Valid controls complete. Passwords are configured in the fixture so a stronger
  user's password-enrollment 401 tests policy, not a disabled feature. Existing
  mailbox lifecycle paths also deny the stronger account.
- Database totals: 31 credentials, 20 existing enrollment audits, 11 email-free
  passkey-required users/signup audits, 17 authentication audits, 28 total passkey
  sessions, 27 authentication-finish and 33 signup-finish admissions, zero pending
  enrollment/authentication/signup, one backed-up and one used-zero-counter key.
  The old counterless storage fixture stays limited to its old seeded account;
  anonymous signup has no such setup. Exact fixture database removal is reported
  and independently confirmed by a zero browser-DB catalog count.
- Fmt, strict all-target/all-feature Clippy, compiled-advisory and cargo-deny pass.
  Source scans with Gitleaks 8.24.3 and 8.30.1 pass. No dependency versions/lockfile,
  published migrations, prior browser artifacts or scanner/advisory policy changed.
  CI now builds the example with its required signup feature and exercises the
  same expanded native suite. Hosted exact-head status is tracked in Huly.

Signup handlers/types/composition/contract live in a focused feature folder.
Browser signup cases and ceremony helpers likewise have their own folder; fixture
summary queries are separate. Canonical wire schemas are shared with narrow
parent-feature visibility. HTTP-only cookie anonymity remains in transport, while
proof, rate and transaction policy stays in core/PostgreSQL. Full M03, real hardware,
other browsers, contact attachment, recovery and later release milestones remain
unfinished; these results imply no production or conformance claim.

## AUTH-53 contact attachment increment — 2026-10-19

The shared-core/PostgreSQL and experimental HTTP contact attachment implementation
passes **84 default-feature** and **152 all-feature** unique workspace cases,
sequentially, plus strict all-target/all-feature Clippy. The all-feature breakdown
is Axum unit 2, HTTP/database 23, core 10 and PostgreSQL 117; the logging subprocess
body counts once. Fifteen new PostgreSQL cases cover binding/provenance, migration,
cleanup, admission, one-use, occupied targets, both deterministic mailbox-signup
race orderings, rollback and expiry/freshness after observed lock/audit waits.
Three new HTTP cases cover captured proof delivery, explicit confirmation/rotation,
boundary/opt-in behavior, generic occupied/available initiation and delivery failure.

These attachment cases arrange storage sessions with passkey provenance and use a
capturing delivery adapter. They are not new native private-key or actual SMTP
attachment evidence. The existing SMTP adapter implements the new required method;
actual SMTP/native attachment acceptance remains pending. Compiled-advisory and cargo-deny gates pass; source scans pass with Gitleaks
8.24.3 and 8.30.1. The inactive SQLx MySQL/RSA advisory remains visible. No dependency
versions, lockfile, published migrations or scanner exceptions changed. Earlier native signup
artifacts remain unchanged. See [the contact attachment guide](../guides/email-attachment.md)
for exact limits and residual scope. Hosted signup-evidence runs 39256989158 and
39256989794 at 6d0df66 both passed Rust and secrets, including the existing 31 native
cases. AUTH-53 remains In Progress; ordinary activation stays gated through AUTH-20.

## AUTH-53 native SMTP contact acceptance — 2026-10-19

The separate [canonical attachment record](../../tests/browser/passkeys/results/2026-10-19/chromium-email-attachment.json)
resolves the preceding checkpoint's pending SMTP/native evidence. Its immutable
producer is `c13d7dedd4b526049dd5d3b392cedddfdfca9a24`; all **268** recorded source
hashes were independently checked with `git show producer:path`, and its executable
hash matches the freshly built binary. Versions: Chromium156.0.8078.4,
Playwright1.64.1, PostgreSQL17.11 and Mailpit1.27.11; Node/platform details are in
the record. Previous native artifacts remain unchanged.

Two additional cases use anonymous native platform/internal and roaming/USB resident
registration and genuine required-UV assertions, with original production options.
They start without seeded identities/sessions or credential metadata changes. The
server example calls actual `configured_auth` with the private production SMTP
adapter and explicitly composes the experimental signup router. The ordinary
server binary and older constructors acquire no new routes. No capture/no-op mail,
fixture HTTP mutation or synthetic proof bypass participates.

The cases prove real SMTP delivery, identical occupied-address initiation/delivery,
occupied completion rejection without merge, independent browser-binding rejection,
no GET/page-load consumption, fragment removal before explicit confirmation,
no-store/CSP headers, preserved owner/display label and normalized verified email,
rotated session and old-cookie revocation, replay denial, weaker password/lifecycle
rejection, and later account-bound plus modal discoverable passkey login.

Aggregate facts: two users, credentials, verified stronger users, signup facts and
attachment facts; four later authentication facts; zero weak sessions, changed
attachment method/time, pending signup or attachment rows. The source query checks
initiating/replacement owner/method/time and initiating revocation. The owned random
DB is reported removed and independently confirmed by zero matching DBs in the
PostgreSQL catalog. Exactly three owned test messages are removed; recipient-scoped
search verifies their absence. Cleanup never submits an empty IDs list/delete-all.
Neither the artifact nor logs contain proof tokens, cookie values, addresses, raw
mail bodies, virtual private keys or browser storage.

Final sequential Rust suites remain **84 default** and **152 all-feature** cases;
strict all-target/all-feature Clippy, fmt, JS syntax and diff checks pass. The
fixture adds only an already-locked serde_json dev-dependency edge, with no package
version change; the explicit server experimental feature forwards existing passkey
features and does not alter ordinary composition. Compiled-advisory/cargo-deny
checks pass with the inactive MySQL/RSA finding still visible. CI now runs the
existing31-case suite and this separate2-case real-SMTP suite, with Mailpit and no
external provider credentials. Exact-head hosted status is recorded in Huly.

AUTH-53 remains In Progress pending the final hosted acceptance audit. Stronger-
account management/recovery/last-key policy, physical devices, other browsers and
ordinary activation remain AUTH-20/M03 work. Full initial-release provider/native/
issuer/security scope remains unfinished; no production or conformance claim.

## AUTH-53 acceptance audit: enrollment final-write deadlines — 2026-10-19

The audit found a gap in the older enrollment transaction: it consumed its proof
before potentially blocking credential/audit writes. A deterministic test against
the previous implementation reached the real audit insert before the deadline,
then crossed challenge expiry and incorrectly committed. That test failed as
expected. The fix retains the pending row lock and consumes only after all writes,
with exact binding/state and original session freshness/idle/absolute/revocation
checks in the final statement. User/session authorization stays protected by their
held locks. A miss rolls back the credential, fact and consumption together.

Three new PostgreSQL cases cover unchanged pending-row and RP-wide uniqueness
waits plus a final audit matrix for challenge expiry/original freshness under both
mailbox and passkey-required policy. The latter arranges stored policy/method
explicitly; it is not native assertion provenance evidence. All pass after the fix,
as does the existing owner-wait case. Tests observe PostgreSQL locks and database
clock crossing, with positive before-deadline checks rather than guessed sleeps.
Final workspace results: **84 default / 155 all-feature** unique cases (Axum2,
HTTP23,core10,PG120; subprocess logging body counts once); strict all-target/all-
feature Clippy,fmt,diff and JS checks pass.

Both native suites were freshly rebuilt and rerun against immutable producer
`5e526639452c171f5881735a5c74705ebb970914`:

- [31-case native regression](../../tests/browser/passkeys/results/2026-10-19/chromium-enrollment-tail.json):
  all247 source hashes checked against the producer, with actual executable hash.
  Existing registration/assertion/signup and hostile-context cases retain their
  original counts and zero pending state.
- [2-case real SMTP regression](../../tests/browser/passkeys/results/2026-10-19/chromium-smtp-enrollment-tail.json):
  all269 source hashes checked likewise. Two stronger verified users/keys/signup/
  attachment facts, four later sign-ins, zero changed provenance/weak sessions/
  pending state, and three owned messages removed.

Both owned fixture DBs are reported removed and independently absent from the
PostgreSQL catalog. Earlier published artifacts remain immutable; these refresh
native regression evidence after the storage correction, without claiming that
browser cases themselves induce the database timing failure. Dependency/scanner
results and exact-head hosted state are recorded with this checkpoint in Huly.

AUTH-54 now tracks the analogous final-write audit in older mailbox/password/
lifecycle/session operations under M09. Source inspection suggests additional
surfaces; this enrollment correction does not claim those paths fixed or verified.
That separate work is a first-release security gate and should follow this scoped
acceptance work. Full stronger-account management/recovery remains AUTH-20; ordinary
activation and the rest of M03/later release scope remain gated.

## AUTH-54 final transaction deadlines — 2026-10-19

Mailbox sign-in, password enrollment/reset, email change/deletion and sensitive
session revocation retain the exact original database authority deadline through
all writes. A final table-free wall-clock check rejects expired authority before
commit and rolls back durable side effects. Session validation/inventory share
owner-before-session locking, post-wait policy validation and an original
idle/absolute cap captured before touch. See [ADR 0010](../architecture/adr/0010-final-transaction-deadlines.md).
Public APIs, dependencies and published migrations are unchanged.

Eight controlled pre-fix PostgreSQL regressions failed at their authorization
assertions. The initial unrestricted run instead hit pool/observer starvation and
is excluded from application reproduction evidence. SQLx 0.8.6's test pools share
20 parent permits; the Cargo test default now uses four workers, with an independent
bounded deadline observer. Setup, lock-observation and clock failures remain fatal;
Unavailable is explicitly distinguished from the required Unauthorized result and
needs separate database/pool diagnosis. No expected rejection accepts arbitrary errors.

Local checks with real PostgreSQL 17.11 and the documented development services:

- `cargo fmt --all -- --check`; default and all-feature
  `cargo clippy --locked --workspace --all-targets [--all-features] -- -D warnings`
  pass.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace`: **93 tests** pass
  (2 Axum unit, 12 HTTP/database, 4 core, 75 PostgreSQL).
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace --all-features`:
  **164 tests** pass (2 Axum unit, 23 HTTP/database, 10 core, 129 PostgreSQL).
  The isolated logging subprocess executes one already-counted core test.
  No failed or ignored tests in the successful full runs.
- Nine deadline tests include proof/freshness expiry during final audit/notice
  writes, session validation/inventory unchanged-row waits, individual/all
  revocation and a four-case final-touch matrix covering both idle and absolute
  expiry in validation/inventory. They require observed waits before expiry and
  unchanged realm-scoped identity, credentials, sessions, proofs, audit, notices
  and admission snapshots after rollback. Existing successful flows, retry,
  one-winner concurrency, binding and realm/owner isolation remain covered.
- Freshly built native Chromium 156.0.8078.4/Playwright 1.64.1 suites pass
  **31 browser cases and 2 real-SMTP contact cases**. Sanitized source/binary
  fingerprints and owned cleanup are in
  [browser evidence](../../tests/browser/passkeys/results/2026-10-19/chromium-auth54.json)
  and [SMTP evidence](../../tests/browser/passkeys/results/2026-10-19/chromium-smtp-auth54.json).
  Each database is removed; the SMTP suite removes exactly its three owned messages.
- `scripts/smoke.py --password --recovery --sessions --lifecycle` passes in
  standalone and `--embedded` compositions, each with a disposable database and
  the real SMTP worker. The embedded fixture now checks the exact core User shape,
  including mailbox policy, against the public identity projection at all three
  checkpoints. Its former exact comparison omitted the core-only policy field;
  no application authorization or identity assertion is relaxed.
- `python3 scripts/audit.py` passes the compiled dependency gate; the existing
  inactive SQLx/MySQL `rsa` lockfile advisory remains visible. `cargo deny
  --all-features check` and `npm audit --audit-level=low` pass. Redacted Gitleaks
  scans cover the staged changes, including new regression/evidence files.

Environment failures were diagnosed separately: Docker's unresponsive engine was
recovered without removing volumes; the first native attempt lacked its pinned
Chromium path and cleaned its empty fixture database; an all-feature build hit
host disk exhaustion before tests. Removing only this repository's generated
incremental cache and disabling incremental generation allowed the full rerun.
These failed attempts are not counted as successful regression evidence.

The source review keeps the deadline type private and feature transaction ownership
explicit. No new module exceeds 300 lines. The longer locked caller operation and
feature transactions retain their lock/validation/mutation/rollback sequence in one
place; [reviewed size exceptions](../architecture/code-organization.md) explain why.
Session validation now performs additional database round trips; previous latency
measurements are historical. The deadline check precedes commit and cannot bound
commit/response latency or later consuming-application work. No production, audit,
protocol interoperability or new performance claim is made here.

## AUTH-20 management storage checkpoint — 2026-10-19

AUTH-20 remains **In Progress**. Optional core/PostgreSQL management now provides
bounded metadata, expected-version rename and removal requiring another key with
real assertion-use evidence. Genuine fresh passkey-method authority, owner/session/
key lock order, post-write original deadlines, session/pending invalidation,
typed target audit and verified-contact notices are in the owning modules.
[ADR 0011](../architecture/adr/0011-passkey-management-and-recovery.md) and the
[management guide](../guides/passkey-management.md) describe the contract and
remaining work. No HTTP management or ordinary activation is enabled here.

Local checks at this checkpoint:

- `cargo fmt --all -- --check`; strict locked workspace/all-target Clippy with
  default and all features pass.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace`: **93 tests** pass
  (2 Axum unit, 12 HTTP/database, 4 core, 75 PostgreSQL).
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace --all-features`:
  **175 tests** pass (2 Axum unit, 23 HTTP/database, 10 core, 140 PostgreSQL).
  The isolated logging child counts once. No failed or ignored tests in these runs.
- Eleven new PostgreSQL cases use actual registration/assertion positive controls;
  distinguish storage-policy setup from protocol evidence; cover both contact
  modes, weak/legacy/future/stale/idle/absolute denial, metadata redaction, stale
  versions, same-realm foreign ownership, cross-realm/RP denial, proven-last-key
  protection, concurrent rename/removal, a preverified assertion after removal,
  audit/notice failure with retry, upgrade preservation and scoped target erasure.
  The final-write matrix observes actual advisory waits before original freshness
  expiry for rename/removal through audit and notice tails, requiring Unauthorized
  and rollback. Infrastructure errors do not count as expected policy rejection.
- Existing native Chromium suites pass **31 browser + 2 real-SMTP cases**, with
  exact owned databases removed and exactly three owned messages cleaned. These
  are existing-flow regressions, not management UI or new-notice delivery proof.
  Exact-source/binary fingerprints are in
  [browser evidence](../../tests/browser/passkeys/results/2026-10-19/chromium-management-storage.json)
  and [SMTP evidence](../../tests/browser/passkeys/results/2026-10-19/chromium-smtp-management-storage.json).
- `python3 scripts/audit.py`, `cargo deny --all-features check`, npm advisory check
  and redacted staged Gitleaks scan pass. The preexisting inactive SQLx/MySQL RSA
  advisory remains visible; dependency versions and scanner policies are unchanged.
- `CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=target cargo check --locked --offline
  --manifest-path benchmarks/adoption/Cargo.toml --features easy --bin probe-easy`
  passes. Its explicit disabled-mail implementation was updated for required ports,
  including previously missing contact attachment; historical measurements/artifacts
  remain unchanged and are not measurements of this implementation.

Migration 0012 is additive; all published predecessor SQL remains byte-identical.
Older upgrade fixtures now apply it before current adapter writes, retaining their
assertions. Feature entry files declare/reexport only, admission/authorization/
inventory/mutation/notice persistence are separate cohesive modules, and the longer
removal transaction keeps its security order explicit. No new implementation file
exceeds 300 lines; the longer transaction is documented in code organization.

Remaining AUTH-20 scope includes HTTP/schema/browser management and actual new
notice delivery evidence, stronger additional-enrollment proof and activation,
pre-enrolled all-keys-lost recovery with delay/cancellation/expiry/notification,
ordinary embedded/standalone activation policy, and physical-device/other-browser
acceptance. No completion, production-readiness, independent security review,
assurance-level or conformance claim follows from this checkpoint.

## AUTH-20 experimental management HTTP/native checkpoint — 2026-10-19

AUTH-20 remains **In Progress**. The separate `passkey-management` feature and
explicit management constructor compose base, enrollment, sign-in, signup and
contact routes with GET inventory and expected-version rename/remove endpoints.
Older constructors and schemas remain unchanged. The new
[full OpenAPI](../architecture/openapi-passkey-management.json) is compared with the
live response and all prior schemas/routes. No ordinary server route is enabled.

Local verification at this checkpoint:

- Formatting, strict locked default/all-feature workspace/all-target Clippy, diff
  checks and native JavaScript syntax checks pass.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace`: **93 tests** pass
  (2 Axum unit, 12 HTTP/database, 4 core, 75 PostgreSQL).
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace --all-features`:
  **182 tests** pass (2 Axum unit, 30 HTTP/database, 10 core, 140 PostgreSQL).
  The isolated core logging subprocess counts once; no failed or ignored tests in
  the final successful runs.
- Seven new HTTP/database tests include genuine registration/assertion controls,
  nullable contact and exact public metadata, opt-in/startup/full-schema compatibility,
  strict Origin/duplicate-cookie/closed-JSON/query/media/body bounds, weak/legacy/
  stale authority denial, foreign target/version denial, proven-last-key protection,
  all-session invalidation and all seven action/auth cookie removals. Injected notice
  persistence failure returns generic 503 without success cookies or state mutation;
  the exact operation retries after removing the injected failure.
- The existing **31 native Chromium regressions** pass. The **two platform/USB SMTP
  cases** now also perform inventory, rename/stale-version rejection, last-working-key
  denial, independent resident spare-device enrollment and actual spare assertion
  before removal. Removal clears cookies and invalidates the peer session; an actual
  removed-key signature fails, then a real surviving-key signature completes the same
  challenge. Later account-bound/discoverable login works with the remaining key.
- The fixture uses the real `configured_auth`, private SMTP adapter and production
  `notification_worker`. Four management notices reach the exact owned recipients
  without credential links or untrusted labels. Aggregate facts: two remaining proven
  keys, two rename/two removal facts, eight passkey authentication facts, zero weak
  sessions, changed contact provenance or pending management notices. Owned DB removal
  and deletion of exactly **seven** owned messages are confirmed; unrelated mail is
  retained. Earlier native artifacts remain immutable. Final sanitized fingerprints:
  [browser](../../tests/browser/passkeys/results/2026-10-19/chromium-management-http.json),
  [management/SMTP](../../tests/browser/passkeys/results/2026-10-19/chromium-smtp-management-http.json).
- Both standalone and embedded `scripts/smoke.py --password --recovery --sessions
  --lifecycle` flows pass with real SMTP, each in an owned disposable database which
  is removed. The ordinary compositions retain the mailbox/password contract.
- Compiled dependency advisory gate, all-feature cargo-deny, npm audit and staged
  redacted Gitleaks pass. Only a pinned, already-resolved software-authenticator
  dev dependency edge was added for actual assertion controls; versions and scanner
  policy are unchanged. The inactive SQLx/MySQL RSA advisory remains visible.

The first HTTP cookie assertion used an incorrect shorthand for the existing
email-change cookie; it was corrected to the actual fixed cookie name, preserving
all seven checks. Early native attempts correctly rejected reusing an authenticator
present in excludeCredentials; those are failed fixture attempts, not application
success evidence. The final fixture uses independent native virtual authenticators
and CDP presence selection without exporting keys or changing stored credentials.
Registration preserves original exclusion/residence/UV options. Assertion selection
narrows a returned allowed ID for the positive proof; the signed negative deliberately
requests the removed ID with server state unchanged. The valid retry uses that same
challenge with the surviving key. Fixed stage labels diagnose failures without
printing assertion data, cookie values, message bodies or addresses.

Handlers delegate to core; transport types, routing and schema each have owning
modules, all below 300 lines. Longer composition/test functions retain explicit
ordered boundaries as documented in code organization. ADR 0011's heading was
corrected to match its filename. Recovery, stronger additional-enrollment/activation
policy, ordinary activation and required physical-device/other-browser evidence
remain unfinished; this checkpoint does not establish their completion or any
production, independent-review, assurance-level or conformance claim.


## AUTH-20 additional-enrollment authority — 2026-10-19

AUTH-20 remains **In Progress**. The core method rule now distinguishes known
first-key bootstrap from adding keys to an existing realm/account. Any existing
key, including another RP, requires a genuine fresh passkey-method session.
Unknown legacy provenance is rejected even for bootstrap. Context, save, load and
commit apply the same rule after owner/session locks and a new statement reads
current key presence. Registration changes neither account policy nor method/time.
Original session caps follow stage writes; completion retains proof expiry and
checks database wall time after conditional consumption itself.

Four controlled pre-fix cases failed at application assertions: weaker-method
additional enrollment, another-RP bypass, concurrent first-key bootstrap and
preparation expiry during an observed insert wait. This does not claim every
later assertion in their multi-stage cases was independently reproduced red.
The expanded seven PostgreSQL cases now also cover recent legacy denial, a key
committed during an unchanged-owner wait and proof expiry during a final-delete
trigger wait. The latter are added guard coverage, not independently recorded
pre-fix reproductions. Exact Unauthorized is required; infrastructure errors are
never accepted as race losers or authorization rejections.

Existing protocol negatives, valid retries, last-slot races and deletion assertions
remain intact. Their positive fixtures now retain their authenticator and perform
actual signed authentication before additional enrollment. A new HTTP test keeps
the original mailbox session valid for ordinary session retrieval while requiring
401/no success cookie for additional enrollment, with a genuine passkey control.

Final local verification with the documented real PostgreSQL 17.11/Mailpit setup:

- `cargo fmt --all -- --check` and strict locked workspace/all-target Clippy with
  default and all features pass.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace`: **93 tests pass**.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace --all-features`:
  **190 tests pass** (2 Axum unit, 31 HTTP/database, 10 core, 147 PostgreSQL).
  The logging subprocess repeats one already-counted core case. No failures or
  ignored tests in the successful full suites.
- Freshly rebuilt pinned native suites pass **31 Chromium cases and 2 real-SMTP
  cases**, including mailbox-session denial and real assertion-authorized additional
  enrollment. Source and binary hashes match the saved
  [browser report](../../tests/browser/passkeys/results/2026-10-19/chromium-enrollment-authority.json)
  and [SMTP report](../../tests/browser/passkeys/results/2026-10-19/chromium-smtp-enrollment-authority.json).
  Both owned databases are removed; exactly seven owned SMTP messages are removed.
  The SMTP aggregate retains two proven surviving keys, two renames/removals,
  eight actual authentication facts and zero weaker sessions/pending notices.
- Standalone and embedded `scripts/smoke.py --password --recovery --sessions
  --lifecycle` pass with real SMTP and owned database cleanup.
- Compiled dependency audit, all-feature cargo-deny and low-threshold npm audit
  pass. The inactive SQLx/MySQL rsa advisory remains visible. No dependency or
  migration changes are introduced by this enrollment-authority boundary. A redacted
  Gitleaks scan of the complete staged diff also passes.

The method policy and locked database state each have a focused module; existing
preparation/completion retain transaction boundaries and final checks. New files
remain under 300 lines. Longer tests/transactions keep their ordered invariants
visible, following the documented size review exceptions. No structural cleanup
is deferred by this change. Reviewed recovery proof/delay/cancellation, notification
limits, safe stronger-policy activation, ordinary composition and physical-device/
other-browser evidence remain open. These results do not complete AUTH-20 or M03.


## AUTH-20 experimental saved-code configuration — 2026-10-19

AUTH-20 remains **In Progress**. [ADR 0012](../architecture/adr/0012-saved-passkey-recovery.md)
separates implemented saved-code configuration from the proposed delayed/cancellable
all-keys-lost protocol. No recovery login, new HTTP endpoint, policy activation or
ordinary enablement is implemented or claimed. Independent recovery review and
physical-device/other-browser evidence remain acceptance work.

Core uses the existing 256-bit `Secret` primitive; PostgreSQL stores only verifiers.
Known genuinely fresh passkey-method authority and an owned proven configured-RP
key are required. Preparation replaces only a bounded exact-session pending setup,
retaining any active saved code. Confirmation atomically replaces its version,
consumes pending state, records actor-owned `passkey_recovery_configured` audit and
queues a fixed `passkey_recovery_changed` notice to an existing verified contact.
Original proof/session caps follow all writes. Email-free users have no fabricated
recipient or independent email alert. Configuration changes neither account policy
nor authentication method/time. Active saved codes currently have no age expiry;
recovery consumption remains unimplemented. This is not usable all-keys-lost recovery.

A separate behavior-preserving extraction shares locked passkey-method authority;
all **11 existing management cases** passed after it. The new **12 real-PostgreSQL
configuration cases** cover confirmation/rotation with preserved old code, replay,
one-winner concurrency, genuine other-owner denial, exact session/realm/RP/code
binding, weak/legacy/stale/future/idle/absolute/revoked authority, configured-RP use
evidence, durable failed-attempt admission, audit/notice rollback and retry,
additive migration constraints, account-deletion erasure and realm isolation.
An observed-wait matrix crosses original deadlines during preparation, audit,
notification and final consumption. It requires exact Unauthorized, an actual
pre-expiry lock wait and unchanged durable state; infrastructure errors cannot
satisfy authorization assertions. This is new-functionality evidence, not a claimed
pre-fix exploit reproduction. Published migrations are unchanged; migration 0013
creates no saved code or stronger provenance for existing accounts.

Final local checks:

- `cargo fmt --all -- --check`; strict locked workspace/all-target Clippy with
  default and all features pass.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace`: **93 pass**.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace --all-features`:
  **202 pass** (2 Axum unit, 31 HTTP/database, 10 core, 159 PostgreSQL).
  A logging subprocess repeats one included core case. No failures or ignored
  tests in successful full suites.
- The changed required `EmailDelivery::passkey_recovery_changed` port is implemented
  in SMTP and all repository fixtures/adoption probe. A locked `cargo check
  --manifest-path benchmarks/adoption/Cargo.toml --features easy --bin probe-easy`
  passes; no adoption performance measurement is claimed.
- Fresh native builds pass **31 Chromium and 2 real-SMTP cases** on PostgreSQL 17.11.
  Saved [browser](../../tests/browser/passkeys/results/2026-10-19/chromium-recovery-setup.json)
  and [SMTP](../../tests/browser/passkeys/results/2026-10-19/chromium-smtp-recovery-setup.json)
  source/binary fingerprints match the final source. Both owned databases and the
  native SMTP suite's seven owned messages are removed. These exercise the existing
  enrollment/sign-in/signup/contact/management regression boundary, not recovery login.
- Standalone and embedded full password/recovery/sessions/lifecycle SMTP smokes pass
  with owned database cleanup.
- `python3 scripts/smoke_recovery_notice.py` passes with both local Compose and the
  explicit test-container mode used by CI. Each run owns one queue fixture, observes
  the purpose-specific real SMTP message and queue acknowledgement, removes exactly
  its one message and drops its disposable DB. This proves new-notice transport;
  PostgreSQL tests separately prove authorized configuration enqueues it. The script
  is added to CI with the job's PostgreSQL service container and loopback DB URL.
- Compiled-dependency audit, all-feature cargo-deny and low-threshold npm audit pass.
  The inactive SQLx/MySQL rsa advisory remains visible; no dependency change is made.
  Redacted Gitleaks scanning of the complete staged diff also passes.

The initial notice smoke reached SMTP/acknowledgement but its cleanup assumed a
JSON DELETE response. Mailpit returned success text; the fixture now discards that
body, retains safe ownership checks and reports infrastructure/assertion failures
separately. Both final modes pass. A host Python cache permission error was resolved
by using a writable temporary bytecode cache. Neither initial attempt counts as a
successful full smoke. No application security assertion was weakened.

New production/test files stay below 300 lines. The shared authority, recovery core
flow/port and PostgreSQL configuration/delegation keep responsibilities separate.
The longer confirmation transaction and owned-resource smoke main retain explicit
lock/write/final-check/cleanup order; the organization guide documents these size
exceptions. No structural cleanup is deferred. Proposed delay/receipt/cancellation,
new-key proof, one-use recovery completion, HTTP integration, activation and M03
external evidence remain incomplete; these checks do not establish their safety.


## AUTH-20 experimental HTTP saved-code configuration — 2026-10-19

AUTH-20 remains **In Progress**. A separate `passkey-recovery-setup` feature and
`experimental_passkey_recovery_setup_router` expose only saved-code preparation
and confirmation. Startup aligns all service realms/origins. The earlier constructors
and full schemas remain unchanged; the new
[full contract](../architecture/openapi-passkey-recovery-setup.json) adds two closed
POST bodies under `/v1/passkeys/recovery/code/{prepare,confirm}`. Exact Origin,
host-session cookie parsing, 8 KiB JSON, no query selectors, no-store and generic
errors remain shared. Only successfully persisted preparation serializes `{id,code}`;
Secret's general serialization prohibition and zeroization remain intact. Neither
operation issues a session/action cookie, upgrades policy or authenticates recovery.

A separate composition/contact extraction passed the existing **8 HTTP management
and 2 real-SMTP native cases** before behavior extension. The new **8 HTTP tests**
prove full contract/prior-schema preservation, old-constructor route absence,
realm/origin startup rejection, cookie/Origin/body/media/query boundaries, weak and
stale authority, exact session/foreign-pending/wrong-code rejection with valid retry,
durable rate limiting, confirmation/rotation with no policy or method/time change,
email-free absence of fabricated notice, SMTP queue retry and atomic persistence
failure with no returned code/success cookie. Initial draft tests expected different
error labels; they were corrected to the existing published generic codes rather
than changing application responses or accepting arbitrary errors.

Final local checks with PostgreSQL 17.11 and documented Mailpit:

- `cargo fmt --all -- --check`; strict locked workspace/all-target Clippy with
  default and all features pass.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace`: **93 pass**.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace --all-features`:
  **210 pass** (2 Axum unit, 39 HTTP/database, 10 core, 159 PostgreSQL).
  The logging subprocess repeats one included core case. No failures or ignored
  tests in successful full suites.
- Fresh pinned native runs pass **31 Chromium and 4 real-SMTP cases**. Final evidence
  uses fixed owned copies of producer binaries after Cargo checks/builds finish;
  recorded source/binary hashes match the
  [browser report](../../tests/browser/passkeys/results/2026-10-19/chromium-recovery-http.json)
  and [SMTP report](../../tests/browser/passkeys/results/2026-10-19/chromium-smtp-recovery-http.json).
  Earlier reports remain immutable. The original management cases retain every
  assertion, while two additional platform/USB cases use separate accounts and
  genuine signup assertions to confirm saved-code setup while email-free, then
  rotate it after independent real-SMTP contact proof. They reject wrong/replayed
  codes, retain no browser storage and receive a purpose-specific real notice.
  No source/admission limit, exclusion option or security assertion is weakened.
- The SMTP aggregate requires four verified stronger users/proven remaining keys/
  signup/contact facts, eight later authentication facts, two rename/removal facts,
  four recovery-configuration facts and two active code-verifier records. Invalid
  attachment/recovery provenance, weaker sessions, pending state and queued notices
  are all zero. Both native databases and exactly eleven owned SMTP messages are
  removed. These remain virtual-device results, not physical-device evidence.
- Newly built standalone and embedded full password/recovery/sessions/lifecycle
  SMTP smokes pass with owned database cleanup. The separate new-notice transport
  smoke also passes with its exact one-owned-message/database cleanup.
- Compiled-dependency audit, all-feature cargo-deny and low-threshold npm audit pass;
  the inactive SQLx/MySQL rsa advisory remains visible. No dependency version or
  migration changes are introduced by this HTTP boundary. The complete staged
  diff also passes redacted Gitleaks scanning.

Source review keeps thin handlers, private concrete transport DTOs and feature
composition separate from the existing core/PostgreSQL policy. New files stay below
300 lines; the explicit seven-service constructor and longer fixtures/tests keep
alignment, assertions and owned-resource order visible. No structural cleanup is
deferred by this change. Recovery claim/delay/notification receipts/cancellation,
new-key proof and one-use recovery completion remain proposed, not implemented;
independent review, safe activation, ordinary composition and physical-device/
other-browser acceptance remain open. This checkpoint does not complete AUTH-20.

## AUTH-20 recovery claim scheduling and cancellation checkpoint (2026-10-19)

AUTH-20 remains **In Progress**. The experimental core/PostgreSQL service now
supports starting, resuming, inspecting and cancelling an owner/RP/browser-bound
claim with a reserved saved-code generation. Additive migration 0014 records
single consumption, a seven-day original expiry and a fixed 24-hour delay. With a
verified contact, only an accepted current SMTP lease starts that delay; without
a mailbox, it starts at creation and no alert is fabricated. Readiness is metadata,
not authority. There is no claim HTTP route, replacement-key completion, recovery
session issuance or stronger-account activation in this checkpoint.

The separate notification/sensitive-admission extraction passed **84 existing
PostgreSQL passkey cases and one default notification case** before behavior
changes. The new **23 real-PostgreSQL cases** cover exact realm/owner/RP/browser/
code-generation bindings, same-browser retries and lost-response resume, one-winner
claim races, immutable delay/expiry, source/account/browser admission, rollback,
fresh-key cancellation, reserved-code denial after all sessions are revoked,
current/stale/failed/expired SMTP leases, first receipt timing, rotation/deletion
races and erasure, schema upgrade constraints and observed post-write deadline
waits. Cancellation and receipts share owner-before-claim-before-notice locking.
Source-only admission for reserved-code cancellation prevents anonymous account
budget exhaustion from suppressing an alerted owner's denial; that proof grants
no access, new claim, browser transfer or ordinary authentication.

A controlled failing regression reproduced `RateLimited` when bad-code account
traffic blocked a legitimate bound browser's continuation. Continuation now uses
an owner/RP/browser capability budget distinct from code guessing, preserving the
source limit. The regression passes without weakening assertions. Initial full
default checks also exposed three historical migration fixtures that stopped at
schema 0012 before calling today's audit adapter. Seven affected upgrade fixtures
now explicitly finish later migrations after their historical setup/assertions;
published migrations and assertions are unchanged. A test-only expiry trigger
leaking into the next matrix setup was also fixed rather than accepting generic
infrastructure errors as authorization rejection.

Final checks with PostgreSQL 17.11 and the documented Mailpit setup:

- `cargo fmt --all -- --check`; locked workspace/all-target Clippy with default
  and all features and `-D warnings` pass.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace`: **93 pass**.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace --all-features`:
  **233 pass** (2 Axum unit, 39 HTTP/database, 10 core, 182 PostgreSQL). The
  logging subprocess repeats one included core case. Successful full suites have
  no failed or ignored tests. The focused claim suite independently passes all
  **23** cases.
- The locked adoption benchmark's `easy` binary check passes, including the new
  explicit delivery-port methods. No dependency versions changed.
- Fresh pinned native runs pass **31 Chromium and 4 real-SMTP cases**. These verify
  existing signup/authentication/management/code-configuration behavior, not a
  nonexistent claim HTTP flow. Fixed owned producer copies were made after Cargo
  builds/checks; all recorded source/binary hashes match the immutable
  [browser report](../../tests/browser/passkeys/results/2026-10-19/chromium-recovery-claims.json)
  and [SMTP report](../../tests/browser/passkeys/results/2026-10-19/chromium-smtp-recovery-claims.json).
  Existing assertions and limits remain intact. Both owned native databases and
  exactly eleven owned SMTP messages are removed. These are virtual-device results.
- The expanded normal-server notice smoke passes configuration, claim-start and
  cancellation delivery plus accepted-lease receipt/24-hour delay, both through
  local Compose discovery and an explicitly selected PostgreSQL container as in
  CI. Each run removes exactly three owned messages and its database. Its dummy
  schema-only claim/verifier fixtures prove transport/worker behavior, not claim
  authorization or recovery login. Newly built standalone and embedded full
  password/recovery/session/lifecycle SMTP smokes also pass with owned cleanup.
- Compiled-dependency audit, all-feature cargo-deny and low-threshold npm audit
  pass. The inactive SQLx/MySQL rsa advisory remains visible. The complete staged
  diff passes redacted Gitleaks scanning before publication.

Source review keeps claim flow/port/types, admission, ownership, creation,
cancellation and receipt responsibilities in named modules with narrow visibility.
New Rust modules stay below roughly 300 lines. Longer creation/cancellation/
receipt transactions and observed-wait scenarios retain explicit lock, mutation,
deadline and rollback order as documented size exceptions. No generic recovery
engine or deferred structural cleanup is introduced. Required delivery methods
are documented for custom adapters. Independent recovery-policy review, private
replacement-key proof and one-use completion, claim HTTP boundaries, safe
activation and physical-device/other-browser evidence remain open. Browser loss,
claim expiry and prolonged SMTP outage fail closed; a consumed code cannot silently
restart recovery. This checkpoint does not complete AUTH-20 or its release gates.

## AUTH-20 private replacement assertion and completion checkpoint (2026-10-19)

AUTH-20 remains **In Progress**. The separate experimental core/PostgreSQL
`PasskeyRecoveryReplacement` service now persists a private registration, advances
only an exact verified registration to a candidate assertion, then requires its
actual signature before atomic one-use completion. Migration 0015 adds bounded
private candidate state and completed-claim tracking without changing published
migrations. Every stage revalidates current claim/browser/owner/RP/code generation,
receipt/delay and original deadlines under owner/claim/candidate locks. Public
readiness metadata never authorizes completion. Candidates remain outside normal
inventory/sign-in. No HTTP recovery route or ordinary activation is added.

Completion checks RP-wide uniqueness before removing prior keys, invalidates old
owner keys/sessions/bound proofs and other-RP saved codes, issues one passkey-method
session, records an owned issued-session/claim-target fact, queues a fixed verified-
contact completion notice and consumes private/claim state atomically. Original
claim and two-minute ceremony deadlines cap all final writes. Optional email locks
precede owner locks and nullable email is revalidated, matching mailbox proof
consumers. Policy/contact ownership are unchanged. Lost completion response is
resolved by normal sign-in using the installed key; replay retrieves no bearer or
second grant. The saved code remains consumed and must be replaced after sign-in.

The **18 new real-PostgreSQL cases** cover delay/receipt gating, registration-only
non-authority, actual completion with no live prior session for both contact and
email-free users, replay/lost-response sign-in, exact binding, candidate restart,
cancellation/rotation/deletion/expiry of preverified proofs, stale old-key proofs,
owner/realm and other-RP invalidation, audit/notice rollback, completion/cancellation
races, one-winner completion, RP-wide collision, additive migration constraints,
mailbox-before-owner lock order and observed unchanged-row/final-write expiry waits.
Verified-contact fixtures acknowledge an actual current start-notice lease and
assert its full delay before a trusted clock fixture advances time. They do not
fabricate stronger sessions or bypass the production delay configuration.

Initial fixture/compiler errors were corrected: a reserved SQL clock alias, raw
user deletion conflicting with intentional audit ownership constraints, and a
same-realm fixture encountering another owner's queued start notice. Tests now
use actual owned notice/deletion flows and preserve their negative assertions.
Default-feature lint also caught a facade cleanup that removed existing reexports;
those exports were restored. Infrastructure/setup failures were never counted as
successful authorization rejection. Deliberate write-failure tests require
`Unavailable`; authority/expiry failures require `Unauthorized` and exact rollback.

Final local evidence with PostgreSQL 17.11 and documented Mailpit:

- `cargo fmt --all -- --check`; strict locked workspace/all-target Clippy with
  default and all features and `-D warnings` pass.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace`: **93 pass**.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace --all-features`:
  **251 pass** (2 Axum unit, 39 HTTP/database, 10 core, 200 PostgreSQL).
  The logging subprocess repeats one included core case. No failed or ignored
  cases in successful full suites. The all-feature suite was repeated after
  strengthening actual-receipt fixtures; all 18 new cases pass there too.
- The locked adoption benchmark `easy` binary check passes with the newly required
  delivery method. No dependency versions changed.
- Fresh pinned native runs pass **31 Chromium and 4 real-SMTP cases**, preserving
  existing negative assertions/admission. These cover existing signup/authentication/
  management/code configuration, not a nonexistent recovery HTTP flow. Fixed owned
  producer copies were made after Cargo checks/builds; source/binary hashes match
  the new immutable [browser report](../../tests/browser/passkeys/results/2026-10-19/chromium-recovery-replacement.json)
  and [SMTP report](../../tests/browser/passkeys/results/2026-10-19/chromium-smtp-recovery-replacement.json).
  Both owned native databases and exactly eleven owned messages are removed.
- The normal-server worker delivers configuration/start/cancellation/**completion**
  notices with accepted-lease receipt/full-delay checking through both Compose
  discovery and explicit CI-style PostgreSQL container selection. Each run removes
  exactly four owned messages and its database. Dummy schema fixtures prove
  transport/worker behavior, not recovery authorization. Fresh standalone and
  embedded full password/recovery/session/lifecycle SMTP smokes pass with owned
  database cleanup. Native results remain virtual-device evidence.
- Compiled-dependency audit, all-feature cargo-deny and low-threshold npm audit pass;
  the inactive SQLx/MySQL rsa advisory remains visible. The complete staged diff
  passes redacted Gitleaks scanning before publication.

Source review keeps flow/port/verified transitions, readiness/locks, registration,
assertion completion, owner-proof invalidation and delegation in named modules.
New Rust modules remain below roughly 300 lines. Longer completion transactions
and integration scenarios retain explicit ordering and full-state assertions as
reviewed size exceptions; no structural cleanup is deferred. ADR 0012 and the
contracts/model/guides/threat model distinguish implemented core behavior from
remaining independent review, consent/usability, recovery HTTP/native/physical-
device evidence and safe activation. Logical expiry does not establish physical
retention cleanup. This checkpoint does not complete AUTH-20 or its release gates.

## AUTH-20 explicit recovery HTTP checkpoint (2026-10-19)

AUTH-20 remains **In Progress**. The separate `passkey-recovery` feature now exports
an explicitly aligned seven-service constructor and additive full OpenAPI for ten
closed POST operations: browser prebinding, claim start/resume/status, three denial
paths and private replacement start/registration/finish. Older constructors/routes/
full schemas and ordinary server composition remain unchanged. Exact Origin,
no-store/generic errors, no query selectors, 8 KiB ordinary/32 KiB WebAuthn response
bounds and the existing core/PostgreSQL policy are shared. Only committed actual
replacement assertion sets one session; anonymous operations reject any session
cookie rather than silently switching accounts. The independent HttpOnly recovery
cookie is established before code consumption and retained for any other claim;
rebind/metadata never extends original database deadlines.

A usability review found that a surviving-key owner receiving a fixed alert may not
know the claimant-only UUID. New `cancel_current_with_key` and the corresponding
repository method select the current owned configured-RP claim through the same
fresh-key lock/transaction path. HTTP key cancellation accepts `{}`; no anonymous
lookup, owner selector, weaker authority or status grant is added. The original
explicit-ID core API remains supported. No migration/dependency versions changed.

The separate setup route extraction (`b8b6c44`) passed all **8 existing setup HTTP
cases** before behavior extension. **15 new HTTP/real-PostgreSQL cases** and **one
new PostgreSQL current-claim cancellation case** pass. Coverage includes prebinding/
retention and lost-start resume, purpose/session/duplicate-cookie separation,
HTTPS/development policy, Origin/closed-body/query/selector/size/media boundaries,
no-ID genuine-key/retained-code/browser denial, bad-code flood isolation, all-service
realm/origin startup mismatch rejection, complete published/live contract equality
and prior-schema preservation, actual signed contact/email-free completion without
a prior live session, registration-only non-authority, replay/lost-finish key sign-in,
one session cookie under concurrent completion, exact rollback/retry, cancelled/bad
proof denial and failed-notification readiness gating. Deliberate persistence
failure requires generic 503, authority failure generic 401, neither with a success
cookie; tests do not count arbitrary infrastructure errors as denial evidence.
Verified-contact clock fixtures follow actual current-lease worker acknowledgement.
Software residence hints change only the test client, preserving production options
and existing signature/UP/UV/origin/RP verification.

Final local checks with PostgreSQL 17.11 and documented Mailpit:

- `cargo fmt --all -- --check`; strict locked workspace/all-target Clippy with
  default/all features and `-D warnings` pass.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace`: **93 pass**.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace --all-features`:
  **267 pass** (2 Axum unit, 54 HTTP/database, 10 core, 201 PostgreSQL). The
  logging subprocess repeats one included core case. Successful full suites have
  no failed or ignored cases. The locked adoption `easy` binary check also passes.
- Fresh pinned native baseline runs pass **31 Chromium and 4 real-SMTP cases**
  with unchanged existing assertions/admission. These cover prior signup/sign-in/
  management/code configuration, not native recovery HTTP interoperability. Fixed
  owned producer copies were made after Cargo checks/builds; all **378/404 source
  and binary hashes** match the immutable [browser report](../../tests/browser/passkeys/results/2026-10-19/chromium-recovery-transport.json)
  and [SMTP report](../../tests/browser/passkeys/results/2026-10-19/chromium-smtp-recovery-transport.json).
  Both owned native databases and exactly eleven owned messages are removed.
- The normal-server worker's four-purpose notice/accepted-lease/full-delay smoke
  passes through both Compose discovery and explicit CI-style container selection;
  each run removes exactly four owned messages and its database. Dummy schema
  fixtures prove delivery/receipt transport, not recovery authorization. Fresh
  standalone and embedded full password/recovery/session/lifecycle SMTP smokes
  pass with owned database cleanup. These native runs remain virtual-device evidence.
- Compiled-dependency audit, all-feature cargo-deny and low-threshold npm audit
  pass. The inactive SQLx/MySQL rsa advisory remains visible. The complete staged
  diff passes redacted Gitleaks scanning before publication.

Source review keeps named composition/body-limit route groups, private wire/schema,
binding, anonymous-cookie policy, metadata, denial and replacement handlers in
focused modules. No SQL or independent recovery policy enters transport. Current-
key denial shares existing transaction/deadline code with explicit-ID denial.
New implementation modules and feature test files stay below roughly 300 lines;
longer integration fixtures/scenarios retain actual proof, resource and full-state
assertions rather than hiding ordering. No structural cleanup is deferred. ADR 0012,
API/organization/threat-model docs, README and the management guide now document
public account-ID retention, prebinding, cancellation and lost-response steps.
Reference pages/consent usability, native/physical-device/other-browser recovery
proof, independent policy review and safe ordinary activation remain required.
This checkpoint does not complete AUTH-20 or any release/security-review gate.

## AUTH-20 reference recovery pages checkpoint (2026-10-19)

AUTH-20 remains **In Progress**. Five static reference resources are available only
through the explicit recovery constructor. Setup uses genuine fresh key sign-in,
public account-ID retention and deliberate code preparation/reentry/confirmation.
Recovery requires explicit logout, consumption/browser-retention consent and a
separate replacement consent. Metadata controls presentation only; core/database
policy still authorizes every operation. Transient proof clears on confirmation,
failed input and navigation; page-scoped network/native operations abort and late
results cannot repopulate secret fields. Requests reject redirects and never import
proof from URLs or persist it in JavaScript storage. No dependency/migration or
ordinary server activation changed.

The owned SMTP lifecycle was extracted separately in `0d0c93b`; all four existing
native SMTP cases passed before behavior extension. A new seven-case native suite
uses actual resident internal/USB registration and signed assertions for contact
and email-free recovery, plus browser/code/genuine-key cancellation. It removes the
original virtual authenticator before replacement, checks original claim expiry,
requires actual contact-notice acknowledgement before arranging elapsed time, and
covers lost start/finish responses, reload/resume, new-key sign-in, old signed-proof
rejection, independent browser denial, consent, redirect rejection, navigation
clearing and page errors. The fixture's bounded inherited stdin clock command is
restricted to its owned database; no HTTP or production clock override exists.
It preserves original expiry and the production 24-hour policy. This is virtual-
device evidence with arranged elapsed time, not physical-device or real-day proof.

Expanded native assertions initially exposed stale previous-error feedback during
a new request. The client now immediately displays an in-progress status. The
original field-clearing assertion remains unchanged and passes on the final run;
arbitrary infrastructure failures are never counted as authorization rejection.
Both unsuccessful native runs also removed their owned resources.

Final local checks with PostgreSQL 17.11 and Mailpit 1.27.11:

- Formatting and strict locked workspace/all-target Clippy with default/all
  features pass. The all-feature lint/suite were repeated after the UI fix.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace`: **93 pass**.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace --all-features`:
  **268 pass** (2 Axum unit, 55 HTTP/database, 10 core, 201 PostgreSQL).
  The logging subprocess repeats one included core case; no failures or ignored
  cases. One added HTTP/database case verifies all five assets, restrictive headers,
  no mutation/cookie/echo and absence from older constructors. Adoption check passes.
- Fresh pinned native runs pass **31 baseline + 4 SMTP + 7 recovery cases**.
  All **389/420/420 source hashes**, respectively, and their fixed producer binary
  hashes match the saved [baseline](../../tests/browser/passkeys/results/2026-10-19/chromium-recovery-pages-baseline.json),
  [SMTP](../../tests/browser/passkeys/results/2026-10-19/chromium-smtp-recovery-pages-baseline.json)
  and [recovery](../../tests/browser/passkeys/results/2026-10-19/chromium-recovery-pages.json)
  reports. Final recovery aggregates show seven starts, four completions, three
  cancellations, four unused newly configured codes, thirty source admissions and
  zero pending candidates/claims/setups/notices or invalid/weak provenance. All
  three owned databases and exactly eleven baseline/fourteen recovery messages
  are removed.
- Four-purpose normal-worker notice/receipt/delay smokes pass through both Compose
  discovery and explicit container selection, removing four owned messages and the
  database each time. Full standalone and embedded password/recovery/session/
  lifecycle SMTP smokes pass with owned database cleanup.
- Compiled-dependency audit, all-feature cargo-deny and low-threshold npm audit
  pass; the inactive SQLx/MySQL rsa advisory remains visible. The complete staged
  diff is scanned with redacted Gitleaks before publication.

Source review keeps static assets, client transport/lifetime, setup and recovery
controllers, fixture clock/database composition and native scenario groups in named
modules below roughly 300 lines. No SQL/policy enters the production pages and no
cleanup is deferred. ADR 0012, API/organization/threat-model docs and the management
and native guides document the implementation and limits. Independent recovery
review, physical-device/other-browser evidence and safe ordinary activation remain
required. This checkpoint does not complete AUTH-20 or its release/security gates.

## AUTH-20 ordered configuration/completion contention (2026-10-19)

Two additional real-PostgreSQL regressions run both email-free and verified-contact
accounts through actual candidate registration/assertion before arranging contention.
A final-audit advisory gate proves the first transaction already holds the owner;
an independent one-connection observer identifies its backend and requires a second
backend actually blocked by it before release. Bounded observation/action timeouts
fail as infrastructure problems. Each losing operation must return exactly
`Unauthorized`; storage errors cannot pass as policy evidence.

When saved-code confirmation commits first, the waiting preverified replacement
cannot install a key or session. Its old claim/candidate disappear, the new code
remains unconsumed, the original session and actual original-key assertion work,
and the new code can start a distinct claim. When recovery commits first, waiting
confirmation from the revoked original session cannot revive its pending setup or
replace the consumed generation. Exactly one active replacement session remains;
the original session is rejected, and a rejected confirmation retry leaves the
full durable state unchanged. Production behavior already enforces both orders;
this change adds regression evidence without changing APIs, policy, SQL, migrations
or dependencies.

Final checks pass: formatting, strict locked default/all-feature workspace/all-target
Clippy, **93 default workspace tests**, **270 all-feature workspace tests** (2 Axum
unit, 55 HTTP/database, 10 core, **203 PostgreSQL**; logging subprocess repeats an
included core case), compiled-dependency audit, all-feature cargo-deny and npm audit.
No failed/ignored tests. The inactive SQLx/MySQL RSA advisory remains visible.
The complete staged diff receives redacted Gitleaks scanning before publication.
The 42 native cases and SMTP evidence in the preceding checkpoint apply to the
unchanged application/fixture behavior; they were not rerun for this test-only
extension, and their historical source reports remain immutable.

The new feature-specific test module is under 300 lines and shares the existing
claim write gate. Its two longer scenario functions retain proof preparation,
observed ordering and outcome assertions together as a justified test-size exception.
No structural cleanup is deferred. AUTH-20 remains In Progress; independent review,
physical-device/other-browser evidence and safe activation remain open.

## AUTH-20 human device-fixture bootstrap (2026-10-19)

The owned development example now serves a fixture-only signup page. It creates
an email-free account through the actual registration and separate assertion APIs,
with deliberate disposable-credential consent and same-origin native WebAuthn JSON
handling. It seeds no account/key/session, preserves resident/UV requirements, and
shares existing client abort/redirect/error protections. Static resources use
no-store/no-referrer/nosniff/CSP. They do not enter library or normal server routes.

An eighth native case verifies static headers, absence of cookies/authority from
GET, no signup before consent, actual create/get, the resulting public account ID,
confirmed code setup and empty browser storage. All seven prior recovery scenarios
and their protocol/denial assertions remain. Final owned aggregates reflect only
the added account: eight users/keys/signup audits/codes, twelve configurations,
five unused codes, seven starts/four completions/three cancellations, thirty
source admissions and zero weak/provenance/pending errors. All fourteen exact
owned messages and the automated database are removed. The new
[report](../../tests/browser/passkeys/results/2026-10-19/chromium-manual-bootstrap.json)
records eight passing cases; all 425 source hashes and the fixed producer binary
hash match the checked source. Earlier published reports remain immutable.

Formatting, strict locked default/all-feature all-target Clippy, **93 default** and
**270 all-feature real-PostgreSQL workspace tests**, compiled-dependency audit,
cargo-deny and npm audit pass. The inactive SQLx/MySQL RSA advisory remains visible.
No production API, SQL, migration or dependency changes are part of this fixture
extension. Fixture static routing, manual assets and its additional native case
remain focused modules under 300 lines; no structural cleanup is deferred.
The native guide describes private operator entry, arranged-time limits and separate
credential-manager cleanup. Automated emulation cannot establish real-device success.

## AUTH-20 same-provider replacement investigation (2026-10-19)

The supervised [Safari/Dashlane record](../../tests/browser/passkeys/results/2026-10-19/safari-dashlane-recovery.json)
is a **partial failure**, not an interoperability pass. Safari 27.2
(22625.2.4.1), macOS 27.2 (26B5086k) and the observed Dashlane native save provider
6.2641.0 (544922) were identified without inspecting the vault. Actual signup plus
separate signed assertion, fresh sign-in/code confirmation, reservation, immediate
ineligibility, reload/resume and original-expiry-preserving elapsed-time arrangement
succeeded. The signup provider was not separately observed. Two replacement attempts
stayed on the native save sheet after operator-reported fingerprint approval.
The page reported an uncompleted native prompt; exact database stage remained
`registration`, with no verified private credential, completed claim or recovered
audit. The original server key remained; provider-side private-key preservation
was not established. Existing unrevoked session-row count is not fresh/unexpired
authority. The owned process exited successfully and its database was removed.
Credential-manager entry cleanup is unverified. Codes, assertion/registration
responses, vault contents and security-setting changes are absent from the record.

A pending replacement row had initially been mistaken for verified registration
while investigating. The fixture now reports pending registration and pending
assertion separately, retaining the older total for compatibility. Neither a row
count nor registration alone grants access. No speculative assertion-flow change,
provider switch, identity randomization or weakened verification was retained.
The save callback's root cause remains unproven; the display-field difference and
existing-provider-entry interaction are diagnostic hypotheses only.

A ninth native case fills a real coverage gap: it keeps the original resident
virtual authenticator rather than removing it as the earlier lost-device cases do.
The actual same-device creation/assertion succeeds. It checks stable account user
handle, empty exclusion list and unchanged RP, algorithms, timeout, attestation,
residence/UV and extensions; username/display metadata differ from signup. A gated
finish request proves the browser is still anonymous after registration. The
resulting authenticator has one different resident credential, and a still-fresh
old signed proof is rejected. New code configuration succeeds. This demonstrates
Chromium behavior, not the cause or resolution of the real-provider hang. ADR 0012,
the guide and threat model now distinguish SQL rollback from provider storage:
creation may replace a provider entry before server commit, which SQL cannot undo.

Final checks: formatting, strict locked default/all-feature workspace/all-target
Clippy, **93 default** and **270 all-feature workspace tests** (203 PostgreSQL),
compiled-dependency audit, all-feature cargo-deny and npm audit pass. No failed or
ignored tests; inactive SQLx/MySQL RSA advisory remains visible. All **9 current
native recovery/fixture cases pass**, including all seven original scenarios.
The [new report](../../tests/browser/passkeys/results/2026-10-19/chromium-same-device-recovery.json)
matches all **426 source hashes** and its fixed producer binary. Aggregates are
nine users/keys/signup audits/codes, eight starts/five completions/three cancellations,
fourteen configurations/six unused codes, thirty-five source admissions (original
limit forty), and zero remaining registration/assertion/total candidates, weak
provenance or pending work. The automated database and fourteen exact owned messages
are removed. Earlier published 31-browser/four-SMTP and eight-case reports remain
immutable; normal application behavior is unchanged. Physical evidence uses its
previous `af1bf4f` producer, matched to that checkpoint's source/binary report.
The complete staged diff receives redacted Gitleaks scanning before publication.

The new 79-line native module keeps its longer ordered actual-device/proof/state
scenario together as a test-size exception. The 69-line fixture query table stays
cohesive despite the function-size trigger: it maps fixed aggregate names to SQL,
not independent policy. No structural cleanup is deferred. No production service,
protocol options, SQL transaction, dependency or migration changes were needed for
these diagnostic tests. Both preceding hosted CI runs (39305280503 and 39306302790)
completed successfully. AUTH-20 remains In Progress; the unresolved Safari/Dashlane
path, wider device evidence, independent review and safe activation remain gates.

## AUTH-20 safe client prompt attribution (2026-10-19)

Investigation found a client diagnostic bug: the same text described native
`NotAllowedError`, native `AbortError` and the client's own navigation cancellation.
The earlier Safari/Dashlane observation therefore cannot establish its exact native
exception category. It remains a partial failure; this change does not establish
a fix or retroactively attribute it to a provider defect.

The shared reference transport now preserves finite creation/verification categories
and distinguishes request interruption from a changed page. Its generation check
runs on rejected operations as well as successful results, including page restoration
before an earlier abort's promise continuation. Native error messages and causes
are discarded rather than echoed, logged or persisted. Unknown native errors map
to fixed failure text. Backend authority, options, proof checks, deadlines and
redacted HTTP errors remain unchanged; UI categories grant nothing.

The existing retained-authenticator scenario now runs controlled creation rejection,
creation abort, verification rejection and simulated persisted pagehide/pageshow
cases before actual successful native signatures. It requires different fixed
messages, no synthetic private detail in output, no registration submission from
failed creation/navigation and exact 401 session rejection. Native methods are
restored; the original authenticator then creates/proves a new credential and the
still-fresh old signed proof is rejected. Only the old-proof issuance moves after
the controlled failures to preserve its original two-minute validity; the existing
110-second freshness assertion and all earlier security checks remain. Controlled
failures and simulated events are diagnostic tests, not real-provider reproduction.

Final checks pass: formatting; strict locked workspace/all-target Clippy with
default/all features; **93 default** and **270 all-feature real-PostgreSQL workspace
tests** (2 Axum unit, 55 HTTP/database, 10 core, 203 PostgreSQL; the logging subprocess
repeats an included core case); compiled-dependency audit, cargo-deny and npm audit.
No failures or ignored cases; inactive SQLx/MySQL RSA advisory stays visible.
All **9 native recovery/fixture cases pass**, preserving the original seven cases.
The [new report](../../tests/browser/passkeys/results/2026-10-19/chromium-prompt-errors.json)
matches **427 source hashes** and its fixed producer binary. Source admission is
**39 under the unchanged 40 limit**; original continuation admission also remains
unchanged. Final registration/assertion/total pending and weak/provenance counts
are zero. The owned database and fourteen exact owned messages are removed.
Historical reports remain immutable. The complete staged diff receives redacted
Gitleaks scanning before publication.

Source review keeps transport/classification private in the 111-line shared module
and controlled scenarios in a separate 73-line feature test module. The longer
ordered negative case retains abort/restore/no-request assertions together as a
justified test-size exception. No structural cleanup is deferred. No Rust API,
OpenAPI, SQL, migration or dependency changes. ADR/guide/threat-model/organization
and native instructions record the limits. Further device prompts or provider/
security-setting changes were not requested or performed. The Safari/Dashlane
creation cause, wider device evidence, independent review and safe activation
remain open; AUTH-20 is still In Progress.

## AUTH-22 OAuth state transaction boundary (2026-10-19)

The optional `oauth-transactions` core/PostgreSQL boundary now has independent
state/nonce/S256 generation, verifier-only persistence, browser/realm/connection/
client/revision/purpose binding, explicit callback-issuer/dedicated-route policy,
original linking-session checks, capacity/admission and atomic consume/cancel.
It creates no provider identity, application session or authentication audit.
See [ADR 0013](../architecture/adr/0013-oauth-state-transactions.md) and the
[guide](../guides/oauth-transactions.md). Migration 0016 is additive; published
migrations 0001–0015 are unchanged.

Final local commands pass with `CARGO_INCREMENTAL=0` and the documented PostgreSQL
17.11 setup, running feature variants sequentially:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --all-features
cargo test --locked -p easy-auth-postgres --features oauth-transactions --test lifecycle oauth::
python3 scripts/audit.py
cargo deny --all-features check
npm audit --audit-level=low --prefix tests/browser/passkeys
```

Results: **93 default** and **296 all-feature workspace tests**; the latter comprises
2 Axum unit, 55 HTTP/database, 12 core and 227 PostgreSQL cases. The logging subprocess
repeats one included core case. No final failures or ignored cases. The focused
OAuth-only PostgreSQL run passes **24 cases** without enabling passkeys. Two new
core cases cover the RFC 7636 S256 vector, secret redaction and exact configuration/
callback policy. Compiled advisory, license/source/bans and npm checks pass; the
inactive SQLx/MySQL RSA RUSTSEC-2023-0071 entry stays visible, without an advisory ignore.
The complete staged change receives redacted Gitleaks scanning before publication.

New PG tests preserve valid controls after wrong state/browser/nonce/PKCE/realm/
connection/client/purpose and actual callback-route/issuer attempts. They distinguish
Unauthorized, RateLimited and Unavailable, including an injected database failure.
Single-winner callback, callback/cancel and concurrent capacity cases assert exact
loser categories. Observed-lock tests establish both disable orderings and expiry
during unchanged-row selection, final deletion, row insertion and before the insert
clock is evaluated. The latter motivated filtering an expired insert rather than
reporting a schema constraint as Unavailable. Deletion failure rolls back state;
an upgrade preserves original identity/session/audit data. Linking storage-policy
fixtures cover stale/revoked/foreign sessions and method rejection for stronger
email-free users; they are not native authenticator evidence.

Review also made configuration generations non-restorable: every configuration
write returns a fresh persisted snapshot, disable rotates its revision, reconfiguration
preserves disable, and explicit re-enable requires the current snapshot. A controlled
sequence proves an old exchange/configuration cannot become current again afterward.
Future provider identity commit must still recheck enabled revision and original
deadline after network exchange. No state claim grants authentication authority.

One preliminary test failed because an email-free fixture inherited the mailbox
timestamp default. Explicit NULL corrected that fixture; the valid database
constraint was retained. Independent one-connection lock observers and four test
workers preserve the SQLx shared harness budget. Infrastructure timeouts cannot
count as negative-security test successes.

Maintainability review keeps feature configuration/proofs/use cases/port in core,
configuration/admission/ownership/transactions in PostgreSQL and tests grouped by
invariant. All new modules are below 300 lines. Longer ordered transactions/races
retain visible locking, final deadlines, rollback and assertions; the size rationale
is in code-organization.md. No unrelated structural cleanup is deferred. No new
dependency, HTTP/OpenAPI route, ordinary activation or provider conformance claim.
Native suites were not rerun locally for this core/SQL-only change; exact-head hosted
CI remains a separate publication gate and runs the existing browser/SMTP pipeline.
AUTH-20's Safari/Dashlane failure and independent recovery review remain open.


## AUTH-28 constrained document egress (2026-10-19)

The optional document client implements configured HTTPS origins/ports, conservative
public IPv4/IPv6 admission, whole-answer DNS checks, pinned addresses with original
Host/SNI and normal certificate validation, no proxies/redirects/retries, bounded
input/deadlines/concurrency and two exact-configuration cache slots. See
[ADR 0014](../architecture/adr/0014-oidc-egress.md) and the
[guide](../guides/oidc-egress.md). No provider identity/session, JOSE verifier,
new HTTP route or migration is added; migrations 0001–0016 remain unchanged.

Final local checks use `CARGO_INCREMENTAL=0`, PostgreSQL 17.11 and four test workers,
with default/all-feature workspace suites run sequentially:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --all-features
python3 scripts/audit.py
cargo deny --all-features check
npm audit --audit-level=low --prefix tests/browser/passkeys
```

Results: **93 default**, **320 unique all-feature tests**, no final failures or
ignored cases. All-feature totals are 2 Axum unit, 55 HTTP/database, 23 core,
232 PostgreSQL and 8 server transport tests; the logging child repeats one included
core case. Formatting, both strict Clippy variants, compiled dependency advisory,
license/source/bans and npm checks pass. SQLx's inactive MySQL RSA advisory remains
visible without an ignore. Full staged changes receive redacted Gitleaks scanning
before publication. Hosted exact-head CI is a separate publication gate.

Eleven new core cases cover exact issuer, malformed/private JWKS input, cache aging,
miss throttling, overload, timeouts, mixed/private/link-local/special-use IPv4/IPv6,
ports/literals and rebinding. Five new real-PG cases cover current revision, cache
isolation, disable during held network I/O, infrastructure failure and an identical
connection/revision relocated to another realm. No DB locks span network work and
no user/session/OAuth-transaction/audit records are created by fetching.

Eight server cases use owned TLS fixtures: positive Host/SNI/address pinning,
zero fallback DNS/proxy calls, trusted/untrusted-root and wrong-hostname controls,
closed size/status/encoding/header/type/timeout failures, peer mismatch, body-age
reduction, cache headers, canceled native DNS permit ownership and a cold child
without a process-global TLS provider. A separate socket reset must remain Network,
not Certificate. Infrastructure failure cannot count as certificate rejection.
Fixture roots/loopback addresses are private to component tests; production policy
has no bypass. No user credential or system proxy/security setting is changed.

An initial certificate-specific assertion exposed generic network classification:
`io::Error::source` skipped the boxed rustls error. Typed payload inspection fixed
attribution without raw message matching; the strict certificate and socket-reset
controls pass afterward. Preliminary mock resolver type and missing locked-registry
archive failures were setup/build failures, not application security evidence.
One automatic approval review timed out before execution; the approved retry and
normal locked dependency fetch completed. No final operation remains policy-blocked.

Maintainability review preserves feature ownership, thin entry modules, private
adapter/test internals and reuse of the exact existing PostgreSQL registry check.
All new modules are below 300 lines; longer ordered response validation and fixture
scenarios are justified in code-organization.md. No unrelated cleanup is deferred.

Native passkey/SMTP suites were not rerun locally for this optional backend feature;
hosted CI runs the existing browser/SMTP/recovery pipeline. These tests establish
component behavior, not real-provider interoperability or independent security
review. Uncancellable native DNS retains bounded permits and may delay shutdown.
Private-network/private-CA IdPs are unsupported. JOSE selection, token exchange,
claims/key rotation, final identity transactions, provider tests, SAML and outbound
issuer remain gates. AUTH-20's Safari/Dashlane failure remains unresolved and does
not justify further provider/security-setting changes or an activation claim.


## AUTH-29 bounded key-refresh checkpoint (2026-10-19)

This checkpoint adds the document refresh primitive only. AUTH-29 remains in
progress: code+S256 exchange, established-library signature verification, mandatory
typed claims/algorithm/key policy, one unknown-key retry per transaction, local
Keycloak and final provider acceptance remain unfinished. No new dependency,
migration, HTTP route, identity or session grant is introduced.

Using `CARGO_INCREMENTAL=0`, the documented PostgreSQL setup and four test workers:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked -p easy-auth-postgres --features oidc-egress --test lifecycle oidc::
cargo test --locked --workspace
cargo test --locked --workspace --all-features
python3 scripts/audit.py
cargo deny --all-features check
npm audit --audit-level=low --prefix tests/browser/passkeys
```

All final checks pass: **93 default** and **327 unique all-feature tests** (2 Axum
unit, 55 HTTP/database, 28 core, 234 PostgreSQL and 8 server transport). The logging
child repeats one included core case. All seven new cases are confirmed in the
full-suite output; focused OIDC PostgreSQL also passes all seven existing/new cases.
No final failures or ignored tests. Compiled advisory, licenses/sources/bans and
npm checks pass; the inactive SQLx/MySQL RSA advisory remains visible without an
ignore. Full staged changes receive redacted secret scanning before publication.

Five new core cases establish the one-second cold-fetch boundary and 30-second
forced-attempt boundary, reuse of a completed newer snapshot, failed-attempt budget
retention, non-cacheability, concurrent miss rejection, DNS timeout/slot release
and disable rejection. Two new real-PG cases check disabled cached observations and
disable committing during held key fetch without a DB lock spanning I/O. Exact
Unauthorized/RateLimited/Unavailable assertions distinguish policy from setup
failure. These are envelope/cache tests, not valid signing-key or token evidence.

An initial strict Clippy run rejected a nested cache conditional. It was flattened
without changing policy or assertions, and both strict variants passed afterward.
Final all-feature lint was repeated after adding the timeout/non-cacheable cases.
No application failure was hidden or converted into a successful negative test.

Maintainability review retains a single bounded key slot and private snapshot
identity comparison, with no key-ID map or duplicated transport/policy. Named test
modules separate refresh cases. The ordered `load_keys` size exception and complete
scenario rationale are recorded in code-organization.md; all affected Rust modules
remain below 300 lines. No unrelated cleanup is deferred.

Native browser/SMTP scripts were not rerun locally for this core/cache change;
exact-head hosted CI remains a separate gate and runs them. The previous AUTH-28
implementation's [CI39326434266](https://github.com/Deuspheara/easy-auth/actions/runs/39326434266)
passed all gates. A later checkpoint cannot inherit that run as proof of its own
hosted result. Independent review, real provider verification and ordinary activation
remain open, including the previously recorded Safari/Dashlane failure.


## AUTH-29 optional signature/claim checkpoint (2026-10-20)

The explicit `oidc-verification` core/PostgreSQL boundary now consumes a claimed
OAuth exchange, verifies real compact signatures using pinned josekit0.10.3/OpenSSL,
checks mandatory typed claims and exact context, and returns an opaque capped
identity value. It adds no token endpoint exchange, callback, local session/linking
grant or ordinary activation. AUTH-29 remains in progress pending its full code+
S256, local Keycloak, provider and final acceptance work. See
[ADR0015](../architecture/adr/0015-oidc-token-verification.md) and the
[guide](../guides/oidc-verification.md).

Final checks use `CARGO_INCREMENTAL=0`, the documented PostgreSQL setup and four test
workers. Database suite variants run sequentially:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked -p easy-auth-core --features oidc-verification oidc::verification::
cargo test --locked -p easy-auth-postgres --features oidc-verification --test lifecycle oidc::verification
cargo test --locked --workspace
cargo test --locked --workspace --all-features
python3 scripts/audit.py
cargo deny --all-features check
npm audit --audit-level=low --prefix tests/browser/passkeys
```

Passed: **93 default** and **349 unique all-feature tests** (2 Axum unit, 55 HTTP/DB,
43 core, 241 PostgreSQL, 8 server). The logging child repeats one included core case.
Focused verifier passes15 core scenarios; focused PostgreSQL passes7 context cases.
All final added cases are confirmed by name in the full-suite output. No final
failures or ignored tests. Formatting, strict default/all-feature all-target lint,
compiled advisory, license/source/bans and npm gates pass. The all-feature suite was
repeated after the key-use classification, email-optional and cancellation cases;
default-feature source was unchanged after its passed run. Complete staged changes
receive redacted secret scanning before publication. Hosted exact-head CI is a
separate publication gate; it cannot be inherited from a predecessor.

New15 core scenarios include actual generated RS256/PS256/ES256 positive and wrong-key
controls, signature-valid original duplicate/extension header/claim bytes, exact
issuer/client/nonce/audience/azp/time/type failures, explicit algorithm/key-use
policy, duplicate/malformed key metadata, one real-signature rotation refresh and
bounded unknown IDs. A controlled owned blocking queue proves canceled native jobs
retain capacity: overload rejects promptly, then fresh valid work succeeds after
release. No production hook, permissive verifier, global crypto provider installation
or user/system security setting is introduced.

Seven new real-PG cases cover exact revision and realm despite identical metadata,
current database time without auth records, infrastructure failure as Unavailable,
original linking-session revocation, original expiry after unchanged-configuration
wait, freshness after unchanged-owner wait, and original linking cap despite a later
freshness timestamp. Independent lock observation uses one connection; observation
failure is an explicit infrastructure test failure. No DB lock spans network/crypto.

Review found and fixed two authority distinctions before publication. Verified
results retain the minimum original OAuth, token expiry and original token-age cap;
verification cannot restart any window. Optional email is independent of subject
identity: an absent address remains a valid signed identity but a standalone
email_verified flag cannot produce a verified email attribute. Malformed flag types
still reject. No signature, nonce, audience, issuer, context or freshness assertion
was removed. Valid-but-incompatible key restrictions return Unauthorized, distinct
from malformed provider material returning Unavailable; a mixed-algorithm negative
and valid control prove that distinction without forcing refresh.

Initial strict lint found a large private result enum and ignored must-use positive
results. Claims are now boxed and controls assert the actual subject. Final strict
lint passes; these were not successful security-negative test results. No final
operation remains policy-blocked.

The combined graph adds10 packages with no prior locked version removed/upgraded.
No advisory ignore or license exception was added; SQLx's inactive MySQL RSA entry
stays visible. josekit's upstream license texts are retained. Native OpenSSL upgrade/
deployment and strict clock synchronization remain responsibilities. Component
signatures generated/verified using one library are not independent interoperability
or audit evidence; real Keycloak code exchange/rotation/replay remains mandatory.

Maintainability: feature-specific policy/input/claims/keys/flow/port/result modules,
thin entries, private constructors and reused PG configuration/owner policy. All new
Rust modules remain below300 lines. Selected-key and ordered matrix/queue/wait
function-size exceptions are justified in code-organization.md. No schema migration,
HTTP/OpenAPI route, account-policy duplication or unrelated cleanup is introduced.
Native browser/SMTP scripts were not rerun locally for this optional backend layer;
hosted CI runs the existing pipeline. Final local identity/session transactions,
independent review, SAML, outbound issuer and ordinary activation remain gates.


## AUTH-29 code exchange and non-cacheable metadata (2026-10-20)

The optional core code exchange now constructs the original code/S256/redirect
request with explicit registered public, secret-Basic or secret-Post authentication.
Its authorization URL carries original state/nonce/challenge and bounded openid
scopes. Backend-owned zeroizing/redacted values have no Clone/Serialize; the
trusted adapter alone accesses encoded requests. Response parsing selects only the
protected ID-token field for established signature/claim verification and discards
unused access/refresh tokens. There is no local session grant or HTTP callback.

Eleven new core scenarios pass. They use actual ES256 signature controls through
all three registered authentication methods, special-character Basic component
encoding, exact code/original PKCE/redirect binding, absence of proof in URL/body
where inappropriate, no method fallback, reserved query rejection, provider error
classification, duplicate/missing/invalid response fields, MIME/encoding/size
limits, new-flow nonce replay denial, post-DNS expiry before credential transmission,
disable during POST, shared operation admission and recovery after network failure.
Exact Unauthorized/Unavailable/RateLimited assertions separate application rejection
from broken infrastructure; successful signature controls remain intact.

A new regression first failed against the current implementation: discovery with
zero HTTP freshness was loaded again after a successful code POST, so the same
operation hit its own ordinary fetch budget. The fix carries one validated snapshot
only inside the bounded logical exchange/verification, including unknown-kid refresh.
The regression passes and checks one discovery plus one JWKS fetch, then immediate
separate-operation RateLimited with no second POST or cross-operation cache reuse.
All42 OIDC core tests pass, retaining existing rotation/claims/worker/admission tests.

Two new TLS POST cases pass alongside all8 existing server transport cases. They
obtain the actual opaque request through core begin/consume/exchange and call the
same internal production POST/reader against an owned TLS listener, private fixture
root and explicit test-only address mapping. Production public-address/root rules
remain unchanged. HTTP400 invalid_grant reaches exact Unauthorized as a positive
transport control; HTTP401 invalid_client reaches Unavailable without a transport
failure. Headers/form/SNI/Host/PKCE/redirect and no-cookie behavior are checked using
non-secret assertion output. Redirect, declared/chunked oversize, header/MIME/
encoding and timeout negatives require exact finite transport causes and no retry.
The sandbox's initial listener denial and a canonical-origin fixture typo were
infrastructure failures, not acceptance evidence. No security check was relaxed.

An owned metadata-only probe uses official
[Keycloak26.8.1](https://www.keycloak.org/getting-started/getting-started-docker),
image digest `sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244`.
The loopback-only disposable container becomes ready, then is stopped/removed.
Its public discovery reports `no-cache, must-revalidate, no-transform, no-store`,
S256 and issuer-response support, and Basic/Post among its advertised client methods.
It does not advertise none; no public-client compatibility is inferred.
This confirms the relevance of the no-cache regression, not token/code/provider
interoperability. No provider account, production credential or token is used.
Actual local Keycloak code/S256/signature/rotation/replay and final identity/session
acceptance remain required; AUTH-29 remains In Progress.

Final local gates pass: `cargo fmt --all -- --check`; strict locked workspace/
all-target Clippy with default and all features; `cargo test --locked --workspace`
(**93 tests**) followed sequentially by its `--all-features` variant (**362 unique
cases**: 2 Axum unit, 55 HTTP/database, 54 core, 241 PostgreSQL, 10 server; the logging
subprocess repeats one included core case). No failed or ignored cases. Compiled
advisory audit, all-feature cargo-deny and browser npm audit pass. Inactive SQLx/MySQL
RSA advisory remains visible; no exception is added. The staged diff receives
redacted Gitleaks scanning before publication.

The earlier structural extraction is separate commit `e12826f`; its 31 OIDC tests
and strict all-feature lint passed before behavior was added. New modules keep
explicit protocol policy, HTTPS, SQL and test responsibilities separate; all remain
under 300 lines. Longer request construction and ordered fixture/scenario functions
retain exact proof/credential/operation ordering as reviewed size exceptions. No
migration, dependency version, public HTTP schema or ordinary composition changes;
no unrelated structural cleanup is deferred. Previous signature checkpoint
`b100462` has completed successful hosted CI39334677522. New exchange publication
and hosted acceptance are recorded separately; the ticket is not complete here.

## AUTH-29 owned Keycloak acceptance — 2026-10-20

The [immutable sanitized record](../../tests/browser/oidc/results/2026-10-20/keycloak-code-rotation.json)
passes **11 named cases** on Node24.21.0, Playwright1.64.1 and
Chromium156.0.8078.4 using official Keycloak26.8.1 pinned to the previously recorded
image digest. All **521 source fingerprints** match the final sources and the fixed
producer executable hash matches the actual binary. This is run/source provenance,
not a reproducible-binary or general provider/compliance/production-readiness claim.
The [reproduction guide](../../tests/browser/oidc/README.md) describes the boundary.

The owned example uses actual PostgreSQL begin/consume/context checks and core
code/S256/RS256 verification. It includes the same private production TLS builder,
GET/POST and bounded response readers by source path, without widening their public
API. A private fixture alone supplies the owned TLS root/address mapping. Rust still
validates hostname/SNI, certificate, peer, timeout, MIME/encoding/body limits and
redirect/proxy behavior; actual certificate/transport negatives remain separate.
Fresh browser contexts contact only the owned provider/callback using process-only
resolver/proxy arguments and fixture certificate tolerance. No user/device/system
setting, credential manager or production public-root/address policy is changed.

Actual Keycloak browser login and code+S256 produces verified identity proof with
matching subject/configuration/original cap and omitted email, without creating a
local account/contact/session. Exact PostgreSQL state replay and the provider's
original code/form/verifier replay reject. Actual provider-signed wrong nonce and
untrusted additional audience reject, as does wrong S256. Controlled proxy byte
corruption and substitution of an earlier genuinely signed token are separately
labeled; claim/signature negatives require an actual successful provider token
envelope and exact Unauthorized, never arbitrary infrastructure failure. An actual
new provider RSA signing key becomes active and verifies. A fresh valid control
succeeds after all negatives; disabled PostgreSQL context sends no code/client secret.

Aggregate facts are **8 application token POSTs**, **7 successful provider token
responses**, one deliberate signature fault and one deliberate old-token fault.
Administrative provisioning and exact code replay use the owned loopback provider
backend; application document/code requests use the shared HTTPS code through its
owned TLS proxy. Keycloak's actual no-store discovery/JWKS headers are preserved;
the real rotation case is not evidence for the forced-refresh cache branch, which
retains separate bounded actual-signature regressions. The fixture's full provider
user profile is not a local verified contact; this client requests only openid/profile.

Final database counts are zero users/sessions/audits/pending transactions. Native
exit0, normal exact-owned database removal, owner-labeled provider removal and
private-file removal are required and pass, with no unexpected diagnostics or
emergency cleanup. Proof-bearing IPC stays in private process pipes, never ordinary
logs/reports/traces/browser storage. Earlier failed runs identified an undefined IPC
match and a redirect-hop callback DNS failure in Playwright routing. Request-event
capture plus a real owned callback listener corrected those fixture defects. A
failed-run PostgreSQL55006 cleanup exposed residual fixture connections; pool
closure now precedes terminating connections only in its validated random-owned
database. None of those failures counts as application denial evidence, and no
application policy or meaningful regression assertion was relaxed.

The behavior-preserving POST-source extraction is separate `12ba9d8`, verified with
all10 prior TLS cases, strict all-feature lint and redacted staged scanning before
fixture extension. Named database/composition/transport and provider/proxy/browser/
IPC/scenario/runner modules remain below300lines. Longer ordered composition and
resource try/finally functions keep proof, cleanup and fixed-error boundaries
visible as documented size exceptions; no unrelated structural cleanup is deferred.
No migration, dependency version, public HTTP schema or ordinary composition changes.
The new explicit CI command follows pinned browser dependency setup; ordinary Cargo
suites remain independent of provider tooling, without ignored acceptance tests.

Final local commands pass: formatting; strict locked workspace/all-target Clippy
with default/all features; sequential default93 and all-feature362 unique cases
(2 Axum unit/55 HTTP-PG/54 core/241 PostgreSQL/10 server; the logging subprocess
repeats one included core case); compiled advisory audit, all-feature cargo-deny,
existing browser npm audit and JS syntax/diff checks. Inactive SQLx/MySQL RSA advisory
remains visible and compiled findings remain fatal. The complete staged diff receives
redacted Gitleaks scanning before publication. Prior exchange CI39337567832 at
`b206d0f` is completed SUCCESS; new exact-head publication/hosted evidence is tracked
separately. Final mapping/JIT/local session issuance, broader provider/native
acceptance, independent review, ordinary activation, SAML and outbound issuer remain
separate open gates. No ticket/project completion follows from local results alone.

## AUTH-29 fast-callback admission and final lease audit — 2026-10-20

A later adversarial audit corrected the earlier acceptance assessment. The original
provider runner inserted1100ms pauses between operations. Two new real-signature
regressions first failed: an immediate valid callback after no-store authorization
metadata returned RateLimited with zero code POSTs; independently cached discovery
with no-store keys caused the second valid exchange to fail after two total code
POSTs. These are application self-throttling failures. The earlier paced provider
record remains immutable and does not prove this timing boundary.

The code flow now holds its existing operation lease while waiting at most the
remaining one-second interval before each first ordinary discovery/key fetch. It
then invokes the unchanged normal loader once. No failed-request, state, code or
unknown-kid retry loop is added; no-store documents are refetched and ordinary/
forced budgets remain unchanged. Cache-slot/database locks are released before the
admission timer. Standalone document/token APIs and forced refresh keep prompt
admission. Authorization preparation is bounded by one admission second plus the
existing five-second document bound; exchange/verification keep30/15second bounds.
Original post-DNS and final database authority/deadline checks remain mandatory.

A third failing regression identified premature permit release on a successful
unknown-kid native retry. An actual rotated signature reached a controlled final
repository wait; a second operation occupied its initial wait. The third timed out
inside the repository instead of immediate RateLimited. The retry now receives a
lease clone, preserving the operation's original reference through final authority
and claims checks. Both valid signed controls succeed after release. No application
crypto, identity/session policy, migration or dependency change is needed.

Six new core cases cover those two fast-flow failures, metadata-admission expiry/
disable/registry classification, canceled admission and recovered capacity,
original expiry after a key wait reaching the final valid-signature check, and
rotated-signature final-read capacity. Existing meaningful no-cache tests retain
generic immediate miss denial and require a fresh discovery/key fetch for each
new admitted operation. No stale reuse or same-code retry is permitted. All48 OIDC
core tests pass, retaining algorithm/claim/key/rotation/native-worker boundaries.

The [new unpaced provider record](../../tests/browser/oidc/results/2026-10-20/keycloak-fast-callbacks.json)
passes all **11 original Keycloak cases**, with `runner_admission_delays: false`.
All **522 source hashes** match final sources and the fixed producer binary hash
matches. Node24.21.0/Playwright1.64.1/Chromium156.0.8078.4 and the pinned Keycloak
image remain unchanged. Actual cache headers are preserved. Aggregate8application
POSTs/7provider-success responses/one signature fault/one token replay, zero local
users/sessions/audits/pending, normal exit0 and exact database/container/private-file
removal all pass. No emergency cleanup or unexpected diagnostics. The image declares
no anonymous data volumes. Earlier records and their source/binary hashes are unchanged.

Final local gates pass: formatting, strict locked default/all-feature workspace/
all-target Clippy, sequential **93 default** and **368 unique all-feature tests**
(2 Axum unit/55 HTTP-PG/60 core/241 PostgreSQL/10 server; one included core logging
case repeats in a subprocess), compiled advisory audit, all-feature cargo-deny,
existing browser npm audit and JS syntax/diff checks. No failed/ignored tests.
Inactive SQLx/MySQL RSA advisory remains visible and no exception is added. The
complete staged diff receives redacted Gitleaks scanning before publication.

Changed modules remain below300lines. First-fetch scheduling stays in the owning
cache module, leased orchestration selects it, and native retry ownership stays
with verification. Controlled admission cases have their own feature module;
worker cases keep observed waits, release and valid signatures together as reviewed
function-size exceptions. No public root/IP override, protocol downgrade, wire
schema, ordinary composition or unrelated structural cleanup is introduced.
Prior exact-head CI39340016588 at eb3281b completed SUCCESS. That checkpoint's green
result is distinct from these corrections' new hosted run, tracked separately.
AUTH-29/project completion and independent review/ordinary activation are not
claimed from local evidence alone.


## AUTH-30 scoped mapping checkpoint — 2026-10-20

AUTH-30 remains **In Progress**. The optional core `oidc-identities` feature now
consumes a verified external identity through immutable exact-connection policy,
an explicit bounded issuer allowlist and typed display-claim selection. JIT
configuration defaults to deny; no local provisioning/session transaction is
implemented yet. Provider email never selects a local owner or becomes verified
contact. No HTTP/OpenAPI, account-policy enum, dependency or migration changes.
[ADR 0016](../architecture/adr/0016-oidc-identity-mapping.md) records implemented
behavior and the remaining persistence/lifecycle requirements separately.

Six signed mapping cases cover display selection, exact allowlists including eight
valid distinct issuers versus a ninth, other registrations/stale revisions,
unavailable selected profile data without fallback, UTF-8 byte bounds, duplicate
signed profile fields, redacted diagnostics and preserved subject/purpose/deadline/
authentication-time/email provenance. Every other-registration configuration has a
fresh revision; this matrix is not independent evidence of each database key
constraint. A separate verification-only case proves unrecognized profile data
remains ignored without the new feature, and CI now runs that feature combination.

Local checks pass using PostgreSQL 17.11 and the documented loopback development
services, `CARGO_INCREMENTAL=0`, sequential database suites and four test workers:

- `cargo fmt --all -- --check` and default/all-feature strict locked workspace/
  all-target Clippy pass. Final all-feature lint reruns after test-bound expansion.
- `cargo test --locked --workspace`: **93 distinct tests** pass.
- `cargo test --locked --workspace --all-features`: **374 distinct tests** pass
  (2 Axum unit, 55 HTTP/PostgreSQL, 66 core, 241 PostgreSQL, 10 server).
  The logging subprocess repeats one already-counted core case. No failures or
  ignored tests. After strengthening the issuer bound case, the core all-feature
  suite reruns: all **66** pass; application implementation is unchanged.
- Core `--features oidc-identities`: **60** tests pass; separate core
  `--features oidc-verification`: **55** pass, including compatibility coverage.
- Compiled-dependency advisory and all-feature cargo-deny advisory/license/source/
  bans gates pass. Inactive SQLx/MySQL RSA advisory remains visible. Local doc
  links and diff whitespace pass. The complete staged changes receive redacted
  Gitleaks scanning before publication.

An initial test compilation failed because a new assertion requested Debug for
OAuthPurpose. The assertion now matches the existing closed variant without adding
secret-bearing diagnostics or changing production types. No failed compilation is
counted as regression evidence.

Source review keeps policy, opaque mapped proof and profile decoding in separate
cohesive modules; all new source files remain under 300 lines. Longer issuer-bound,
cross-registration and invalid-profile tables retain cases/controls together as
reviewed test-size exceptions. No unrelated cleanup is deferred.

Real PostgreSQL policy persistence, provisioning/linking atomicity, disabled-callback
and deletion races, actual JIT denial and provider session provenance remain
required before completing AUTH-30. No new native/provider acceptance run is claimed
for this core-only mapping checkpoint. Existing browser reports stay immutable;
AUTH-20's Safari/Dashlane failure and independent recovery review remain open.


## AUTH-30 transactional policy storage checkpoint — 2026-10-20

AUTH-30 remains **In Progress**. PostgreSQL `oidc-identities` now adds trusted
`configure_oidc_identity_policy` and additive migration 0017. Each application
allocates a fresh connection revision, cancels old pending OAuth state and writes
policy in one transaction. Existing disable is retained. The returned typed policy
carries the persisted revision. A stale policy row does not authorize an identity:
current enabled configuration/policy must still be checked by the unimplemented
final resolver. No user, session or authentication audit is created here.

The configuration SQL was first extracted without behavior changes in a separate
commit; all **24 existing OAuth PostgreSQL regressions** and strict all-feature
workspace/all-target lint pass after extraction. Policy storage then reuses that
private transaction function without duplicating configuration or cancellation SQL.

Six new actual-PostgreSQL cases prove:

- Policy/revision persistence, original pending cancellation and rejection of a
  previously consumed exchange, with no local user/session/audit creation.
- An injected policy-write fault is exactly Unavailable, and rolls back revision,
  pending cancellation and prior policy. The old exchange remains usable after
  rollback; removing the trigger permits a valid retry and invalidates that exchange.
- Concurrent policy application and disable retain disable; reapplying stale policy
  receives a new revision, stays disabled and requires explicit latest re-enable.
  This checks administrative configuration concurrency, not final callback commit.
- Identical connection/local-client IDs in different realms, and another client in
  the original realm, retain independent current policies and revisions.
- Upgrade from migration 0016 preserves mailbox user/session/audit, registry and
  pending OAuth state. The existing session and original callback remain usable;
  migration creates zero implicit policies.
- Closed modes, empty/null/oversized issuer arrays and cross-realm foreign keys
  reject with exact PostgreSQL constraint codes, not arbitrary errors. Omitted SQL
  JIT mode defaults to deny. URL spelling/uniqueness/membership remain core validation.

Final local checks with PostgreSQL **17.11**, `CARGO_INCREMENTAL=0`, four workers
and sequential database suites pass:

- Formatting and strict locked default/all-feature workspace/all-target Clippy.
- `cargo test --locked --workspace`: **93 distinct tests**.
- `cargo test --locked --workspace --all-features`: **380 distinct tests**
  (2 Axum unit, 55 HTTP/PostgreSQL, 66 core, 247 PostgreSQL, 10 server).
  The logging child repeats an included core case; no failures or ignored tests.
- Compiled-dependency advisory and all-feature cargo-deny gates. The inactive
  SQLx/MySQL RSA advisory remains visible. No dependency/lockfile changes.
- Local documentation links, diff whitespace and redacted staged Gitleaks checks.

Source review keeps policy persistence in its 61-line owning module. The longer
administrative transaction retains revision/cancellation/policy/commit together.
Policy and migration/schema cases have separate modules under 200 lines; their
longer ordered cases keep setup, fault/operation, observation and valid controls
visible. No public API is widened for tests and no unrelated cleanup is deferred.
README, ADR0016, architecture, API and threat-model descriptions match this scope.

Actual JIT denial/provisioning, external subject uniqueness, disabled callback
commit races, deletion behavior and provider account/session provenance remain
required AUTH-30 work. Explicit linking/unlinking is the separate AUTH-25 boundary;
the eventual sign-in resolver must reject linking-purpose proofs until it exists.
No new browser/provider run, ordinary activation or release/audit claim is made.


## AUTH-30 final identity/JIT/session checkpoint — 2026-10-20

AUTH-30 remains **In Progress** pending updated owned-Keycloak acceptance and hosted
publication evidence. Optional core/PostgreSQL now implement final sign-in resolution:
consume the opaque mapped proof, reject linking purpose, lock current exact configuration/
policy, serialize scoped subject ownership and atomically create/resolve provider-only
user, identity, source-bound session and fixed-schema oidc_authenticated audit. All writes
precede the last original-proof database clock check. Policy/storage errors remain finite;
no raw token, subject or provider attributes enter audit/log output.

Migration 0018 adds provider_required policy, exact C-collated issuer/subject identity keys,
composite source/owner session constraints and pseudonymous deletion cooldown metadata.
Current-source checks precede owner/session locks. Old/missing auth_time never becomes
freshness; a genuine recent provider time can authorize owned session revocation. Neither
verified contact, provider amr nor preverified passkey/retained recovery proof bypasses
method policy. Ordinary activation, linking and provider-only public lifecycle remain gated.
See [ADR0016](../architecture/adr/0016-oidc-identity-mapping.md) and the
[identity guide](../guides/oidc-identities.md) for exact API, lock and retention limits.

A new signed-token/real-PostgreSQL regression first failed at the mapper with actual
Unauthorized after successful verification: an already-bound subject lost access when
optional name was absent. The mapped display candidate now returns Option<&str>; the
final new-owner branch still requires the selected usable field, with no alternate/email
fallback. Repeat login preserves stored presentation. Existing malformed-profile cases
now require an absent candidate; new-owner denial is asserted in the database transaction.
This is an explicit refinement of the new feature-branch API, not a removed released API.

**29 signed identity PostgreSQL scenarios** now pass, covering:

- Default-deny JIT versus existing-subject resolution and explicit persisted allow;
  unpersisted policy changes and old-revision proofs reject without creating authority.
- Genuine source/authentication-time provenance, stable owner/profile, matching verified
  provider email without merge, optional-profile login and missing-profile new-owner denial.
- Real same-subject isolation by realm/local client, issuer reconfiguration without owner
  transfer, and explicit case-sensitive identity storage independent of database locale.
- Concurrent independent valid proofs resolve one owner and create distinct sessions;
  the final transaction never revives consumed OAuth state.
- Observed configuration locks prove both callback/disable orders. A callback committing
  first has unusable authority after waiting disable commits; disable first prevents all
  provisioning. Session validation/inventory also reject disable after an observed source wait.
- Session/audit write faults are exactly Unavailable with complete rollback and a new-flow
  valid control. A missing policy table is infrastructure failure, not a passing JIT denial.
- Observed final-audit expiry rolls back user/identity/session/audit. Observed unchanged-source
  waits cross original idle/provider freshness caps, with unchanged session touch/state.
- Both deletion/owner-lock orders and anonymous callbacks obey cascade/cooldown/original
  caps. The owned deletion fixture follows owner lock and audit erasure; it is not a new
  provider-only deletion endpoint. Retention fixtures explicitly arrange expiry; no real
  five-minute/provider/device wait or autonomous cleanup is claimed.
- Migration 0017->0018 preserves mailbox users, sessions and trusted policy, without inventing
  sources. Exact 23514/23503 errors prove missing source and wrong-owner FK constraints.

Two additional actual-passkey/PostgreSQL cases reject a preverified assertion/new admission
and a retained saved recovery code after provider-required policy, preserving credential/
session/audit/pending state and leaving the recovery code unconsumed. Existing passkey,
mailbox/password/lifecycle/realm/concurrency negative assertions remain intact.

Final local checks use the documented PostgreSQL setup, four workers and sequential database
suites with CARGO_INCREMENTAL=0:

- cargo fmt --all -- --check and strict locked default/all-feature workspace/all-target Clippy pass.
- cargo test --locked --workspace: **93 distinct tests** pass.
- cargo test --locked --workspace --all-features: **411 distinct tests** pass
  (2 Axum unit, 55 HTTP/PostgreSQL, 66 core, 278 PostgreSQL, 10 server).
  The logging subprocess repeats one included core case; no failures or ignored tests.
- Compiled-dependency advisory and all-feature cargo-deny gates pass. The existing SQLx/MySQL
  RSA advisory remains visible only in the inactive optional lockfile graph.
- No package version or production crypto dependency is added. Existing pinned josekit is
  now a PostgreSQL test dependency; Cargo.lock changes only that package's dependency entry.
- Documentation links/diff whitespace and redacted staged secret scanning precede publication.

An initial new recovery test used a nonexistent start method; it was corrected to the
existing begin API without a production API change. A formatting-only edit briefly left
whitespace rejected by rustfmt; it was corrected before final gates. Neither failed attempt
is counted as passing evidence. The intentional optional-profile pre-fix failure is retained
separately from infrastructure outcomes.

Maintainability review separates core port/sign-in, PostgreSQL policy/ownership/completion,
session source/guard/inventory and feature test scenarios. New transaction/test entry
modules contain declarations; existing facades add only declarations/reexports.
All new modules stay under 300 lines. Longer owning transactions and ordered lock/fault/
migration tables retain setup, snapshot checks, original caps, writes and rollback in visible
order as documented size exceptions; no unrelated cleanup is deferred. Local sessions gain
a method-snapshot query, and provider sessions add current-source reads/locks; old latency
measurements are historical, with no new performance claim.

Earlier checkpoint CI39346346832 (058579a) and CI39347344289 (afd4cb3) both completed SUCCESS.
These results do not establish hosted/native acceptance of the newer final resolver. Existing
Keycloak/browser reports remain immutable; the next provider run must exercise actual local
JIT/session behavior with its own current source/binary fingerprint. AUTH-25 linking and
AUTH-20's unresolved Safari recovery/independent-review gates remain open.


## AUTH-30 owned Keycloak JIT/session acceptance — 2026-10-20

AUTH-30 remains **In Progress** until hosted publication and final completion review.
The [new immutable report](../../tests/browser/oidc/results/2026-10-20/keycloak-identity-jit.json)
records **19** actual Keycloak/browser/PostgreSQL cases. It matches all **560** code/
configuration hashes and its frozen producer binary. Source base is the separate
fixture extraction commit plus the reported working-tree files; final Git-blob hash
verification accompanies publication. Earlier eleven-case reports remain unchanged.

Callback/state capture was first extracted without behavior change into a private
transaction module and separately committed as `8974d0d`. All **11** original provider
cases passed with exact zero user/session/audit/pending state, 8 application posts,
7 successful provider token responses, one controlled signature mutation and one
captured-token replay. All 554 source hashes and the fixed binary matched at extraction.
Strict all-feature lint passed before that structural commit.

The extension keeps those eleven cases intact, including their zero-state and proxy
assertions before identity setup. It adds eight named scenarios:

- An actual bound mailbox-repository proof as the existing-owner control; no seeded
  user/session or SMTP/device-delivery claim.
- A genuinely verified provider proof rejected by persisted JIT deny, without local
  authority changes. It has a usable selected display claim, so missing profile cannot
  masquerade as policy denial.
- Explicit persisted allow with a provider-signed verified email matching the mailbox;
  the local provider user is different, provider_required and has no local contact.
- Actual optional-profile scope omission at Keycloak, yielding a signed missing-name
  token that still resolves the bound subject and preserves local presentation.
- An opaque proof held after code/signature verification, rejected after real policy
  reconfiguration while its original cap is still live; earlier provider sessions
  become unusable under the new revision.
- Bound-subject login under deny despite missing optional profile.
- A different enabled provider user with valid signature/nonce/audience and usable
  selected display, rejected by JIT deny without provisioning.
- A held verified proof rejected after local disable, plus rejection of the latest
  provider session while the independent mailbox session remains usable.

Email/profile scopes and the disposable provider users use actual owned administration
APIs. The new claim cases do not rewrite token payloads at the proxy. Original controlled
signature/token faults remain separately labeled. The native fixture explicitly applies
and re-enables its latest configuration after the earlier deliberate disable; this is
not an application fallback or automatic ordinary activation. Finite private outcome flags
prove signature verification precedes final policy denial, and an original-cap-live check
prevents timeout from counting as the intended revision/disable rejection. Infrastructure
errors cannot satisfy exact Unauthorized assertions.

Normal completion requires **2 users, 4 sessions, 4 audits, 0 pending transactions**; **1 external identity,
1 provider-required user, 3 OIDC sessions, 0 provider contacts, 0 weak provider sessions**. Proxy
counts are **15 posts / 14 successful provider token responses**, retaining exactly the original
one signature mutation and one token replay. All three positive local provider sessions
validate current source/ownership and preserve the returned optional authentication time.
Missing/old auth_time semantics additionally retain their distinct signed-software tests;
no inference is made that Keycloak necessarily omits it. Provider email never becomes local
contact. Original OAuth/HTTP/verification admission bounds/cache headers remain unchanged,
and the runner adds no admission delays.

The owned database, owner-labeled Keycloak container and private directory are normally
removed with native exit 0. Emergency cleanup and unexpected native diagnostics are false.
No account IDs, local sessions, codes, assertions, passwords or provider credentials are
report fields. The private fixture retains protected client credentials only for its
administrative revision/service reconstruction; no production constructor or transport
bypass is exposed. User devices, system security settings and credential managers are not
accessed. No production-provider, public callback, wider native/client, conformance,
independent security or ordinary activation claim follows.

CI now compiles the verification-only example, builds the identity-capable producer and
requires EASY_AUTH_OIDC_IDENTITIES=1. Capability, nineteen-case count, all original checks,
new exact aggregates and normal cleanup are mandatory. Explicit legacy compatibility mode
still requires eleven cases and zero local authority; it cannot satisfy identity-mode CI.

Final local checks pass with CARGO_INCREMENTAL=0 and sequential real-PostgreSQL suites:
formatting; strict default/all-feature workspace/all-target Clippy; strict verification-only
example Clippy; **93 default** and **411 distinct all-feature** tests (278 PostgreSQL, 55 HTTP/PostgreSQL, 66 core,
10 server, 2 Axum; logging child repeats an included core case), zero failures/ignored; compiled
advisory/license/source/bans and npm audits; JavaScript syntax and documentation/diff checks.
The inactive optional SQLx/MySQL RSA advisory remains visible. No package version, lockfile,
production application behavior or migration changes in this fixture extension. Staged
redacted secret scanning precedes publication.

An initial new fixture compile used a sibling module path after moving private command
adaptation; it was corrected before the native run. This is not counted as successful
acceptance or an application authorization failure. The first complete nineteen-case run
passed; no security assertion was removed to obtain it.

Source review keeps private protocol construction, callback transactions, identity command
adaptation, state/evidence and Node cases in separate named modules below 300 lines. Longer
ordered setup/command/case bodies retain resource ownership, actual provider operation,
finite outcomes and cleanup as documented size exceptions; no unrelated cleanup is deferred.
The server feature forwards existing optional core/PostgreSQL capabilities and activates no
ordinary route. Core/PG resolver evidence remains in the preceding checkpoint.

CI run 39350358984 for `38fda0b` completed SUCCESS, verified from GitHub. The newly extended fixture
requires its own hosted run before AUTH-30 completion. AUTH-25 linking, provider-only public
lifecycle, AUTH-20's unresolved Safari/recovery evidence and the other first-release gates
remain open independently.

## AUTH-30 hosted acceptance and remaining delivery gates (2026-10-20)

[CI run 39353249042](https://github.com/Deuspheara/easy-auth/actions/runs/39353249042)
completed SUCCESS for `1ffc809387620da2b34a6de6385d90c646e196ad`, including both
Rust and secret-scanning jobs. All required steps passed: formatting, strict
all-feature/all-target lint, default and all-feature real-PostgreSQL workspace
tests, verification-only core tests and example compilation, the nineteen-case
owned Keycloak suite, existing passkey/SMTP/recovery browser suites, recovery-notice
delivery, compiled advisory checking and all-feature cargo-deny. No failed step
was skipped or retried to obtain acceptance.

The local report still matches all 560 source/configuration hashes and its frozen
producer binary. The subsequent documentation-only checkpoint records this hosted
result and explicit ownership of remaining gates; it changes no tested code,
configuration, dependencies, migrations or immutable evidence report.

AUTH-55 owns provider-required account deletion without weaker fallback. AUTH-56
owns supported embedded/standalone OIDC web composition and depends on that lifecycle
boundary. These are first-release blockers, not implemented capabilities. AUTH-25
linking, AUTH-20's unresolved Safari/Dashlane recovery evidence, broader provider
acceptance, SAML, outbound issuer and independent review remain open. Acceptance
of AUTH-30's scoped backend boundary does not complete M05 or the full release.

## AUTH-55 deletion-purpose preparation checkpoint (2026-10-20)

This checkpoint implements preparation, not provider account deletion. The explicit
OAuth purpose binds the active initiating provider-required owner/session to the
exact current connection/client/issuer/revision and policy row. Source/policy locks
precede optional email, owner, session and identity locks. Wrong configuration
rejects without acquiring an unrelated source-configuration lock. The original
idle/absolute cap bounds start, consumption and later exchange context checks;
no preparation operation changes authentication time or grants deletion/sign-in.
Without `oidc-identities`, PostgreSQL rejects the purpose. Migration 0019 extends
closed purpose/owner/session constraints and preserves original pending rows.

The typed reauthentication URL adds only fixed maximum-age/login parameters to
the existing state/nonce/S256 request. Provider metadata cannot supply competing
parameters, including decoded/case variants. Neither URL parameters, a new token
nor an old/unknown initiating authentication time is evidence of fresh private
provider proof. Final deletion must still implement signed `auth_time`, exact
subject, explicit destructive confirmation and original-cap authorization.

Ten new real-PostgreSQL tests cover actual signed-provider/session setup, old/unknown
time preservation, wrong purpose/browser/owner/source/realm/method, one-use state,
direct sign-in use-case/repository denial, revoked/idle/absolute/policy invalidation,
source disable and owner-policy lock ordering, migration compatibility and observed
owner/pending/final-INSERT waits across the original session deadline. A separate
verification-only database case proves feature-disabled denial; two new core tests
check fixed URL policy, original proof binding and metadata conflicts. Expected
authorization failures are exact Unauthorized; setup, observer, SQL or socket
failures never count as rejection evidence. Session snapshots assert no touch,
revocation or other mutation during rejected preparation.

Before migration, the valid raw purpose/binding case failed with actual check
constraint SQLSTATE 23514. This demonstrates missing schema support, not an account
takeover. The first wait fixture's table lock stopped earlier expired-state cleanup,
so its INSERT observer timed out; a trigger now gates the actual INSERT and checks
that the observed wait precedes expiry. A subsequent aggregate assertion incorrectly
assumed one session per user despite earlier successful control logins. Exact
pre-action counts and unchanged session-row snapshots replace that invalid fixture
assumption. Neither failure is recorded as an application defect or a passing
regression; final rejection and rollback assertions remain mandatory.

Final local gates pass with `CARGO_INCREMENTAL=0`: formatting, strict locked
default/all-feature workspace/all-target Clippy, **93 default** and **423 distinct
all-feature** workspace tests (288 PostgreSQL, 55 HTTP/PostgreSQL, 68 core, 10 server,
2 Axum; the logging child repeats an included core case), **57 verification-only
core tests**, and the separate feature-disabled PostgreSQL test. No failed or ignored
cases in these final runs. Compiled advisory, all-feature license/source/bans and npm
audits pass; the inactive optional SQLx/MySQL RSA advisory remains visible. No
dependency/version change, advisory exception or published migration edit is added.

All nineteen existing owned Keycloak cases pass after the extension. The immutable
[baseline report](../../tests/browser/oidc/results/2026-10-20/keycloak-purpose-preparation-baseline.json)
matches **572 source/configuration hashes** and its frozen producer binary. Final
counts remain 2 users/4 sessions/4 audits/0 pending, 1 identity/1 provider user/0
provider contacts/3 OIDC sessions/0 weak provider sessions; the native process exits
zero and removes its database, provider container and private files with no emergency
cleanup or unexpected diagnostics. This is unchanged-flow regression evidence,
not native reauthentication or deletion acceptance. Earlier reports are immutable.

New implementation/test modules stay below 300 lines. The longer ordered source
authorization and security scenarios retain visible locks, original caps, error
classification and valid controls as reviewed exceptions. No unrelated cleanup,
production HTTP route or ordinary activation is introduced. ADR 0017 remains
proposed for the final deletion/HTTP boundary. AUTH-55 stays In Progress pending
those operations, their actual rollback/race/negative and native acceptance tests,
full gates and hosted evidence. AUTH-56 remains a separate composition gate.

## AUTH-55 final provider deletion backend (2026-10-20)

The optional `OidcAccountDeletion` use case/port now consumes a mapped deletion-purpose
proof. Both core and PostgreSQL reject sign-in/linking or missing-time proof. The
owning transaction reuses the full current-policy/configuration guard and active
provider authorization locks, matches the initiating session's exact existing subject,
and requires genuine signed authentication within the public 300-second policy.
Future time is rejected upstream and checked against database time again. No profile
display, provider email, token issuance or local session creation becomes authority.

Before erasure, retain the earliest original OAuth/token, active-session and signed
freshness deadline. Shared account erasure now supports absent verified contact:
email-free deletion fabricates no recipient; stored verified contact queues only the
existing subject-free notice, never a provider-supplied attribute. Original mailbox
authorization and its Some-contact path remain intact. Final table-free database time
after every destructive/audit/notice write rolls expiry back atomically, including
already-deleted rows, erased audit attribution and inserted subject cooldown. Consumed
OAuth state is not resurrected. No lock spans provider I/O/signature verification.

The focused real-PostgreSQL group now has **28 tests**, including eighteen new final
deletion scenarios alongside the ten preparation cases. They cover successful email-free
erasure, stored-contact notice and mailbox fallback denial, unrelated mailbox/realm
preservation, profile-free deletion under JIT-Deny, exact signed subject/case and
purpose denial in both layers, missing/old/future time, revocation/policy/disable/revision,
audit/notice storage faults, unavailable policy storage, concurrent one-winner and both
sign-in/disable orderings. A future-time test identifies token verification as the
rejecting layer, rather than claiming an invalid proof reached deletion.

Two ordered matrices cross all three proof/session/signed-freshness caps during
unchanged configuration/owner waits and exact final audit/notice INSERT triggers.
Each observes the actual wait before expiry, retains exact private account/session/
audit/notice/pending/cooldown snapshots, requires Unauthorized rather than infrastructure
failure and completes a new genuine login/flow as valid control. Storage faults require
Unavailable and exact rollback; duplicate valid deletions produce one deletion fact.
A callback admitted before deletion can commit, after which its new session is erased;
deletion winning first rejects the waiting callback without JIT resurrection.

Final local gates pass with `CARGO_INCREMENTAL=0` and sequential database suites:
formatting; strict locked default/all-feature workspace/all-target Clippy; verification-only
example compilation; **93 default** and **441 distinct all-feature** workspace tests
(306 PostgreSQL, 55 HTTP/PostgreSQL, 68 core, 10 server, 2 Axum; the logging subprocess
repeats an included core case); **57 verification-only core tests**; and the separate
feature-disabled PostgreSQL case. No failed/ignored cases in these final suites. Compiled
advisory, all-feature license/source/bans and npm audits pass, retaining the visible
inactive SQLx/MySQL RSA advisory and no exception/dependency/version changes. Published
migrations, including the preceding purpose migration 0019, remain immutable.

All **23 owned Keycloak cases pass**, preserving the original nineteen assertions and
their exact pre-deletion counts. The immutable
[report](../../tests/browser/oidc/results/2026-10-20/keycloak-provider-deletion.json)
matches **585 selected source/configuration hashes** and its frozen producer binary.
Four new cases establish a genuinely current source without reviving old sessions,
actual fixed-parameter reauthentication and signed wrong-subject rejection, exact-owner
deletion without optional profile, and a fresh usable-profile JIT request rejected under
live cooldown/current enabled JIT-Allow. The native fixture retains the original typed
purpose in private pending/replay state; callers supply no owner/session selector.

Final native counts are one surviving mailbox user/session, six audits, zero pending/
identity/provider/oidc/weak-provider rows, one deletion, four erased provider audits,
one intact mailbox audit and one live cooldown. Proxy totals are 19 posts/18 successful
responses with the unchanged one signature mutation/replay. Native exit is zero; owned
database/container/private files are removed, without emergency cleanup or unexpected
diagnostics. No raw credential, callback, token, account ID or signed authentication-time
value is report data.

The initial extension hit fixture provisioning failures: a reused additional-user name,
then an overlong generated mailbox local part. Per-run bounded sequence names correct
both without changing application assertions. A later wrong-subject case could not
count as acceptance because required signed authentication time was absent. A fixed
diagnostic confirmed that exact missing field; the minimal client had omitted
Keycloak's documented built-in `basic` scope. Assigning that authentic server-session
mapper only for the new phase makes the signed claim available; no timestamp is seeded
or inferred, and missing-time rejection remains mandatory. All failed native attempts
exited/cleaned normally; none is a passing case or a claimed application defect.

The existing documented `scripts/smoke.py --lifecycle` also passes against actual
PostgreSQL/Mailpit in **standalone and embedded modes**, including real password
enrollment, two-address email change, stable identity, old-session rejection, mailbox
deletion and safe notices. An owned supervisor uses the existing development environment
and transport setup with separate random databases/ports/realms. It stops both owned
servers, removes both databases and deletes exactly six matching test-recipient messages
per mode (twelve total), never an empty Mailpit deletion list or unrelated mail. This is
mailbox lifecycle/SMTP regression evidence for shared erasure, not provider-contact SMTP
or user-device evidence.

Responsibility review keeps core use case/port, PostgreSQL authorization/completion,
shared erasure and fixture deletion evidence in focused named modules. Only crate-private
policy-guard visibility widens for concrete reuse. Longer ordered transactions/test
matrices keep original caps, lock order and cleanup visible; all new modules are below
300 lines, with no generic deletion engine or unrelated cleanup. HTTP/browser proof
transport and explicit destructive confirmation remain unimplemented; AUTH-55 stays
In Progress until that boundary and final hosted acceptance are complete. AUTH-56,
AUTH-25, AUTH-20's Safari/recovery failure and the broader first-release gates remain open.

The preceding purpose checkpoint's exact-head CI39357516806 at `c887386` completed
SUCCESS. This extended backend/23-case checkpoint requires its own hosted run;
the earlier result is not substituted for its acceptance.

## AUTH-55 opt-in HTTP checkpoint — 2026-10-20

The optional `easy-auth-axum/oidc-account-deletion` composition now provides exact
trusted service/realm/HTTPS-callback alignment, session-derived owner, independent
host-only Secure/HttpOnly proof cookies, closed bounded exact-Origin POSTs and
explicit start/finish destructive confirmation. The callback GET serves fixed
bytes and never consumes proof or deletes. Reference JavaScript immediately scrubs
callback parameters, rejects malformed/duplicate/unknown fields, never automatically
submits deletion, and discards transient proof on navigation. The ordinary router,
server activation and existing authentication policy remain unchanged. The combined
[OpenAPI snapshot](../architecture/openapi-oidc-account-deletion.json) is exported
from the same contract. No migration or dependency version changes are introduced;
the already-pinned workspace JOSE library is reused for signed HTTP test fixtures.

All **18** new real PostgreSQL HTTP regressions pass. They verify actual ES256
proofs through production core/PG services, exact binding/purpose/session checks,
confirmation before consumption, wrong subject/time/issuer/state, cookie tampering/
duplicates, no callback GET mutation, cancellation/logout and failure handling.
An independently observed final-audit lock wait proves no response/clear-cookie
headers are returned before deletion commits. A storage exception returns 503,
restores account authority and leaves consumed OAuth state consumed; removing that
fault permits the positive control. Token transport unavailability also returns
503 rather than counting as expected Unauthorized. Initial fixture failures were
an incomplete provider success envelope and a wrong expected logout cookie count;
production token validation and meaningful assertions remain intact.

Frozen source passes `cargo fmt --all -- --check`, strict workspace/all-targets
Clippy both default and all-features, and sequential `cargo test --locked
--workspace` (**93**) and `cargo test --locked --workspace --all-features`
(**459** distinct tests: 306 PostgreSQL, 73 HTTP, 68 core, 10 server and 2 Axum
unit tests). The logging child repeats one core case and is not counted twice.
Verification-only core tests pass **57** cases, and the verification-only native
example still compiles. Runs use documented PostgreSQL and `CARGO_INCREMENTAL=0`.
Compiled advisory, cargo-deny, npm audit and the complete staged diff secret scan
pass; npm reports zero vulnerabilities. The inactive SQLx/MySQL RSA advisory stays
visible without an ignore. All new source/test modules remain below 300 lines;
fixture and ordered transaction-wait scenarios retain visible setup and invariants.

The separate `node tests/browser/oidc/deletion-client.cjs` Chromium check passes
seven malformed-callback cases plus explicit final confirmation, URL scrub,
reload denial, cancellation, 503 feedback and no browser storage. It uses actual
reference-page bytes with controlled intercepted responses. This is **not** actual
provider-to-HTTP interoperability evidence. The existing immutable 23-case Keycloak
report proves the backend at its earlier source checkpoint. Backend commit
`121d68eafdc343cf16e3e127bfae1d62ced9a4e3` has successful hosted CI run
[39361408467](https://github.com/Deuspheara/easy-auth/actions/runs/39361408467).
The new HTTP source still needs its own exact-commit CI and owned
Keycloak-to-HTTP acceptance. AUTH-55 remains In Progress, ordinary activation stays
gated, and no independent audit or production-readiness claim follows.

## AUTH-55 actual provider-to-HTTP acceptance — 2026-10-20

A separate owned server-package example now composes the real opt-in Axum deletion
router, core verifier and PostgreSQL port. It reuses the existing production TLS
builder/GET/POST/readers with private owned certificate/address mapping, plus the
existing exact-owned-database cleanup. Bounded private IPC was first extracted in
`52b7d8f` and verified separately with all 23 native cases, strict lint and
verification-only compilation. Initial session establishment uses genuine signed
Keycloak/core sign-in and a one-use exact-Origin fixture-only cookie-delivery
capability; no session/identity is seeded or emitted as a bearer on IPC. Ordinary
provider login/server activation remains separate AUTH-56 work.

The [six-case HTTP record](../../tests/browser/oidc/results/2026-10-20/keycloak-provider-deletion-http.json)
passes real provider reauthentication through actual reference pages/callback GET,
protected session/proof cookies, explicit start/final confirmation and HTTP deletion.
Callback GET and cancellation preserve account/session authority; a wrong genuinely
recent signed subject reaches the verified deletion port and is rejected by real
PostgreSQL. Finite observations forward the original opaque proof unchanged and
preserve the actual repository result. Injected token-service unavailability at the
owned proxy returns **503**, does not reach deletion and never counts as expected
Unauthorized. Successful deletion clears cookies and rejects captured original
cookies/callback replay. A fresh signed same-subject login reaches account resolution
and rejects with its original proof live and the cooldown independently observed live.

Exact HTTP final counts: zero users, sessions, identities, pending transactions,
contacts and notices; two deidentified audit facts, no retained subject references,
and one live cooldown. Mail calls remain zero through a rejecting email-free fixture
tripwire; this is not provider-contact SMTP evidence. Both normal and failure runs
remove the owned DB/container/private files without emergency cleanup or unexpected
diagnostics. The first run's replay observation failed in Playwright's separate Node
request DNS resolver after successful deletion. Restoring only the actually issued
old cookies inside the owned Chromium context fixes that infrastructure issue and
retains the precise 401/no-provider-POST assertion. No application check was weakened.

The [same-source backend regression record](../../tests/browser/oidc/results/2026-10-20/keycloak-provider-deletion-http-backend-regression.json)
retains all **23** prior cases and exact aggregates (19 token POST attempts, 18
successful token responses, one controlled signature mutation/replay, final mailbox
control user/session and deidentified provider facts). The new suite independently
requires **6** cases, 5 POST attempts, 4 token responses and one controlled 503.
Both reports preserve source/binary hashes, versions, named outcomes and normal
cleanup. The controlled reference-client suite also passes seven malformed callback
forms, explicit confirmation, URL scrubbing, reload denial, cancellation and 503
feedback without browser storage. CI runs all three suites; no earlier report is
replaced and ordinary sign-in acceptance is not inferred from fixture bootstrap.

Frozen source passes formatting, strict default/all-feature workspace/all-target
Clippy, sequential default workspace tests (**93**) and all-feature tests (**459**
distinct: 306 PostgreSQL, 73 HTTP, 68 core, 10 server and 2 Axum unit). The logging
child repeats one core test and is not double-counted. Verification-only core tests
pass **57** and the verification-only native example compiles. Compiled advisory,
cargo-deny, npm audit and complete staged-diff secret checks pass; inactive
SQLx/MySQL RSA remains reported without an ignore. The only added manifest wiring
is an explicit experimental feature/example and the already-pinned workspace serde
dev dependency. No migration, protocol version, production root override or policy
change is introduced. All new modules are below 300 lines; composition and ordered
acceptance scenarios retain visible prerequisites, precise outcomes and cleanup.

Hosted CI on the final pushed commit is still required before ticket completion.
Local or fixture acceptance is not an independent security review, production-provider
interoperability claim, provider-contact SMTP acceptance or ordinary activation.

### AUTH-55 hosted completion

Final commit `e55dded204aaa0011d7e6e6c3802aaaaabfad26c` passed hosted run
[39365720693](https://github.com/Deuspheara/easy-auth/actions/runs/39365720693),
including both rust and secrets jobs. The run verified formatting, strict
all-target/all-feature lint, default/all-feature workspace tests, verification-only
core behavior, all 23 backend and 6 HTTP Keycloak cases, controlled reference-client
checks, retained native passkey/SMTP/recovery suites, real notice smoke, compiled
advisories and cargo-deny dependency/license policy. The exact head and final
completed/success conclusion were checked before AUTH-55 completion. Ordinary OIDC
web sign-in remains AUTH-56 work; wider release gates remain unchanged.

## AUTH-56 stable startup identity policy checkpoint — 2026-10-20

The trusted PostgreSQL `load_or_initialize_oidc_identity_policy` operation now
loads an unchanged enabled full definition without DML, revision rotation,
pending cancellation, session touch or audit rewrite. Only an absent registry key
can initialize policy, always with a fresh revision rather than a historical caller
snapshot. A competing initializer's committed revision is read and fully checked;
mismatched, generic, stale or disabled records are never adopted/repaired/re-enabled.
The private policy write was first extracted in separate commit `89d9767`, with all
**57** existing PostgreSQL identity cases and strict lint passing before behavior
was added. Administrative configure retains its original rotation/cancellation.
No schema or dependency changes were introduced.

All **15** new real PostgreSQL cases pass. DML-rejecting triggers prove unchanged
loads perform no connection/policy insert/update/delete. Genuine signed sign-in
and pending-context controls prove reload preserves existing authority. Removing/
recreating configuration rejects a previously verified old context, and stale
startup input reads the latest valid revision without reviving old sessions.
Full-definition variants, cross-realm/local-client keys, global callback collision,
existing generic OAuth, stale policy revision and operator disable fail precisely
without overwriting state. Initial policy-write failure rolls back configuration;
missing schema and corrupt stored revision return Unavailable, not expected
Unauthorized. Positive controls establish usable storage/authority around faults.

Concurrency cases observe **both** initial inserts blocked after absent reads before
releasing the owned advisory gate. Equal definitions converge on one fresh revision;
competing definitions have one winner and one exact non-mutating mismatch. Separate
observed configuration/policy lock waits cover both startup/disable orders, and a
snapshot returned before disable cannot become current afterward. Observers use
independent one-connection pools to avoid the shared SQLx harness limit.

A new signed core case verifies nil metadata revisions are rejected and restoring
policy metadata cannot rewrite a verified identity's original configuration. The
public restoration method creates only validated definition metadata; the OAuth
mutator remains crate-private and no proof constructor is exposed. All new/affected
modules remain below 300 lines, with configuration-before-policy checks/commit
visible in the startup transaction and ordered test scenarios kept together.

Final source passes `cargo fmt --all -- --check`, strict default/all-feature
workspace/all-target Clippy, default workspace tests (**93**), final all-feature
workspace tests (**475** distinct: 321 PostgreSQL, 73 HTTP, 69 core, 10 server,
2 Axum unit), verification-only core tests (**57**), advisory/deny/npm checks and
the complete staged secret scan. The logging child repeats one core case and is
not counted twice. An earlier complete all-feature run passed 474 before the last
stale-policy regression had been compiled; the recorded final run includes that
case and all 475 tests. No failing/ignored assertion or infrastructure error was
reclassified to make acceptance pass. Inactive SQLx/MySQL RSA remains reported
without an ignore.

This checkpoint implements only the Rust metadata/startup boundary. Ordinary OIDC
server settings, combined browser callback/login routes and actual supported
embedded/standalone login acceptance remain AUTH-56 work. No new native provider
acceptance, activation, production-readiness or independent-review claim follows
from these component tests. Hosted CI for the pushed checkpoint must be inspected
separately before being claimed as successful.

## AUTH-56 opt-in shared OIDC HTTP checkpoint — 2026-10-20

AUTH-56 remains **In Progress**. The Axum `oidc-web` feature now supplies trusted
services, one exact HTTPS common callback, public start/finish/cancel routes and
fixed reference sign-in/error pages alongside the existing deletion use case.
Callback GET uses canonical unique state-cookie matching only as a fixed UI hint;
it performs no database/provider call, consumption, cookie grant or deletion.
Deliberate Origin-protected POST retains the existing opaque core/PG proof chain.
Presented current-session cookies reject sign-in at both stages; cancellation
retains an ambient session. Request-snapshot checks are explicitly not a global
browser/session epoch. The [guide](../guides/oidc-web.md),
[ADR 0018](../architecture/adr/0018-oidc-web-composition.md) and concrete OpenAPI
record the contract and remaining delivery gates.

**25 new real-PostgreSQL HTTP scenarios** exercise actual ES256 signatures through
a controlled provider port, without seeded users/sessions or proof constructors:
public sign-in/session/logout and common-callback deletion; unique/nonmutating/
malformed callback selection; Origin/closed query/JSON/body limits; all four cookie
components, issuer/audience/nonce, expiry and replay; current-session arrival and
cancellation; overlapping starts/one-use concurrent completion; default-deny JIT,
trusted profile scope/display mapping; provider/discovery infrastructure failures,
admin disable/revision and atomic audit failure. An independent one-connection
observer verifies the final audit lock wait and absence of any successful response
or externally visible owner/session before commit. The shared actual-signature
provider fixture has one definition and an independently supplied expected redirect.

Two new-test failures were investigated explicitly rather than accepted as protocol
rejections. Peer IP was incorrectly assumed to be an identity binding; ADR0013 and
storage show it is committed abuse admission. Its replacement test exhausts the
actual peer quota, requires 429 despite a forged forwarding header, retains proof,
and completes with the same peer after releasing only that owned quota. No security
binding or application check was removed. The expiry arrangement initially used two
volatile clock observations, occasionally exceeding the unchanged five-minute schema
cap by one microsecond (23514). One statement timestamp now arranges exact expiry;
a separate assertion verifies both expiry and the original cap before testing 401.

Final local checks pass: formatting; strict locked default/all-feature workspace/
all-target Clippy; **93 default** and **500 all-feature workspace tests** (2 Axum,
98 HTTP/database, 69 core, 321 PostgreSQL, 10 server; the logging subprocess repeats
one included core case); and **57 verification-only** core cases. No failures or
ignored cases in the final runs. Compiled-dependency advisory, all-feature cargo-deny,
npm audit and complete staged redacted secret scanning pass. The inactive SQLx/MySQL
RSA advisory remains visible; no dependency version, exception or migration changed.

Both controlled Chromium reference clients pass seven malformed callbacks each,
explicit finish/confirmation, URL scrubbing, no automatic proof import or reload
replay, fixed failure text and no browser storage; the sign-in client also checks
restored-page proof loss. These are controlled-response tests, not provider acceptance.
All **6 existing rebuilt Keycloak HTTP deletion cases** and **23 backend cases** pass
with original assertions and owned database/container/file cleanup. The backend
report matches every current source hash and its fixed producer binary. The six-case
HTTP report predates only subsequent Rust test-fixture corrections; its production
source is unchanged. These native cases retain their documented fixture-only initial
session bootstrap and do not prove the new public sign-in against Keycloak.

The structural feature-tree refactor was separately committed as `340f04a` after
18 HTTP cases, unchanged generated deletion OpenAPI, six native cases and the client
checks passed. Startup commit `aa22baa9e3278721fe42d142e00830c4e75173b7` has exact-head
hosted CI success in run **39371009045**. The new HTTP checkpoint still requires its
own exact-head CI. Supported standalone/embedded configuration/factory and native
public sign-in through both modes remain unfinished; AUTH-56 is not complete.
Independent review, AUTH-20's unresolved Safari recovery and the broader release
gates remain open. No further manual device prompts or settings changes were made.

Maintainability review keeps production modules below 300 lines and separates
composition, handlers, callback selection, DTOs, contract and fixed clients. Longer
ordered fixture/scenario functions retain prerequisites, observed waits and positive
controls together as documented size exceptions. No unrelated cleanup is deferred.
