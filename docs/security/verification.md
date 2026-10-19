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
