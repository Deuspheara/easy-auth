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

## AUTH-56 shared server configuration checkpoint — 2026-10-20

AUTH-56 remains **In Progress**. Separately verified structural commit `a7ec437`
adds `ConfiguredApplication`/`configured_application`, used by standalone and embedded
entrypoints while preserving the auth-only `configured_auth` signature. Existing
93 default workspace tests, strict all-feature/all-target lint and real SMTP lifecycle
in both modes passed before adding settings behavior; twelve exact owned messages
and both disposable databases were removed.

The explicit server `oidc-web` feature now validates a closed typed environment
contract before database loading/listening, prepares exact HTTPS callback/issuer/
stable IDs, explicit egress/algorithm/client-auth choices and default-deny JIT, then
uses the stable policy loader and existing production transport/core/PG/Axum services.
Confidential credentials require a bounded protected regular UTF-8 file; there is no
missing-secret/public fallback. Unknown/partial/invalid Unicode/oversized settings
and root/address/raw-secret/redirect overrides fail closed. `configured_auth` refuses
enabled browser settings instead of silently dropping requested routes. Core's new
metadata-only document validation API reuses its existing egress policy before
provisioning; it creates no proof, I/O or current authority. No migration, dependency
version, insecure transport setting or alternate authentication policy was added.

**13 new pure settings/file cases pass** with OIDC enabled; **4 cases pass** without
it, including explicit unsupported-build refusal. They exercise required/malformed/
duplicate settings, exact policy choices, bounded/invalid/control-containing files,
client-method consistency, redaction, Unix permissions, HTTP/nonpublic literal
rejection and unavailable files. The feature-specific build exposed an old test
fixture's accidental dependency on unrelated `Url` serde feature unification. Its
JSON now uses explicit URL strings with unchanged content/assertions; no production
serialization dependency was added. All **23 feature-specific server cases** pass.

A new normal-binary supervisor passes **13 real-PostgreSQL startup cases**: standalone
and embedded shared routes, unchanged cross-mode revision, zero fabricated user/
session/pending/audit authority, unsupported build, partial settings, forbidden root/
address/raw-secret fields, development HTTP refusal, missing/publicly readable secret,
valid explicit confidential file without revision rotation, policy mismatch and
operator disable preservation. Expected refusals require exact finite stderr reasons;
a database/bind/build failure cannot stand in for them. The supervisor removes its
owned random database/private file and sends no provider request or mail. It uses
child-process environments without mutating the test runner's global environment.
CI builds both feature states and runs this supervisor with its owned PostgreSQL service.

A final feature-specific TLS run initially lacked sandbox loopback-listener access:
eight cases stopped at `PermissionDenied`/`Operation not permitted` before protocol
assertions. The same 23-case suite then passed with the authorized local-network
permissions used by the full workspace run. No assertion or security check changed.

Final local gates pass: formatting; strict locked default/all-feature workspace/
all-target lint; **97 default** and **513 all-feature workspace tests** (2 Axum,
98 HTTP/database, 69 core, 321 PostgreSQL, 23 server; subprocess repeat excluded);
**57 verification-only** core cases; advisory/license/source/npm checks; finalized
normal-binary startup cases; and actual SMTP lifecycle in both modes with exact owned
message/database cleanup. No failures or ignored cases in the final runs. The inactive
SQLx/MySQL RSA advisory remains visible, with no exception. Python's optional cache
write outside the workspace was denied; in-memory syntax validation and actual script
execution passed instead. The complete staged diff receives redacted secret scanning.

The previous HTTP head `15f89fd` has live exact-head CI run **39373559701**, last
observed installing cargo-audit after all earlier steps with no failures and a green
secrets job. Do not substitute observation timeout for terminal status or restart it.
This server checkpoint still needs its own final-source hosted CI. These startup
cases establish supported composition/configuration behavior, not real public
provider sign-in. Native Keycloak public-login/session/logout/deletion acceptance
through both modes remains required before completing AUTH-56. Broader release,
independent-review and unresolved Safari recovery gates remain open.

Maintainability review keeps the shared factory/entrypoints thin, typed settings,
credential-file I/O and OIDC service construction in named owning modules, and the
existing protocol/transaction boundaries visible. New modules stay below300lines;
ordered startup supervision and test matrices retain prerequisites, exact reasons
and cleanup as reviewed function-size exceptions. No unrelated cleanup is deferred.

## AUTH-56 configured public-provider acceptance — 2026-10-20

AUTH-56 remains **In Progress pending final exact-head hosted CI**. Its local delivery
work now includes shared configured startup, actual public sign-in/callback/finish,
committed session/protected application use, logout/relogin and fresh provider
deletion in both standalone and embedded compositions. Prerequisites AUTH-30 and
AUTH-55 were re-read in Huly as Done; native blocker relations remain intact.

The owned example compiles unchanged configured-application/settings sources and
the actual embedded application-route module. Only the concrete transport name in
this private crate is substituted with the existing owned certificate/address port,
which shares production TLS/GET/POST/response code. Production has no injection,
private trust or insecure/address setting. This is explicitly **not a normal-binary
public-root positive TLS test**, production-provider interoperability, independent
review, conformance certification or production readiness. Normal-binary startup/
refusal and SMTP checks remain separate. No user browser/device/security settings
were changed and no further Safari/passkey prompts were requested.

The [current immutable report](../../tests/browser/oidc/results/2026-10-20/keycloak-configured-public-web-restarts.json)
passes **18 real Keycloak/browser cases, nine per mode**, with all **679 current
source hashes** and the fixed producer binary matched. The
[earlier baseline](../../tests/browser/oidc/results/2026-10-20/keycloak-configured-public-web.json)
is preserved unchanged and must not be counted as eighteen additional cases.
Actual public routes are the exclusive session source: initial SQL authority is
zero and `/fixture/session` is absent. Exact confidential `client_secret_basic`
comes from the real protected file/configuration boundary, with no seeded local
user/session, fabricated signed freshness, bearer delivery capability or proof
constructor. Twelve token requests use Basic; ten actual provider responses and
two deliberate proxy503s occur, with no signature or token substitution.

Cases cover fixed configured/anonymous routes; nonmutating callback GET and cancel;
503 infrastructure rejection with no grant; genuine signed public login held at the
actual final audit before success; ambient-session start/finish refusal, explicit
logout and old-bearer rejection; returning owner reuse; actual fresh signed wrong
subject denial; two-stage destructive confirmation, account erasure and old-cookie/
callback replay; and a fresh verified public login denied during deletion cooldown.
The cooldown case observes the actual core/PG scoped subject lock after signature/
claim mapping, with current JIT-Allow/source and a live original pending cap, so an
infrastructure, missing-profile or expiry failure cannot stand in for that denial.
All expected401/503 results are exact; observer/process/TLS/cleanup failures remain
failures rather than accepted authorization outcomes.

A separate max-one PostgreSQL observer verifies real waits. Final-audit checks
observe actual HTTP response and cookie delivery as well as page completion; no
session cookie may arrive before the held transaction commits. Both modes restart
the actual factory process while a callback is pending and after session commit.
Exact pending binding, current persisted revision and original local owner/session
survive, with no extra authentication audit. Protected file content is retained.
All **six application instances** and both database-owner processes exit normally;
no emergency cleanup is accepted. The fixture changes no callback state, identity,
session, clock or signed proof; its gates are private database observations/locks.

Final per-mode facts are zero users/sessions/identities/pending/contact/notices and
retained audit subjects, four deidentified audits, and one live cooldown. Both owned
databases, the pinned provider container and all private files are removed. Reports
contain finite facts/source hashes only: no tokens, credentials, assertion/registration
responses, callback URLs, raw headers, codes, storage state, traces or video.

Structural preparation was committed separately: `23f57dc` extracts the embedded
application-owned route (strict lint and both actual SMTP lifecycle modes pass);
`9d68867` shares bounded private JSON pipes/process-group lifetime and explicit
module paths (all existing six HTTP and23 backend provider cases pass). New scenario
work retains every previous assertion. The final rebuilt existing **23 backend +6
HTTP** Keycloak regressions pass again with the finite authentication observation
added separately from their unchanged original proxy fact shape. Both controlled
reference clients pass. No application behavior fix, schema, dependency version or
advisory exception was required for this acceptance work.

Final local gates pass: formatting; strict locked default/all-feature workspace/
all-target lint; **97 default** and **513 all-feature workspace tests** (2 Axum,
98 HTTP/database,69 core,321 PostgreSQL,23 server; logging subprocess repeat excluded);
**57 verification-only** core cases; compiled advisories, cargo-deny and npm audit.
No failures or ignored cases. The inactive SQLx/MySQL RSA advisory remains visible.
CI now runs the public suite and uses the documented nonincremental Cargo setting.
The full staged diff receives redacted secret scanning before publication.

Configuration head `ff2df6a3c91e9c40efa90011a9c730f8ac8eea71` has exact hosted CI
**39375349191 SUCCESS**; HTTP head `15f89fd` has **39373559701 SUCCESS**. The new
acceptance head still requires its own exact CI before AUTH-56 completion. Broader
release/manual-provider/native-app/SAML/outbound-issuer/independent-review gates and
AUTH-20's unresolved Safari recovery remain open. No production-readiness or general
provider interoperability claim follows from this owned-provider evidence.

Maintainability review keeps the producer's lifecycle, mode serving, transport,
SQL observation and audit/subject gates separate; Node owns resources/browser actions,
sign-in and lifecycle scenarios, orchestration and immutable reporting in named
modules. Production policy/SQL remain in their existing crates. Modules stay below
300lines; longer ordered test/supervision functions keep exact waits, positive
controls and cleanup visible as reviewed size exceptions. No unrelated cleanup is
deferred and no generic test engine or widened production proof API is added.

## AUTH-23 explicit desktop return metadata — 2026-10-20

AUTH-23 remains In Progress. This checkpoint implements only trusted exact desktop
return metadata, not a Google verifier/profile, system-browser transport, mobile
return mechanism or supported Google activation. The
[proposed ADR](../architecture/adr/0019-google-code-flow.md) retains those acceptance
requirements, including usable genuinely fresh provider deletion and the manual
provider matrix. No device/provider prompt or security-setting change was requested.

Structural commit `d433086` extracts the unchanged exact URL validator before
behavior changes. Its two existing core cases,25 real-PostgreSQL OAuth cases and
strict selected-feature lint pass. New feature-owned tests initially fail compilation
because the explicit redirect/reconfiguration API does not exist (E0425/E0599);
this is a missing-feature result, not evidence of an exploited application failure.
After implementation, three new core and three new PostgreSQL cases pass.

`OAuthRedirect::https` and `OAuthConnection::new` remain HTTPS-only. The explicit
desktop constructor accepts only literal `127.0.0.1`/`::1`, an exact nonzero port
other than80 and a canonical non-root path, with existing URL bounds and no query,
fragment, credentials, encoded alias or network-path spelling. It validates metadata,
not listener ownership or provider registration. Exact callback port/address/path
and issuer checks remain mandatory. Administrative persistence copies immutable
validated metadata at a fresh revision rather than rejecting it through the web-only
constructor. Existing transactions still retain disable, cancel old pending work
and enforce current source/realm/client policy. No migration, HTTP contract, server
setting, provider network exception, dependency or cryptographic change is added.

Core controls cover explicit IPv4/IPv6 selection, unchanged web rejection, wrong
port/path/issuer, malformed native addresses/paths, bounds, metadata validation and
fresh revision copying. Real PostgreSQL covers exact port/protocol/address mismatch
without consuming the valid pending operation, single-winner callbacks, cancellation,
disable retention and revision invalidation. Actual signed generic ES256 identity
controls prove startup preserves the original local session, reconfiguration rejects
old signed proof/session authority, current proof resolves the original owner, and
callback uniqueness still prevents another realm/client from claiming the same URI.
Infrastructure failures cannot substitute for the exact expected authorization
results. These are not Google RS256 or real native callback/provider tests.

Final local commands pass with `CARGO_INCREMENTAL=0` and the documented real
PostgreSQL setup; default/all-feature workspace runs execute sequentially:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --all-features
cargo test --locked -p easy-auth-core --features oidc-verification
cargo build --locked -p easy-auth-server --example oidc-web-native --features oidc-web
node tests/browser/oidc/web/run.cjs
python3 scripts/audit.py
cargo deny --all-features check
npm audit --audit-level=low --prefix tests/browser/passkeys
```

Results: **97 default**, **519 all-feature** workspace cases (2 Axum,98 HTTP,
72 core,324 PostgreSQL,23 server; the logging subprocess repeats an included case),
and **60 verification-only** cases. No failures or ignored cases. Compiled advisory,
license/source/bans and npm checks pass; the inactive SQLx/MySQL RSA advisory stays
visible without an exception. The complete staged diff receives redacted Gitleaks
scanning before publication.

The rebuilt [Keycloak regression report](../../tests/browser/oidc/results/2026-10-20/keycloak-native-metadata-regression.json)
passes all **18 existing public-flow cases**, with **683 source hashes** and its
fixed producer binary matched before publication. Both standalone and embedded
factory restarts, exact confidential authentication, actual final commit/subject
waits, session/logout/deletion/cooldown and normal owned cleanup remain intact.
All six application instances stop normally and both owned databases, provider
container and private files are removed. Original assertions and immutable reports
are unchanged. This is generic web regression evidence through the existing private
TLS/source-copy boundary, not a native loopback or Google interoperability result.
The original provider/passkey/SMTP suites remain required in hosted CI.

Prerequisite composition ticket AUTH-56 separately completed after exact final-head
hosted run [39379861505](https://github.com/Deuspheara/easy-auth/actions/runs/39379861505)
passed at `0e8dcb28a917f38247cb8992e39769d92994f8bf`; implementation run39378959095
also passed. Its branch is unchanged. AUTH-23's new checkpoint requires its own
hosted evidence and does not close Google/manual/native/lifecycle acceptance.
Broader release, independent review, SAML/outbound and AUTH-20 recovery gates remain.

Maintainability review keeps URL admission/typed redirects, immutable connection
metadata and original PostgreSQL transaction ownership separate. All affected
modules remain below300lines. Longer ordered race and signed-session cases retain
their valid controls, precise rejection and lifecycle assertions as reviewed
function-size exceptions; no unrelated cleanup or generic provider engine is added.

## AUTH-23 Google sign-in code component — 2026-10-20

AUTH-23 remains In Progress. The opt-in core `google` feature now composes the
existing opaque OAuth exchange, constrained document/token ports and reviewed
signature/claim verifier as `GoogleCodeExchange`. It fixes canonical Google issuer,
RequireIssuer, three exact endpoint origins, RS256 with no additional audience trust,
fixed openid/email/profile scopes and explicit registered Basic/Post authentication.
Public authentication and non-sign-in purposes are rejected without token POST.
The result is the existing verified identity proof, not local session authority.
No SQL/schema, HTTP route, browser/native transport, server setting, dependency
version or cryptographic implementation is added. The
[component guide](../guides/google.md) records exact limits and usage.

Structural commit `2ecb534` first extracts the unchanged actual-signature and
protected token-response fixtures into private named test support. A missing Value
import was caught by compilation and corrected before completing that extraction;
its final72 all-feature core cases,60 verification-only cases and strict core lint
pass. Existing assertions/defaults are retained. Google's test configuration then
uses an explicit fixture connection/metadata, retaining the legacy defaults.
The new tests initially fail compilation because GoogleCodeExchange is absent;
this is a missing API, not an exploited application failure.

All **10 new offline Google component scenarios pass** with genuine library-generated
RS256 signatures/JWKS and controlled Google-shaped metadata/code responses. They
exercise canonical issuer/response defense/authentication refusal without I/O;
fixed scopes and original state/nonce/S256; explicit cancellation/replay denial;
foreign/private endpoint, missing S256/authentication and response-issuer failures
before code disclosure; disabled-source Unauthorized versus storage Unavailable;
wrong issuer/audience/presenter/nonce/subject/time and invalid email flag types;
actual foreign signatures/another algorithm; original signed duplicate flag fields;
and valid matching presenter/email-attribute controls. An absent email value never
becomes verified from a standalone flag; false/absent flags do not erase a valid
signed subject or establish local contact.

Both HTTPS and explicit desktop-loopback metadata retain the exact original code,
PKCE verifier, redirect and selected Basic/Post wire method. A missing signed
authentication time is preserved as missing. Cross-source, linking and provider
deletion contexts fail before token POST. Invalid grant remains Unauthorized while
credential/provider infrastructure failures are Unavailable, with no foreign detail
in diagnostics. The component fixture's in-memory repository is not proof of
Google/PostgreSQL authority or real system-browser registration/return handling.
Those tests and the manual provider matrix remain required under AUTH-23.

Final local commands pass with `CARGO_INCREMENTAL=0` and the documented real DB
setup; workspace DB runs execute sequentially:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --all-features
cargo test --locked -p easy-auth-core --features google
cargo test --locked -p easy-auth-core --features oidc-verification
python3 scripts/audit.py
cargo deny --all-features check
```

Results are **97 default**, **529 all-feature** workspace cases (2 Axum,98 HTTP,
82 core,324 PostgreSQL,23 server; included logging-subprocess repeat excluded),
**70 Google-only** and **60 verification-only** cases. No failures or ignored cases
in final runs. Strict lint, compiled advisory and all-feature license/source/bans
checks pass. The inactive optional SQLx/MySQL RSA finding remains visible with no
exception. Dependency versions/browser assets/lockfiles are unchanged. The complete
staged diff receives redacted secret scanning before publication. CI additionally
runs Google without optional local identity mapping to catch feature unification.
Hosted/native/browser/SMTP checks remain required; no new local Google browser or
production-provider run is claimed.

The exact native-metadata checkpoint `d16674a` retains its separate hosted run;
the earlier ADR head `7be4cf6` has hosted39380816271 SUCCESS. New Google component
changes need their own final-head hosted evidence. Earlier public reports remain
immutable historical evidence, not a new Google/provider run or current-source
certificate for this checkpoint. Safe provider-required fresh deletion, native
transport/registration, Google callback handling and the manual matrix remain open.
No local iat/rotation/prompt substitutes for signed provider authentication time.
Broader release, independent review, SAML/outbound and AUTH-20 recovery gates remain.

Maintainability review keeps concrete Google composition in its named feature
module with a thin entry. Tests separate configuration, claims, exchange and shared
setup; established signing/token fixtures stay private and reusable without a
production bypass. All affected modules remain below300lines. Longer ordered wire,
claim and purpose matrices keep valid controls and exact errors together as
reviewed function-size exceptions. No duplicated verifier, SQL, generic provider
engine or unrelated cleanup is added.

## AUTH-23 Google/PostgreSQL and cold-discovery regression — 2026-10-20

AUTH-23 remains In Progress. The PostgreSQL `google` feature selects the existing
identity ports plus the core Google component; no production SQL, schema, verifier,
network policy, HTTP activation or native transport is added. Ten feature-owned
integration scenarios exercise actual PostgreSQL state consumption, Google profile
exchange, RS256 verification, mapping and existing local identity/session commit.
The external provider is a controlled offline fixture, not actual Google.

Its one-use code registry requires the exact original registered client, redirect,
PKCE and credential before emitting a signed response. Separate POST/signature
counters prevent a missing/invalid fixture response from satisfying an expected
authorization rejection. Real flows create provider-required owners without
fabricated contact or matching-email linking; returning signed subjects retain
ownership across email-attribute changes. JIT denial occurs after verified code,
with valid controls after policy changes. Shared provider issuer/client/key/subject
data remains isolated by realm/local-client/callback source. Concurrent callback
claims produce one code exchange and commit; distinct verified proofs serialize
one owner with separate sessions.

Wrong signed nonce is Unauthorized after an actual signed response, while a
controlled provider failure and a final audit write fault are Unavailable. Local
authority rolls back and consumed state does not revive; valid fresh flows recover.
Disable during an observed token POST and later revision changes reject old
authority. A real final audit table wait uses an independent one-connection observer,
confirms the original cap was live on entry, then observes its database expiry and
requires Unauthorized with zero committed user/identity/session/audit or pending
state. The arranged row preserves the exact original five-minute preparation window;
no production clock, proof constructor or final policy is bypassed.

Issuance never fabricates provider authentication time. Controlled offline signed
authentication-time claims can qualify a later session without rewriting an earlier
one; these are fixture-signature controls, not proof that an actual registered Google
client supplies the claim. Real provider freshness and usable provider-required
deletion remain activation gates alongside callback/native transport and the manual
matrix. No real Google or OS/browser return run is claimed.

### Hosted failure diagnosis and retained HTTP assertions

Component-head run [39383836570](https://github.com/Deuspheara/easy-auth/actions/runs/39383836570)
at `9dff398` failed the all-feature HTTP suite: the pre-existing
`overlapping_starts_remain_distinct_and_cancel_independently` expected200 but received
429, with97 other HTTP cases passing. Source review and deterministic reproduction
identify an invalid cold-cache setup assumption. Bounded discovery-slot contention
is intentionally RateLimited; overlapping cold starts are not guaranteed success.
The failed run was inspected, not restarted or relabeled successful.

Separate commit `3f3fe99` keeps every original two200/distinct-proof/pending-count/
independent-cancel/no-session/no-token assertion, first explicitly warming and
cancelling a valid attempt. A new held-discovery test requires prompt429 without
cookies/authority, cancellation of the denied pending attempt, continued blocking
of the admitted start until release, valid200 recovery and explicit cleanup. All
26 OIDC web cases pass with exact outcomes. No production cache, worker, admission,
timeout or queue policy changes. The gate is default-off private test support.
The earlier native-metadata head `d16674a` separately has complete hosted
[39382065934 SUCCESS](https://github.com/Deuspheara/easy-auth/actions/runs/39382065934).

The ten focused Google/PostgreSQL cases pass with the explicit feature combination,
and strict default/all-feature workspace/all-target lint passes. Full workspace
revalidation follows the hosted failure and additional deterministic regression;
final evidence is recorded below before publication. CI also runs the isolated
Google/PostgreSQL feature without passkeys to detect accidental feature unification.

All new modules remain below300lines. Provider signing/wire validation, configured
setup/caps, independent observer, lifecycle, binding and atomicity responsibilities
are separate. Longer ordered race/wait/fixture functions keep valid controls and
exact results together as reviewed function-size exceptions. Existing assertions
and published reports remain unchanged; no unrelated cleanup or production hook.

Final local revalidation passes after the cold-cache regression correction, using
`CARGO_INCREMENTAL=0` and the documented PostgreSQL setup, with DB variants
executed sequentially:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --all-features
cargo test --locked -p easy-auth-postgres --features google --test lifecycle oidc::google
cargo test --locked -p easy-auth-axum --all-features --test browser oidc_web::
python3 scripts/audit.py
cargo deny --all-features check
```

Results are **97 default** and **540 all-feature** workspace cases (2 Axum,99 HTTP,
82 core,334 PostgreSQL,23 server; logging subprocess repeat excluded). The focused
Google/PostgreSQL10 and OIDC-web26 cases also pass. No failures/ignored cases in
final local runs. Compiled advisory and all-feature license/source/bans checks pass;
inactive optional SQLx/MySQL RSA finding remains visible without an exception.
The full staged diff receives redacted secret scanning before publication. Changed
documentation links and module boundaries are reviewed. Lockfiles, migrations and
earlier public provider reports are unchanged. Native/browser/SMTP and final-head
hosted acceptance remain required; no new real-provider or browser run is claimed
from these local SQL/HTTP tests. AUTH-23's callback, native OS return, registration,
actual provider freshness/deletion and manual matrix remain open.

## AUTH-23 bounded Google callback decoding — 2026-10-20

The opt-in core decoder now accepts the actual bounded raw query, exact canonical
returned issuer on success/errors, canonical state and exactly one code/error
outcome. Six new unit scenarios exercise decoded duplicates, malformed encoding,
controls/fragments, wrong/missing issuer, contradictory results, token uploads,
limits, redaction and finite denial/provider-failure classification. Bounded
Google-documented presentation fields and error details are discarded; unknown
members fail closed in an explicitly documented supported subset, without claiming
general OAuth conformance. The existing redacted authorization-code type and
transaction/private-proof boundary are reused. No route or session is added.

Two additional real PostgreSQL callback scenarios prove decoding leaves authority
and pending state unchanged, wrong private proof/browser does not consume/cancel,
valid consume makes one actual offline RS256 exchange/session commit, replay makes
no second token POST, and bound denial/provider-failure cancellation creates no
identity/session/audit or token POST. An actual signed positive control follows
cancellation. All twelve Google PostgreSQL cases pass, including earlier
concurrency, realm/source isolation, fault rollback and final-deadline controls.

Final local commands pass using documented PostgreSQL, CARGO_INCREMENTAL=0 and the
unchanged four-worker/shared-connection budget:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-features --all-targets -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --all-features
cargo test --locked -p easy-auth-core --features google
cargo test --locked -p easy-auth-postgres --features google --test lifecycle oidc::google
python3 scripts/audit.py
cargo deny --all-features check
```

Results: **97 default / 548 all-feature workspace tests**, including 2 Axum unit,
99 HTTP,88 core,336 PostgreSQL and23 server cases (logging subprocess repeat
excluded); **76 isolated core Google cases** and **12 Google PostgreSQL cases**.
Final runs have no failures/ignored cases. Compiled-dependency advisory and
all-feature license/bans/source checks pass; inactive optional SQLx/MySQL RSA
advisory remains visible. The final staged diff receives redacted secret scanning.
Documentation local links, changed tree, visibility and responsibility boundaries
are reviewed. New decoder/unit/PostgreSQL files remain under300lines; longer
ordered database scenarios keep negative bindings, observed facts, valid controls
and replay/cancellation together as justified function-size exceptions. No unrelated
cleanup is deferred. No migration, dependency, generic callback or browser behavior
changes; historical browser/provider reports remain immutable. Hosted final-head
browser/SMTP/security acceptance remains separate from these local checks.

Primary-source lifecycle research is recorded in ADR0019: Google's optional signed
authentication-time claim needs provider-application eligibility/configuration and
does not provide a supported Google reauthentication request. Neither generic OIDC
reauthentication parameters nor a new token/session can substitute for fresh proof.
No provider settings, user browser or credential manager were changed. AUTH-23
remains In Progress: Google web/native delivery, registered/manual provider evidence
and a usable reviewed provider-required deletion path remain unfinished. AUTH-20's
Safari failure is unresolved; no new device prompts or interoperability claims.

## AUTH-23 shared Google authorization orchestration — 2026-10-20

`GoogleAuthorization` now composes exact transaction/code snapshots for shared
sign-in start, decoded callback completion and explicit operation cancellation.
Non-sign-in purposes reject before admission/provider work. Returned and retained
state plus actual issuer/redirect must match before any mutation. Code completion
uses the existing one-use consume/S256/signature path; denial/provider failure uses
the same database-bound private proof for cancellation and makes no token POST.
Failed preparation attempts exact cleanup and propagates storage failure. Verified
completion owns a boxed existing opaque identity proof and creates no local grant.
No alternate verifier, proof constructor, SQL, route or retry is introduced.

Six new real PostgreSQL scenarios cover mixed configurations/purposes, private
callback/cancellation bindings, concurrent one-use callbacks, observed document
failure with start cleanup, actual cancellation-trigger storage failure and actual
signed nonce rejection versus token transport failure. Database facts and separate
provider GET/POST/signature counters precede final conclusions; valid signed commit
controls follow injected faults. No meaningful existing assertion was removed.

An initial new negative failed because it treated network source as a credential
binding. ADR0013 and actual admission/transaction SQL show network source is an
independent abuse budget, not stored pending-account authority. The corrected test
adds wrong nonce and PKCE negatives, then proves roaming retains exact provider/
browser/state/purpose/private-proof bindings and independently observes the changed
network-source budget. Production admission/storage policy is unchanged; no IP-based
authentication rule or security downgrade was added to make a test pass.

Final local checks pass with CARGO_INCREMENTAL=0, documented real PostgreSQL and
unchanged four-worker/shared connection limits:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-features --all-targets -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --all-features
cargo test --locked -p easy-auth-core --features google
cargo test --locked -p easy-auth-postgres --features google --test lifecycle oidc::google
python3 scripts/audit.py
cargo deny --all-features check
```

Results: **97 default / 554 all-feature workspace tests**, including 2 Axum unit,
99 HTTP,88 core,342 PostgreSQL and23 server cases (logging subprocess repeat
excluded), **76 isolated core Google cases** and **18 Google PostgreSQL cases with
passkeys disabled**. Real database suites ran sequentially. Final runs have no
failures/ignored cases. Compiled-dependency advisory and all-feature dependency/
license checks pass; the inactive optional SQLx/MySQL RSA advisory remains visible.
The staged diff receives redacted Gitleaks scanning before publication. Changed
documentation file links and code organization are reviewed. The 133-line owning
core flow and feature-specific binding/failure/setup test modules remain under
300lines. Longer cohesive completion and ordered binding/fault scenarios retain
private checks, mutation, observed facts and valid controls as documented size
exceptions; no unrelated cleanup is deferred. Dependencies, migrations, generic
browser contracts and historical provider reports are unchanged.

Hosted CI39387067241 at exact25a6e8f completed successfully, including its named
browser/SMTP/security checks. That is evidence for its own head, not the new flow.
Final-head hosted acceptance is tracked separately in the development ticket.
AUTH-23 remains In Progress: actual Google web/native transport, registered/manual
provider evidence and a usable reviewed provider-required deletion path remain
unfinished. No Google/browser/device interoperability or production-readiness claim
follows from these offline-signature/database controls. No provider/browser/security
settings changed and AUTH-20's Safari recovery failure remains unresolved.

## AUTH-23 owned desktop loopback transport — 2026-10-20

The optional server-library `google-desktop` feature now owns a concrete ephemeral
literal127.0.0.1/::1 socket before exposing exact typed redirect metadata. Bounded
Hyper HTTP parsing checks origin-form HTTP/1.1 GET, exact Host/path, no body and
canonical returned state/issuer through the existing decoder. Only actual delivery
constructs an opaque callback that supplies its captured URI to shared core
completion. No session, provider identity, remote token or database cancellation
follows merely from receive. Explicit core cancellation remains required.

One active connection/eight sequential attempts,32headers/16KiB parser buffer,
two-second header/three-second connection timeouts and an original-expiry-derived
five-minute maximum bound local resource use. Cancel/drop/expiry closes the owned
listener/stream without detached tasks. Finite transport outcomes remain distinct
from later proof, provider and storage errors. Fixed handled HTML has no reflected
proof or cookie, no-store/no-referrer/frame protections and a CSP-hashed inline
query/fragment scrubber. No handwritten HTTP parser or permissive fallback is added.

Nine actual-socket tests pass, covering IPv4/IPv6, alias/wildcard/path refusal,
wrong method/Host/state/issuer/body/encoding/absolute-target inputs, bounded queries,
request/header limits, slow headers, partial-stream cancellation, close-after-drop/
expiry and valid controls after rejected input. A test initially assumed all error
responses use HTTP/1.1; Hyper correctly mirrors an invalid HTTP/1.0 request while
retaining status400. Another initially treated a TCP reset after oversized unread
input as infrastructure failure. The final test still requires an actual complete
HTTP431 response before permitting that reset, plus unchanged receive state and a
valid callback afterward. Reset alone proves no rejection or authentication result;
no meaningful security check or prior regression assertion was weakened.

The [owned Chromium report](../../tests/browser/google-desktop/results/2026-10-20/chromium-owned-loopback.json)
passes its actual browser/socket case with all **712 code-source hashes** and the
fixed producer binary matched. Real CSP-authorized script execution removes the
query; fixed HTML reflects no state/code, and cookies/script storage remain empty.
No external request or unexpected fixture diagnostic occurs and the owned producer
exits0. Private parent/child protocol IPC remains in memory, without proof URLs,
codes, trace or storage files in reports/logs. This is not Google, OS default-browser
launch, registered native-client, identity/session or mobile interoperability.
No user device prompts or browser/provider/security settings changes occurred.

Final local checks pass using CARGO_INCREMENTAL=0 and the documented real database:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-features --all-targets -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --all-features
cargo test --locked -p easy-auth-server --features google-desktop google_desktop
cargo build --locked -p easy-auth-server --features google-desktop --example google-desktop-browser
node tests/browser/google-desktop/run.cjs
python3 scripts/audit.py
cargo deny --all-features check
npm audit --audit-level=low --prefix tests/browser/passkeys
```

Results: **97 default / 563 all-feature workspace tests** (2 Axum unit,99 HTTP,
88 core,342 PostgreSQL,32 server; logging subprocess repeat excluded), **9 isolated
desktop socket cases** and **1 actual owned Chromium case**. Final runs have no
failures/ignored cases. SQLx suites remain sequential under the original shared
connection/four-worker budget. Compiled advisory, all-feature dependency/license
and pinned browser dependency audits pass; inactive optional SQLx/MySQL RSA advisory
remains visible. Hyper1.12.0/hyper-util0.1.21 (MIT) become optional direct edges;
no package version/checksum or crypto changes. The full staged diff receives
redacted Gitleaks scanning. Changed links, module boundaries and naming are reviewed.
Socket lifetime, HTTP validation/response and captured completion/error modules
stay below300lines; ordered boundary/resource tests retain observed failure and
valid control as function-size exceptions. No unrelated cleanup is deferred.

CI39389038579 at exactf24439a completed successfully; acceptance for each later
head is tracked separately. Normal startup, generic callbacks, schema and older
browser reports are unchanged. AUTH-23 remains In Progress: real listener-to-
PostgreSQL/signed-provider acceptance, supported OS browser launch/return, registered
Google/manual matrix and usable reviewed provider-required deletion remain open.
AUTH-20's Safari issue, independent review and broader release gates remain open.

## AUTH-23 owned native return through real PostgreSQL — 2026-10-20

The separate structural commit82f4ea2 moves actual-signed Google provider and
independent clock/lock fixtures to root tests/support/google without changing their
bytes. Existing socket helper function bodies and complete-rejection assertions
are also retained. Original Google/PostgreSQL18, native socket9 and strict scoped
lint pass before adding acceptance behavior; no production visibility changes.

Nine new server integration cases now carry actual owned IPv4/IPv6 receives through
the public opaque callback completion method, shared core flow, real PostgreSQL
state consumption, actual offline RS256/JWKS responses, mapping and final session
commit. Receipt and verification alone create no local authority. Matching signed
verified email does not merge a mailbox owner; provider-required policy and missing
authentication-time provenance remain intact. Another owned listener cannot stand
in for the configured return URI. Trusted rebinding retains existing revision/
cancellation policy; captured old delivery with its original service snapshot and
private proof remains unauthorized before token POST.

An actual capture racing a restored private operation yields one signed exchange
and one local commit. Received denial/provider failure and explicit pending cancel
preserve unrelated sessions and issue no authority. Transport cancel leaves pending
work until separately authorized original-proof core cancellation. Actual signed
nonce rejection is Unauthorized, while deliberate token transport/final audit faults
are Unavailable; counters and valid controls distinguish these from infrastructure
or fixture failure. Real audit-trigger failure rolls back user/identity/session/fact
without restoring consumed state. An independently observed final audit lock wait
crossing the original proof deadline similarly rolls back all authority. Its short
owned timing arrangement retains the original five-minute pending window and final
clock check; no production clock override or cap restart exists. Positive signed
controls follow faults, cancellation, stale configuration and expiry.

Final local checks pass with CARGO_INCREMENTAL=0 and documented real PostgreSQL:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-features --all-targets -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --all-features
cargo test --locked -p easy-auth-server --features google-desktop,oidc-identities --test google_desktop
cargo build --locked -p easy-auth-server --features google-desktop --example google-desktop-browser
node tests/browser/google-desktop/run.cjs
python3 scripts/audit.py
cargo deny --all-features check
```

Results: **97 default / 572 all-feature workspace cases** (2 Axum unit,99 HTTP,
88 core,342 PostgreSQL-crate,32 server unit,9 server real-database; logging subprocess
repeat excluded), with the **9 native/PostgreSQL cases also passing in their explicit
feature-combination target**. Final runs have no failures/ignored cases. Real DB
suites remain sequential with the same shared20-permit/four-worker budget; the
independent audit/clock observer has exactly one connection. Compiled advisory and
all-feature license/bans/source checks pass; inactive optional SQLx/MySQL RSA advisory
remains visible. Server adds only development usage of the selected josekit0.10.3;
no package version, production dependency, schema or application code changes.

The [fresh Chromium transport report](../../tests/browser/google-desktop/results/2026-10-20/chromium-loopback-shared-fixtures.json)
passes its one existing browser case after extraction, matching all **721 current
code-source hashes** and the rebuilt fixed producer. It proves actual callback
delivery/CSP query scrubbing/nonreflection/empty cookies and script storage/clean
exit, not database authority. The separate nine database cases establish the latter
component path. The previous712-source report remains immutable and is not counted
as an additional distinct browser case. No authorization code, assertion, token,
private key, user-setting data or trace is saved; private fixture IPC is not
forwarded to logs.

The full staged diff receives redacted Gitleaks scanning before publication.
Changed links, fixture privacy and responsibility boundaries are reviewed. Native
test modules separate attempt metadata, configured setup/rebinding, actual delivery,
lifecycle, binding/concurrency and atomicity. All remain below300lines. Longer
ordered full-boundary cases retain actual receipt, observed facts, fault results
and signed positive controls as justified function-size exceptions; no unrelated
cleanup is deferred. CI explicitly runs the native/identity feature combination
sequentially so the new database coverage cannot disappear behind feature gating.

AUTH-23 remains In Progress: actual registered Google/provider TLS and manual matrix,
supported OS system-browser launch/return, mobile mechanisms and a usable reviewed
genuinely fresh provider-required deletion path remain unfinished. Offline signed
fixtures/Chromium are not substitutes for those outcomes, independent review or
production readiness. No user/device prompts or provider/browser/security settings
changes occurred. AUTH-20's Safari recovery failure remains unresolved.

## AUTH-23 explicit eligible-client Google session-age proof profile — 2026-10-20

Trusted composition can now convert a validated Google exchange to
`GoogleSessionAgeCodeExchange`. It adds only fixed essential signed `auth_time`
request/validation, preserving original scope/state/nonce/S256/redirect and existing
issuer/egress/RS256/client rules. Decoded/case-folded metadata `claims` collisions
reject. No arbitrary claims, unsupported Google reauthentication parameter, new
dependency or insecure fallback is added. The base sign-in-only profile and generic
OIDC request behavior remain unchanged. Shared `GoogleAuthorization::new_session_age`
selects the explicit concrete profile without duplicating callback/cancel policy;
exact snapshot equality remains mandatory.

Separate exchange methods accept sign-in versus original account-deletion purpose
and reject other/linking contexts before token POST. Actual signed capability
absence is provider-profile Unavailable; malformed/invalid signed claims remain
Unauthorized. Old signed time stays old after new issuance/local session creation.
A deletion exchange yields only existing opaque proof; deliberate confirmation,
exact original owner/session/subject/current source, genuine freshness and all
original/final caps remain with the existing mapped deletion use case/PostgreSQL.
Selecting/requesting the capability neither proves eligibility nor forces a new
Google authentication event, and activates no ordinary route.

Six new actual-signature core scenarios cover fixed request projection/default
preservation/redaction, metadata collisions, signed missing versus malformed claim
classification, source/transport errors, cross-purpose/link refusal before POST
and unchanged old authentication time. Private protocol fields are compared without
formatting them on assertion failure. Five new real PostgreSQL cases cover selected
managed sign-in and no freshness promotion; missing/malformed/stale claim denial
before any erasure; exact owner/current session/subject and sign-in-purpose refusal;
one deletion/fact from concurrent valid proofs; full private account/session/identity/
audit/notice/cooldown rollback after a real audit-trigger fault; successful signed
controls and deleted-subject cooldown. Older unknown-authentication sessions may
initiate the bounded action, but only new qualifying signed proof can finish it.
No application SQL, published migration or meaningful existing assertion changes.

Final local checks pass with CARGO_INCREMENTAL=0 and documented real PostgreSQL:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-features --all-targets -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --all-features
cargo test --locked -p easy-auth-core --features google
cargo test --locked -p easy-auth-core --features oidc-verification
cargo test --locked -p easy-auth-postgres --features google --test lifecycle oidc::google
python3 scripts/audit.py
cargo deny --all-features check
```

Results: **97 default / 583 all-feature workspace cases** (2 Axum unit,99 HTTP,
94 core,347 PostgreSQL-crate,32 server unit,9 server real-DB; logging subprocess
repeat excluded), **82 isolated core Google**, **60 isolated generic verifier** and
**23 Google PostgreSQL** cases. Final runs have no failures/ignored cases. Real DB
suites retain sequential execution, original shared20/four-worker budget and bounded
observers. Compiled advisory and all-feature license/bans/source checks pass;
inactive optional SQLx/MySQL RSA advisory remains visible without exception. The
full staged diff receives redacted Gitleaks scanning; changed local documentation
links, responsibilities, visibility and naming are reviewed. New profile/dispatcher
modules72/36lines and existing flow150lines stay focused; test files remain below
300lines. Longer request/purpose/rollback matrices retain signed controls as
function-size exceptions. No unrelated cleanup is deferred.

Existing immutable browser reports remain historical; no new browser/provider/manual
interoperability run is claimed for this profile checkpoint. Current full workspace
checks retain the native socket and real-database acceptance scenarios. Hosted
CI39395320135 at exactdf682f5 completed successfully; acceptance of the new final
head is tracked separately in Huly. AUTH-23 remains In Progress for Google web/
deletion delivery, supported OS/browser/native registration/manual evidence and a
genuinely usable repeatable provider-required freshness/deletion path. The optional
claim/component success is not ordinary activation, independent review or production
readiness. No user/device prompts or provider/browser/security settings changed;
AUTH-20's Safari recovery failure and broader release gates remain unresolved.


## AUTH-23 desktop closure observation correction — 2026-10-20

Exact-head CI [39398973050](https://github.com/Deuspheara/easy-auth/actions/runs/39398973050)
at49b9de6 failed two server desktop tests at the final socket-closure observation;
callback rejection/positive-return assertions had already passed. The secret job
passed. This run is a failure, not acceptance of that head or a provider denial.
The first local all-feature suite also reproduced the old closure assertion failure
after all PostgreSQL cases passed; it remains recorded as a failed run.

An isolated diagnostic in the existing owned Linux development container bound
netcat's source and destination to the same unused loopback port and received its
own fixed non-secret marker without a listener. Source-port self-connection is a
concrete false-positive mechanism. However, a distinct-source probe still reproduced
a local failure. Its connected stream then had no peer address, and a temporary
same-process socket-listener diagnostic found no listening socket at that endpoint.
Explicit earlier listener drop and an independent blocking connect did not remove
the failure; those experiments and temporary process inspection are not retained.
The exact cause of the hosted failures cannot be established from their old logs.
No production listener or provider behavior change is retained.

The shared test probe binds a distinct source before connect. A connect result
alone does not prove a usable listener: if a returned stream proves EOF/reset/
disconnection, the probe may make another bounded observation. It still requires
an actual ConnectionRefused result to establish closure, never accepts EOF alone,
and fails if a stream responds, remains open or the three-observation budget is
exhausted. Each connect/read step is bounded to one second. Unexpected socket
errors and connection-observation timeout are explicit infrastructure failures.
There is no unconditional sleep, application retry or relaxed credential check.

Actual socket controls force source-port collision and check closed IPv4/IPv6
endpoints, reject an idle live listener, and reject a live listener that immediately
closes every accepted connection. Original HTTP/body/header/cancellation assertions
remain. The private shared fixture stays under250lines with no dependency or
production visibility change. This is test-observation evidence, not new Google,
OS default-browser or real-provider interoperability.


## AUTH-23 bound Google deletion authorization checkpoint — 2026-10-20

`GoogleAccountDeletionAuthorization` adds the missing core start/callback/cancel
boundary for original provider-account deletion intents. It accepts only the
explicit eligible-client session-age exchange and matching persisted configuration.
Its private concrete purpose selection reuses the existing sign-in operation's
state/actual issuer/actual route/private browser/nonce/PKCE checks, bound cancellation
and cleanup. Both public sign-in constructors remain sign-in only; deletion rejects
sign-in/linking before admission or provider I/O. No SQL, migration, dependency,
HTTP/OpenAPI, ordinary startup or provider reauthentication behavior changes.

Seven new real-PostgreSQL scenarios use the actual offline RS256/JWKS/code fixture.
They cover constructor/purpose rejection, wrong owner/session/browser/state/nonce/
PKCE/route for codes and provider errors, explicit cancellation without ambient
session revocation, unavailable document preparation and cleanup, cancellation SQL
fault versus provider denial, actual signed missing/invalid/old authentication and
nonce rejection versus token transport failure, one-use callback concurrency and
final audit rollback with a complete private account-state comparison. Positive
signed deletion controls follow faults. Verification alone changes no account or
session; the existing mapped deletion transaction retains genuine freshness,
original caps, owner/source/subject/session and atomic erasure. A consumed callback
cannot be revived after failed exchange or final deletion rollback.

Final checks pass with `CARGO_INCREMENTAL=0` and the documented local PostgreSQL17.11:

- `cargo fmt --all --check`.
- `cargo clippy --locked --workspace --all-targets -- -D warnings` and the same
  command with `--all-features`.
- `cargo test --locked --workspace`: **97** tests.
- `cargo test --locked --workspace --all-features`: **594** tests:2Axum unit,
  99HTTP/database,94core,354PostgreSQL-crate,34server unit and11server integration.
  The logging child repeats one included core case; it is not another acceptance
  case. Two socket-observer controls run in each importing server test binary;
  the original nine desktop/database scenarios remain unchanged.
- `cargo test --locked -p easy-auth-core --features google`: **82** tests.
- `cargo test --locked -p easy-auth-postgres --features google --test lifecycle oidc::google`:
  **30** Google PostgreSQL cases. All23earlier scenarios are retained.
- Compiled-dependency `scripts/audit.py` and `cargo-deny deny --all-features check`:
  pass. Inactive SQLx/MySQL RSA0.9.10/RUSTSEC-2023-0071 remains explicitly visible;
  there is no advisory exception or dependency/version change.

The final closure observer also passes ten consecutive full concurrent server-unit
runs,34tests per run; these repeated observations do not increase scenario counts.
The fresh [owned Chromium report](../../tests/browser/google-desktop/results/2026-10-20/chromium-bound-deletion-closure.json)
passes its one existing native-return browser case and matches all736source hashes
and the fixed rebuilt producer binary. It checks actual socket delivery, CSP-allowed
query scrubbing, no cookies/storage/proof reflection and successful fixture exit.
Older reports remain immutable. No physical passkey or Google prompt, browser/vault/
provider setting, real Google credential or claimed interoperability is involved.

Review keeps the new62-line public deletion service in its owning feature module,
the143-line shared flow and47-line private dispatcher cohesive, with no duplicate
callback or persistence policy. Managed deletion tests separate binding, lifecycle,
preparation, failure and setup; files remain below300lines. Longer ordered binding/
fault matrices retain unchanged-state, actual faults and signed positive controls
as justified function-size exceptions. The private snapshot visibility is scoped
only to the Google test feature. No unrelated cleanup is deferred. Changed-document
file links and diff whitespace pass; the complete staged publication is secret-scanned.

This is core authorization acceptance, not finished Google web transport or release.
Google HTTP/browser delivery, supported OS system-browser launch/return, registered
provider/manual eligible-client freshness and a genuinely usable reviewed lifecycle
remain open. AUTH-20's Safari recovery failure is unresolved. AUTH-23 remains
In Progress; exact final-head hosted CI is tracked separately in Huly.


## AUTH-23 experimental Google HTTPS composition checkpoint — 2026-10-20

The opt-in Axum `google-web` composition now supplies actual HTTPS-only Google
sign-in/deletion HTTP routes, fixed reference pages and a separate generated
[OpenAPI contract](../architecture/openapi-google-web.json). Typed services require
the eligible-client session-age profile and exact persisted snapshots. The router
requires matching realm/origin/callback; private proof uses dedicated Google host
cookies. GET only selects fixed UI through the existing core Google parser and one
unique purpose-state match. Explicit POST still owns bound code/error completion,
current-policy mapping and existing sign-in/deletion transactions. Stale/malformed
callbacks cannot clear newer proof cookies. Repeated exact deletion confirmation,
actual initiating owner/session/subject, genuine signed age and original caps remain.
No production SQL, migration, cryptographic implementation, generic OIDC contract or
ordinary server startup behavior changes. No unsupported reauthentication parameter
or weak fallback is added.

Before behavior, c41b711 extracts existing anonymous-session presence and explicit
revocation proof-cookie hygiene without changing either OIDC composition. All44
existing OIDC HTTP/PG cases and strict Axum all-target/all-feature lint pass at that
structural boundary. Previous exact-head hosted CI
[39403142719](https://github.com/Deuspheara/easy-auth/actions/runs/39403142719)
at9d98136 is terminal success. It is not acceptance of this later HTTPS change.

Seventeen new real HTTP/PostgreSQL cases cover exact Origin/closed input/bounds,
protected cookies and logout hygiene, realm/private browser/state/nonce/PKCE binding,
stale callback preservation, finite provider denial versus infrastructure failure,
actual signed claims, one-use callback races, current owner/session/subject deletion,
old/missing/malformed age and genuine positive controls, final audit rollback and
contract/GET bridge isolation. The shared offline provider sees public authorization
inputs, not the browser's private proof. Existing PG/native callers retain the same
original hash, registered client/redirect, one-use code, token authenticator and
verifier checks. The first15-case HTTP run had13passes and2fixture-setup failures:
second realms attempted to reuse a globally unique callback. Distinct fixture
origins correct that assumption; no schema constraint or authorization assertion
was relaxed. The final17-case focused suite passes.

Final checks use `CARGO_INCREMENTAL=0`, locked dependencies and actual PostgreSQL17.11:

- `cargo fmt --all --check`.
- `cargo clippy --locked --workspace --all-targets -- -D warnings`, and the same
  with `--all-features`.
- `cargo test --locked --workspace`: **97** tests.
- `cargo test --locked --workspace --all-features`: **611** tests:2Axum unit,
  116HTTP/database,94core,354PostgreSQL-crate,34server unit and11server integration.
  The logging child repeats an included core case rather than another scenario.
- `cargo test --locked -p easy-auth-axum --features google-web --test browser google_web`:
  **17** tests without passkeys; all earlier99HTTP cases remain in the full suite.
- Compiled-dependency audit, all-feature cargo-deny and pinned browser npm audit:
  pass. Inactive SQLx/MySQL RSA0.9.10/RUSTSEC-2023-0071 remains explicitly visible;
  no advisory exception. The only lockfile change is an Axum development edge to
  the already selected base640.22.1, with no package/version update.

All final test suites have zero failed/ignored cases. The fresh
[owned HTTPS Chromium report](../../tests/browser/google-web/results/2026-10-20/chromium-https-code-flow.json)
passes **13** browser cases and matches all **773** source hashes and its fixed
rebuilt producer. Actual fixed pages/core/PostgreSQL perform code/signature/claim
verification and session/deletion commits behind an owned HTTPS proxy. Google
navigation is intercepted only in the isolated context; all other external traffic
is blocked. Provider-denial/failure cancellation, bad-query fixed content,
navigation restoration and fragment proof drop, signed nonce rejection, explicit
sign-in, ambient switch denial, deletion cancellation/denial and old/missing/fresh
signed time are exercised. The resulting account stays accessible through failed
or cancelled deletion and is removed only after repeated confirmation and a valid
signed proof. Callback URLs are scrubbed, script cookies/storage and foreign-detail
reflection remain absent, and there are no unhandled page errors.

Cleanup verifies exit0, normal owned database removal, no emergency cleanup or
diagnostics, and temporary TLS file removal. Aggregate facts are zero users/
identities/sessions/pending, two audit facts and five actual token POSTs/signatures.
The private certificate exception is context-local; no real Google endpoint,
provider setting, system/browser trust setting, vault or manual device prompt is
involved. The owned provider/database failures have distinct fixed fixture failure
categories, and are never accepted as credential rejection. No codes, tokens,
assertions, private keys, screenshots, traces or browser storage state are recorded.
The first12-case exploratory browser run also passed; the final13-case report adds
an independent fragment-only client boundary, not another real-provider sample.

File-tree/responsibility/visibility/naming review keeps modules below300lines and
handlers thin; owning core/PG policy is reused. Longer ordered fixture construction,
provider-response and browser/binding/fault scenarios retain invariants and actual
positive controls together as documented function-size exceptions. No unrelated
cleanup is deferred. Changed-document links and diff whitespace pass. The full
staged publication receives redacted secret scanning before push. CI now runs the
isolated HTTP feature and owned HTTPS browser suite alongside all earlier gates.

This is experimental owned-component acceptance. Ordinary standalone Google
configuration/activation, supported OS system-browser launch/return, actual
registered/manual eligible-client freshness and a genuinely usable reviewed
provider lifecycle remain open. AUTH-20's Safari recovery failure, independent
review, SAML/outbound issuer and broader release gates remain unresolved. AUTH-23
stays In Progress; exact final-head hosted CI is tracked separately in Huly.


Final source review also found and corrected an owned-fixture cleanup edge: the
initial private IPC write occurred after database creation but before the error
path that closes it. Preparation/IPC/server Result errors now all pass through
owned close. An actual closed-stdout smoke with the identical final producer exits1,
emits only the fixed failure message and leaves zero difference in the owned
database set; the normal13-case browser run is its successful bootstrap/cleanup
control. This is infrastructure evidence, never an authentication-denial result.
Formatting and strict all-feature/all-target lint pass after the fixture-only fix,
and the rebuilt final13-case browser report again matches all773source hashes and
producer. No application source, API schema or611-case application regression
behavior changed at this last cleanup correction. The superseded unpublished
browser checkpoint was retained privately; published reports were not overwritten.

## AUTH-23 owned native launcher — 2026-10-20

The optional server `google-desktop-launch` component adds one owned native sign-in
operation around the existing Google authorization/listener boundary. Private
browser/state/nonce/S256 proof remains in memory. Only the first reviewed platform
command is selected from pinned MIT open5.4.4; Tokio owns execution with null streams,
five-second/original-expiry cap and one-second explicit child reaping on failure.
No fallback iteration, system setting, public command override, callback upload API,
SQL policy copy, schema/migration or default startup activation is introduced.

Callback capture runs while the opener is alive, because delivery can precede its
exit. Both successful handoff and an actual owned callback precede core verification.
Exit0 alone grants nothing. Provider denial/failure, actual signature rejection,
launcher failure and core/storage failure remain distinct. Transport cancellation
closes resources but does not promise SQL cancellation; consuming `cancel()` retains
original private binding. Dropping a future requests child termination without
claiming confirmed reaping or asynchronous SQL cleanup. Interrupted token I/O cannot
restore consumed state. Verified completion still requires mapping and atomic
current-policy/session/audit commit under the original final database-time cap.

Thirteen new real-PostgreSQL process cases cover IPv4/IPv6 return before exit,
exit0 without callback, nonzero exit before/after callback, missing executable,
already-requested cancellation, running-child cancellation, future drop, launcher
versus original expiry, held token-I/O cancellation, provider errors, actual signed
nonce rejection versus transport failure, mismatched listener/source, literal
platform command construction and revision-bound session lifetime. Ordered cases
include positive commit controls and check authority/pending-state facts. Private
Python actors use actual child processes and socket delivery, not the real OS
browser or credential manager. The existing shared closure observer is imported
once in the unit test binary; its two controls remain separate from the thirteen
new database scenarios.

An initial fixture expiry arrangement sampled database time twice and violated its
five-minute-window constraint. It now uses one clock sample; no constraint or
application deadline was weakened. Strict lint also caught duplicate socket imports;
behavior-preserving extraction ab6a652 passed the original eleven transport cases
before the launcher behavior was extended. Final missing-executable failures are
explicit infrastructure outcomes, never accepted as application Unauthorized.

Final verification at this checkpoint:

- `cargo fmt --all -- --check` and strict locked workspace/all-target Clippy with
  default and all features pass; `CARGO_INCREMENTAL=0` is retained.
- `DATABASE_URL=... cargo test --locked --workspace`: **97 passed**.
- `DATABASE_URL=... cargo test --locked --workspace --all-features`: **624 passed**
  (2 Axum unit,116 HTTP,94 core,354 PostgreSQL,47 server unit,11 desktop integration).
  The filtered logging subprocess repeats an included core case and is not added
  to that count. Final default/all-feature runs have zero failures or ignored cases.
- Final server all-feature target: **47 unit + 11 integration passed**; focused
  `--features google-desktop-launch,oidc-identities --lib google_desktop::operation`:
  **13 passed**. Isolated `google-desktop-launch` without local mapping: **11 passed**.
- Compiled-graph advisory check, all-feature cargo-deny and browser-tooling npm audit
  pass. Inactive SQLx/MySQL RSA0.9.10 RUSTSEC-2023-0071 stays visible; no advisory or
  license exception is added. Linux is-wsl0.4.0/is-docker0.2.0 are reviewed MIT code.
- CI retains all existing gates and adds isolated launcher feature and owned
  process/PostgreSQL checks. Previous exact-head run39408462999 at d0107ee succeeded;
  the new publication requires its own hosted run. Historical browser source-hash
  reports remain unchanged and do not claim to match this checkpoint.

Source-rebind regression proves the deliberate existing limitation: persisting a
new ephemeral redirect rotates revision and invalidates earlier source sessions,
even if their stored rows are unrevoked. A later signed same-subject sign-in keeps
its original owner and obtains current authority. No exact-redirect/revision guard
is relaxed. Stable registration/concurrent-client lifecycle, actual Google client
and eligible freshness behavior, supported OS browser delivery and ordinary
activation remain open. The configured OS handler is trusted, not authenticated by
exit0. No production readiness, Google/OS interoperability or real device success
is claimed. AUTH-20's Safari failure remains unresolved; no further prompts,
credential-manager access or security-setting changes were requested.

Maintainability review keeps process ownership, orchestration and finite errors in
three focused private modules with deliberate public operation/error reexports.
Tests separate binding, completion, cancellation, resources, actor and setup;
all new files stay under300lines. Longer ordered scenarios retain negative, observed
resource outcomes and positive controls together as justified function-size
exceptions. No unrelated cleanup or persistence refactor is deferred.

## AUTH-23 connect-reset closure observation — 2026-10-20

A full native-policy regression run reached the server suite and failed the
missing-opener case at the shared closure observer: macOS returned ConnectionReset
from connect, before a stream existed. The preceding launcher-error assertion
passed. This is an observed infrastructure-probe outcome, not evidence of an
application authorization failure or a proven listener leak. Its exact kernel
cause is not established.

The shared test-only observer now permits a connect reset/abort to spend another
observation inside its original three-attempt budget. Only actual ConnectionRefused
can establish closure. EOF/reset, a closing live listener, data, idle/budget
exhaustion and unexpected errors cannot become successful closure. No application
retry, security assertion removal, timeout extension or policy change is introduced.
The existing distinct-source collision guard and live-listener controls remain.

A new controlled case requires a real socket refusal after an injected first reset,
rejects reset/abort-only exhaustion and preserves unexpected PermissionDenied as
an infrastructure error. It is fault-classification evidence, not a deterministic
reproduction of the macOS kernel event. Actual transport controls pass12 cases;
the current owned-process/PostgreSQL native operation suite passes18. Strict locked
all-feature workspace/all-target Clippy and formatting pass. This observer fix is
published separately from the native registration behavior. Full final native-policy
acceptance remains subject to its complete rerun and exact-head hosted verification.

The262-line shared fixture keeps the bounded observer and its fault-injection seam
private to tests. The longer ordered control retains budget/non-success/error and
actual-network assertions together as a function-size exception. The fixture is
imported once per binary; repeated controls are not additional authentication
scenarios. No unrelated cleanup is deferred.

## AUTH-23 stable native registration and exact operation returns — 2026-10-20

[ADR0020](../architecture/adr/0020-native-oauth-operation-returns.md) records the
explicit stable desktop source profile and per-operation return binding. Exact
HTTPS/native profiles remain the default. The new profile requires RequireIssuer,
canonical literal127.0.0.1/::1, fixed registered path and a concrete nonzero/nondefault
port. Actual listener ownership still belongs to transport. Each pending operation
persists its exact return; callback and cancellation require that same value with
all original private/browser/state/nonce/S256/purpose/source/deadline bindings.
Code exchange sends the retained operation URI; identity mapping/local commit keeps
the stable source snapshot. A port-only reopen no longer changes source authority.
Real operator disable or administrative revision changes still invalidate it.

The shared Google authorization composition propagates its exact operation URI.
Old anchor-only URL helpers reject the new profile before I/O because a bare start
cannot carry the return. They retain exact-profile behavior. Public Start/Request
layouts and old repository methods are unchanged; new return-aware methods have
fail-closed defaults for alternate returns. PostgreSQL uses the same locked
transactions and original final database-time caps. No public route, remote token
family, default startup activation, dependency, crypto or trust-root change appears.

Additive migration0020 stores profile/return, defaults old sources to exact and
backfills existing pending returns without changing proof hashes, revision, binding
or cap. Published migrations/global callback uniqueness are unchanged. Deploy the
matching adapter/schema together and drain older OAuth writers before migration;
older SQL lacks the new required field. Mixed-version rolling upgrade/downgrade is
not supported. Historical migration fixtures now use original schema columns,
retain their original assertions and finish later schema before today's adapter.
Their provider row models stored legacy state with no verified mailbox and unknown
authentication time; it is not evidence of a new signed protocol ceremony. An
initial fixture check-constraint failure exposed the mailbox default and was fixed
without relaxing a constraint or inventing freshness. The post-upgrade assertion
requires the provider authentication time to remain unknown.

Final evidence, with CARGO_INCREMENTAL=0 and documented PostgreSQL17 setup:

- Formatting and strict locked workspace/all-target Clippy pass for default and
  all features. Advisory gate and all-feature cargo-deny pass without exceptions;
  inactive SQLx/MySQL RSA0.9.10 RUSTSEC-2023-0071 remains visible.
- `cargo test --locked --workspace`: **97 passed**.
- `cargo test --locked --workspace --all-features`: **637 passed**, zero failures or
  ignored cases:2 Axum unit,116 HTTP,96 core,358 PostgreSQL,53 server unit,12 desktop
  integration. The filtered logging child repeats an included case and is excluded.
  Shared socket controls repeat in the two importing binaries; they are not extra
  distinct authentication scenarios.
- Final focused native process/PG suite: **18 passed**, including five new stable
  source cases for reopen/IP-family preservation, actual concurrent-port JIT,
  exact cross-port callback/cancel rejection, real administrative invalidation and
  bound-URL composition. Actual signatures, sockets/processes and final session/
  audit commit are required. No actual system browser is invoked by these cases.
- PostgreSQL desktop profile group: **4 passed**; historical migration-name suite:
  **17 passed**; upgrade-name suite: **12 passed**. Cases preserve full metadata/
  disable, one-use, exact-return/private-proof and original-cap checks. Foreign
  realm/client controls deliberately admit the same actual return under different
  unique registration anchors, so URI difference cannot stand in for isolation.
  Storage failure remains Unavailable and is followed by a healthy positive control.
- Core OAuth tests: **7 passed**, including explicit profile negatives and all three
  legacy backend methods refusing alternate returns without invoking old storage.
- [Owned desktop regression](../../tests/browser/google-desktop/results/2026-10-20/chromium-regression-after-native-returns.json):
  **1 passed**, all786 source hashes and fixed producer binary matched. Its scope
  remains captured transport/CSP/query/storage behavior, not database identity or
  OS-launch acceptance.
- [Owned Google HTTPS regression](../../tests/browser/google-web/results/2026-10-20/chromium-https-regression-after-native-returns.json):
  **13 passed**, all792 source hashes and fixed producer binary matched. Final facts:
  users/identities/sessions/pending0,audit2,tokenPOSTs5,actual signatures5. The fixture
  exits normally and removes its owned database/TLS files without emergency cleanup
  or diagnostics. This exercises the unchanged exact HTTPS profile under the new
  schema, not registered Google or public-root/provider TLS.

The earlier full-run connect-reset probe failure is retained above; its independent
observer fix0798745 requires actual refusal and has its own negative controls. The
complete final rerun passes after that correction. Browser reports use source base
0798745 plus their verified complete source hashes and retained private producers;
older published reports are unchanged. Existing ff333e8 hosted run39413883420 was
successful. The new behavior publication requires its own exact-head hosted run;
local evidence does not substitute for that result. CI adds isolated PostgreSQL
native-profile checks while retaining all prior acceptance/security gates.

Maintainability review keeps configuration/admission in core OAuth, exact wire
selection in the existing verifier/Google modules, SQL/locks in PostgreSQL and
actual listener matching in the server. Scenario modules and legacy schema setup
remain feature-owned, private and under300lines. Longer ordered negative/race/
upgrade/positive-control cases retain their sequence as justified function-size
exceptions; no unrelated structural cleanup is deferred. No meaningful regression
assertion, security check, timeout policy or original final cap is weakened.

AUTH-23 remains In Progress for actual registered Google/OS-browser evidence,
usable genuine freshness and broader native lifecycle/ordinary activation review.
Remote application authority remains a separate issuer gate. Independent review,
SAML and the unresolved AUTH-20 Safari recovery path are not completed by this
work. No credential-manager access, device prompts or system security setting
changes were requested; no production-readiness or interoperability claim is made.


## AUTH-23 native command-selection failure cleanup — 2026-10-20

The prior stable-registration commit09897ef has exact-head hosted acceptance:
[run39422202699](https://github.com/Deuspheara/easy-auth/actions/runs/39422202699)
completed successfully, including Rust job118625697725 and secrets job118625698303.
Decoded logs confirm97 default and637 all-feature tests, the isolated native
profile4 and owned process/PostgreSQL18 cases, and successful browser/startup/SMTP
and security gates. That result establishes the published baseline, not this later
cleanup change.

Review found `GoogleDesktopSignIn::run` returned command-selection errors before
capture took the listener. The socket therefore remained owned until explicit
cancellation/drop, contradicting the documented close-on-error contract. The
private prepared-command boundary now drops that listener on selection failure,
then propagates the original finite error. It does not consume/cancel SQL proof,
change expiry, launch a fallback or issue local authority. Existing spawn/capture/
verification behavior and public API are unchanged.

The new feature-owned resource regression injects unavailable selection before any
child exists. An independent actual-socket refusal probe must prove closure. Scoped
SQL facts must retain exactly one pending row and no user/identity/session/audit;
the stored original expiry must match. No provider POST or signature occurs.
Explicit cancellation then removes only that pending row. Reopening with the same
stable registration must still permit actual process/socket delivery, RS256
verification and atomic identity/session/audit commit. Temporarily removing the
cleanup made this regression fail at `owned listener must be closed`; the fix was
restored before final verification. This deterministic failure injection does not
establish actual unsupported-OS behavior or registered-provider interoperability.

Final local evidence uses CARGO_INCREMENTAL=0 and the documented real PostgreSQL17
setup, with the two full workspace suites run sequentially:

- `cargo fmt --all -- --check`: pass.
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
  and the same command without `--all-features`: pass.
- Focused native process/PostgreSQL suite:19 passed, zero failures/ignored.
- `cargo test --locked --workspace --all-features`:638 passed, zero failures/ignored
  (2 Axum unit,116 HTTP,96 core,358 PostgreSQL,54 server unit,12 desktop integration).
  The filtered logging child repeats an included case and is not counted again.
- `cargo test --locked --workspace`:97 passed, zero failures/ignored.
- Compiled dependency advisory check and all-feature cargo-deny: pass, no new
  exceptions. Inactive SQLx/MySQL RSA0.9.10 RUSTSEC-2023-0071 remains disclosed.

The earlier browser reports remain immutable evidence for their recorded source,
not new browser runs for this cleanup. The changed error path is exercised by the
actual-socket/process/PostgreSQL regression; it performs no real OS browser launch.
Hosted acceptance of this new commit requires its own exact-head run.

Maintainability review keeps resource release in the owning operation and the
scenario in its existing resource-test module. Both files remain below300lines;
the new scenario remains below50lines. The small private prepared-command boundary
permits deterministic failure coverage without a public injection API or process
framework. No core policy, persistence logic, migration, dependency or unrelated
cleanup changes are needed. AUTH-23 remains In Progress for actual Google/OS,
genuine freshness and ordinary lifecycle/activation gates. No Safari prompts,
credential-manager access or system settings were involved.


## AUTH-23 public Google metadata and production TLS preflight — 2026-10-20

The opt-in `google-provider-preflight` example now exercises real public Google
metadata with unchanged production `OidcHttps` DNS/egress/public roots and real
PostgreSQL registry checks. It creates/migrates only its own random local database
and holds an actual native listener. Google authorization preparation and exact
operation return checks use the existing core services, followed by explicit
pending cancellation and actual source disable. No production code/policy, schema,
HTTP endpoint, credential loader, startup activation or dependency changes.

The [fixed-producer record](../../tests/provider/google/results/2026-10-20/public-provider-preflight.json)
passes:3 public GETs, discovery S256/response issuer/client-secret-post admission,
bounded public JWKS envelope, actual native authorization preparation, one pending
row then cancellation, zero users/identities/sessions/audits/pending, and exact
Unauthorized on cached discovery after real source disable. The token transport
refuses every POST and must observe0 attempts. Static unregistered placeholders
are never submitted. No browser is opened or authorization URL visited; raw URLs,
proof/documents and foreign errors are not recorded. JWKS-envelope admission is
not signature/claim verification.

Four fixed-producer controls independently pass with exit1 and exact fixed stages,
empty stdout and no credentials/foreign causes: injected probe failure after DB
creation; nonlocal database URL; a loopback URL with host-override query; missing
explicit mode. The common lifecycle closes the owned database after success or
probe failure. Independent catalog queries find0 matching databases after every
control. Docker port inspection confirms that observer is the same PostgreSQL17.11
server at the configured literal loopback port. A forcibly interrupted process
cannot promise asynchronous cleanup.

Provenance is base commitdd7c9f971b6acec568454f61e9c8e7f8d8903dab plus all6 changed/new
runtime-source overlays (manifest and5 example modules). All other runtime sources
are verified unchanged from that base; Cargo.lock is unchanged. Every overlay hash
and the retained fixed executable SHA256 were rechecked against the record. This
is source/run provenance, not a reproducible-binary claim. Historical browser
reports remain unchanged and are not new browser evidence for this example.

Final local verification, CARGO_INCREMENTAL=0/documented real PostgreSQL setup:

- Formatting and strict locked workspace/all-target Clippy for default and all
  features: pass. The example also compiled with its minimal google-desktop feature.
- `cargo test --locked --workspace --all-features`:638 passed, zero failures/ignored
  (2 Axum unit,116 HTTP,96 core,358 PostgreSQL,54 server unit,12 desktop integration).
  The filtered logging child is not counted twice.
- `cargo test --locked --workspace`:97 passed, zero failures/ignored.
- Compiled dependency advisory gate and all-feature cargo-deny pass without new
  exceptions. Inactive SQLx/MySQL RSA0.9.10 RUSTSEC-2023-0071 remains visible.
- The explicit live run and4 controls are separate acceptance observations, not
  additional default-suite authentication cases or successful provider denials.
  External availability is allowed to fail the live preflight; it is not run by
  default CI and no external credentials are required.

Maintainability review separates entry/lifecycle composition, restricted owned DB,
production GET observation/token refusal, trusted service setup and ordered probe
assertions. All5 modules stay below200lines and functions below50lines; visibility
is confined to the example. No generic fixture framework, production test hook or
unrelated cleanup is introduced. The interoperability table now distinguishes this
Google evidence from unimplemented Apple support.

This establishes only public metadata/TLS compatibility at the recorded time.
Actual registered-client acceptance, callback/token/signature/claim behavior,
OS-browser handoff, genuine Google freshness, usable provider-required deletion,
ordinary activation and independent review remain AUTH-23 gates. No account,
provider setting, credential manager or security configuration was changed. The
existing cleanup commit's hosted run39427439051 remains a separate tracked run;
new preflight publication will require its own exact-head CI result.


## AUTH-23 owned Google database fixture extraction — 2026-10-20

Before preparing registered-client acceptance, the existing public preflight's
restricted database fixture moved to root `tests/support/google/database.rs` for
private reuse. The complete body matches commit87b8b63 byte-for-byte; only the
preflight's static import path changes. No application/API/schema/dependency or
lifecycle behavior changes. Strict all-feature workspace/all-target Clippy,
formatting/diff checks, the actual production-TLS public preflight (3GETs/zero
local authority), all4 unchanged failure controls and independent catalog cleanup
pass after extraction. Previously published source/producer records remain
unchanged. Full workspace results recorded above belong to87b8b63; they are not
claimed as a new run for this structural-only extraction. Subsequent behavior
needs its own final verification.


## AUTH-23 registered native acceptance tool preparation — 2026-10-20

Both prior published heads now have hosted success: cleanup dd7c9f9
[run39427439051](https://github.com/Deuspheara/easy-auth/actions/runs/39427439051)
and public preflight87b8b63
[run39429805345](https://github.com/Deuspheara/easy-auth/actions/runs/39429805345).
Rust/secrets jobs completed successfully; decoded Rust logs confirm the638-case
workspace, native19 and final security gates. These runs establish their exact
published heads, not the following new tool.

The explicit `google-native-acceptance` example prepares registered-client/OS
acceptance with protected local client inputs, stable owned native operation and
the existing core/PG final mapping/commit. Input checks and public owned-setup
checks cannot visit the authorization URL or invoke the opener; only a separate
real sign-in command with explicit disposable-account consent does so. No actual
manual sign-in has been run. Normal server startup/API, core policy, migrations,
dependencies and verified-proof constructors are unchanged.

The existing protected secret-file body is imported privately rather than exposed
or copied. The restricted DB fixture is shared from root tests/support after the
separate byte-identical6822ea1 extraction. Each real run would use an exclusive new
local database/source, validate and revoke only its local session, require scoped
facts (1user/1identity/1revoked session/2audits/0pending), then remove its database.
Real provider grants are separate owner cleanup; local DB removal does not revoke
them. Only signed authentication-time presence is reported, never manufactured
freshness/deletion success. No raw user/account/credential/protocol material is
emitted. Error classification preserves typed rejection versus infrastructure
failure, including cancellation-signal failure and unconfirmed opener cleanup.

Final local checks, CARGO_INCREMENTAL=0/documented PostgreSQL17 setup:

- Formatting; strict locked workspace/all-target Clippy default and all features:
  pass. The example also builds with its minimal launch+identity feature set.
- Explicit example suite:13 passed, zero failures/ignored. Ten feature cases plus
  three reused independent socket-observer controls; these are not13 distinct new
  authentication scenarios. No OS opener is invoked. Actual RS256/JWKS, IPv4/IPv6
  delivery, PostgreSQL and final validation/revocation are required by positives.
- The suite retains explicit profile requests and actual native-operation cancel,
  signed wrong-nonce versus transport-failure counters, required signed claim
  absence, no authority from provider denial/failure, actual source disable after
  verification and final-audit SQL failure/rollback followed by healthy signed
  completion. Old signed auth_time is present without invented freshness.
- `cargo test --locked --workspace --all-features`:638 passed, zero failures/ignored
  (2 Axum unit,116 HTTP,96 core,358 PG,54 server unit,12 desktop integration). The
  filtered logging child is not counted twice. The explicit example suite is
  separate from these unchanged workspace target counts; CI adds its own command.
- `cargo test --locked --workspace`:97 passed, zero failures/ignored.
- Compiled advisory gate and all-feature cargo-deny pass without new exceptions;
  inactive SQLx/MySQL RSA0.9.10 RUSTSEC-2023-0071 remains visible.

The [fixed-tool record](../../tests/provider/google/results/2026-10-20/native-tool-validation.json)
verifies9 CLI observations: input-only and production-public-metadata owned setup
for base/IPv4 and session-age/IPv6, plus missing mode, missing consent, nonlocal DB,
non-Unicode argument and permissive-secret-file failures. Only owned placeholders
were used. Owned setups prepare/cancel through actual production TLS and PostgreSQL,
but do not submit credentials or open a browser. Independent same-server catalog
checks find0 owned databases. All13 runtime source overlays and the retained fixed
producer executable hash match the record; unchanged reused sources and Cargo.lock
match base6822ea1. Source/run provenance is not a reproducible-binary claim.
Historical reports remain immutable and are not new actual-browser evidence.

Maintainability review keeps entry composition, typed inputs, setup, operation,
opaque completion and read-only observations separate. All files stay below300lines
and implementation functions below50lines. Longer ordered provider/socket and
negative-plus-healthy-control test cases retain their visible security sequence
as justified size exceptions. Shared signer/socket/DB fixtures and secret reading
are reused privately. No generic fixture framework, public injection API or
unrelated cleanup is deferred.

Actual registered Google sign-in, OS/browser handoff, genuine eligible-client
freshness/deletion, broader native persistence/lifecycle, ordinary activation and
independent review remain open. Owner client availability is not established; no
Cloud app, provider settings, account, credential manager or system security setting
was changed. AUTH-23 remains In Progress. New publication needs its own exact-head
hosted result; the two earlier successes cannot substitute for it.


The first staged secret scan flagged the provenance map entry for `secret_file.rs`
as generic-api-key. Independent recomputation proved the matched value is exactly
that existing source file's SHA256, not a credential. The unpublished record now
separates reused-source paths and digests into explicit fields; hashes are retained
and reverified. No scanner rule/ignore or application/test behavior is changed.
Publication still requires the complete staged scan to pass.

## AUTH-23 registered Google native sign-in — 2026-10-20

The owner supplied a locally downloaded Google Desktop registration and completed
the real OS-browser sign-in/consent. The owner identified the browser as Helium;
its version was not recorded. The host reports macOS 27.2, build 26B5086k.
The [sanitized live record](../../tests/provider/google/results/2026-10-20/registered-native-signin.json)
identifies source revision `ebac3d63cad8cfba7defab6c748ec4ed26296264` and the fixed
producer previously built for the preparation record. Before this run, its SHA256,
all 13 runtime overlay hashes, reused-source hashes and Cargo.lock were reverified.
No production code, dependency, migration, policy or assertion changed for this run.

Protected input validation and owned public-metadata/PostgreSQL setup both exited
zero before browser interaction. The explicit `--run-manual-signin
--disposable-account-consent` run then exited zero: actual Google signature verified,
local session committed, validated and revoked. Scoped facts were one user, one
identity, one revoked session, two audits and zero pending operations. The tool
reported owned database removal; an independent query against the same documented
loopback PostgreSQL server found zero `easy_auth_google_probe_` databases.
The owner separately reported sign-in completed. No credential, client/account
identifier, authorization URL, wire response, code or token is published.

This is one registered Desktop, IPv4, `client_secret_post`, base-profile successful
sign-in. Signed `auth_time` was absent; genuine freshness and deletion remain
unaccepted. Other platforms/browsers, registered negative/cancellation cases,
broader persistence/lifecycle, ordinary activation and independent review retain
their separate gates. Local session revocation/database cleanup does not establish
Google authorization-grant revocation. Historical preflight and preparation reports
are unchanged and retain their narrower claims. AUTH-23 remains In Progress.

## AUTH-23 registered Google IPv6 native sign-in — 2026-10-20

After the owner explicitly selected the IPv6 test and completed sign-in in Helium,
the same fixed producer passed through the literal `::1` callback. The
[separate IPv6 record](../../tests/provider/google/results/2026-10-20/registered-native-signin-ipv6.json)
retains the finite successful result and provenance. Runtime overlays, reused-source
hashes, lockfile and fixed producer were reverified against the preparation record;
only documentation had changed since the producing revision. Owned setup and real
sign-in each exited zero. Actual signature verification, local session commit,
validation/revocation and scoped facts matched the IPv4 result. An independent
same-server catalog query found zero owned probe databases after completion.
Signed `auth_time` was again absent. This adds IPv6 registered return evidence on
the same macOS/Helium setup; other platforms, web/negative/cancellation matrix,
genuine freshness/deletion, ordinary activation and independent review remain gated.

## AUTH-32 preliminary native candidate evidence — 2026-10-20

The [source-pinned research recipe](../../tests/provider/saml/native/README.md)
builds unchanged samael 0.0.22 at `2d27dfe4930c4632b202f32886a85b2d1f9226c2`
with its original lockfile. The complete archive digest is checked before extraction;
an independently altered copy fails that guard before compilation. The pinned
Rust image and actual native-library/compiler/test-executable versions are retained
in the [finite result](../../tests/provider/saml/native/results/2026-10-20/upstream-native.json).
The build/run installs no host libraries and adds no application dependency.

Network-disabled, read-only execution with dropped capabilities and no host mounts
produced 86 passed / 0 failed / 1 ignored. Explicit execution of the ignored
`idp::tests::test_accept_signed_with_correct_key_idp` produced 0 passed / 1 failed,
exit 101, with the original assertion intact and native RSA-SHA1 signature failure.
The public fixture metadata and embedded certificate contain different keys; a
passing companion has matching keys. This observation is consistent with the
rejection; no embedded certificate was substituted as trusted configuration.
The default-suite success and explicit failure remain separate outcomes.

This is upstream research, not application or protocol acceptance. Runtime policy,
migrations and security assertions are unchanged. Original upstream fixtures and
keys remain outside this repository. Required hostile parser/resource observers,
verified-node/profile/algorithm policy, PostgreSQL correlation/replay/isolation,
native advisory/license review and focused independent security review remain open.
No SAML ACS or production verifier is enabled. AUTH-32 remains In Progress.

## AUTH-32 bounded native parser observations — 2026-10-20

The [owned parser overlay and observer](../../tests/provider/saml/native/parser-probe/README.md)
compiled offline against the exact previously source-verified native image. No
upstream implementation, assertion or fixture changed. The actual parser, owned
source, executable, observer and inherited-image fingerprints are recorded in the
[finite result](../../tests/provider/saml/native/results/2026-10-20/parser-defaults-observation.json).

Eight DTD/entity/malformed inputs were accepted by the direct default parser.
Healthy parser, real sentinel-file access and real loopback HTTP controls worked
before and after them. The case observations saw zero sentinel-file calls,
connection calls and HTTP requests. The driver exited 1 for candidate policy gaps,
not as a passing SAML security suite. Actual observer executable unavailability
instead exited 2 with an infrastructure result and no rejection observations;
the valid run afterward reproduced the original outcomes. Child process groups,
HTTP connections and cleanup have explicit bounds. All parser runs were network-
disabled, read-only and without host mounts or extra capabilities.

Formatting and Python syntax checks passed. Full upstream package/example strict
Clippy failed on 20 diagnostics in unchanged library files; no owned-probe location
was reported. That failure is retained. Separately, the owned probe passed the
matching `clippy-driver` with `-W clippy::all -D warnings` and actual compiled
dependency artifacts. Clippy was fetched only inside disposable lint containers;
lint compilation was offline. Linting modified only disposable containers, leaving
the host toolchain and assessment images intact. No exemptions or assertion changes
were introduced.

These observations reproduce default-parser policy gaps without claiming a SAML
bypass, comprehensive resource denial or XXE safety. Signature/canonicalization/
reduced-fragment paths, strict profile/algorithm/verified-content policy, native
advisory/license review, application/PostgreSQL acceptance and focused independent
security review remain open. No production verifier or SAML ACS is selected.

## AUTH-32 signed Response verification checkpoint — 2026-10-20

The resumed [owned signature probe](../../tests/provider/saml/native/signature-probe/README.md)
builds offline on the same source-verified native parent, with unchanged upstream
implementation, lockfile, fixtures and assertions. Generated in-memory RSA-2048
fixtures explicitly select SHA-256 reference digests before signing, and every
verification retains the RSA-SHA256/SHA-256 allowlist. No private key or raw XML
is published. The [finite record](../../tests/provider/saml/native/results/2026-10-20/signature-observation.json)
includes exact source/executable/observer/image fingerprints and inherited-layer
verification.

All 34 case/mode rows execute in both nonlegacy reduction modes. Six healthy
controls and both configured-rollover rows return only the expected trusted
subject. Both modes reject unsigned content, altered signatures and subjects,
wrong keys, missing configured trust, attacker KeyInfo, SHA-1 digests and duplicate
IDs. Forged siblings before/after the signed Response are excluded from returned
verified content. These observations do not establish SAML profile or application
authentication acceptance.

The driver exits **1**, retaining six policy failures: DOCTYPE, truncated closing
tag and multiple document roots are accepted in both modes. The trusted subject
still verifies after permissive parsing, which fails strict input rejection policy.
An actual hidden executable instead yields exit **2**, infrastructure failure;
a restored normal run reproduces all outcomes. Four reporting tests pass and
ensure invalid/missing IPC, failed positives and unknown engine errors cannot
become successful security rejections. They supply no cryptographic evidence.

Overlay Rust formatting and owned strict Clippy pass after fixing one redundant
`Ok(...?)` in fixture serialization. Full upstream strict Clippy still exits 101
on 20 unchanged library diagnostics, preserved separately without exemptions or
source patches. The matching component is fetched only in a disposable container;
Cargo compilation is locked/offline and the host toolchain remains unchanged.

Repository checks for this checkpoint:

- `cargo fmt --all -- --check` and overlay `rustfmt --edition 2021 --check`: pass.
- `cargo clippy --locked --workspace --all-targets -- -D warnings` and its
  `--all-features` variant: pass.
- `cargo test --locked --workspace`: **97 passed**, zero failures/ignored.
- `CARGO_INCREMENTAL=0 cargo test --locked --workspace --all-features`:
  **639 passed**, zero failures/ignored. Both workspace runs use the real local
  PostgreSQL service, including migrations, concurrency and realm-isolation cases.
- Compiled advisory check (`scripts/audit.py`), all-feature `cargo deny` and
  staged Gitleaks: pass. The inactive SQLx/MySQL RSA advisory remains visible.
- Four reporting tests, evidence/source fingerprint checks, local documentation
  links and whitespace checks: pass.

The initial sandboxed workspace run failed on 12 database connection setup errors
(`Operation not permitted`); the permitted PostgreSQL rerun passed all 97 tests.
The first all-feature build exited 101 after `No space left on device`; removing
only generated incremental cache and disabling incremental compilation resolved
that build failure. A subsequent session interruption stopped the next run before
completion. Neither partial run is counted as passing; the final fresh run above
completed with exit 0. No required database suite was skipped.

The changed tree keeps fixture construction, cases, engine invocation and reporting
in separate focused modules, with an eleven-line example entry point. All new
implementation modules remain under 300 lines; no production code, migration,
dependency, public contract or visibility boundary changes. Native resource-access
observation through signature/canonicalization/fragment paths, signed Assertion-only
and broader hostile coverage, native advisory/license review, application/PostgreSQL
SAML acceptance and independent security review remain required. AUTH-32 stays
In Progress and SAML remains gated.

## AUTH-32 signed Assertion and algorithm follow-up — 2026-10-20

The same [signature overlay](../../tests/provider/saml/native/signature-probe/README.md)
now generates signed Assertions inside unsigned Responses as well as signed
Responses. Fixture construction reuses the candidate's template/signer; extraction
uses its typed Response/Assertion parsers. A feature-named `assertion_cases.rs`
keeps the additional scenarios out of the entry point and existing Response cases.
Every verification still specifies RSA-SHA256/SHA-256 only. No upstream source,
application dependency, runtime behavior, schema or public contract changes.

The [new immutable record](../../tests/provider/saml/native/results/2026-10-20/assertion-signature-observation.json)
retains 56 case/mode rows and verifies that the previous 34 outcomes are unchanged.
All ten healthy rows and two rollover rows pass. Both modes reject unsigned or
tampered Assertions, wrong/missing trust and duplicate signed Assertion IDs;
unsigned Response metadata and forged Assertion siblings are omitted. The existing
signer also generates an RSA-SHA1 signature with a SHA-256 digest as a separate
negative, rejected in both modes without allowing SHA-1 for verification.

The assessment still exits 1 on the six earlier XML-policy failures. Actual hidden
executable failure exits 2; a restored run reproduces all 56 outcomes. Four
reporting tests pass, now independently faulting each of the five positive case
labels. Owned strict Clippy passes with no diagnostics; full upstream strict
Clippy separately retains exit 101 and 20 unchanged diagnostics. Overlay and
workspace formatting, source fingerprints, documentation links and secret scanning
are checked for this change. Full application regression is the prior 97/639-test
PostgreSQL checkpoint at `4e912ba`; those suites are not rerun for this isolated
research-overlay change. No ticket acceptance or security gate is marked complete.

Broader wrapping/transform/algorithm/resource and profile coverage, native
dependency advisory/license review, application/PostgreSQL SAML acceptance and
focused independent security review remain required. SAML stays gated.

## AUTH-32 bounded signature-child resource observation — 2026-10-20

The [separate resource observer](../../tests/provider/saml/native/signature-probe/RESOURCES.md)
reuses the earlier parser observer's bounded child execution, HTTP trap and actual
file/HTTP control executable. Both copied artifacts match the prior fingerprints;
the new image inherits the verified signature-image layers. Candidate source,
lockfile, native stack and explicit RSA-SHA256/SHA-256 verification policy are
unchanged. Build and observation run offline, read-only at execution, without host
mounts or capabilities. Clippy component download occurs separately in a disposable
online container, with offline Cargo compilation.

Twenty case/mode rows exercise healthy signed Response/Assertion controls around
six DTD/entity variants. Both sets of independent direct-parser/file/HTTP controls
work. Aggregate tracing over the signature child and descendants observes zero
sentinel-file calls, connection calls and HTTP requests. The counts include fixture
generation, verification and reduction; they do not identify individual internal
parser/transform stages or establish general resource safety.

The [record](../../tests/provider/saml/native/results/2026-10-20/signature-resource-observation.json)
preserves exit 1: six DOCTYPE/external-DTD/parameter-entity acceptances fail strict
XML rejection policy, and six internal/file/HTTP-entity engine errors remain
unresolved. Neither opaque errors nor absence of observed access become successful
security rejections. Actual unavailable `strace` instead returns exit 2,
`infrastructure_failed`, with no rejection observations. A restored run reproduces
all counts/outcomes. The resource binary's default path reproduces all 56 earlier
signature outcomes unchanged.

Eight reporting tests pass, including failed signed controls, missing IPC rows,
opaque error handling and resource-call counts that prevent a passing assessment.
Owned strict Clippy passes without diagnostics; full upstream Clippy separately
retains exit 101 and 20 diagnostics in unchanged source. Overlay/workspace
formatting, evidence fingerprints, local links and secret scanning are checked.
Application regression remains the earlier real-PostgreSQL 97/639-test checkpoint
at `4e912ba`; those suites are not rerun for this isolated research overlay.

The new resource fixtures, entry point and observer have separate responsibilities
and remain below the implementation size thresholds. Existing observer/control
code is reused rather than copied into another framework. No production runtime,
schema, dependency or public API is changed. Strict XML/resource policy, opaque
error review, broader hostile/profile and SAML PostgreSQL acceptance, native
advisory/license review and focused independent security review remain gates.


## AUTH-34 concrete gated SAML adapter checkpoint — 2026-10-21

The opt-in core/PostgreSQL `saml-verification` component uses the immutable
qualified saml-rs snapshot and its three existing patches, with AWS-LC only.
No verifier/C14N code, qualification patch or adversarial fixture changes here.
Core owns bounded POST input, concrete message verification, authenticated typed
projection, strict clock/profile policy and an opaque noncloneable proof.
PostgreSQL supplies exact current enabled registration/pins and fresh DB time;
XML/crypto runs after storage locks are released. The proof contains staged replay
hashes and no local user/session authority. Normal composition still has no SAML ACS.

Ordinary scenarios use the established typed IdP API with an unchanged public
upstream test key/certificate. OpenSSL reencodes that same PKCS#1 key as PKCS#8 for
the selected AWS-LC signer; the initial fixture-encoding failure is corrected,
without generating a key or changing the verifier. Cases cover actual signed POST
facts, invalid subject/excessive lifetime, signed InResponseTo, wrong trusted
certificate/explicit rollover overlap, stale source, storage failure and realm
isolation with identical connection/client IDs. These are local component tests,
not actual Shibboleth/Keycloak interoperability or independent security review.

The adopting root lock adds 56 dependency packages and removes/upgrades none of
its existing versions. It selects Bergshamra 0.9.2, uppsala 0.10.1,
kryptering 0.6.0/AWS-LC, aws-lc-rs 1.18.2 and aws-lc-sys 0.46.0. The last two differ
from the qualification checkout's standalone lock; old native qualification does
not establish this build's approval. No RustCrypto/legacy/PKCS#11/PQ/FIPS feature
is selected. Unsuppressed compiled-graph audit and cargo-deny advisory/license/
source/bans checks pass. Inactive SQLx/MySQL rsa 0.9.10/RUSTSEC-2023-0071 remains
reported, without a global ignore. Native distribution/advisory mapping and patch
maintenance ownership still require production acceptance.

Verification commands for this checkpoint are the required default/all-feature
workspace tests with real development PostgreSQL, strict default/all-feature
Clippy, formatting/diff checks, warning-free all-feature docs, the compiled audit,
all-feature cargo-deny, source/patch integrity plus its four Python regressions,
and project-source Gitleaks (11.83 MB; no findings). The default workspace passes
110 tests and the final all-feature workspace passes 685, with zero failures/ignored
tests. Isolated core SAML passes 9 tests. Publication/CI status is recorded with the
delivery commit. No research overlay, new adversarial XML,
bypass/fuzz/stress probe or custom signature-concurrency experiment is run.

Mandatory remaining work: full ordinary condition matrix and actual IdP/browser
interoperability, durable atomic response/Assertion replay rejection and final
current-source/cap recheck, identity/JIT and source-bound session/lifecycle, reviewed
HTTP/browser binding, maintained dependency approval, XML/signature/backend review
and separate named independent security review. Staged hashes do not establish
replay protection. Implemented/tested/internal-reviewed/independently-approved are
separate states; none authorizes SAML activation by implication.


The separate behavior-preserving AUTH-34 extraction `094ae43` isolates persistent
NameID policy and parameterizes the existing ordinary IdP fixture. Its existing
9 core and 6 actual-signature PostgreSQL regressions plus strict all-feature Clippy
pass. Follow-up ordinary coverage now passes 11 isolated core SAML tests and 26
PostgreSQL SAML cases: real library-generated nonpersistent-format/wrong-issuer
rejections and corresponding signed positives, plus pure typed-policy qualifiers,
aliases, value preservation and UTF-8 limits. These counts are targeted follow-up
checks; the complete 110/685 workspace checkpoint above belongs to `ac4edb1`.
The upstream IdP builder does not emit supplied qualifier attributes, so typed
policy unit tests do not claim actual XML qualifier extraction/interoperability.
That evidence remains open; no bespoke XML/signature fixture is generated.


## AUTH-35 gated SAML identity-policy checkpoint — 2026-10-21

The preceding behavior-preserving extraction `5d7accf` shares existing presentation
validation, atomic caller-owned pin replacement and the private signed IdP fixture.
Its core all-feature 107 tests (plus existing child-process control), real PostgreSQL
SAML 26 cases and strict workspace/all-target/all-feature Clippy pass. It is pushed;
publication/CI is tracked separately from security approval.

The optional `saml-identities` component adds exact-registration immutable policy,
explicit default-deny JIT configuration, opaque real-proof mapping and revision-bound
PostgreSQL persistence (migration 0023). Atomic replacement retains disable and rolls
back registration/pins/cancellation if policy insertion fails. Any revision change
invalidates old policy in the same transaction. This creates no user/session/replay
or audit authority. Mapping retains original/signed/pin caps and authenticated replay
reservations; display metadata is optional and never ownership/contact/role input.

Final default workspace 110 tests and all-feature workspace 696 tests pass against
real PostgreSQL, with zero failures/ignored. Isolated core SAML 12 and PostgreSQL
SAML 32 pass. New ordinary cases cover original-schema upgrade, exact real-proof
mapping/no local authority, stale policy, absent optional presentation, explicit
JIT values, atomic rollback, disable/pin-only invalidation, database-only competing
configuration writers and identical identifiers across realms. No custom signature
concurrency experiment, adversarial XML, newly generated key material or verifier change is introduced.

Formatting/diff checks, strict default/all-feature Clippy, warning-free all-feature
docs, source integrity: 234 files/three unchanged patches and its four Python
regressions, unsuppressed compiled-graph audit, all-feature cargo-deny advisory/
license/source/bans checks and source Gitleaks pass. Inactive SQLx/MySQL
rsa 0.9.10/RUSTSEC-2023-0071 remains reported without a global ignore. No new dependency,
license exception or native backend feature is added by mapping.

[ADR 0022](../architecture/adr/0022-saml-identity-policy.md) records exact ownership
namespace (including both configured IdP and SP entities), the dependency's missing
typed attribute NameFormat evidence, and deliberate lack of attribute-selected
mapping. No custom XML extraction bridge is introduced. AUTH-34 durable replay and
final identity/session/current-policy transaction, source-bound lifecycle and HTTP,
actual IdP/attribute/qualifier/browser acceptance, maintained dependency approval,
XML/signature/backend review and separate named independent approval remain open.
Normal SAML stays disabled. Internal code/maintainability review checks cohesive
modules, exact visibility, no policy duplication, scope, transaction ownership,
closed modes and original caps; it is not independent security review.
