# Initial execution evidence — 2026-10-18

This is alpha implementation evidence, not an independent security audit or a production release.

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

The SQL transaction uses database time and conditional updates. Revocation applies on the next validation; requests already authorized may finish. Email-only sign-in assumes mailbox control and is not phishing-resistant. Cross-device link redemption and unrelated-domain app integrations are intentionally unavailable in this slice.
