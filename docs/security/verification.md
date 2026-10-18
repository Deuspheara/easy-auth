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

Password reset/email-change and production blocklist coverage/review; session listing/individual/revoke-all controls; complete account deletion/linking/audit lifecycle; rate/challenge/audit retention; passkeys and real authenticator tests; Google/Apple web/native; enterprise OIDC; a pinned reviewed SAML validator and hostile XML corpus; outbound issuer/client isolation/key rotation/conformance; recovery policy; external security review; operational restore/key/migration drills; accessible polished reference UI and broader SDKs. No production-provider interoperability is claimed.

## AUTH-12 password evidence — 2026-10-18

- `cargo fmt --all -- --check`, strict workspace/all-target clippy and `cargo test --locked --workspace` passed: 20 tests, zero failures/ignored (2 Axum unit, 5 HTTP/database, 4 core, 9 PostgreSQL). Real migration 0002 adds password credentials and bounded audit/admission kinds.
- New coverage: fixed Argon2id parameters/random salts, valid/invalid/dummy verification, malicious costly PHC rejection, NFC/long Unicode/length bounds, blocklist membership and worker saturation; PostgreSQL freshness, realm isolation, concurrent enrollment with one winner, session-insert rollback, old-session rejection, stale credential recheck and shared admission; HTTP generic errors for unknown/email-only/wrong-password accounts and disabled feature.
- `python3 scripts/smoke.py --password` and `--embedded --password` passed against actual loopback SMTP/PostgreSQL, using `AUTH_SMOKE_URL=http://127.0.0.1:58418`. Both preserved the same verified identity through password enrollment/login; embedded mode also validated its custom protected route. No real credentials were printed. Test server processes were stopped afterward.
- Production startup with HTTPS/TLS SMTP configuration and the example corpus rejected startup with the expected minimum-corpus error, without attempting SMTP delivery.
- Release KDF measurement: `cargo run --locked --release -p easy-auth-core --example password_cost`, macOS arm64/Rust 1.95.0, five samples: hash 85–91 ms, verify 85–92 ms at 64 MiB/t=3/p=1. This is not a deployment throughput guarantee.
- Compiled advisory gate and cargo-deny passed with the new graph; inactive SQLx MySQL/RSA finding stays visible. Source-only gitleaks scan passed. A whole working-directory scan also included generated data and reported findings; it is not used as the source acceptance result. No broad secret rule was disabled.
- [Password policy/limits](../guides/passwords.md) and [ADR 0003](../architecture/adr/0003-password-enrollment.md) describe opt-in configuration, the development-only corpus and incomplete recovery/release gates. The default reference page remains email-only; password APIs are headless. Hosted CI for this feature is separate evidence and is not claimed here.

The SQL transaction uses database time and conditional updates. Revocation applies on the next validation; requests already authorized may finish. Email-only sign-in assumes mailbox control and is not phishing-resistant. Cross-device link redemption and unrelated-domain app integrations are intentionally unavailable in this slice.
