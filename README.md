# easy-auth

Experimental Rust-first authentication for developers embedding Axum and teams self-hosting a small headless service. Both modes use the same core and PostgreSQL transactions. MIT OR Apache-2.0 for original code.

**Alpha: not suitable for production identity infrastructure. No independent security audit or OIDC/SAML conformance claim.**

Available: same-browser email magic-link sign-in, verified email identity creation, opaque revocable sessions, a protected session endpoint, bounded session inventory, individual/all-session revocation, logout, PostgreSQL migrations, local SMTP and a minimal reference client. Opt-in headless password enrollment/sign-in and recovery use an explicit compromised-password corpus; see the [password guide](docs/guides/passwords.md). Tested negative cases include replay, cross-realm use, misbound browser proof and expiry. There is no Better Auth compatibility promise.

Planned and required before the first feature-complete release: passkeys, Apple, Google, enterprise OIDC, SAML SP, outbound OIDC issuer, account/credential management and native integration. See the [Huly backlog export](docs/planning/backlog.json). Verified email changes and confirmed account deletion are available through the [lifecycle API](docs/guides/account-lifecycle.md). SAML validator review and issuer interoperability are release blockers. Password recovery and notification operations are documented in the [recovery guide](docs/guides/password-recovery.md).

An explicit [experimental passkey-enrollment boundary](docs/guides/passkey-enrollment.md)
now has core/PostgreSQL, HTTP and Chromium virtual-authenticator evidence. It is
disabled in normal server composition. Optional [core/PostgreSQL passkey sign-in](docs/research/passkey-authentication.md)
now verifies proof and atomically issues sessions through an explicit
[experimental HTTP API](docs/guides/passkey-authentication.md), with native platform/USB
assertions and resident discovery checks. Passkey-first accounts and reviewed
stronger-account policy remain unfinished. See the
[reproducible browser checks](tests/browser/passkeys/README.md); virtual tests are
separate from real-device/provider interoperability.

The [optional-mailbox model](docs/guides/optional-mailbox.md) now preserves existing
mailbox accounts while supporting null email, display labels and passkey-required
policy without weaker login/reset fallback. Anonymous passkey signup and verified
contact attachment are still in progress; ordinary passkey composition stays gated.

## Run locally

Requirements: Rust 1.95, Docker Compose, and a shell. Development ports: PostgreSQL 59473, SMTP 1025, Mailpit 8025, server 58417 (all loopback).

```sh
git clone https://github.com/Deuspheara/easy-auth.git
cd easy-auth
docker compose up -d --wait
cp .env.example .env
set -a
. ./.env
set +a
cargo run -p easy-auth-server --bin easy-auth
```

Open http://127.0.0.1:58417, submit a test email, then open http://127.0.0.1:8025 and follow the email link **in the browser that requested it**. No external email account is needed. The link expires after ten minutes; requesting another link replaces that browser's pending binding. A GET never consumes a link. The page removes the fragment before posting the token.

Sessions expire after 30 minutes idle or seven days absolute. Logout revokes the server-side record immediately for subsequent validations. [Session management](docs/guides/sessions.md) lists owned sessions and supports fresh-authenticated individual/all-session revocation. Authentication secrets are 256 random bits; only SHA-256 verifiers are stored. Mailbox compromise can compromise email-only authentication. Case-insensitive conservative ASCII email policy is documented in the [domain model](docs/architecture/domain-model.md).

The local SMTP endpoint is intentionally unencrypted and is permitted only in explicit loopback development mode. Production startup requires HTTPS and TLS SMTP credentials, but the alpha has further operational/security release gates. See [deployment](docs/architecture/deployment.md).

## Embedded Axum

Use workspace/path dependencies while crate names and APIs are unpublished:

```toml
[dependencies]
auth-core = { package = "easy-auth-core", path = "crates/auth-core" }
auth-postgres = { package = "easy-auth-postgres", path = "crates/auth-postgres" }
auth-axum = { package = "easy-auth-axum", path = "crates/auth-axum" }
```

Construct `Postgres` from an SQLx pool, run its migrations and provision a trusted realm. Provide `EmailDelivery`, then mount `auth_axum::router(Auth::new(realm, repository, email), BrowserConfig::new(public_url, development)?)`. `GET /v1/session` is a protected Axum route using the core's session verification. The standalone binary is a complete executable composition example. Run the [embedded example](apps/auth-server/examples/embedded.rs) with `cargo run -p easy-auth-server --example embedded`; it adds `/private` to the same application and uses `auth_axum::authenticate` to retrieve the user. The binary and example share the real SMTP/PostgreSQL composition.

Standalone alpha supports same-origin first-party browser apps. Unrelated applications must wait for the outbound OIDC issuer; do not share cookies or treat incoming vendor ID tokens as our application sessions. Application roles and business permissions remain in the consuming backend.

## Verify

With development services running and environment loaded:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
# With the server running:
python3 scripts/smoke.py
```

Database tests run migrations in isolated real PostgreSQL databases, including concurrent one-time proof consumption and transaction rollback. They fail if PostgreSQL is unavailable. No external provider credentials are required. CI also runs cargo-audit through a compiled-graph gate (inactive optional lockfile findings remain visible), cargo-deny and secret scanning; their configured presence is not a claim of a completed audit.

Validation details: [initial evidence](docs/security/verification.md), [interoperability matrix](docs/guides/interoperability.md), and [generated OpenAPI](docs/openapi.json).

Architecture: [overview](docs/architecture/overview.md), [API contract](docs/architecture/api-contract.md), [flows](docs/architecture/auth-flows.md), [research](docs/research/ecosystem.md), [build decision](docs/architecture/adr/0001-build-versus-contribute.md). Read [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) before contributing. Huly AUTH is the development tracker; the exported backlog records IDs, not a separate roadmap.

The [native adoption comparison](docs/research/adoption-comparison.md) provides reproducible RustAuth/lucid-auth integrations and raw measurements. It tests a small session workload; it does not establish a general memory, security or full-server performance advantage.

Committed lifecycle operations produce [typed, owned audit facts](docs/guides/audit-events.md) without free-form secret-bearing payloads. Provider account linking remains a separately gated future flow; matching email never merges accounts.
