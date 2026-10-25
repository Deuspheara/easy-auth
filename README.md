# easy-auth

Experimental Rust-first authentication for developers embedding Axum and teams self-hosting a small headless service. Both modes use the same core and PostgreSQL transactions. MIT OR Apache-2.0 for original code.

**Alpha: not suitable for production identity infrastructure. No independent security audit or OIDC/SAML conformance claim.**

Available: same-browser email magic-link sign-in, verified email identity creation, opaque revocable sessions, a protected session endpoint, bounded session inventory, individual/all-session revocation, logout, PostgreSQL migrations, local SMTP and a minimal reference client. Opt-in headless password enrollment/sign-in and recovery use an explicit compromised-password corpus; see the [password guide](docs/guides/passwords.md). Tested negative cases include replay, cross-realm use, misbound browser proof and expiry. There is no Better Auth compatibility promise.

Planned and required before the first feature-complete release: passkeys, Apple, Google, enterprise OIDC, SAML SP, outbound OIDC issuer, account/credential management and native integration. See the [Huly backlog export](docs/planning/backlog.json). Verified email changes and confirmed account deletion are available through the [lifecycle API](docs/guides/account-lifecycle.md). SAML’s independent-review waiver leaves unresolved assurance findings; issuer acceptance and broader production gates are documented separately below. Password recovery and notification operations are documented in the [recovery guide](docs/guides/password-recovery.md).

An explicit [experimental passkey-enrollment boundary](docs/guides/passkey-enrollment.md)
now has core/PostgreSQL, HTTP and Chromium virtual-authenticator evidence. It is
disabled in normal server composition. Optional [core/PostgreSQL passkey sign-in](docs/research/passkey-authentication.md)
now verifies proof and atomically issues sessions through an explicit
[experimental HTTP API](docs/guides/passkey-authentication.md), with native platform/USB
assertions and resident discovery checks. Reviewed stronger-account management,
recovery remain unfinished. Contact attachment has experimental core/HTTP tests
and native platform/USB signup-to-SMTP confirmation evidence. See the
[reproducible browser checks](tests/browser/passkeys/README.md); virtual tests are
separate from real-device/provider interoperability.

The [optional-mailbox model](docs/guides/optional-mailbox.md) now preserves existing
mailbox accounts while supporting null email, display labels and passkey-required
policy without weaker login/reset fallback. [Experimental anonymous signup](docs/guides/passkey-signup.md)
now has core/PostgreSQL, explicit HTTP and native Chromium resident platform/USB
evidence; it creates an account/session only after registration and verified assertion.
[Verified contact attachment](docs/guides/email-attachment.md) now has core/PostgreSQL
and experimental HTTP tests plus native Chromium/SMTP confirmation evidence.
Ordinary passkey composition stays gated. The optional
[experimental recovery HTTP API](docs/guides/passkey-management.md#experimental-recovery-http)
now exposes delayed browser-bound claims and signed replacement completion;
reference setup/recovery pages now have native Chromium/SMTP coverage. Independent
review, physical-device/other-browser evidence and ordinary activation remain open.

The optional [OAuth transaction boundary](docs/guides/oauth-transactions.md) now
persists and consumes browser-bound state with real PostgreSQL regression coverage.
It provides exchange context only; provider login/linking and their HTTP/native
transports remain unimplemented.

The optional [OIDC document client](docs/guides/oidc-egress.md) adds constrained
HTTPS discovery/JWKS fetching with exact issuer checks, pinned public addresses
and bounded caches. It creates no identity or session and enables no provider route.

The experimental [OIDC token verifier](docs/guides/oidc-verification.md) now checks
transaction-bound signatures and required claims, with explicit S256 code exchange
and owned Keycloak evidence. Optional [identity mapping](docs/architecture/adr/0016-oidc-identity-mapping.md)
adds typed display selection, exact issuer allowlists, explicit JIT and atomic local
identity/session issuance with provider source/provenance checks. The optional [browser/startup boundary](docs/guides/oidc-web.md) supplies explicit
HTTPS sign-in and confirmed deletion under exact persisted provider policy. Broader
provider/production acceptance stays separate. See the
[identity guide](docs/guides/oidc-identities.md) for scope and limitations.

The optional [independent Rust client](docs/guides/oidc-client.md) performs bounded
S256/state/nonce, real discovery/JWKS and RS256 verification without issuer cookies.
The explicit [configured issuer](docs/guides/issuer-standalone.md) shares one
application factory between executable and embedded modes, requires HTTPS and a
protected key matching current persisted policy, and defaults off. Owned PostgreSQL,
SMTP, browser, Node/Rust and native-loopback acceptance has bounded parity evidence;
[verification scope](docs/security/oidc-client-standalone-verification.md) separates
these results from production approval and independent assurance.

## Run locally

The optional [SAML provider](docs/guides/saml.md) supports normal standalone/embedded
login with `saml-web`, explicit configuration and already-provisioned trusted IdP
pins/policy. It defaults off. The maintainer waived independent review under
[ADR0032](docs/architecture/adr/0032-saml-maintainer-directed-activation.md); this is
not an independently audited implementation.

The binary supports `--help` and `--version` without configuration or database
access. See [command-line usage and setup diagnostics](docs/guides/server-cli.md).
The [clean-checkout walkthrough](docs/guides/setup-walkthrough.md) records the
default development journey; [integration selection](docs/guides/provider-setup.md)
separates provider/native setup from [custom UI](docs/guides/custom-ui.md) and
independent relying parties. [Apple preparation](docs/guides/apple-setup.md)
documents prerequisites and the experimental backend component; ordinary Apple
activation and registered-provider acceptance remain gated.

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

Default standalone alpha supports same-origin first-party browser apps. Explicit `issuer-web` composition supports independent relying parties with their own callback state and application sessions; see the [issuer setup](docs/guides/issuer-standalone.md). Do not share issuer cookies or treat incoming vendor ID tokens as local application sessions. Application roles and business permissions remain in the consuming backend.

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

The Cargo configuration defaults to four test workers. SQLx 0.8.6 shares a
20-connection parent budget across each integration binary's isolated databases;
lock-gate tests need connections for the gate, concurrent actions and observation.
Running too many workers can exhaust those permits before a required lock is
reached. Keep default/all-feature runs sequential. An explicit
`RUST_TEST_THREADS` or `--test-threads` override must preserve this connection
budget; each scenario still runs its own concurrent actions. Deadline observers
use a separate bounded connection and fail setup/observation independently of
application authorization assertions.

Validation details: [initial evidence](docs/security/verification.md), [interoperability matrix](docs/guides/interoperability.md), and [generated OpenAPI](docs/openapi.json).

Architecture: [overview](docs/architecture/overview.md), [API contract](docs/architecture/api-contract.md), [flows](docs/architecture/auth-flows.md), [research](docs/research/ecosystem.md), [build decision](docs/architecture/adr/0001-build-versus-contribute.md). Read [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) before contributing. Huly AUTH is the development tracker; the exported backlog records IDs, not a separate roadmap.

The [native adoption comparison](docs/research/adoption-comparison.md) provides reproducible RustAuth/lucid-auth integrations and raw measurements. It tests a small session workload; it does not establish a general memory, security or full-server performance advantage.

Committed lifecycle operations produce [typed, owned audit facts](docs/guides/audit-events.md) without free-form secret-bearing payloads. Provider account linking remains a separately gated future flow; matching email never merges accounts.

## Project website

The original landing page and searchable developer guides live in
[website/](website/README.md). Run `npm ci --ignore-scripts`, `npm run build` and
`npm run preview` from that directory for a local preview. The GitHub Pages target is
[deuspheara.github.io/easy-auth](https://deuspheara.github.io/easy-auth/); the
Website workflow deploys verified builds from `main` after Pages is enabled.
