# easy-auth

Rust-first authentication for Axum applications. Embed it in your backend or run
it as a headless service; both modes share the same core and PostgreSQL transactions.

**Experimental alpha. Not suitable for production identity infrastructure. No
independent security audit or OIDC/SAML conformance certification has been completed.**

[Documentation](https://deuspheara.github.io/easy-auth/) ·
[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

## What it provides

- Browser-bound email sign-in and verified email accounts.
- Opt-in password enrollment, sign-in and recovery with a required compromised-password corpus.
- Opaque server-side sessions, bounded inventory, logout and individual/all-session revocation.
- Verified email changes, confirmed account deletion and transactional audit events.
- Shared Axum integration, PostgreSQL migrations, SMTP delivery and a reference account interface.

Additional authentication methods have explicit availability limits:

| Feature | Status | Details |
| --- | --- | --- |
| Passkeys | Experimental registration, sign-in, signup, management and recovery components; ordinary activation remains gated | [Passkey guide](docs/guides/passkey-enrollment.md) |
| Inbound OIDC | Opt-in provider integration with explicit issuer, trust and JIT policy | [OIDC setup](docs/guides/oidc-web.md) |
| SAML SP | Opt-in standalone/embedded integration with persisted trust and certificate pins | [SAML setup and limitations](docs/guides/saml.md) |
| Google | Provider and native-browser components with limited registered-provider acceptance | [Google integration](docs/guides/google.md) |
| Outbound OIDC issuer | Explicit experimental composition and independent Rust client; complete interoperable release remains gated | [Issuer setup](docs/guides/issuer-standalone.md) |
| Apple and provider account linking | Planned; matching email addresses never merge accounts | [Identity model](docs/architecture/domain-model.md) |

Feature compilation alone does not activate a provider. SAML's independent-review
prerequisite was explicitly waived under [ADR 0032](docs/architecture/adr/0032-saml-maintainer-directed-activation.md);
its unresolved assurance limits remain documented. Outbound OIDC interoperability
remains a release gate. See the [interoperability matrix](docs/guides/interoperability.md)
for the scope of recorded tests.

## Quick start

Install Rust 1.95, Docker Compose and a POSIX-compatible shell, then run:

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

Open [the local application](http://127.0.0.1:58417), enter a test email address,
then open [Mailpit](http://127.0.0.1:8025) and follow the sign-in link **in the same
browser profile**. No external email account is required. Links expire after ten
minutes; requesting another replaces that browser's pending binding.

Development services bind to loopback: PostgreSQL on `59473`, SMTP on `1025`,
Mailpit on `8025`, and the application on `58417`. These development credentials
and unencrypted local SMTP settings are for local use only. Non-development startup
requires HTTPS and TLS SMTP configuration; see [deployment](docs/architecture/deployment.md).

The binary supports `--help` and `--version` without configuration or database access.
See the [CLI guide](docs/guides/server-cli.md) for setup diagnostics.

## Embed in Axum

Crates are unpublished. Use workspace/path dependencies as shown in the
[embedded example](apps/auth-server/examples/embedded.rs), and run it with:

```sh
cargo run -p easy-auth-server --example embedded
```

The example adds a protected `/private` route to the same PostgreSQL/SMTP
application factory used by the standalone binary. `auth_axum::authenticate`
validates the local session; your application owns roles and business permissions.

The default browser integration is same-origin. Independent relying parties need
their own callback state and application sessions through the explicit
[issuer composition](docs/guides/issuer-standalone.md). Do not share issuer cookies
or use incoming provider ID tokens as local application sessions.

## Documentation

Start with the [documentation index](docs/README.md) for integration guides,
architecture, security evidence and research. Common references:

- [Sessions](docs/guides/sessions.md) and [account lifecycle](docs/guides/account-lifecycle.md).
- [Passwords](docs/guides/passwords.md) and [password recovery](docs/guides/password-recovery.md).
- [Architecture](docs/architecture/overview.md), [API contract](docs/architecture/api-contract.md) and [OpenAPI](docs/openapi.json).
- [Threat model](docs/security/threat-model.md) and [recorded verification](docs/security/verification.md).

The static documentation website is built from [website/](website/README.md).

## Development

With local services running and the environment loaded:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

Database tests use isolated real PostgreSQL databases and fail if PostgreSQL is
unavailable. See [CONTRIBUTING.md](CONTRIBUTING.md) for all-feature, browser and
security checks, including the required database connection budget.

Bug reports, documentation improvements and focused pull requests are welcome.
Read the [contribution guide](CONTRIBUTING.md) and [code of conduct](CODE_OF_CONDUCT.md).
Report vulnerabilities using the [security policy](SECURITY.md).

## License

Original project code is dual-licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option. Vendored dependencies and bundled
assets retain their own licenses and notices; see [third-party provenance](third-party/README.md).
