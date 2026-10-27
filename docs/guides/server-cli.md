# Server command line and setup

Build with Rust 1.95 from the repository root:

```sh
cargo build --locked -p easy-auth-server --bin easy-auth
./target/debug/easy-auth --help
./target/debug/easy-auth --version
```

`--help` (`-h`) and `--version` (`-V`) exit successfully without reading application
configuration, opening a database, running migrations or starting a listener.
Version reports the Cargo package version, not a Git revision or provider status.
The separate `migrate` and `retention` commands are described below. Only one command/option is accepted.
Unknown arguments, positional values, combined options
and extra arguments exit with status 2 and a fixed diagnostic that omits their
values. Earlier versions ignored arguments; scripts must now invoke the server
without arguments to start it. There are no command-line credential options.

With no arguments, the existing environment-based startup runs. The binary does
not automatically load `.env`. Follow the [local setup](../../README.md#run-locally)
to start PostgreSQL and Mailpit, copy `.env.example`, and export its settings before
starting the binary. That file contains development-only credentials. Use a
disposable mailbox in Mailpit and open the sign-in link in the requesting browser.

The minimal settings are `AUTH_REALM_ID` (realm UUID), `DATABASE_URL` (PostgreSQL),
`AUTH_PUBLIC_URL` (the trusted public origin), and SMTP configuration.
`AUTH_BIND` defaults to `127.0.0.1:8080`. Explicit `AUTH_DEVELOPMENT=true` permits
only loopback HTTP/bind/SMTP configuration; production requires HTTPS and SMTP TLS.
The deployment guide describes [transport and startup policy](../architecture/deployment.md).
Help is usage information, not a configuration, database or provider health check.
For a disposable first run, use the [clean-checkout walkthrough](setup-walkthrough.md).

## Schema administration

`easy-auth migrate` uses only `DATABASE_URL` to apply the embedded SQLx migrations,
then exits with `database migrations completed`. It starts no listener, mail worker
or provider composition. Supply the migration role's connection setting through a
protected environment; there are no credential arguments. Missing/invalid settings,
connection failures and migration errors fail with fixed diagnostics.

Normal executable and embedded startup accept `AUTH_DATABASE_MIGRATIONS=run|verify`.
The default `run` preserves automatic migration. Select exact `verify` with a
separate runtime role after administration: it checks the complete embedded migration
history/checksums without creating history or applying DDL. Missing, dirty, future
or mismatched history fails startup without a migration fallback. Empty, unknown,
case-changed and non-Unicode values are rejected. Verification is not a full schema
drift or privilege audit. Normal auth operations and realm initialization need DML.

See [database role and migration procedure](database-roles.md) for grants, lock-wait
limits, disposal tests and upgrade limitations.

## Retention maintenance

Explicit `easy-auth retention` instead runs one finite cleanup pass and exits.
It requires protected database configuration, a non-nil realm and explicit
`AUTH_RETENTION_AUDIT`/`AUTH_RETENTION_NOTICES` choices (`keep` or supported whole
seconds). It verifies the current schema without migration fallback and starts
no runtime services. Categories commit independently; failures can follow earlier
commits. See [retention maintenance](retention.md) for exact effects, preserved
state, scheduling and exact bounded local qualification.

## Startup diagnostics

Malformed values produce setting-specific diagnostics without echoing values.
Environment settings must be valid Unicode. An invalid-Unicode value now fails
startup instead of selecting a default or treating SMTP credentials as absent;
unset values retain their documented defaults. Password blocklist and OIDC secret
file checks retain their existing bounds and policy. These diagnostics are shared
by the standalone binary and embedded application factory. Error text has changed;
operators should not use parser/debug messages as a stable machine-readable API.

| Startup diagnostic | Check |
| --- | --- |
| `invalid command line; run easy-auth --help` | Remove extra/unsupported arguments; supply settings through the environment |
| `AUTH_REALM_ID is required` | Export a stable realm UUID before starting |
| `AUTH_REALM_ID must be a UUID` | Correct the configured UUID syntax |
| `AUTH_BIND must be a socket address` | Use a literal IP address and port, such as `127.0.0.1:8080` |
| `AUTH_PUBLIC_URL must be an allowed origin (HTTPS, or loopback HTTP in development)` | Use the trusted origin without credentials, path, query or fragment |
| `DATABASE_URL is required` | Export the database connection URL without putting it in arguments or logs |
| `database connection failed` | Check the configured database service, connectivity and role permissions privately |
| `database migration failed` | Stop administration and investigate privately; never edit migration history to force success |
| `AUTH_DATABASE_MIGRATIONS must be run or verify` | Use one exact supported value; verification never falls back to DDL |
| `AUTH_DEVELOPMENT must be true or false` | Use the exact lowercase value; production defaults to `false` |
| `development bind must be loopback` | Use a loopback listener for development |
| `development SMTP must be loopback` | Use the local development relay or configure production TLS |
| `SMTP_PORT must be a valid port number` | Use an unsigned 16-bit decimal port number |
| `SMTP_FROM must be a valid mailbox` | Correct the sender mailbox syntax |
| `SMTP_HOST cannot configure a TLS relay` | Check the relay hostname and TLS configuration privately |
| `<SETTING> must be valid Unicode` | Correct the environment's encoding; do not print the value in reports |
| `OIDC configuration requires the oidc-web server feature` | Build with `--features oidc-web` only when deliberately configuring the supported OIDC boundary |
| `unknown AUTH_OIDC setting` / `unknown AUTH_SAML setting` / `unknown AUTH_ISSUER setting` | Correct the setting name against the selected startup contract; no unknown override is accepted |
| `OIDC requires AUTH_OIDC_ENABLED=true and a complete configuration` | Supply a complete explicit definition, or remove the other OIDC settings when disabling it |
| `SAML requires AUTH_SAML_ENABLED=true and a complete configuration` | Supply the complete explicit SAML definition, or leave only `AUTH_SAML_ENABLED=false` |
| `SAML configuration requires the saml-web server feature` | Build the deliberately selected SAML boundary; compiling it does not provision trust |
| `SAML browser composition requires HTTPS` | Configure the trusted HTTPS public origin; development mode does not relax this provider boundary |
| `issuer configuration requires the issuer-web server feature` | Build the explicitly selected outbound issuer composition |
| `issuer signing key input is unavailable or invalid` | Check the protected operator file privately; do not print the path, contents or foreign parser error |
| `issuer requires an enabled current persisted signing key` | Provision and approve the exact intended key through trusted administration; startup will not enable or repair policy |
| `issuer signing key does not match the current persisted public key` | Match the protected input to the current persisted key; do not install an old-key fallback |

Startup can run migrations and provision the configured realm. Back up persistent
data and review the [deployment requirements](../architecture/deployment.md) before
running against an existing database. Do not paste environment dumps, connection
URLs, callback queries, tokens or private file contents into diagnostic reports.

## Provider and UI boundaries

The ordinary server offers the current email/session flows. Passwords require the
explicit [password corpus setup](passwords.md). Optional components require their
documented construction and acceptance gates; compiling a feature is not provider
validation or permission to enable another authentication path.

| Integration | Current setup reference and limit |
| --- | --- |
| Enterprise OIDC | [Browser settings](oidc-web.md) and [startup contract](../architecture/deployment.md#explicit-oidc-browser-startup); exact HTTPS issuer/callback and explicit client authentication |
| Google web/native | [Component and acceptance guide](google.md); experimental components/examples do not activate Google in ordinary server startup; registered-provider/OS/lifecycle evidence remains required |
| Passkeys/custom UI | [Enrollment](passkey-enrollment.md), [sign-in](passkey-authentication.md) and [management/recovery](passkey-management.md); preserve RP/origin, browser proof and stronger-account policy; ordinary activation remains gated |
| Apple | [Experimental backend and account preparation](apple-setup.md); no startup contract or ordinary routes; registered web/native and remote-provider acceptance remain pending |
| SAML | Explicit `saml-web` and complete persisted HTTPS trust; [ADR0032](../architecture/adr/0032-saml-maintainer-directed-activation.md) waives independent review, which was not performed |
| Outbound OIDC issuer | Explicit `issuer-web` and protected matching persisted key; [standalone setup and bounded parity](issuer-standalone.md); production release/assurance gates remain separate |

Custom clients use the [public API contract](../architecture/api-contract.md),
preserving exact Origin, same-browser proof cookies and explicit confirmations.
Application authorization remains the embedding application's responsibility.
These CLI checks do not establish production readiness or provider interoperability.

Use [integration selection](provider-setup.md) to choose the provider/native/RP
boundary and [custom UI integration](custom-ui.md) for first-party pages. The
normal binary and embedded `configured_application` factory share validation and
policy. An auth-only `configured_auth` consumer refuses enabled provider/issuer
settings instead of silently discarding requested routes.
