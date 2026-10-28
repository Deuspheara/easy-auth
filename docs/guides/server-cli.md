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
Only one option is accepted. Unknown arguments, positional values, combined options
and extra arguments exit with status 2 and a fixed diagnostic that omits their
values. Earlier versions ignored arguments; scripts must now invoke the server
without arguments to start it. There are no command-line credential options.

With no arguments, the existing environment-based startup runs. The binary does
not automatically load `.env`. Follow the [local setup](../../README.md#quick-start)
to start PostgreSQL and Mailpit, copy `.env.example`, and export its settings before
starting the binary. That file contains development-only credentials. Use a
disposable mailbox in Mailpit and open the sign-in link in the requesting browser.

The minimal settings are `AUTH_REALM_ID` (realm UUID), `DATABASE_URL` (PostgreSQL),
`AUTH_PUBLIC_URL` (the trusted public origin), and SMTP configuration.
`AUTH_BIND` defaults to `127.0.0.1:8080`. Explicit `AUTH_DEVELOPMENT=true` permits
only loopback HTTP/bind/SMTP configuration; production requires HTTPS and SMTP TLS.
The deployment guide describes [transport and startup policy](../architecture/deployment.md).
Help is usage information, not a configuration, database or provider health check.

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
| `AUTH_DEVELOPMENT must be true or false` | Use the exact lowercase value; production defaults to `false` |
| `development bind must be loopback` | Use a loopback listener for development |
| `development SMTP must be loopback` | Use the local development relay or configure production TLS |
| `SMTP_PORT must be a valid port number` | Use an unsigned 16-bit decimal port number |
| `SMTP_FROM must be a valid mailbox` | Correct the sender mailbox syntax |
| `SMTP_HOST cannot configure a TLS relay` | Check the relay hostname and TLS configuration privately |
| `<SETTING> must be valid Unicode` | Correct the environment's encoding; do not print the value in reports |
| `OIDC configuration requires the oidc-web server feature` | Build with `--features oidc-web` only when deliberately configuring the supported OIDC boundary |

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
| Apple | Not implemented; Apple client-secret, capability, callback/native and grant-lifecycle acceptance remain pending |
| SAML | Explicit `saml-web` and complete persisted HTTPS trust; [ADR0032](../architecture/adr/0032-saml-maintainer-directed-activation.md) waives independent review, which was not performed |
| Outbound OIDC issuer | Explicit `issuer-web` and protected matching persisted key; [standalone setup and bounded parity](issuer-standalone.md); production release/assurance gates remain separate |

Custom clients use the [public API contract](../architecture/api-contract.md),
preserving exact Origin, same-browser proof cookies and explicit confirmations.
Application authorization remains the embedding application's responsibility.
These CLI checks do not establish production readiness or provider interoperability.
