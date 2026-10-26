# Deployment design

The [default container walkthrough](../guides/containers.md) uses committed public
source, a nonroot distroless image and a separate disposable loopback stack. Probe
its actual HTTP health/readiness externally; container-running is not readiness.
The [backup guide](../guides/backups.md) and [client examples](../guides/minimal-clients.md)
record their operational limits. [ADR0046](adr/0046-default-container-and-client-examples.md)
preserves development bind/SMTP checks and the separate release gates.

One auth-server process, PostgreSQL and a configurable SMTP relay. Compose development starts PostgreSQL and Mailpit with loopback-only ports and disposable development credentials. Production requires HTTPS at a trusted reverse proxy, private database access, SMTP TLS, persistent database backups and protected environment/file secrets. No Redis or Node runtime required.

Start `easy-auth` without arguments after exporting configuration. `--help`/`-h`
and `--version`/`-V` print static information without configuration or database
access. Extra or unsupported arguments fail with status 2 and omit their values.
See [CLI setup diagnostics](../guides/server-cli.md); these options do not validate
configuration or establish readiness.

`easy-auth migrate` is a separate one-shot administration command requiring only
the migration role's private `DATABASE_URL`. Normal configured startup defaults to
`AUTH_DATABASE_MIGRATIONS=run` for compatibility; separately migrated deployments
can select exact `verify` with runtime credentials. Verification checks complete
SQLx history/checksums before realm initialization and serving, without DDL or a
migration fallback. Use the [role procedure](../guides/database-roles.md) for grants,
timeouts, failure handling and the limits of this implementation evidence.

Typed startup validation rejects production HTTP, public development HTTP, malformed public URLs and unsafe SMTP configuration. Bind loopback by default; proxy headers are not trusted to select origins, realms, secure cookies or identity. The configured public URL is authoritative. A production proxy must enforce body/time/connection limits and forward only the intended host; application limits also apply. Migration runs before readiness, fails closed, and must have backup/restore compatibility tests before a release.

Sessions and challenges remain durable across processes. Admission counters use database atomicity and a database clock; service replicas must not introduce local-only revocation or rate-limit semantics. SMTP delivery cannot be rolled back with database transactions; tokens remain expiring and require browser binding. A durable encrypted delivery outbox is a later reliability improvement, not a reason to store plaintext session secrets.

Graceful shutdown drains requests. Structured logs include safe event names/request IDs and opaque identifiers only. Never trace raw headers, URLs containing credentials, email contents, passwords, tokens, assertions or provider client secrets. Health is liveness; readiness checks the database. Metrics use bounded labels, no user/email/client-generated labels.

Before production: define retention/cleanup schedules for expired challenges, rate counters and revoked sessions; encrypted backups, least-privilege runtime and separate migration roles, tested restoration, rolling migration procedure, secret/signing-key rotation and incident revocation runbook. These are M09 release requirements, not current operational guarantees.

## Explicit OIDC browser startup

Build `easy-auth-server` with `--features oidc-web` and use the shared
`configured_application` factory, as both the normal binary and embedded example
do. Its public result contains auth, browser configuration, router and bind address;
the application owns its listener and notification worker. The existing
`configured_auth` API remains auth-only and refuses enabled OIDC browser settings
rather than silently discarding requested routes. No settings (or only
`AUTH_OIDC_ENABLED=false`) retain default composition. Any other `AUTH_OIDC_*`
setting requires explicit activation and complete supported configuration.

| Setting | Contract |
| --- | --- |
| `AUTH_OIDC_ENABLED` | Exact `true` to activate; absent is disabled |
| `AUTH_OIDC_CONNECTION_ID` | Required stable non-nil UUID |
| `AUTH_OIDC_LOCAL_CLIENT_ID` | Required stable non-nil UUID; preserves the identity namespace |
| `AUTH_OIDC_ISSUER` | Required exact HTTPS issuer; it is also the sole tenant issuer allowlist entry |
| `AUTH_OIDC_PROVIDER_CLIENT_ID` | Required exact registered provider client |
| `AUTH_OIDC_ALLOWED_ORIGINS` | Required comma-separated exact HTTPS origins for issuer/discovery/token/JWKS egress, bounded to eight by core |
| `AUTH_OIDC_CLIENT_AUTH_METHOD` | Required explicit `none`, `client_secret_basic` or `client_secret_post`; no discovery-selected fallback |
| `AUTH_OIDC_CLIENT_SECRET_FILE` | Required only for a confidential method; forbidden with `none` |
| `AUTH_OIDC_SIGNING_ALGORITHMS` | Required comma-separated nonempty distinct subset of `RS256,PS256,ES256` |
| `AUTH_OIDC_DISPLAY_CLAIM` | `sub` by default; explicit `name` or `preferred_username` requests profile display metadata |
| `AUTH_OIDC_JIT` | `deny` by default; explicit `allow` permits new provider-only owners without email linking |
| `AUTH_OIDC_MIXUP_DEFENSE` | `issuer` by default; deliberate `dedicated_redirect` selection retains global exact callback uniqueness |

`AUTH_PUBLIC_URL` must be HTTPS even in development. The callback is exactly its
origin plus `/oidc/callback`; no OIDC redirect override is supported. OIDC fields, URLs,
policy, bounded file content and compiled support are validated before database
loading/listening. Unknown, partial, invalid Unicode and oversized settings fail
closed with credential-free errors. Private-root/address/proxy/insecure overrides,
raw client-secret environment settings, dynamic tenant templates and additional
provider audiences are not accepted. Normal transport uses the existing public-root,
DNS/address-bound, redirect-free `OidcHttps` adapter; startup performs no provider
request and database readiness does not establish provider availability.

A client-secret file must be a regular bounded UTF-8 file containing the existing
core secret format (1–4096 bytes, no control characters), with at most one final LF
or CRLF removed. Unix mode must deny group/other access (for example 0600 or 0400).
Protect its directory and platform ACLs; startup does not inspect Windows ACLs.
File paths/content and authentication values are never returned in public schemas
or persisted in policy rows. A missing or invalid secret never makes a confidential
client public. Credential loading does not rotate identity authority; coordinate
provider-side rotation separately and use administrative revision changes when
old sessions/contexts must be invalidated.
The persisted equality check covers the OAuth connection and identity-mapping/JIT
policy. Egress allowlists, accepted signing algorithms and client-auth credentials
remain trusted process settings, not fields in those policy rows. Coordinate them
across replicas and explicitly rotate the connection revision before changing
verification trust when prior contexts/sessions must be invalidated; a local setting
change alone is not a persisted revocation event.

Startup only loads an exact unchanged enabled policy or atomically provisions a
genuinely absent one. It preserves the actual stored revision and operator disable.
Mismatch, existing generic OAuth configuration, corrupt storage and database errors
fail startup; no automatic reconfiguration, adoption, repair or re-enable occurs.
Explicit administration owns definition/revision changes and callback registration
migration. Keep the same realm/connection/local-client identifiers on restart.

Local startup regression uses normal binaries, PostgreSQL and owned synthetic secret
files without a provider exchange or seeded user/session:

```sh
CARGO_INCREMENTAL=0 cargo build --locked -p easy-auth-server --bin easy-auth
cp target/debug/easy-auth /tmp/easy-auth-oidc-disabled
CARGO_INCREMENTAL=0 cargo build --locked -p easy-auth-server --bin easy-auth --example embedded --features oidc-web
EASY_AUTH_OIDC_UNSUPPORTED_TEST_BINARY=/tmp/easy-auth-oidc-disabled python3 scripts/smoke_oidc_startup.py
```

Use the documented development database/Mailpit setup; CI provides its owned service
container. The script drops only its random database and removes its private file.
These checks are not Keycloak public-login, production-provider, independent-review
or release-readiness evidence. AUTH-56's separate [owned public-flow suite](../guides/oidc-web.md#owned-public-flow-evidence)
now records sign-in/lifecycle acceptance through both composition modes with explicit
private-TLS/source-copy limits. Final exact-head hosted CI and broader release gates
remain explicit.

## Opt-in SAML composition

Compile `saml-web` and use `configured_application` for standalone/embedded routing.
Unset SAML settings or only `AUTH_SAML_ENABLED=false` keep routes absent. Explicit
true requires complete HTTPS configuration and matching already-provisioned enabled
registration/JIT with active certificate pins. Startup is read-only for SAML;
there is no automatic trust import, rotation, provisioning or re-enable.
The [configuration guide](../guides/saml.md#normal-server-configuration) and
[release guide](../guides/saml-release.md) document operator inputs and resource
limits. [ADR0032](adr/0032-saml-maintainer-directed-activation.md) records the
maintainer's independent-review waiver and unresolved assurance limitations.

## Explicit outbound issuer startup

The server `issuer-web` feature and complete `AUTH_ISSUER_ENABLED=true` settings
select the existing issuer services through the same `configured_application` used
by the executable and embedding. Require trusted HTTPS public origin, stable realm
and protected current matching key input; startup performs no issuer provision or
enable writes. Current enabled registry/key and exact public material must match
before binding a listener. Client/native/consumer policy remains request-time
persisted authority. The optional authenticated native inspection route requires
its own explicit boolean setting. Old auth-only consumers refuse enabled issuer
settings. Default routes remain absent. See [setup, rollover and bounded acceptance](../guides/issuer-standalone.md).

Owned parity uses disposable PostgreSQL, local SMTP and a private TLS proxy, not a
live deployment. Public DNS/system-root operation, platform vault integration,
independent assurance and production operations remain separate. Compiling or
passing these checks is not production approval. SAML ADR0032 review waiver stays
explicit and does not approve any other boundary.
