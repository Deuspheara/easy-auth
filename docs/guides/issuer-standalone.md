# Explicit standalone OIDC issuer and independent clients

Build the server with `--features issuer-web`. Unset issuer settings, or only
`AUTH_ISSUER_ENABLED=false`, keep issuer routes absent. The same
`configured_application()` composes the executable and embedded router. The older
`configured_auth()` refuses enabled issuer settings so consumers cannot silently
omit the selected boundary.

| Setting | Meaning |
| --- | --- |
| `AUTH_ISSUER_ENABLED=true` | Explicitly select issuer HTTP composition |
| `AUTH_PUBLIC_URL` | Exact trusted HTTPS root issuer and browser origin |
| `AUTH_REALM_ID` | Exact persisted realm |
| `AUTH_ISSUER_KEY_ID` | Nonzero UUID of the current active persisted signing key |
| `AUTH_ISSUER_KEY_FILE` | Protected operator PKCS#8 file matching that exact public key |
| `AUTH_ISSUER_NATIVE_INTROSPECTION_ENABLED` | Optional exact `true`/`false`, defaults false; mounts authenticated native consumer inspection |

Unknown, duplicate, malformed, partial, non-Unicode or inert extra issuer settings
fail startup. An enabled configuration in a build without `issuer-web` fails before
a database connection. HTTPS remains mandatory even with development SMTP.

Provision clients, native refresh/consumer policies and key publication/activation
through the existing trusted administration API before startup. Startup requires an
enabled current signing registry/key whose public material matches the protected
file, including exact realm and issuer. It makes no issuer enable/provision writes.
Normal migration/realm initialization follows existing server policy. Unix key
loading enforces a regular owner-only file and refuses final symlinks; control its
parent directories, owner and distribution. Unsupported platforms fail closed.
There is no default/generated startup key, stored private key or old-key fallback.

The optional composition serves existing discovery/JWKS, explicit consent,
code/token, access status/revocation and native refresh routes. Actual persisted
client profile/policy decides each request. Native policy installation or compiling
a feature grants no consent. Consumer introspection needs both its explicit route
setting and exact enabled persisted reader/audience permission; public identity and
cookies cannot authenticate it. Every current cryptographic/source/session/key/
PKCE/correlation/replay/realm/clock check remains in its owning feature module.

Inbound OIDC/SAML can be explicitly selected alongside issuer delivery. Their exact
persisted configuration, HTTPS callbacks, provider trust, lifecycle and realm checks
remain independent. One router/combined contract uses existing handlers and wraps
all selected routes with the required proof cleanup. SAML independent review was
waived under ADR0032, not performed. No trust is inferred from the combined router.

Key publication/rollover is operator managed. Restart with the new exact active
private key after coordinating the existing propagation/overlap policy. A current
key change unsupported by the running signer fails issuance; it cannot silently
select the old key. Retained public keys remain governed by persisted publication
windows. No automatic hot reload or secret rotation service is provided.

Use [the Rust SDK](oidc-client.md) with its own callback state and application
session. Do not share issuer cookies with unrelated applications. Applications own
business authorization and protected per-user credential storage.

## Bounded owned acceptance

With the documented local PostgreSQL/Mailpit services and installed browser runtime:

```sh
cargo build --locked -p easy-auth-server --features issuer-web,oidc-client --bin easy-auth --example issuer-client-acceptance
node tests/browser/issuer-standalone/run.cjs
```

Supply the normal local `DATABASE_URL` privately. The runner creates a random owned
database, ordinary ephemeral operator keys and private TLS files. It runs the actual
binary and embedded factory in separate processes with identical trusted settings.
Both perform real SMTP email sign-in and browser confirmation, then independent
cookie-free HTTPS Node, Rust and pinned third-party `openid-client` clients fetch
actual discovery/JWKS and verify production-issued tokens. The third-party RP
explicitly enables JWS verification, rejects wrong state before any code POST and
checks ordinary tokens before/after rollover. The [2026-10-27 local acceptance
extension](../security/outbound-oidc-acceptance-2026-10-27.md) records eighteen true
facts per mode and the still-open outbound release/independent-review gates. Replay, bound denial without POST, access/local-session
separation, browser privacy and logout are checked in both modes. It also sends an SDK native authorization through an actual already-bound
loopback listener, rotates its credential once and verifies logout refuses another refresh.
It checks normal fixture-parent exit, database removal, exact owned mail removal
and private-file cleanup.
The same suite prepublishes one ordinary replacement key, waits the unchanged
300-second policy plus a one-second margin in each mode, and genuinely signs in
again. It issues and verifies healthy tokens before and after explicit activation
and restart with the exact protected replacement file. Independent Node verification
checks retained overlap and rejects a different trusted audience expectation against
the unchanged healthy token. The same Rust client verifies both sides of rotation.
No pending operation spans the wait and no ready-at/authentication timestamp is
rewritten. The two-mode suite therefore takes at least ten minutes.

The child is forcibly stopped for fixture teardown; graceful shutdown is not tested.

The unchanged owned TLS transport substitutes only its local address/certificate;
it retains hostname/SNI/peer checks and production request/response readers. It is
not a public DNS/system-root test or production network override. The independent
Node test uses maintained Node crypto for normal verification, not certification or
new adversarial fixtures. No external production credentials are required. These
checks establish bounded implementation evidence only. Independent review,
production operations and broader release requirements remain separate.
