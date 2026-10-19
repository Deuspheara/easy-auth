# Owned Keycloak code-exchange acceptance

This explicit native suite uses the real PostgreSQL OAuth begin/consume/context
ports and core authorization/code/S256/signature verifier against official
Keycloak 26.8.1, pinned to the image digest in `keycloak.cjs`. It is separate from
ordinary Rust tests and is mandatory in CI after browser dependency setup.

Start the documented development PostgreSQL service and export its loopback
`DATABASE_URL`. Use Rust 1.95, Docker, OpenSSL CLI, Node 24 and the existing pinned
browser package; no new npm dependency or production provider account is needed:

```sh
npm ci --ignore-scripts --prefix tests/browser/passkeys
cd tests/browser/passkeys && npx --no-install playwright install chromium
cd ../../..
CARGO_INCREMENTAL=0 cargo build --locked -p easy-auth-server --example oidc-keycloak --features oidc-verification
node tests/browser/oidc/run.cjs
```

The runner owns a random loopback-only Keycloak container, random bootstrap/client/
user credentials, private temporary directory, TLS proxy, isolated Chromium
contexts and random PostgreSQL database. The application runtime has no fixture
endpoint or setting. Do not deploy the example or run its private IPC directly in
a terminal/log. Never capture IPC, browser storage, response bodies, traces,
screenshots, headers, provider assertions, passwords or codes. Ordinary output
contains only finite case outcomes, versions, aggregate counts and cleanup facts.

The example recompiles the same internal production TLS builder, GET/POST and
bounded response readers without widening their API. Only its private transport
maps the core's checked fixture hostname/address to its owned TLS listener and
certificate. Rust still validates hostname/SNI, certificate, peer, time/body/type
limits and redirect/proxy policy. Chromium's disposable context tolerates only the
fixture certificate in practice because all traffic is constrained to the owned
provider and intercepted callback. The host resolver and proxy arguments apply to
that owned browser process only; no hosts file, system security setting, credential
manager or user browser is changed.

Administrative provisioning and the exact captured code/verifier replay use the
owned loopback provider backend; actual application metadata/code requests use
the production HTTPS sources through the owned TLS proxy.

The required cases cover actual code+S256/RS256 identity proof; exact PostgreSQL
consumed-state and original provider-code/verifier replay; actual provider-signed
wrong nonce and untrusted additional audience; wrong PKCE; deliberate proxy
signature corruption and old-token substitution; actual Keycloak signing-key
rotation; a fresh valid control after negatives; and disabled database context
before credential transmission. Missing provider email claims remain valid and
create no local contact/session. The disposable provider user has a complete
profile, while this client requests only openid/profile and has no email scope.

Between distinct operations the runner observes the unchanged one-second metadata
miss budget. It preserves actual provider discovery/JWKS cache headers. Keycloak's
no-store keys mean the real rotation case does not prove the forced-refresh cache
branch; separate actual-signature/cache tests prove that bound. Controlled signature
corruption and captured-token substitution happen at the owned proxy, never inside
Keycloak; other invalid claims are actually signed by the provider. These facts
must remain distinct in any evidence or interoperability claim.

Normal completion requires native zero exit, exact aggregate zero local users/
sessions/audits/pending transactions, normal owned database removal and provider/
private-file cleanup. Timeout cleanup can remove only the exact generated database
and owner-labeled container; emergency cleanup never converts a failed suite to a
pass. No external-provider credentials, independent security audit, final local
identity/session grant or production interoperability is established by this suite.

`EASY_AUTH_OIDC_TEST_BINARY` can select a fixed owned producer copy.
`EASY_AUTH_TEST_REPORT` creates a new immutable sanitized report with versions,
source/binary hashes, case outcomes and cleanup facts; it refuses to overwrite an
existing file. Reports contain no raw token, account IDs, credentials or proof.
