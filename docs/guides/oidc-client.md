# Independent Rust OIDC client

The optional `easy-auth-core/oidc-client` component provides discovery, a bounded
S256 authorization-code operation, callback correlation, RS256 token verification
and native credential rotation. Owned standalone/embedded parity is covered separately in the
[acceptance guide](issuer-standalone.md); library operations alone do not establish
production approval.

Create `OidcClientConfiguration::web` with the exact trusted HTTPS issuer, registered
UUID client, canonical HTTPS return and explicit Public or ClientSecretBasic method.
Secret POST is unsupported. For a public native client, bind an actual literal
loopback socket first, then pass its address and registered path to `::native`.
Request offline access only when the matching persisted native policy permits it.
Provision registrations, credentials, policies and signing keys separately.

Pass the same maintained `easy-auth-server::OidcHttps` instance to both HTTP ports
of `OidcClient::new`. The transport owns DNS pinning, TLS, redirect/proxy refusal and
resource bounds. An arbitrary implementation of these trusted ports can invalidate
those guarantees. There is no production private-address or local-CA override.
Enable the server `oidc-client` feature to use its discovery and token ports.

Call `authorize()`, retain its opaque non-cloneable operation privately, and direct
the user's system browser to `authorization_url()`. Retain pending state in memory;
never put it in URLs, logs, web storage or an unprotected file. Pass the actual
received callback URL and move the operation into `complete()`. It checks the exact
return, fixed query, response issuer and state before sending a code. Operations
expire after five minutes and belong to one service instance. Do not share the
issuer's browser session cookie with the relying party.

A successful result contains verified pairwise RP metadata and opaque credentials.
It is not an easy-auth local session or an application permission. The application
must establish its own bounded session and authorization policy. The SDK checks
issuer, audience, nonce, fixed RS256 signature, issuance/expiry and original pending
caps; it does not infer email ownership or automatically link accounts.

Use `take_refresh_token()` to move a native generation into `refresh()`. A successful
refresh returns replacement access/refresh credentials with conservative expiry
computed from request start. It returns no new identity, ID token or authentication
time. Atomically replace the old generation in protected per-user OS storage; the
SDK supplies no platform vault. Restoring a stored credential with
`OidcClientCredential::parse` validates its encoding only, not authority. Never
persist raw tokens in logs, browser storage, command arguments or examples.

Every exchange/rotation makes at most one POST. On timeout, cancellation, storage
failure after success or any ambiguous transport result, discard the old operation
or refresh generation and begin a new authorization. Retrying a consumed native
generation permanently revokes its server-side family. Redacted finite errors
separate callback/denial/expiry, invalid client/grant/token, protocol, admission and
availability failures without returning remote diagnostic text or credentials.

Use the explicit `expose()` boundary only for protected transport or vault storage.
Ownership cannot prevent an application deliberately copying a secret. Access and
identity metadata have separate expiries; a refresh does not extend an existing
application login. Current server-side revocation/source/tenant checks still apply.
The client supports the easy-auth issuer profile, not arbitrary OIDC providers or
an independent audit/conformance certification. See [ADR0040](../architecture/adr/0040-independent-oidc-client-and-standalone.md).
