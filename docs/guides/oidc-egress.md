# Experimental OIDC document client

The explicit `oidc-egress` feature provides bounded, configured discovery/JWKS
fetching in core/PostgreSQL and the server library. It has no HTTP route, token
exchange, JWT verifier or authentication result. See
[ADR 0014](../architecture/adr/0014-oidc-egress.md) for policy, limits and caveats.

Trusted composition provisions the realm and calls
`Postgres::configure_oauth_connection`. Use the **returned** current snapshot to
construct `OidcDocuments` with the PostgreSQL port, a shared `OidcHttps` adapter and
an explicit canonical HTTPS origin allowlist. Include the issuer origin and all
approved authorization/token/JWKS origins, including their effective ports.
No wildcard, request-selected origin or private-network fallback exists.

Keep one shared adapter and one document service per persisted context. An origin
policy change must reapply configuration, obtain a fresh revision and replace the
service. This invalidates old holders; constructing a new policy object alone is
not an administrative configuration update. Reconfiguration preserves a prior
disable, and re-enable remains an explicit current-revision operation.

`discovery()` constructs the well-known URI, checks all DNS answers and pins them
into a strict TLS client. It preserves the hostname for Host/SNI/verification,
validates the exact issuer and checks each endpoint against the origin/port list.
`supports_s256()` and `supports_response_issuer()` report metadata; they do not grant
assurance or choose a weaker flow. Missing S256 cannot justify a `plain` fallback.

`jwks()` returns an `OidcJwksDocument` with a bounded original JSON envelope. Debug
is redacted; use `as_bytes()` only at the reviewed backend verifier boundary. Known
private/symmetric key parameters are rejected before caching. A successful fetch
does not establish a valid algorithm/key/signature/claim or provider identity.
The optional [signature/claim verifier](oidc-verification.md) rejects ambiguity and
validates required token claims; final authentication commit must recheck current configuration/deadlines.
Do not log response bodies, target URLs, headers or raw HTTP errors.

Two cache slots are scoped to the immutable realm/connection/client/revision.
Cache reuse requires explicit supported HTTP freshness, capped at five minutes;
Age/body-read time reduces it. There is no stale fallback. Failed/non-cacheable
misses also spend a one-second retry interval; concurrent misses or exhausted
transport capacity return RateLimited. Disabled/stale configuration returns
Unauthorized before cached data or network access; database/network/protocol
failures return Unavailable. None of these outcomes authenticates a user.

The whole operation has a five-second deadline and the shared adapter permits four
operations. Native DNS jobs cannot be killed by an async timeout; they retain their
permit until completion, including after cancellation. This prevents detached-job
growth but can delay runtime shutdown or exhaust the bounded resolver capacity.
There is no production readiness/load claim. Origins resolving to private,
link-local, transition, documentation or conservatively excluded special-use space
remain unusable, even if explicitly listed. The adapter uses public WebPKI roots;
private-CA/internal-IdP deployment policy is not implemented by this feature.

Focused checks with the documented PostgreSQL setup:

```sh
cargo test --locked -p easy-auth-core --features oidc-egress oidc::
cargo test --locked -p easy-auth-server --lib --features oidc-egress oidc_http::
cargo test --locked -p easy-auth-postgres --features oidc-egress --test lifecycle oidc::
```

Run workspace default/all-feature database variants sequentially. TLS tests use
owned loopback fixtures and test-only roots inside the private adapter component;
the public address guard has no test escape. A cold child scopes proxy environment
variables to itself and verifies a real direct request without process-global TLS
initialization. No system proxy/security setting, credential manager or user
credential is changed. Real provider/browser/native interoperability remains
subsequent acceptance work; normal server composition activates no provider flow.


The document primitive `refresh_jwks(&observed)` supports the future
verifier's unknown-key path. Supply the prior `OidcJwksDocument`, not a URL or key
ID. An already completed newer fresh snapshot is reused; otherwise a forced attempt
requires the fixed 30-second refresh budget and ordinary one-second miss interval.
Failure spends the refresh budget and returns an error without old-data fallback.
A caller immediately retrying a cold fetch can receive RateLimited. Normal cache
expiry still follows the ordinary miss interval. Share the document service to
share these limits; recreating it per request defeats the intended resource policy.
No token verification or automatic retry loop is provided by this method.

Trusted startup can call `OidcDocuments::validate_configuration(&connection,
&origins)` before provisioning services. It reuses the constructor's private URL/
egress metadata policy, performs no DNS/HTTP/database I/O and establishes no current
enable/revision or identity authority. The actual document constructor still
validates its inputs, and every operation retains existing current-source, address,
cache and deadline checks. The server factory uses this metadata check before
its stable identity-policy loader; no development root/address override is added.
