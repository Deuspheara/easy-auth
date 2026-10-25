# ADR0040: Independent OIDC client and configured standalone composition

Status: accepted; full verification and exact-source CI are recorded separately.

## Context

An unrelated relying party needs its own authorization operation, discovery and
signature verification. A provider cookie, server-side OAuth transaction or local
session cannot supply this authority. Embedded and standalone issuer delivery must
share the existing core policy, PostgreSQL transactions and HTTP handlers.

## Decision

Keep the four workspace crates. The optional core `oidc-client` feature exposes an
independent `OidcClient`, immutable trusted configuration, an opaque non-cloneable
pending operation, finite redacted errors and verified RP metadata. It reuses the
existing bounded discovery/JWKS retrieval, public-address policy and maintained
josekit/OpenSSL RS256 implementation. Client results have no conversion to a
server-side exchange, provider completion proof or local session.

Require S256, private random state/nonce/verifier, exact configured callback and
response issuer before any code POST. Bind the retained operation to its originating
service and both a monotonic deadline and wall-clock cap. Consume it on every
completion result. Send a code once, with explicit configured client authentication;
never select a weaker method from discovery or retry an ambiguous POST. Validate
current issuer, audience, nonce and token times using the existing claim policy.
Re-fetch admission-sensitive documents through the shared bounded cache rules.

Native configuration reuses the issuer's exact literal loopback policy and requires
the caller to bind the listener first. Native refresh consumes one credential by
value, sends once, requires a replacement and returns credentials only. Refresh
creates no new ID token, identity or authentication time. Rust ownership reduces
accidental reuse; it cannot prevent a caller copying an explicitly exposed secret.

Transport remains an explicit trusted boundary using the existing `OidcHttp` and
`OidcTokenHttp` ports. Use the same concrete `OidcHttps` instance for both to retain
shared resource limits. No private-address, custom-root or plaintext production
fallback is introduced. Owned acceptance transports remain test-only evidence.

The server `issuer-web` feature adds explicit default-off issuer composition through
`configured_application`, shared by embedded consumers and the binary. Complete
HTTPS configuration and a protected operator key must match the enabled current
persisted key, including realm/issuer/public material. Startup provisions/enables no
issuer registry or client. Optional native consumer introspection requires another
explicit setting and exact persisted consumer policy. Trusted inbound providers
attach around the same issuer handlers and retain independent realm/source policy
and cleanup. Owned actual executable/embedded, PostgreSQL, SMTP, browser, Node and
Rust-client acceptance demonstrate bounded parity, not public-TLS or certification.

## Consequences and limits

The SDK supports this issuer's bounded RS256 code profile and exact `openid` or
native `openid offline_access` scope. It is not a generic provider compatibility or
OIDC certification claim. The application owns its own session, authorization,
clock synchronization, callback listener and protected per-user credential storage.
ID tokens remain bounded snapshots; refresh does not renew their login metadata.
No registry provisioning, migration, custom crypto or new runtime dependency is
needed for the client. Independent security review and production acceptance are
separate gates. SAML's ADR0032 review waiver is unchanged.
