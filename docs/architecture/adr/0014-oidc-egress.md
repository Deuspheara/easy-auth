# ADR 0014: Constrained OIDC document egress

Date: 2026-10-19. Status: accepted for the optional AUTH-28 core/PostgreSQL/HTTPS
boundary. This decision does not activate provider authentication or establish
OIDC interoperability, independent security review or production readiness.

## Context

Discovery and JWKS are untrusted network input. Validating a hostname and then
letting the HTTP client resolve it again permits DNS rebinding. Redirects, ambient
proxies, unchecked ports, compressed/oversized responses and stale configuration
can bypass an otherwise correct issuer check. Metadata and a public-key envelope
are not proof of a provider identity. AUTH-23 must reuse this boundary rather than
introducing a separate permissive Google HTTP client.

Sources: [OIDC Discovery sections 4–5](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig),
[reqwest 0.13.5 ClientBuilder](https://docs.rs/reqwest/0.13.5/reqwest/struct.ClientBuilder.html),
the [IANA IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry) and
[IPv6 special-purpose registries](https://www.iana.org/assignments/iana-ipv6-special-registry),
and [RFC 7518 key parameters](https://www.rfc-editor.org/rfc/rfc7518.html#section-6).
The registries were reviewed on 2026-10-19 and report an update date of 2025-10-09.

## Decision and ownership

Keep the four existing crates. The explicit `oidc-egress` feature adds core policy,
typed metadata, a redacted public-JWKS document, bounded caches and two concrete
ports. PostgreSQL reuses AUTH-22's exact enabled configuration/revision check in a
short committed read transaction. The server library provides `OidcHttps`, shared
by embedded/standalone consumers. No HTTP callback/route, token exchange, JOSE
verifier, identity resolver, session issuer or generic protocol framework is added.

`OidcDocuments` owns one immutable persisted `OAuthConnection` snapshot and an
explicit list of at most eight canonical HTTPS origins. Origins include the
effective port; there are no wildcard hosts or request-selected allowlists. Issuer
origin must be included. On an origin-policy change, trusted composition must
reapply configuration to allocate a new registry revision and replace the document
service. Reusing an old Arc is not a configuration update. No network policy is
selected by callback/token/user input.

Discovery URL construction removes trailing issuer slashes before appending
`/.well-known/openid-configuration`, including issuers with a path. The expected
issuer string itself is retained exactly. The returned issuer must match it without
URL/Unicode normalization. Authorization, token and JWKS endpoints must all have
an allowed HTTPS origin/port, no credentials/fragment/raw controls/backslashes,
and bounded URL length. A required response-issuer mode also requires the metadata
support indicator; dedicated-callback mode remains an explicit AUTH-22 choice.
PKCE support is exposed as data; an absent S256 declaration does not enable `plain`.

## Address and connection policy

Resolve the selected endpoint once. Accept at most sixteen answers, reject empty
or oversized sets and reject the entire set if any address/port is disallowed.
Do not filter private answers out of a mixed result and proceed. Public IP literals
skip DNS but must match the exact checked literal. The private `OidcTarget`
constructor binds the parsed URL to its checked address list; the concrete adapter
accepts that target rather than an arbitrary URL.

IPv4 policy excludes private, loopback, shared, link-local, documentation,
benchmarking, transition, multicast and reserved ranges. IPv6 admits ordinary
`2000::/3` unicast space while excluding assignment/transition/documentation ranges,
including `2001::/23`, `2001:db8::/32`, `2002::/16` and `3fff::/20`. Other IPv6 space,
mapped IPv4, translation prefixes, ULA and link-local are denied. This conservative
policy intentionally also denies some globally reachable special-purpose
assignments; it is not a general routability oracle. Explicit origins never create
a private-network exception. No public local-development escape is introduced.

Pin all checked addresses with `resolve_to_addrs`; preserve the original URL host
for Host, SNI and certificate verification. Its URL port takes precedence in reqwest,
so core validates that effective port and every returned SocketAddr port. Check the
actual connected peer against the pinned set as an additional guard. Do not replace
the URL hostname with an IP or permit a fallback resolver/proxy/redirect.

The adapter disables redirects, retries, proxies, referers, automatic decompression,
verbose connection diagnostics and TLS key logging. It uses HTTP/1 only and sends
no provider credential, authorization header or cookie. TLS uses standard rustls
safe protocol defaults, ring, public WebPKI roots and normal hostname/chain checks.
There is no invalid-certificate setting or custom signature verifier.

TLS configuration is explicitly per client. `rustls-no-provider` otherwise reads
the process-global provider and can panic if none was installed. The implementation
does not assume that SMTP initialized TLS and does not install/replace the embedding
application's global crypto provider. A cold subprocess proves construction and a
real request leave that global provider unset.

## Bounds and cache behavior

| Boundary | Policy |
|---|---|
| Whole public document operation | Five seconds, including registry checks, discovery when loading JWKS, DNS, fetch and validation |
| Connect/read | Two-second connect and per-read limits, within the whole-operation limit |
| Shared adapter work | Four operations; cloned adapters share the budget, with immediate overload rejection |
| Native DNS | Detached blocking jobs retain their permit after caller cancellation until native lookup completes |
| HTTP input | At most 32 parsed headers; reject more than 16 KiB of returned header content; dependency parsers have their own buffers |
| Document body | 64 KiB; enforce declared length and streaming size, then recheck in core |
| Encoding/type | Identity only; JSON metadata or JSON/JWK-set JSON keys; ambiguous duplicate type/encoding headers rejected |
| Cache | One discovery and one JWKS slot per document service, bound to its immutable connection/revision |
| Retention | Explicit HTTP max-age minus Age/body-read time, capped at 300 seconds; no heuristic/stale/conditional fallback |
| Fetch attempts | At least one second between misses per document, including failed/malformed/non-cacheable attempts |

Cache-Control no-store/no-cache, unsupported/ambiguous directives, malformed age,
or Vary:* disable reuse. Time spent reading the body cannot restart freshness.
Cache expiry uses monotonic time. JWKS cache additionally matches the current
validated discovery URI. Invalid or failed refreshes cannot return stale data.
Per-slot try-locks reject concurrent misses promptly instead of queueing unlimited
futures behind network I/O. Forced unknown-key refresh is not exposed; AUTH-29 owns
the subsequent verification/rotation policy.

Native OS DNS is not cancellable. The caller returns by its deadline, while up to
four native jobs can remain until the resolver returns; they keep their permits so
repeated timeouts cannot create unlimited detached jobs. Runtime shutdown can wait
for native work. This is an explicit operational limitation, not a claim that a
request timeout kills an OS resolver. Deployment/retention/load review remains M09
work. Share one adapter across configured connections and one document service per
persisted context; do not instantiate them from untrusted per-request input.

## Configuration, payload and authentication boundaries

Check the exact enabled realm/connection/local-client/revision/issuer/provider-client/
callback/mode before cache use or network access and again after network validation.
Configuration reads commit before I/O; no database lock spans DNS/HTTPS. A disable
can commit while a fetch waits, and a late result is rejected before cache/return.
As with other readonly in-flight operations, a disable after the final snapshot can
race a return; this grants no identity. Future authentication commit must recheck
current enabled revision and original OAuth/session deadlines under its own locks.

Deserialize bounded metadata with normal serde duplicate-field rejection. Validate
only a bounded nonempty JWKS object envelope, preserving original bytes for the later
reviewed JOSE verifier. Reject known private/symmetric key parameters `d`, `p`, `q`,
`dp`, `dq`, `qi`, `oth`, `k` before caching a public JWKS. This is structural input
admission, not cryptographic verification. `OidcJwksDocument` redacts Debug and has
no serialization implementation; parsing bytes requires its explicit accessor.
No algorithm, signature, kid, audience, nonce, subject or email claim is trusted by
this boundary. Token-controlled jku/x5u URLs are never accepted as fetch inputs.

Errors remain fixed core categories. Network/metadata/time/registry failures do not
become authentication success. The private transport distinguishes certificate,
network, timeout, peer, status, header, encoding, MIME and size failures without
retaining URLs/bodies/raw causes. Typed rustls causes inside io::Error payloads are
inspected without matching messages. A socket-reset control cannot stand in for
certificate rejection. No application user/session/audit/permission is created.

## Dependency and evidence gates

Select reqwest 0.13.5 with defaults disabled and rustls-no-provider, existing
rustls 0.23/ring and WebPKI data, plus ipnet 2.12.2 for reviewed prefix matching.
The graph still includes reqwest's platform-verifier helper dependencies even
though the per-client configuration uses explicit roots; audit/license review
covers them. Test-only rcgen 0.14.10 and tokio-rustls 0.26 use ring, with private
fixture keys confined to memory. No existing locked package version is removed.

The separate openidconnect 4.0.1 candidate unconditionally selects rsa 0.9.10 even
without default features. An isolated normal/build dependency tree and audit prove
RUSTSEC-2023-0071 would become selected. It is not introduced and the compiled
advisory gate is not relaxed. This is a dependency-selection blocker, not proof
that public-signature OIDC verification is exploitable by Marvin.

Tests combine controlled core DNS/documents and real PostgreSQL configuration with
owned TLS fixtures for the actual pinning/streaming code. The TLS component's private
fixture supplies loopback/public test roots without adding a production address or
invalid-certificate bypass. Positive Host/SNI/pinning, zero second-resolution/proxy
hits, real certificate rejection, exact response failure categories, detached DNS
leases, age/size/timeout/cache/realm/configuration negatives are separate evidence.
These are component/regression tests, not real Google/Apple/local-IdP interoperability.
Provider token verification, final identity/session transactions, linking, rotation,
real-provider checks, independent review, SAML and outbound issuer remain gates.
