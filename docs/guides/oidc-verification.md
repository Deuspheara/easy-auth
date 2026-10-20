# Experimental OIDC token verification

The explicit `oidc-verification` feature adds a core verifier and PostgreSQL context
checks; the server feature enables those dependencies alongside its HTTPS adapter.
It includes a backend code exchange, with no callback route or ordinary provider login. See
[ADR 0015](../architecture/adr/0015-oidc-token-verification.md) for exact policy.

Trusted composition configures/persists an OAuth connection and retains the returned
snapshot. Share `OidcDocuments`, the PostgreSQL adapter and an `OidcTokenVerifier`
with an explicit `OidcVerificationPolicy`. Choose RS256, PS256 and/or ES256 according
to trusted client registration. Additional audiences are explicit trust entries,
not values copied from a token. Reapply configuration for a new revision when
origins, credentials or verification policy change; replace the service afterward.

After consuming the browser-bound OAuth transaction, pass the owned exchange and
`OidcIdToken::parse` result to `verify`. Token input belongs to the protected backend
provider response's `id_token` field, never an access token or a browser-supplied
application session credential. A signature alone does not establish a token's
protocol source when an issuer reuses keys and claims across token types. The
preferred `OidcCodeExchange` below owns the code+S256 HTTP exchange and selects
that response field. Discard the exchange after parsing/verification failure and start a new flow.
Do not resurrect consumed state or retry a provider code.

A successful `VerifiedOidcIdentity` carries immutable exact configuration, purpose,
subject, optional provider attributes and a capped commit deadline. It is not a
session or linking grant. Final persistence must consume it and recheck the enabled
revision, original caps, linking owner/session and account/identity policy under
locks. That final identity/session operation is not implemented by this feature.
No email match can select or merge a local account.

`issued_at()` reports token issuance, while `authenticated_at()` returns only an
actual auth_time claim. Never substitute iat for missing authentication time or
infer stronger-factor/AAL assurance. `email_verified()` reports the provider's
assertion only when an email value is present. An omitted email remains a valid
identity and yields no verified email attribute even with a standalone flag.
Provider metadata is not proof of local mailbox ownership or
permission to attach a contact, link an identity or recover a stronger account.

Only an unknown signing-key ID can request one snapshot refresh and retry. Bad
signatures for known keys and invalid claims never force refresh. Cooldowns and
concurrent misses can return RateLimited, including immediately after a cold fetch.
Provider key-set errors return Unavailable; expired/stale/foreign context or invalid
tokens return Unauthorized. Do not replace these distinctions with a generic
negative assertion in tests. Malformed cryptographic key metadata can remain cached
as an envelope until HTTP expiry or an explicit bounded administrative refresh;
there is no insecure stale/signature fallback.

NumericDates must be unsigned whole-second JSON numbers. The policy has strict
clocks with no leeway, a five-minute token-age limit and a result deadline no later than either original OAuth authority or token expiry/age.
Two operations per shared verifier and a 15-second whole-operation bound limit work.
Both initial verification and a successful refresh retry retain their operation
lease through final database authority and claim checks.
Native crypto jobs retain their lease after async cancellation until completion;
the timeout does not kill native code. Do not recreate services per request.

Tokens/results have redacted Debug and no Serialize/Clone. Raw input is zeroized on
final owned drop; temporary allocations in dependencies prevent a whole-process
memory-erasure claim. Never log token responses, nonce/PKCE, raw foreign errors,
headers, claims or provider credentials. Install the documented native OpenSSL build
dependencies; this feature uses per-verifier library objects and public key material.

Focused checks with the documented PostgreSQL setup:

```sh
cargo test --locked -p easy-auth-core --features oidc-verification oidc::verification::
cargo test --locked -p easy-auth-postgres --features oidc-verification --test lifecycle oidc::verification
```

Full default/all-feature workspace suites run sequentially. Signature fixtures are
component evidence. The owned Keycloak suite below provides bounded provider
evidence; broader provider acceptance, independent review and ordinary activation
remain required.


## Protected code exchange

Compose one shared `OidcCodeExchange` with the persisted connection's documents,
PostgreSQL repository, explicit verification policy and registered authentication
method. Share the concrete `OidcHttps` adapter across connections. Choose exactly
`Public`, `ClientSecretBasic(OidcClientSecret)` or
`ClientSecretPost(OidcClientSecret)` from trusted registration. No runtime fallback
occurs. The method and S256 must be advertised; missing method metadata means Basic.
Rotate persisted configuration/revision and replace the service when these change.

1. Begin the matching `OAuthTransactions` flow and use `authorization_url` to build
   the code/openid redirect with original state, nonce and S256 challenge. Retain
   its browser-bound proof securely. The URL exposes state/nonce deliberately for
   browser redirection; never log it or store it in analytics.
2. Extract the actual callback through your protected transport and consume state
   with exact redirect/issuer binding. Pass that owned exchange and parsed
   `OidcAuthorizationCode` to `exchange`. Do not accept a browser ID/access token
   in place of the code or construct another verifier after exchange failure.
3. Consume the returned opaque identity through a future reviewed local persistence
   operation. This feature still issues no local session or automatic email link.

A single POST uses the original PKCE verifier and configured redirect. Basic uses
RFC6749 component form encoding; Post/public include the client ID in the body.
Reserved authorization/token endpoint query parameters reject ambiguous bindings.
Unused access/refresh tokens are discarded. HTTP400 invalid_grant returns
Unauthorized, while malformed/configuration/network failures return Unavailable.
No code retries, redirects, cookies or ambient proxies are permitted.

The exchange service shares two leases from discovery through verification and has
a 30-second whole-operation timeout. Verification retains its 15-second bound and
native cancellation ownership. It rechecks database authority after DNS and after
signature verification. Non-cacheable discovery is used within that one operation,
including a possible key refresh, then never reused by a subsequent operation.
The code flow holds its existing lease while waiting at most one second before
its first ordinary discovery or key fetch, then invokes normal admission once.
This handles fast callbacks and independently non-cacheable keys while preserving
fetch rate, freshness and original authority. Authorization URL preparation is
bounded by that one-second wait plus the existing five-second document operation;
exchange/verification retain their 30/15-second bounds including any admission wait.
No database or cache-slot lock is held during the admission timer. Standalone
document/token verification APIs and forced unknown-kid refresh still use prompt
admission. Contention or forced cooldown can still return RateLimited; discard a
failed consumed context and start a new flow, never retry its code.
No database lock spans DNS, HTTPS or native verification.

Run server component TLS POST checks as well as the focused core/PostgreSQL checks:

```sh
cargo test --locked -p easy-auth-server --features oidc-verification oidc_http
```

The loopback/private-root mapping exists only in private test code. Production
remains public-address/public-root HTTPS only. The separate
[owned Keycloak suite](../../tests/browser/oidc/README.md) passes code/S256/RS256,
actual key rotation, invalid claims/signatures, provider-code and PostgreSQL-state
replay, fresh controls and disable-before-POST. It uses the actual shared production
HTTPS request/reader sources with a private fixture certificate/address mapping.
This is specific local-provider evidence, not general production interoperability.

Run its explicit build/Node commands after the documented Docker, PostgreSQL and
pinned browser setup. CI runs it after browser dependencies; it is not an ignored
Cargo test. No production-provider credentials or user-device interaction is needed.
The runner adds no interoperation admission delays. The application schedules
its own first fetch within the unchanged budget. The test preserves actual provider
cache headers, scopes and client configuration;
controlled proxy faults are labeled separately from provider-signed claims. It
requires normal owned resource cleanup and creates no local user/session/contact.
The separate optional [AUTH-30 identity boundary](oidc-identities.md) now implements
mapping/JIT/session persistence. This historical verifier report does not establish
acceptance of that newer boundary; its provider evidence is tracked separately.


The [current fast-callback record](../../tests/browser/oidc/results/2026-10-20/keycloak-fast-callbacks.json)
retains all eleven provider cases with no runner pacing. The earlier paced record
remains immutable. Dedicated core regressions first reproduced immediate no-store
callback and successive no-store-key self-throttling, plus premature lease release
after a rotated-key retry. Exact-error/expiry/cancellation/capacity controls pass;
waiting never revives state, resends a code or extends its original commit cap.
