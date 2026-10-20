# Experimental Google code verification

AUTH-23 adds the opt-in core `google` feature and `GoogleCodeExchange`. This is a
code/identity-proof component, not supported Google web/native activation. No
Google HTTP endpoint, server setting, native browser/listener, mobile return
adapter, local-session grant or provider-deletion flow is supplied by this feature.
The [ADR](../architecture/adr/0019-google-code-flow.md) records the remaining work.

Enable `easy-auth-core/google` and use the existing PostgreSQL and server
`oidc-verification` features for the repository ports and production `OidcHttps`.
The PostgreSQL `google` feature additionally selects its existing `oidc-identities`
ports and the core Google component; it adds no Google-specific SQL or schema.
Construct the component from the exact persisted connection snapshot, the same
authoritative repository for registry/exchange checks, and an explicitly registered
Basic or Post client authentication choice:

```rust
let http = Arc::new(OidcHttps::new());
let google = GoogleCodeExchange::new(
    persisted_connection,
    repository.clone(),
    repository.clone(),
    registered_authentication,
    http.clone(),
    http,
)?;
```

Registry configuration remains trusted administrative work. Match
`OAuthTransactions` to `google.configuration()` and retain its original state,
browser/operation binding, nonce and PKCE verifier in protected transient transport.
`authorization_url(&start)` requests only fixed `openid email profile` scopes and
S256. After validating and atomically consuming the actual bound callback, pass its
opaque `OAuthExchange` and actual `OidcAuthorizationCode` to `exchange`. No API
accepts an unsolicited ID token or constructs a verified identity directly.

The component requires the exact canonical issuer `https://accounts.google.com`
and `RequireIssuer` response defense. It permits discovery-selected endpoints only
within `https://accounts.google.com`, `https://oauth2.googleapis.com` and
`https://www.googleapis.com`, using the existing constrained public-network
transport. It fixes signature policy to RS256, without additional audience trust.
Metadata must still advertise S256, response issuer support and the selected wire
authentication method. Public authentication, another issuer/defense, fallback,
caller-selected algorithms, arbitrary scopes and egress overrides are rejected.

The shared verifier requires the original nonce, exact client audience, matching
`azp` when present, bounded subject and genuine signature/time validity. The legacy
issuer spelling and cross-client hybrid presenters are not silently accepted.
Email and `email_verified` remain signed attributes, never local contact, ownership
or automatic-link authority. Missing/false verification can still identify the
signed subject; a standalone true flag without email does not establish verified
email. Duplicate, null or incorrectly typed security fields fail closed.

Only sign-in contexts are accepted. Link and provider-deletion purposes are rejected
before token POST. A verified result is the existing opaque `VerifiedOidcIdentity`,
not an issued local session; any eventual mapping/commit must retain all original
current-source, realm, owner, one-use and deadline checks. Provider `invalid_grant`
maps to Unauthorized; credential/transport/provider failures remain Unavailable.
Foreign error descriptions, tokens, codes, raw headers and private proofs must
never enter diagnostics. Cancellation/replay remains the original transaction API.

The explicit [desktop redirect metadata](oauth-transactions.md#explicit-desktop-return-metadata)
can carry an exact loopback return through the code request. It does not own a socket,
open a system browser, validate registered desktop credentials or implement mobile
return handling. Installed-client wire secrets cannot prove application authenticity.
The offline tests exercise Basic/Post requests for both HTTPS and explicit loopback
metadata, not successful registered Google/native clients.

## Callback decoding component

`GoogleAuthorizationResponse::parse` accepts the actual raw callback query (without
`?`, URL or fragment), bounded to 8192 bytes and 2048 bytes per decoded value.
It requires one canonical state and the actual exact canonical Google `iss` on
success and error responses. It rejects duplicate decoded names, malformed percent
encoding/UTF-8, controls, unsupported members, code/error contradictions, missing
results and success responses carrying error details. Returned code uses the same
bounded, redacted `OidcAuthorizationCode` as the existing exchange.

The supported closed set is `state`, `iss`, `code`, `error`, `error_description`,
`error_uri`, `scope`, `authuser`, `hd`, `prompt` and `session_state`. Google's
[documented redirect metadata](https://developers.google.com/identity/oauth2/web/guides/use-code-model#authorization_endpoint)
is discarded; it grants no scopes, trusted domain, contact or identity. This
deliberately closed subset does not implement the general OAuth rule to ignore
arbitrary unknown response parameters and makes no protocol-conformance claim.
Error descriptions/URIs are discarded without rendering, logging or dereferencing.
`access_denied` becomes `GoogleAuthorizationOutcome::Denied`; all other nonempty
ASCII errors become `ProviderFailure`. Neither is a verified provider identity.

Decoding does no I/O and cannot cancel or consume state. The transport must retain
the private proof and bind `state()` and actual `issuer()` to its initiated exact
route/browser/source/purpose using `OAuthTransactions`. `outcome()` permits
inspection to select consume versus bound cancellation; it grants no authority.
After successful consume,
`into_outcome()` yields a code for `GoogleCodeExchange`; bound error cancellation
must not perform a token exchange. Malformed callbacks must not cancel unrelated
pending operations. Do not log the incoming query or save it in browser storage.
This component adds no callback route, native return listener or Google activation.

## Shared authorization use case

`GoogleAuthorization::new` composes matching `Arc<OAuthTransactions>` and
`Arc<GoogleCodeExchange>` snapshots, including exact realm/connection/local client,
provider registration, redirect and revision. Use the same authoritative repository
for both underlying services. It accepts only sign-in intent; linking and deletion
are rejected before admission or provider work.

`begin` returns a `GoogleAuthorizationStart`: retain its `transaction` state and
private proof in protected transient transport storage and send only its redacted
`authorization_url` through the reviewed external-browser boundary. The URL is
exposed deliberately at that boundary, never logged. If URL construction/provider
discovery fails after admission, the use case attempts cancellation of that exact
new operation and propagates any cleanup failure instead of claiming success.

`finish` requires the original retained state/private proof, actual trusted callback
route or owned listener URI, request-local intent, and decoded
`GoogleAuthorizationResponse`. Exact returned state/issuer/redirect is checked
before mutation. Success consumes the original database-bound transaction once,
then uses the existing S256/signature exchange. A denied/provider-failure outcome
requires the same private operation binding through committed cancellation and
makes no token POST. Storage/configuration/proof failures remain typed errors,
distinct from `Denied` and `ProviderFailure` completion outcomes.

`GoogleAuthorizationCompletion::Verified` owns a boxed existing verified identity
proof, not a local session. Mapping consumes the enclosed proof and the existing
atomic sign-in use case must still recheck current source/policy/deadlines. Token
or signature failure does not resurrect consumed state. Explicit `cancel` requires
the original private proof and cancels only that operation, preserving ambient
sessions. No new SQL, proof constructor or retry mechanism is introduced.

The intent's network source is an abuse-admission key, not an authentication
credential or provider selector. A changed network source still spends its own
budget while exact provider-configuration/browser/state/nonce/PKCE/purpose bindings
remain mandatory. These use cases do not own a socket, establish callback delivery,
launch a system browser or enable public Google login. Web/native transports and
usable reviewed provider lifecycle remain required before activation.

## Evidence and remaining gates

Feature-owned offline tests use actual RS256 signatures and public JWKS with
Google-shaped discovery/code responses. They cover original code/PKCE/redirect,
fixed scope/egress/authentication, wrong claims/signature/algorithm, duplicate email
flags, email-attribute semantics, cancellation, source/purpose isolation and exact
provider-error versus infrastructure-error results. Their controlled repository is
a component fixture. Eighteen separate PostgreSQL scenarios now exercise the actual
Google code component through real state consumption, signature verification,
mapping and existing local identity/session commit. They cover provider-only
ownership without email merging, JIT, scoped identity ownership, callback and subject concurrency,
rollback, current-source revalidation, decoded callback binding/cancellation and
final-audit deadline waits. Token/JWKS
responses remain controlled offline actual-signature fixtures, not real Google or
system-browser interoperability. See the [verification history](../security/verification.md).

Before ordinary activation, AUTH-23 still needs Google web callback transport
integrated with the tested PostgreSQL flow, actual native
system-browser/OS-return handling, registered-client/manual provider evidence and a
usable genuinely fresh provider-required deletion path. This component does not
request or infer provider reauthentication: issuance time, local session rotation
and an authorization prompt cannot substitute for genuinely recent signed
`auth_time`. No weak recovery/deletion fallback is permitted. Linking, Apple grant
handling, native remote token families and broader release gates remain separate.

Google's [Security Bundle](https://developers.google.com/identity/siwg/security-bundle#authentication_time)
documents optional `auth_time` for a published/verified application with the feature
enabled and the claim requested. It explicitly does not support Google Account
reauthentication requests. This component does not request that claim or reuse the
generic OIDC `prompt=login`/`max_age=0` deletion request as a Google contract. A
returned old authentication time would still fail the existing freshness policy.
Provider-application eligibility, actual signed claim availability and a usable
reviewed lifecycle remain unverified; no provider settings have been changed.
