# Experimental Google code verification

AUTH-23 adds the opt-in core `google` feature and `GoogleCodeExchange`. This is a
code/identity-proof component, not supported Google web/native activation. A
separate optional server `google-desktop` feature supplies owned loopback delivery.
No public Google web endpoint, startup setting, OS browser launcher, mobile return
adapter, local-session grant or provider-deletion flow is supplied by these components.
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

## Owned desktop loopback delivery

The server library's `google-desktop` feature exports `GoogleDesktopListener`,
`GoogleDesktopCallback` and finite `GoogleDesktopError` transport outcomes. It uses
the existing HTTP implementation and does not change normal server startup.
`bind` permits only literal `127.0.0.1` or `::1` and reserves an ephemeral concrete
port before returning `redirect()`. It accepts no wildcard, hostname, address alias
or caller-supplied fixed/wildcard port. The existing exact `OAuthRedirect` validates
the nonroot canonical path. Preserve the owned listener and persist this exact
redirect/revision before creating the matching core authorization services.
Administrative reconfiguration retains its existing revision/cancellation semantics;
the listener does not register providers or bypass configuration policy.

`receive` consumes the listener and requires the retained state, original expiry
and a cancellation future. Its local resource timer is capped at five minutes;
PostgreSQL remains authoritative about the original operation deadline. It permits
eight sequential connections, one active stream, HTTP/1.1 origin-form GET only,
exact Host/path and no body/transfer encoding. Hyper enforces32headers/16KiB parser
buffer, two-second header and three-second connection bounds. Malformed query,
wrong state/issuer, duplicate/unsupported fields, absolute-form targets and alias
hosts never produce a captured return. Invalid/slow requests spend connection
budget without changing authentication state. No detached connection task survives
cancel/drop/expiry. A local process may exhaust this bounded receive operation;
that is a transport failure, never proof of an invalid credential or identity grant.

Handled responses are fixed, nonreflective, no-store/no-referrer, framed out and
cookie-free. Their CSP permits only the fixed inline query/fragment-scrubbing
script; no state/code/error detail enters HTML. A parser-level refusal may use
Hyper's own error response. Oversized unread data may reset TCP after its complete
HTTP431 response; reset alone is not successful rejection evidence in the tests.

Only actual owned-socket delivery constructs the opaque callback. Its `finish`
method supplies the captured listener URI to the existing `GoogleAuthorization`
use case with the original intent/state/private proof. It cannot import a pasted
callback URL or fabricate verified identity. Receive/cancel/drop alone changes no
database state: callers must explicitly cancel the original core operation when
appropriate. `Expired`, `Cancelled`, `RequestLimit` and `Unavailable` are distinct
transport outcomes, separate from later provider/storage/proof errors.

The [owned transport suite](../../tests/browser/google-desktop/README.md) covers
actual IPv4/IPv6 sockets and Chromium query scrubbing. Its fixture creates no
Google account, verified identity or local session. The separate server integration
suite also covers actual listener-to-PostgreSQL delivery, offline RS256 verification
and final commit. Supported OS system-browser launch/return, registered
client semantics, mobile delivery and usable reviewed lifecycle remain required.

## Owned desktop database acceptance

Nine server integration scenarios run actual loopback receives through
`GoogleDesktopCallback::finish`, shared Google authorization, real PostgreSQL
consumption, actual offline RS256/JWKS responses, mapping and local session commit.
Both IPv4/IPv6 preserve provider-only ownership and do not merge a matching verified
mailbox. Receiving and verifying a return grant no local authority before commit.
Foreign owned sockets cannot replace the configured URI. Trusted rebind rotates
the existing source revision and cancels old pending work; a captured old return
remains unauthorized even with its old service snapshot and original private proof.

Actual delivery races against a restored private operation retain one exchange
and one local commit. Provider denial/failure and explicit cancellation do not
revoke an unrelated session or issue a grant. Transport cancellation leaves pending
state for separately authorized core cancellation. Actual signed nonce rejection
remains Unauthorized; token transport and final audit faults remain Unavailable.
Final authority rolls back on audit failure or expiry during an independently
observed audit lock wait; no already consumed state is restored. Signed positive
controls follow faults, cancellation, stale revision and expired-commit outcomes.

The fixture signs only the originally issued code/PKCE/client/redirect and records
independent GET/POST/signature counters. Clock/lock observers use one separate
connection. Owned short-deadline arrangements preserve the original five-minute
pending window, without changing production policy or resetting caps at receipt.
Shared test fixtures remain private; no production proof constructor or hook exists.

Run with the documented real database and both explicit features:

```sh
CARGO_INCREMENTAL=0 cargo test --locked -p easy-auth-server --features google-desktop,oidc-identities --test google_desktop
```

These fixtures do not call Google or validate registered clients, provider TLS,
OS default-browser launch, mobile return, genuine Google freshness or usable
provider-required deletion. Those remain AUTH-23 activation/acceptance gates.

## Evidence and remaining gates

Feature-owned offline tests use actual RS256 signatures and public JWKS with
Google-shaped discovery/code responses. They cover original code/PKCE/redirect,
fixed scope/egress/authentication, wrong claims/signature/algorithm, duplicate email
flags, email-attribute semantics, cancellation, source/purpose isolation and exact
provider-error versus infrastructure-error results. Their controlled repository is
a component fixture. Eighteen PostgreSQL-crate scenarios and nine server-owned
desktop database scenarios now exercise the actual
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
