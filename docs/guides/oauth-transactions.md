# Experimental OAuth transaction boundary

AUTH-22 implements optional core/PostgreSQL state handling under
`oauth-transactions`. It has no HTTP routes, browser client, provider exchange,
token verification, identity linking or session issuance. Normal server/router
composition is unchanged. See [ADR 0013](../architecture/adr/0013-oauth-state-transactions.md)
for policy, lock order, proof transport requirements and later activation gates.

Trusted composition creates an `OAuthConnection`, provisions its realm, persists
it with `Postgres::configure_oauth_connection`, and passes the **returned** configuration
snapshot plus repository to `OAuthTransactions`. Every configuration write allocates
a fresh revision and cancels old pending work; even reapplying an old object cannot
restore its old revision. `disable_oauth_connection` atomically disables the exact
realm/connection/client, rotates its revision and removes pending rows. Reconfiguration
preserves a disable. Only explicit `enable_oauth_connection` with the latest persisted
snapshot re-enables it. These are administrative interfaces, not request handlers.

`begin` takes an `OAuthIntent` containing the host browser secret, trusted source
and a closed purpose. It returns fresh state, private browser proof
and the fixed database deadline. Authorization parameters are state, expected
nonce and the proof's S256 challenge. The raw PKCE verifier must stay in a protected
transient transport; it is not an authorization URL parameter. The library does
not yet implement that transport. No database column stores these raw values.

`consume` requires the original browser/state/private proof, exact intent and actual
callback route/issuer evidence. It returns exchange context once; parallel callback
and cancellation attempts share the same one-use transaction. Missing or wrong
bindings return Unauthorized. A failed database operation returns Unavailable,
never a successful security rejection. Admission/capacity failures return RateLimited.
`cancel` returns no exchange context and cannot authenticate anyone.

The callback's `iss` is mandatory under `RequireIssuer`. `DedicatedRedirect` is an
explicit alternative for a globally unique configured callback; a present wrong
`iss` is still rejected. Never copy the configured issuer into a response's missing
`iss`, derive a trusted callback URI from request body input, normalize issuer
strings or silently fall back between modes. Dedicated callback URLs use canonical
HTTPS spelling and unencoded paths; native/loopback transport is not available in
this boundary.

Link intent binds the original owner/session. The shared database policy requires
fresh authentication and the correct method for a passkey-required account at both
start and consume. Its deadline cannot outlive that original session's freshness,
idle or absolute expiry. This is permission to attempt provider proof, not permission
to attach an identity or downgrade an account. Future linking must prove the new
provider identity and revalidate original authority/policy at its final commit.
Matching email addresses never select or merge local accounts.

AUTH-55 adds `OAuthPurpose::DeleteProviderAccount { user, session }` as preparation
for a distinct provider deletion flow. PostgreSQL requires `oidc-identities` and
the exact active provider-required owner/session/source/configuration revision.
It rejects without that feature. The initiating session may have old or unknown
provider authentication time: requesting new proof grants no action and never
updates that time. The original idle/absolute cap still bounds preparation,
consumption and context checks. Sign-in/linking cannot consume this purpose, and
neither the sign-in use case nor repository can issue a session from its proof.
Migration 0019 extends the closed purpose/session binding without changing old
pending rows or granting deletion authority. The separate
[provider deletion use case](oidc-account-deletion.md) now implements final
exact-subject and signed-freshness authorization in PostgreSQL. No HTTP deletion
endpoint exists; see [ADR 0017](../architecture/adr/0017-provider-account-deletion.md).

`OidcCodeExchange::reauthentication_url` adds fixed `max_age=0` and `prompt=login`
to the existing exact state/nonce/S256 authorization request. Provider metadata
cannot supply competing `max_age`/`prompt` query parameters. The
[OIDC authorization request specification](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
requires an authentication-time claim for maximum-age requests. Parameters alone
are not evidence of a prompt or fresh authentication: the final sensitive action
must require the genuinely recent signed `auth_time` and exact existing identity.

State consumption happens before network exchange and cannot be retried. A provider
failure or lost exchange result requires a new start. `OAuthExchange` does not verify
any token claims and must never be passed to ordinary session issuance as proof of
identity. Future adapters must recheck its original deadline and current configuration
after exchange; a connection disabled in the meantime must not create an identity
or session. Provider identity/session/audit writes must commit atomically afterward.

Focused test command, with the documented PostgreSQL setup:

```sh
cargo test --locked -p easy-auth-postgres --features oauth-transactions --test lifecycle oauth::
```

Run default/all-feature workspace variants sequentially. Four test workers retain
SQLx's shared connection budget; lock observers use independent one-connection
pools. Test-only failure triggers and storage-policy fixtures are neither production
hooks nor proof of real provider/passkey interoperability.
