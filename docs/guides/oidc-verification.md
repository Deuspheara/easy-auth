# Experimental OIDC token verification

The explicit `oidc-verification` feature adds a core verifier and PostgreSQL context
checks; the server feature enables those dependencies alongside its HTTPS adapter.
It adds no callback, token endpoint exchange or ordinary provider login. See
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
library currently does not perform the code+S256 HTTP exchange; this remains AUTH-29
work. Discard the exchange after parsing/verification failure and start a new flow.
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
component evidence; local Keycloak code exchange/rotation/replay, provider acceptance,
independent review and ordinary activation remain required.
