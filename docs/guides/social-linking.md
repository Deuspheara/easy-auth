# Explicit Google and Apple account linking

The optional experimental Axum `social-linking-web` composition lets an existing
account deliberately link or unlink verified Google/Apple identities. Core and
PostgreSQL use `oidc-linking`; select their Google/Apple features as required by
trusted provider composition. Apply the existing migrations, including0037,
before selecting this feature. Ordinary server startup and the separate
Google/Apple router builders do not expose these management routes.

## Trusted composition

Construct the existing `GoogleWebServices` and `AppleWebServices` from their exact
persisted identity policies, provider exchanges and transactions. Construct
`GoogleIdentityLinkAuthorization` (ordinary or explicitly eligible session-age
profile) and web-only `AppleIdentityLinkAuthorization` using those same provider
registrations. Pass the normal web services, both link authorizations and an
`Arc<OidcIdentityLinking>` into `SocialWebServices::new`, then call
`experimental_social_web_router(auth,browser,services)`.

Both sources must belong to the configured realm. HTTPS and the exact trusted
origin plus `/google/callback` or `/apple/callback` are mandatory. Linking and
ordinary sign-in share the same provider registration/subject namespace. Do not
create a second client or redirect just to select a linking page. Native Apple
and desktop Google linking are not implemented by this web composition.
Custom `EmailDelivery` adapters must implement `providers_changed` before draining
the corresponding durable notices; its default returns Unavailable for retry.

## User journey

Open `/social/accounts` from your application's account settings. The page checks
the current session and displays its account and owner-scoped provider inventory.
Authenticate freshly with a method permitted by that account's current policy.
Choose Google or Apple and confirm the destination account deliberately. Completing
the provider redirect alone never links an identity: confirm the returned identity
on the fixed same-origin page too. The original session and owner must still match.
No new local session is issued. Matching email addresses do not merge accounts,
change ownership or establish a verified local contact.

Google's callback selects a fixed page using a unique matching protected state
cookie. Apple's cross-site POST renders only a bounded escaped inert handoff,
without reading cookies/storage or consuming/exchanging the code. Lax cookies are
absent on that POST. After removing the handoff from DOM and scrubbing location,
the fixed script sends only returned public state to the exact-Origin protected
presentation hint. That hint performs no database access or mutation. Only the
subsequent explicit finish carries the actual response through all original
private-proof, signed-claim, current-source and final-commit checks.

Navigation/restoration drops return data; a lost finish is never automatically
retried. Check linked accounts before restarting. Callback cancellation retains
returned state so an old tab cannot clear a newer operation. A separate management
action deliberately cancels the current pending link.

Unlinking requires fresh authentication through a method you retain. You cannot
unlink the identity used by the current OIDC session; first authenticate through
another usable method. Removed-source sessions become invalid, while other
sessions and account policy remain intact. Passkey-required accounts gain no
provider fallback. Apple sessions without signed authentication time cannot acquire
management freshness from a recent local cookie. Local unlink is **not remote
Apple token/grant revocation**; that lifecycle remains unimplemented.

## Contracts and locally reproducible checks

The [selected schema](../architecture/openapi-social-web.json),
[HTTP contract](../architecture/api-contract.md#experimental-social-linking-web-transport)
and [ADR0044](../architecture/adr/0044-explicit-social-identity-linking.md) document
closed inputs, purpose binding, retained-factor policy, cooldown and atomic audit/
verified-contact notice behavior. Separate provider builders remain sign-in-only
(or Google's existing explicit account deletion), even when this feature compiles.

```sh
cargo test --locked -p easy-auth-axum --features social-linking-web --test browser
cargo build --locked -p easy-auth-axum --features social-linking-web --example social-web-browser
cargo build --locked -p easy-auth-axum --features google-web --example social-source-probe
node tests/browser/social/run.cjs
```

Use an owned disposable loopback `DATABASE_URL`, installed Chromium and the existing
`tests/browser/passkeys` npm dependencies. The fixture owns its random database,
mail inbox and private TLS files; it removes them on shutdown. Browser authorization
navigation is intercepted into maintained signed offline producers; actual normal
email/provider proofs and PostgreSQL completion remain required. No fixture route
seeds a verified identity or local session. These checks do not establish registered
Google/Apple interoperability, Apple grant lifecycle, ordinary activation,
independent review or production readiness. See the [Google](google.md) and
[Apple](apple-setup.md) acceptance limits. The SAML waiver and outbound OIDC release
gate remain unchanged.
