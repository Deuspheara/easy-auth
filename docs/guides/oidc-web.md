# Opt-in OIDC browser composition

The Axum `oidc-web` feature provides trusted
`OidcWebServices`, `oidc_web_router` and `oidc_web_openapi` for one provider per
HTTPS origin. The server `oidc-web` feature and explicit trusted startup settings
now use the same `configured_application` factory for standalone and embedding.
Owned Keycloak public-login/lifecycle acceptance is recorded below. Dated checks
are recorded in the [verification history](../security/verification.md); broader
release gates remain explicit.
Default builds and absent settings do not activate these routes. This is not production-readiness,
external-provider interoperability or independent-review evidence.

Use the existing [stable startup policy loader](oidc-identities.md#startup-loading-versus-administrative-changes)
with explicit trusted realm/connection/local-client/issuer/provider-client/callback,
allowlist, display policy and default-deny JIT. Construct `OAuthTransactions` and
`OidcCodeExchange` from the returned policy's configuration. Exchange must use the
reviewed transport and explicit registered client authentication. Its secrets are
never browser input. Then compose the existing use cases:

```rust
let services = OidcWebServices::new(
    policy,
    transactions,
    exchange,
    Arc::new(OidcSignIn::new(repository.clone())),
    Arc::new(OidcAccountDeletion::new(repository.clone())),
)?;
let app = oidc_web_router(auth, browser, services)?;
```

The policy, transaction and exchange snapshots must agree exactly. Router creation
requires the configured realm and the exact HTTPS origin plus `/oidc/callback`.
No request supplies a provider, realm, redirect, credential, scope or JIT setting.
Sign-in requests `openid`, plus `profile` only when the trusted display policy
selects name/preferred_username. It requests no email scope or local contact grant.

Open `/oidc/sign-in` and deliberately continue to the provider. The callback GET
selects a fixed sign-in or deletion bridge only when the canonical returned state
uniquely matches that purpose's protected state cookie. This is a UI hint, never
authority: GET performs no database/provider work, consumes nothing, and issues no
cookie. Missing, ambiguous, duplicate, unknown, malformed or oversized callback
parameters and provider errors get fixed failure content. The script immediately
scrubs query and fragment, retains proof only in memory, and requires a deliberate
confirmation POST. Reload/navigation drops callback proof. There is no automatic
finish, arbitrary URL proof import, browser storage, analytics or provider error echo.

All POSTs require one exact Origin, bounded closed JSON and no query members.
The start, finish and cancel endpoints are `/v1/oidc/sign-in/{action}`. Separate
Secure/HttpOnly/host-only/Lax cookies hold canonical browser/state/nonce/PKCE proof;
JSON carries only the protocol authorization URL or actual returned code/state/iss.
New starts cannot overwrite presented pending proof. Cancel explicitly disposes of
that attempt, even after an unrelated current session arrives, without revoking or
replacing that session. Only a successful committed sign-in returns a session cookie.
Storage/provider outages are 503, authorization failures 401 and boundary timeouts
504; no failure establishes success. An interruption can leave completion uncertain.
Check the current session before starting another flow; never replay automatically.

Start and finish reject any presented session cookie, including malformed, duplicate,
expired or revoked values: explicitly log out first. These are checks of each
request's cookie snapshot. Concurrent anonymous starts can create separate bounded
contexts, and an already in-flight completion is not serialized against every other
authentication method or another tab's later cookie response. Exact one-use state/
proof checks and deliberate confirmation remain mandatory. No browser-wide atomic
account-switch guarantee is claimed. Trusted peer address contributes abuse admission,
not identity binding; browser forwarding headers cannot select that address.

Available capacity and metadata still govern admission: a concurrent start can
receive 429 while another owns a cold discovery fetch. This bounded rejection grants
no session; failed authorization-URL preparation cancels its own new pending attempt.
Successful overlapping starts retain separate proof and cancellation namespaces.

The same router includes the [provider-deletion routes](oidc-account-deletion.md).
They retain current initiating-session/subject binding, two destructive confirmations
and genuine newly signed recent provider authentication; sign-in or callback routing
cannot substitute for that proof. Logout/session-revocation responses clear both
purpose cookie sets. The legacy experimental deletion constructor and dedicated
callback remain available. Moving an existing registration to the common callback
requires explicit provider and administrative reconfiguration with revision rotation;
startup does not silently change it or select another local client identity namespace.

See [ADR 0018](../architecture/adr/0018-oidc-web-composition.md) and the concrete
[OpenAPI](../architecture/openapi-oidc-web.json). Follow the deployment logging
restrictions: never log callback URLs/query strings, code/state, cookies, assertions,
tokens or client credentials in the application or reverse proxy.

## Owned public-flow evidence

The [configured native suite](../../tests/browser/oidc/web/README.md) exercises
actual Keycloak sign-in through public start/callback/finish, local session and
embedded application use, logout/relogin, fresh provider deletion and cooldown in
both supported composition modes. It compiles the unchanged configured factory/
settings and embedded application-route sources with a private owned TLS transport
name substitution; the actual public Axum/core/PostgreSQL code is reused. There is
no fixture HTTP session bootstrap, seeded user/session or invented signed freshness.
Normal production transport/configuration gains no certificate/address override.

The eighteen cases include observed final-audit commit and verified subject-resolution
waits through a separate max-one database observer, protected-file confidential client
authentication and explicit503 versus401 distinctions. Only aggregate facts and
booleans are reported. Each owned database ends with no local authority/contact/
pending work, four deidentified audits and one live deletion cooldown, then is removed.
This complements normal-binary startup checks and the original provider regressions;
it is not a normal-binary public-root positive TLS test, production-provider matrix,
independent review, protocol certification or release-readiness evidence.

The [current report](../../tests/browser/oidc/results/2026-10-20/keycloak-configured-public-web-restarts.json)
also checks real factory process restarts while a callback is pending and after
session commit in each mode. Browser binding, persisted revision and the same local
owner/session survive, with no extra authentication audit. Actual HTTP response and
cookie delivery are observed to wait for the held final-audit transaction. All six
application instances stop normally. The earlier
[baseline report](../../tests/browser/oidc/results/2026-10-20/keycloak-configured-public-web.json)
is immutable historical evidence; the current report still contains eighteen cases.
