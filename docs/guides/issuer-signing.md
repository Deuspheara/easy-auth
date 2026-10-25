# Optional signed issuer component

This explicit crate composition extends [client registration and consent](issuer-clients.md).
It does not activate the standalone server or establish outbound production approval.
Use `issuer-signing` in core/PostgreSQL, `issuer-web` in Axum and optionally
`issuer-signing` in the server library for protected operator file loading.

Trusted embedding supplies one `IssuerAuthority` with a stable HTTPS root issuer
and realm. Wire input cannot select a realm, issuer, owner or source policy. Keep
local session cookies and inbound federation separate from client token credentials.

1. Load explicit operator PKCS8 RSA keys into `IssuerSigningKey` with non-nil key IDs.
   On Unix, `easy_auth_server::load_issuer_signing_key(id, path)` checks the opened
   regular owner-only bounded file and refuses a final symlink. The embedding must
   control parent directories and ownership. Non-Unix file loading fails closed.
2. Publish each allowlisted public projection with `publish_issuer_key`. Configure
   ordered signing/verification windows; verification retention cannot shrink and
   must extend at least300seconds beyond signing. No private material goes into SQL.
3. Explicitly select the initial key with `activate_issuer_key`, then enable the exact
   returned revision using `enable_issuer_signing`. Replacement keys must have been
   persisted for300seconds. Reconfiguration preserves operator disable; activating
   another key does not re-enable a disabled namespace.

Re-enabling a disabled key or reopening an expired publication starts a fresh
300second propagation deadline, even for the selected key. Historical bootstrap
or publication age cannot bypass it. Uninterrupted live publication keeps its
existing matured readiness.
4. Construct `IssuerWebServices` from the exact authority, token/metadata repositories
   and up to four protected keys. Use `experimental_issuer_web_router` with the same
   Auth realm and HTTPS browser origin. Serve with actual socket
   `into_make_service_with_connect_info::<SocketAddr>()`; missing peer data fails closed.

Discovery advertises code/query, openid, S256, pairwise subjects, RS256 and public or
Basic client authentication. Public JWKS retains up to four current/overlap keys.
Per-key emergency disable removes a key from new responses; previously cached keys
are not remotely erased. Global issuance disable retains public verification keys.
Never reuse a key ID with different material or silently fall back when the current
selected private key is absent/mismatched. Keep issuer/realm composition and private
key distribution under trusted operator control.

The existing consent page requires an actual fresh source-aware local session and
explicit preview/approval. Token clients send a closed bounded form POST to
`/oidc/token`, with the same actual redirect and PKCE verifier. Confidential clients
use Basic with each component form-encoded; public clients send client_id. Cookies,
Origin and forwarding headers provide no client/token authority. There is no
client_secret_post, refresh, userinfo, introspection or client assertion in this profile.

Signing is staging only. Final SQL rechecks all current configuration, owner/source/
session, full original code snapshot and time caps before atomically storing the
hash-only access credential, consuming/scrubbing the code and recording audit.
Errors never return staged tokens. Fixed ID claims are iss/aud/sub/nonce/iat/exp/
auth_time; authentication time is the original event. Expiry retains the original
code/session/freshness/key caps, so the current60second code lifetime also bounds
tokens. Access credentials cannot authenticate local sessions or authorize app roles.
Erasure removes local ledger/code/subject rows; it cannot remotely erase an already
issued self-contained ID token or an application's session. Consumers must honor
token expiry and their own session/revocation policy. No immediate offline JWT
revocation or downstream sign-out propagation is claimed.

Focused verification commands (use disposable real PostgreSQL):

```sh
cargo test --locked -p easy-auth-core --features issuer-signing issuer::
cargo test --locked -p easy-auth-postgres --features issuer-signing --test lifecycle issuer_signing
cargo test --locked -p easy-auth-axum --features issuer-web --test browser issuer_web
cargo test --locked -p easy-auth-axum --features issuer-web,oidc-web --test browser issuer_web::rp
cargo test --locked -p easy-auth-server --features issuer-signing issuer_key::
```

The [owned HTTPS runner](../../tests/browser/issuer-web/README.md) uses actual email/
browser consent and a separate cookie-free client, with ordinary unchanged production
tokens. In-process RP cases share the existing verifier dependency; Node verifies the
healthy browser-issued token separately. Neither is external RP certification or
independent security review. Native owned-listener/storage, broader conformance and
production supervision remain separate work. [ADR0037](../architecture/adr/0037-issuer-signing-and-final-issuance.md)
records the current implementation and evidence limits.

The separate optional [access management component](issuer-token-management.md)
adds authenticated introspection and possession-bound revocation. It preserves
this component's original caps and does not create refresh/offline authority.
