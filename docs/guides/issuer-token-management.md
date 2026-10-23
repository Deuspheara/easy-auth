# Optional access revocation and introspection

This is the access-lifecycle increment of AUTH-40. Native refresh families, explicit
offline consent, secure storage and owned native browser acceptance remain unfinished.
Use [ADR0038](../architecture/adr/0038-native-token-lifecycle.md) for authority and
remaining scope. Normal standalone activation and production approval remain gated.

Enable `issuer-token-management` in core/PostgreSQL and
`issuer-token-management-web` in Axum. Supply the same trusted realm/HTTPS root
authority, existing `IssuerWebServices` and an `Arc<IssuerTokenManagement>` created
from that authority and repository to `experimental_issuer_token_management_web_router`.
Use actual socket `into_make_service_with_connect_info::<SocketAddr>()` when serving.
No normal configuration, private key provisioning or deployment is added.

The core service accepts `IssuerPresentedToken::parse` for bounded opaque input,
or `IssuerPresentedToken::from(&secret)` for an existing canonical credential.
Unknown valid token formats remain unknown, rather than bypassing client authentication
or requiring canonical minted-token parsing. No raw input is retained by this type.

| Endpoint | Authentication and result |
| --- | --- |
| POST `/oidc/introspect` | Current confidential Basic client, own audience only; active metadata or only `{"active":false}` |
| POST `/oidc/revoke` | Actual matching token possession plus current registered method; confidential Basic required for confidential clients;200empty body |

Both accept only form members token, optional client_id and optional token_type_hint.
Public revocation needs explicit client_id. An optional body ID must agree with Basic.
The hint is ignored and cannot choose a namespace or grant authority; this profile
looks up access credentials only. Forms are limited to4096bytes and tokens to1024
printable ASCII bytes. Duplicate decoded/unknown members, malformed percent/UTF-8,
queries, Content-Encoding and non-form media reject. No client_secret_post, cookie,
request owner/realm, Origin or forwarding-header authority is accepted. Missing
actual peer information fails503. Existing local cookie endpoints keep Origin checks.

Introspection checks current registration/credential, source/account/session,
retained key/namespace, original consumed grant and original time caps under locks,
then checks the database clock after all waits. It does not touch idle time. Current
active-key rotation preserves a live token under its retained key; disabling that
key or source makes it inactive. Changing the client revision invalidates the old
grant even when new current credentials authenticate correctly. Wrong/disabled client
credentials return401; storage failure503 is never converted into inactive success.
All responses use no-store/no-cache and set no session cookies.

Active metadata contains only active, iss, aud, client_id, pairwise sub, iat, exp,
token_type and scope. It exposes no local user/session identifier, email, nonce, hash,
raw token or business role. Unknown, foreign, expired and revoked input reveals no
active claims. Public identifiers and local cookies cannot authenticate introspection.

Revocation is idempotent and permanent for that credential. It does not change the
local browser session, original code/audit or other clients/realms. Valid possession
can reduce authority after source/session expiry. Offline ID tokens and downstream
app sessions are not remotely erased. A fresh authentication/code is needed to mint
another credential; these APIs cannot refresh or lengthen an existing token.

These extra endpoints are described by `issuer_token_management_openapi`; discovery
retains the existing issuer profile while the full native feature is unfinished.
Default `issuer-web`, consent-only and standalone routers expose no management routes.

Use disposable real PostgreSQL for verification:

```sh
cargo test --locked -p easy-auth-core --features issuer-token-management issuer::tokens
cargo test --locked -p easy-auth-postgres --features issuer-token-management --test lifecycle token_status
cargo test --locked -p easy-auth-axum --features issuer-token-management-web --test browser issuer_web
```

Required full workspace, strict Clippy, formatting, security and exact-source hosted
results are recorded separately; focused passes do not complete the refresh/native
acceptance requirements or establish independent security approval.
