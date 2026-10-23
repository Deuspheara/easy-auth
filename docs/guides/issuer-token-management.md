# Optional access revocation and introspection

This is the access-lifecycle and native consent-library work of AUTH-40. Native
family issuance/rotation/revocation are available as library operations; native token/refresh HTTP
and owned native browser acceptance remain unfinished.
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

## Explicit native policy configuration

Optional core/PostgreSQL `issuer-native-refresh` adds configuration and separate
explicit native consent-library operations. Default issuer HTTP routes do not
accept `offline_access`, issue/rotate refresh credentials or add native routes.
The new offline-capable profile also refuses the existing online-only authorization
flow, even with an enabled policy. Existing ordinary web/native profiles retain
their openid flow. Native HTTP token delivery and owned browser acceptance remain work.
Provision `IssuerClientRegistration::public_native_refresh_loopback` through the
existing trusted client API, then construct `IssuerNativeRefreshPolicy::new` with
the exact saved client, trusted `IssuerAuthority`, absolute seconds and idle seconds.
Only literal127.0.0.1 or[::1] HTTP callbacks with an exact registered path are allowed;
only the actual bound port may vary. A shared loopback IP is never a subject sector.

`configure_issuer_native_refresh_policy` returns a new saved revision, initially
disabled. `enable_issuer_native_refresh_policy` requires that exact definition and
the current enabled client; `disable_issuer_native_refresh_policy` reduces only the
selected realm/issuer/client policy and invalidates old snapshots. Replacement
preserves disable. `load_issuer_native_refresh_policy` restores read-only enabled
configuration after restart; `check_issuer_native_refresh_policy` performs a locked
current-definition check. Neither is a user/consent/token proof. Client replacement
requires a newly configured policy; stale enable cannot restore an old grant.

Absolute lifetime must be1second–7days, idle1second–24hours, idle no greater than
absolute lifetime. The proposed explicit consent grant retains its original source/
session absolute expiry even if configured lifetime is longer. Cookie freshness,
cookie idle and the existing short code are separate authority and remain unchanged.
Migration0033 preserves every existing online row and creates no policy by default.
Feature-disabled/older loaders refuse the distinct offline client profile.
The [native policy receipt](../security/issuer-native-policy-verification.md) records
this configuration increment separately from earlier access-management evidence.

## Explicit native consent library

Create `IssuerNativeAuthorization` with the trusted authority and an
`Arc<dyn IssuerNativeAuthorizationRepository>` (implemented by PostgreSQL). Its
`prepare` takes genuine current-session/private-browser secrets and an
`IssuerNativeAuthorizationInput` wrapping the usual code fields plus exact
`prompt=consent`; scope must be exactly `openid offline_access`. S256, actual bound
return URI, state and nonce retain their existing validation. Native policy must
already be enabled. The default online request/service/repository cannot substitute
for this use case, even when given its validated code component.

Render the safe `preview` metadata and require an explicit owner decision in the
trusted UI. `approve` requires the same genuine fresh session, browser, opaque
handle and authorization selector; it commits a subject, short-lived one-use code,
fixed native consent and the existing typed owner-session authorization audit before
returning code/state/iss. `cancel` removes only pending consent and still works after
policy disable. Consent itself issues no refresh token; the old online signer cannot redeem
that native code. Dedicated confirmation HTTP/routes are described below; do not treat
the input prompt string as proof that a human reviewed a page.

The proposed grant expires at its original preparation time plus the saved lifetime,
capped by the captured original source/session absolute expiry. Preview/approval
never slide that expiry. Actual approval time is separate. Consent/code delivery
keeps the old short/fresh/idle caps and final clock; native refresh authority uses the separate retained grant bounds. Policy/client revision
changes invalidate old decisions; current source/session narrowing cannot widen them.
Apply migration0034 before serving requests on fresh connections. Reconnect after
schema DDL rather than retaining old prepared SELECT * result types.
The [native consent receipt](../security/issuer-native-consent-verification.md)
records the library scope and its explicit remaining acceptance work.

Native clients must keep refresh credentials in protected per-user platform
credential storage, never URLs, logs, source files, browser localStorage or shared
cookies. Serialize refresh operations and atomically replace the stored credential
only after successful rotation; ambiguous/lost refresh outcomes require explicit
reauthentication when reuse detection cannot safely recover. Do not implement a
parallel retry/grace fallback. Local deletion cannot remotely erase a stolen token;
server family revocation and downstream session policy remain necessary. These are
client requirements for the family flow, not completed integration evidence.

## Native family library

Enable core/PostgreSQL `issuer-native-refresh` and apply migration0035 before
requests on fresh database connections. Construct `IssuerNativeTokenIssuer::new`
from the existing `IssuerTokenIssuer` and an
`Arc<dyn IssuerNativeTokenRepository>`. This shares the concrete RS256 signing keys,
capacity and timeouts. Its `exchange` accepts only the separately approved native
code, exact actual callback, original PKCE verifier and matching current client.
It returns short ID/access credentials plus the initial opaque refresh credential
only after the complete consent/code/family/audit transaction commits.

Construct `IssuerNativeRefresh` from the same trusted authority and PostgreSQL port.
`refresh` accepts current client authentication, `IssuerPresentedToken` and actual
peer source; it returns new opaque access/refresh credentials after one-use atomic
rotation. It issues no new ID token. Access lasts at most300seconds; idle rolls only
within the immutable original offline/source absolute cap. Cookie idle/freshness,
authentication time and session expiry are never extended. Logout/revoke-all, changed
source/account method, policy/client revision and disabled key namespace deny refresh.
Maximum10active families per owner/client and10000rotations per family require new
explicit consent when exhausted. Do not run parallel refresh/retry fallbacks.

Any spent refresh replay permanently revokes its family and descendant access.
`revoke` accepts a matching refresh or native access credential and reduces only its
scoped family, including after logout/policy disable. Unknown/repeated input is
indistinguishable success; storage/audit failures remain errors. No cookie session,
application permission, authenticated public introspection consumer or immediate
offline JWT erasure follows. Existing HTTP routes do not expose these native methods.

## Explicit native confirmation HTTP/UI

Enable `issuer-native-consent-web` and construct
`experimental_issuer_native_consent_router(auth, browser, online, native)` with
`Arc<IssuerAuthorization>` and `Arc<IssuerNativeAuthorization>` for the exact same
HTTPS root issuer/realm. Provision the native profile/policy through the trusted
library first. The component retains ordinary consent pages/POSTs and adds:

| Route | Purpose |
| --- | --- |
| GET `/oidc/native/authorize` | Fixed native confirmation page; query is scrubbed and GET allocates nothing |
| POST `/v1/oidc/native/consent/prepare` | Closed usual authorization fields plus exact prompt=consent and openid offline_access |
| POST `/v1/oidc/native/consent/resume` | Empty closed object; recover only the privately bound pending preview |
| POST `/v1/oidc/native/consent/approve` | Explicit displayed authorization UUID plus the genuine initiating session/browser/handle |
| POST `/v1/oidc/native/consent/cancel` | Same private bindings; deny without creating authority |

All POSTs require the same trusted Origin, real session and16KiB closed JSON bounds.
There is no bearer/header/current-session body fallback. Online/native requests share
one private cookie operation slot; a second preparation cannot overwrite it. The
native preview adds immutable proposed grant expiry and idle seconds. The UI displays
both before Allow offline access; only the authenticated server result selects the
return address. No query/localStorage/sessionStorage value becomes a proof. Reload
can resume the original fixed preview; restoration stops further actions. Shared
browser mechanics use a fixed server HTML marker to choose the display/transport
variant, never core authorization policy. Old default HTML/query behavior is unchanged.

Success clears private operation transport; failures preserve retry state, except
unusable resume clears only selected transport. Actual local session replacement
clears that shared slot. Current source/owner/freshness/client/native-policy/code/
consent and final clock remain core/PostgreSQL rules. Cancellation after policy
disable remains possible. Cross-kind/realm/session/operation proofs cannot approve.

`issuer_native_consent_openapi` describes these closed shapes with distinct native
operation IDs. This consent-only composition mounts no token, refresh, revocation
or discovery endpoint; native token HTTP and actual owned native client/browser
acceptance remain AUTH-40 work. A code can currently be exchanged through the
separate concrete native library. Normal standalone outbound-issuer activation stays gated.
