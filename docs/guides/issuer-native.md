# Explicit native issuer wire profile

Optional `issuer-native-web` adds engineering composition for native code/refresh
and revocation, preserving existing online clients. Normal standalone outbound
activation and production approval remain gated. See [ADR0038](../architecture/adr/0038-native-token-lifecycle.md).

Create the existing `IssuerWebServices` with one trusted realm/HTTPS root, protected
operator keys and repositories. Pass it plus native-token, native-refresh and access
status repository ports to `IssuerNativeWebServices::new`, then call
`experimental_issuer_native_web_router(auth, browser, services)`. All services derive
that same authority and native signing shares the original concrete engine/capacity.
Serve with actual socket `ConnectInfo<SocketAddr>`; no forwarding/cookie fallback.
The constructor neither provisions keys/clients nor enables native policy.

Provision the distinct public native registration and exact enabled saved native
policy first. Bind a literal127.0.0.1 or[::1] listener before starting authorization;
retain its exact actual callback, PKCE verifier, random state and nonce privately.
The registered callback template permits only its literal interface/path and actual
bound port variation. A loopback IP never becomes a shared account subject sector.

## Authorization and credentials

Discovery advertises code/refresh_token and openid/offline_access only on this
explicit composition. Standard `/oidc/authorize` selects a fixed local native page
for the offline variant; it creates no state and cannot select an external return.
The native page retains its mode after query scrubbing/reload, shows original grant
expiry/idle and requires explicit protected owner confirmation. Existing online
pages/consent remain unchanged. An enabled native profile cannot enter online-only
approval/signing, even when given an apparently valid code.

POST `/oidc/token` accepts closed, bounded form input. Authorization-code members
remain grant_type, code, redirect_uri, code_verifier and optional client_id (required
without Basic). Current registration selects exactly one existing core operation,
with one committed source admission before lookup, including unknown clients. Every
selected transaction rechecks actual credentials, source/owner/session, original
policy/code/consent/key and caps; failed branches never retry through another flow.

Native code output contains access_token, token_type, expires_in, id_token,
refresh_token, refresh_expires_in and scope. Original short code/freshness/key bounds
still cap initial ID/access; the distinct offline family retains the original
proposed/source absolute cap. Ordinary online clients keep the original five fields
and openid scope, with no refresh credential. Concrete response schemas are closed.

Refresh members are grant_type=refresh_token, refresh_token, optional client_id and
optional scope. Scope must be omitted or exactly `openid offline_access`; other
values fail invalid_scope, never widen authority. Code/redirect/verifier/secret_post
fields cannot select a refresh path. The current native client plus matching opaque
credential are mandatory; cookies, public identification alone and hints confer no
credential authority. Actual peer, strict percent/UTF-8/duplicate/media/query/body
checks and no-store/no-cache/finite errors are shared with existing token transport.
Token forms are at most8192bytes; status forms4096bytes; presented opaque input1024.

Successful refresh returns only opaque access/refresh, type, expiries and original
scope; no new ID token, authentication time or cookie. Access lasts at most300seconds,
within current key/new idle/original absolute bounds. Cookie idle/freshness and
original auth_time are never extended. Current OIDC/SAML source, account method,
client/native-policy revision, session/revoke-all and original absolute cap remain
mandatory even though the explicit grant can outlive cookie idle/freshness.
Maximum10active families per owner/client and10000generations require fresh consent.

One-use refresh rotation, hash-only history and typed credential audit commit
atomically. The final clock includes the old idle deadline after waits/writes.
Spent-credential reuse permanently revokes family/all descendant access before
invalid_grant. There is no parallel retry/grace window. Storage/audit failure is an
error with rollback, never successful credential delivery.

## Cleanup, consumers and storage

POST `/oidc/revoke` accepts token plus optional client_id/token_type_hint under the
existing registered-method rules. Actual registration selects only its scoped
online access or native family reduction; hint cannot select authority. Possession
of either matching native refresh/access can reduce that family after source/policy/
session disable. Unknown/repeated input succeeds with empty200, permanently.
No user-session actor is fabricated. It cannot erase offline ID tokens/downstream
application sessions or grant local authentication/business permissions.

The existing `/oidc/introspect` retains authenticated confidential own-audience online
inspection. To enable native consumption explicitly, call
`services.with_native_introspection(repository)` before building the native router.
This adds POST `/oidc/native/introspect` and its live contract; the route is absent
without that builder. The repository implements `IssuerNativeIntrospectionRepository`
and the separate core service is `IssuerNativeIntrospection`.

Provision a confidential Basic consumer and the native public audience, then save
`IssuerNativeConsumerPolicy::new(authority, consumer, audience)` through
`configure_issuer_native_consumer`. New policy is disabled. Enable the exact saved
policy through `enable_issuer_native_consumer`; disable/load use
`disable_issuer_native_consumer`/`load_issuer_native_consumer`. Both current full
client definitions/revisions are mandatory. Reconfiguration cannot clear disable;
old revisions cannot re-enable themselves. These trusted APIs are not browser input.

Native inspection uses the same strict status form and actual Basic authentication.
Unknown/foreign/inactive/unauthorized tokens return only active=false. Wrong or
missing credentials return401, even for unknown tokens; storage faults remain errors.
Active metadata contains active/iss/aud/client_id/pairwise-sub/iat/exp/Bearer/scope.
Audience/client_id identify the native audience, and scope is openid offline_access.
Current exact consumer permission/native policy, retained key, original provider
source/account/session, family and access bounds remain mandatory after locks/waits.
No cookie idle/auth_time is extended. Public native IDs/cookies/tokens cannot
authenticate a consumer or become a local session/business permission. See
[ADR0039](../architecture/adr/0039-native-introspection-consumers.md).

Production native clients must keep refresh credentials in protected per-user
platform credential storage, never URLs, logs, source, browser storage or shared
cookies. Serialize rotation and atomically replace the stored credential only after
successful delivery. Ambiguous/lost outcomes require reauthentication when reuse
cannot safely recover; no grace/parallel retry fallback. Clear unusable credentials
on permanent denial and use explicit server cleanup for theft/logout. The owned
fixture uses memory only and does not establish OS-vault integration.

## Evidence and limits

[Owned native browser acceptance](../../tests/browser/issuer-native/README.md) uses
actual Chromium, a real bound TCP callback and separate trusted HTTPS PKCE client,
with the unchanged ordinary fixture signer. Genuine OIDC/SAML provider cases reuse
existing normal producers and show original auth_time, no cookie-idle extension,
current-policy/source denial and post-disable credential cleanup. These are bounded
owned tests, not independent certification, a security audit or production approval.
SDK/standalone standards-client parity remains AUTH-41; SAML ADR0032 waived
independent review rather than performing it.
