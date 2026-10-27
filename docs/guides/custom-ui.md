# Build a custom same-origin UI

Use the selected [HTTP contract](../architecture/api-contract.md) and
[reference client](reference-ui.md) as the boundary. You can replace presentation
without copying authentication, freshness or SQL rules into the browser.
The embedding application still owns its business authorization.

## Choose browser cookies or an independent RP

A first-party page served from the trusted authentication origin uses the existing
HttpOnly session and browser-proof cookies. Browser JavaScript cannot read or
construct those secrets. Keep exact-Origin POST enforcement, HTTPS in production,
no-store/no-referrer responses and the selected router's closed request schemas.
Serving unrelated origins does not become supported by adding a permissive CORS
header or sharing the issuer's cookies.

An independent application instead uses the optional
[outbound OIDC issuer](issuer-standalone.md) and its own RP callback/state/session.
The [Rust client](oidc-client.md) verifies RP metadata, not an easy-auth local
session. It cannot turn a vendor ID token or access credential into a local user.
Native applications also need their own protected credential storage and actual
callback-listener ownership; [native issuer setup](issuer-native.md) is separate
from an upstream Google desktop login.

## Request and state ownership

A same-origin session read can use this minimal pattern:

```js
const response = await fetch('/v1/session', {
  credentials: 'same-origin',
  cache: 'no-store',
  redirect: 'error',
});
if (response.status === 401) {
  // Show signed-out UI; this read grants no account authority.
} else if (response.ok) {
  const account = await response.json();
  // Render bounded public fields as text. The backend authorizes every action.
} else {
  // Show a fixed unavailable state; do not expose raw response diagnostics.
}
```

Send the documented JSON POST only after the corresponding deliberate action.
Do not add owner, realm, provider-policy or return-URL selectors absent from the
contract. Keep browser proof in its existing cookie/transient operation, not
localStorage, sessionStorage, a log, a URL or analytics. Clear password/code inputs
after use and navigation. Abort outstanding page work and discard late results;
recheck the current owner before sensitive actions. A browser abort cannot undo
an already committed server operation.

An interrupted credential finish is ambiguous: never automatically repeat it.
After a failed continuation, show an explicit retry only where the API permits
it, such as an inventory GET or a new sign-in attempt with a fresh challenge.
Render request errors using fixed categories and preserve unavailable versus
unauthorized outcomes. Do not fall back to mailbox/password for a stronger account.

## Available methods and account controls

Supply UI capabilities from trusted server composition, rather than from URL
parameters or compiled feature names. The reference root projects only actually
selected interfaces. Passwords additionally require the configured password
service; passkeys/recovery require their explicit experimental constructors.
Provider trust and account policy still apply after a button becomes visible.
There is no placeholder Apple or provider-linking implementation.

`authentication_policy` is public account metadata, not current authentication
method or proof of freshness. Use the existing [passkey management](passkey-management.md)
and [account lifecycle](account-lifecycle.md) operations with their real method,
confirmation and version requirements. A verified contact on a strong account
does not enable weaker login/recovery. Keep users, contacts, provider identities,
credentials and sessions as separate objects.

Inventory reads are bounded and owner-scoped. A reload clears the old rows/count
and pagination cursor before requesting page one; a failed continuation may retain
already accepted pages. Capture the displayed key version for rename/removal.
Do not infer device/location, manufacture a key count or treat provider labels as
HTML/navigation. Reauthentication must be deliberate and retain the same owner;
merely adding a key does not upgrade the current session's method.

## Callback pages and proof handling

Reuse the selected provider's fixed callback/confirmation routes. A callback GET
or SAML POST bridge is not a local grant. Keep the independent purpose cookies,
same-browser operation binding, immediate query/fragment scrubbing and explicit
same-origin completion. Do not upload an unsolicited identity token, parse an
assertion in UI code or replace signed authentication time with local time.

For a separate frontend build, serve fixed local assets under an appropriate
strict CSP. The reference stylesheet's exact hash applies to its own bytes;
modifying CSS requires a new matching policy. Do not enable broad inline styles,
external scripts or third-party telemetry to make a copied page render.

Validate real SMTP/native/provider flows, negative protocol cases, navigation,
keyboard/focus, responsive themes and actual committed database effects. Mocked
successful responses or a screenshot do not establish authentication. The
[reference acceptance instructions](../../tests/browser/reference-ui/README.md)
document its owned fixtures and remaining device/assurance limits.
