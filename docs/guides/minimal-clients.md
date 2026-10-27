# Minimal Rust and TypeScript integrations

The default application exposes same-origin browser APIs and an embeddable Rust
core. An independent relying party uses the separate [Rust OIDC client](oidc-client.md),
not a local session cookie. A public user UUID or authentication-policy label is
metadata, not a token, fresh-method proof or application permission.

## Independent Rust public-HTTP probe

The complete [consumer example](../../examples/clients/rust/src/main.rs) has its
private [HTTP module](../../examples/clients/rust/src/probe.rs),
[manifest](../../examples/clients/rust/Cargo.toml) and lockfile. It is a small
unpublished example outside the authentication workspace, not another server crate
or a new authentication SDK. Against the [local container stack](containers.md):

```sh
EASY_AUTH_CLIENT_ORIGIN=http://127.0.0.1:58418 \
  cargo run --locked --manifest-path examples/clients/rust/Cargo.toml
```

It requires health/readiness 200 and session 401 from an anonymous client, and emits
only those finite results. It carries no browser cookie, proof or RP token. A
browser login must not make this independent process authenticated. The maintained
HTTP client checks normal HTTPS certificates, refuses redirects/proxies/retries,
bounds request time and admits HTTP only for literal-loopback development origins.
It does not implement mailbox confirmation or establish provider availability.

For actual server-side application integration, use the complete existing
[embedded example](../../apps/auth-server/examples/embedded.rs) and its
[protected route](../../apps/auth-server/examples/embedded/application.rs).
Keep the configured application's listener and notification-worker lifetime, use
the shared auth API, and apply business authorization after authenticating.
For an independent RP/native client, follow the [issuer setup](issuer-standalone.md)
and [native client contract](issuer-native.md); issuer release acceptance remains open.

## Same-origin TypeScript browser module

[browser.ts](../../examples/clients/browser.ts) provides three small functions:
`currentUser()`, `requestEmail(email)` and `signOut()`. It validates public response
shape, distinguishes 401/202/429, emits fixed errors and never serializes a private
cookie or automatically retries completion. Compile it with your existing
TypeScript toolchain and serve the resulting JavaScript from your application's
origin under its strict CSP. Repository checks use the locked website compiler:

```sh
website/node_modules/.bin/tsc examples/clients/browser.ts --strict \
  --target ES2022 --module ES2022 --lib ES2022,DOM --outDir target/client-example
```

Compilation is a development step; the module needs no framework or browser/server
Node runtime. With your application serving it at `/assets/easy-auth-client.js`:

```js
import { currentUser, requestEmail, signOut } from "/assets/easy-auth-client.js";

const user = await currentUser();
document.querySelector("#account-name").textContent =
  user?.display_name ?? user?.email ?? "Signed out";

// Call these from deliberate form/button handlers; keep busy/error UI in your page.
// await requestEmail(emailInput.value);
// await signOut();
```

The page supplies `#account-name`. Render provider/profile values as text.
Keep private credentials out of logs, analytics and browser storage. The browser
sets Origin and sends HttpOnly cookies itself; this is not cross-origin CORS support.
An accepted email request is generic and does not prove account existence/delivery.
Use the included email confirmation page in the requesting browser; it preserves
the original binding and scrubs the proof fragment before completion. See the
[custom UI contract](custom-ui.md) for callback, navigation and stronger-method rules.

After genuine confirmation, `currentUser()` must return the actual user. After
`signOut()` returns, it must return null. Clearing UI or browser storage alone
cannot revoke a server session. Optional protocols still require their owning
feature, trusted configuration, signed proof and final policy/realm checks.
