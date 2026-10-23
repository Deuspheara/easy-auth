---
title: Browser integration
description: Read a session, initiate email sign-in and sign out with same-origin fetch examples.
---

These examples run in a browser page served by your local easy-auth application at `http://127.0.0.1:58417`. They do not run from this documentation website. Use the [quickstart](/docs/getting-started/) first.

## Read the current user

```js
async function currentUser() {
  const response = await fetch("/v1/session", {
    credentials: "same-origin",
    cache: "no-store",
  });
  if (response.status === 401) return null;
  if (!response.ok) throw new Error("Session lookup unavailable");
  return response.json();
}

const user = await currentUser();
if (user) {
  // Render public profile data as text, not HTML.
  document.querySelector("#account-name").textContent =
    user.display_name ?? user.email ?? "Signed in";
}
```

Your page supplies an element with `id="account-name"`. Both `email` and `display_name` can be null for provider-only identities. Use `user.id` as the public identity key; do not use email as a stable account-linking rule.

The session cookie is **HttpOnly**. Let the browser send it; do not try to read it with JavaScript, copy it to localStorage or invent a bearer token from the user JSON.

## Request an email sign-in link

```js
async function requestSignIn(email) {
  const response = await fetch("/v1/email/start", {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  if (response.status === 202) return "Check your inbox";
  if (response.status === 429) return "Try again later";
  throw new Error("Sign-in request unavailable");
}
```

Call this from a deliberate form submission. The browser sets the Origin header. A 202 is a generic acceptance response; it is not a signed-in session or proof that an account exists. The browser keeps a binding cookie for the confirmation flow.

For your first integration, use the included confirmation page from the email link. It removes the fragment before posting the token. Custom confirmation clients must follow the same browser-binding and token-handling contract; do not send raw email tokens to analytics or logs.

## Sign out

```js
async function signOut() {
  const response = await fetch("/v1/logout", {
    method: "POST",
    credentials: "same-origin",
  });
  if (response.status !== 204) throw new Error("Sign-out unavailable");
  window.location.assign("/");
}
```

A successful logout revokes the server-side session and clears the cookie. A later `/v1/session` request should return 401. Clearing frontend state alone does not revoke a session.

## Check both HTTP and UI behavior

| Action                                     | Expected result                                        |
| ------------------------------------------ | ------------------------------------------------------ |
| Read session before sign-in                | 401; show signed-out UI                                |
| Request an email link                      | 202; show a generic inbox message                      |
| Confirm the link in the requesting browser | 204 from finish; session cookie established            |
| Read session after sign-in                 | 200; public user JSON                                  |
| Log out                                    | 204; later session lookup is 401                       |
| Exceed admission limits                    | 429; show a retry message, not an automatic retry loop |

The reference application is **same-origin**. Loading a frontend on another port or origin does not automatically work by adding `credentials: 'include'`. The API checks the exact configured Origin on mutation requests; arbitrary CORS and shared-cookie deployment are not provided.

## Find the implemented API

The running server exposes its schema at `http://127.0.0.1:58417/openapi.json`. Use it with the owning feature guides. Do not assume a planned endpoint exists because a similarly named library provides it.

Continue with [password enrollment](/docs/guides/passwords/), [session management](/docs/guides/sessions/) or the complete [protected Axum route](/docs/embedding/).
