---
title: Quickstart
description: From a fresh checkout to a working email sign-in and authenticated browser request.
---

This tutorial runs the local server, PostgreSQL and a disposable email inbox. You will request a sign-in link, confirm it in your browser, read the resulting session and sign out. No external email account or IdP credentials are required.

## 1. Check prerequisites

Use Rust **1.95**, Git, Docker Compose and a POSIX-compatible shell. Start Docker Desktop or your Docker runtime before continuing.

```sh
rustc --version
docker compose version
docker info
```

If `docker info` cannot reach the daemon, start it before proceeding. Windows users can run these shell commands in WSL with Docker integration.

## 2. Clone the repository

```sh
git clone https://github.com/Deuspheara/easy-auth.git
cd easy-auth
```

Run the remaining terminal commands from this repository root. The Cargo packages are not yet published for `cargo add` installation.

## 3. Start the development services

```sh
docker compose up -d --wait
docker compose ps
```

The compose file starts PostgreSQL and Mailpit on loopback. Keep this terminal available for logs.

| Service       | Address                 | Purpose                    |
| ------------- | ----------------------- | -------------------------- |
| PostgreSQL    | `127.0.0.1:59473`       | Authentication database    |
| Mailpit inbox | `http://127.0.0.1:8025` | Read development emails    |
| SMTP          | `127.0.0.1:1025`        | Development email delivery |

## 4. Export configuration and start the server

For a **fresh checkout**:

```sh
cp .env.example .env
set -a
. ./.env
set +a
cargo run --locked -p easy-auth-server --bin easy-auth
```

If you already have a `.env`, inspect and reuse it instead of overwriting it. The binary does not load `.env` automatically: export it in every terminal that starts the server or example. Startup applies migrations before serving requests.

The example configuration uses HTTP, local SMTP and disposable database credentials. It is for loopback development only. Startup should emit the safe event `auth_server_started`. The first compilation can take a while.

In a **second terminal**, verify readiness:

```sh
curl -i http://127.0.0.1:58417/readyz
```

Expect **HTTP 200**. A 503 means the database is not ready; a connection error usually means the server did not start or the bind address differs. See [troubleshooting](/docs/troubleshooting/).

## 5. Sign in through the browser

1. Open `http://127.0.0.1:58417` in your browser.
2. Enter a disposable address such as `developer@example.test` and request a link.
3. Open `http://127.0.0.1:8025` and select that email in Mailpit.
4. Open the sign-in link in the **same browser profile** that requested it.
5. Confirm the address on the reference page.

The browser must retain the binding cookie from step 2. The email link expires after ten minutes; requesting a newer link replaces the pending binding in that browser. Simply opening the URL with GET does not consume it; confirmation performs the state change.

## 6. Check the session and sign out

Open `http://127.0.0.1:58417/v1/session` in the same browser. A signed-in request returns **200** with the public user object. An unsigned request returns **401**. The session secret is in an HttpOnly cookie and is never returned as JSON.

From that local application's developer console:

```js
const response = await fetch("/v1/session", {
  credentials: "same-origin",
});
if (response.ok) {
  const user = await response.json();
  console.log(user.id); // Public user ID, not a session secret.
}
```

Use the reference page's logout control, or call the [browser sign-out example](/docs/browser-integration/#sign-out). Confirm that `/v1/session` then returns 401.

## Stop and resume

Press `Ctrl+C` in the server terminal, then stop the development services:

```sh
docker compose stop
```

Resume with `docker compose up -d --wait`, export `.env` again and restart the server. Stopping services preserves the database volume.

## Next steps

- [Protect a route in Axum](/docs/embedding/): run a real example with a `/private` endpoint.
- [Integrate a browser UI](/docs/browser-integration/): check status codes, cookies and Origin requirements.
- [Prepare a deployment](/docs/deployment/): understand HTTPS, SMTP, storage and provider prerequisites.
