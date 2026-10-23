---
title: Troubleshooting
description: Resolve common setup, email, cookie and provider-startup problems without weakening checks.
---

## Docker cannot connect to its daemon

Start Docker Desktop or your chosen runtime, then run `docker info` again. `docker compose up` cannot start PostgreSQL while the daemon is unavailable.

## Database connection fails at startup

From the repository root:

```sh
docker compose ps
docker compose logs --tail=50 postgres
```

The compose service name is `postgres`. Confirm it is healthy, then export the development `.env` in the **same terminal** used to start the server. `DATABASE_URL` uses loopback port 59473 for this checkout, not PostgreSQL's usual host port 5432.

Do not paste real database connection strings into issue reports or public logs.

## Address already in use

The standalone server and embedded example use the same default development address. Stop the process already listening on 58417 before starting the other. Do not leave two different configurations competing for the same listener.

## The email did not arrive

Open the local Mailpit UI at `http://127.0.0.1:8025`. Development messages are captured there; they are not delivered to your real mailbox. Check that compose is running and `.env` was exported.

For a custom embedded application, keep `notification_worker` alive. The [complete example](/docs/embedding/) includes it. Do not log email contents or sign-in links while diagnosing delivery.

## The link is rejected, expired or opens without a session

Request a fresh link and open it in the browser profile that requested it. Keep cookies enabled. An incognito window, another device or an embedded mail browser may not have the binding cookie.

Use the latest link and confirm it within ten minutes. Loading the confirmation page with GET does not sign you in by itself. Avoid repeated requests that replace the pending browser binding.

## `/private` is 404

That route belongs to the **embedded example**, not the normal standalone server. Run `cargo run --locked -p easy-auth-server --example embedded`. The auth library does not create your application routes automatically.

## `/private` or `/v1/session` is 401 in curl

A new terminal client has no session cookie from your browser. Test in the signed-in browser first. Do not copy raw session cookies into shell history to make the check pass.

## POST returns an Origin or request error

Serve the UI from the configured same origin and use the documented method, JSON fields and content type. A different port is a different origin. Do not solve this by disabling Origin validation or adding permissive CORS.

## Password operations return 503

Passwords are opt-in. Configure `AUTH_PASSWORD_BLOCKLIST_FILE` with a valid file before startup. The example uses a tiny development-only corpus. Production requires a maintained corpus meeting the documented policy; do not reuse the demonstration list.

## Provider settings fail startup

OIDC and SAML are separately opt-in and require their compile-time features, complete settings and trusted persisted configuration. Partial settings fail closed. Read the dedicated [OIDC](/docs/guides/oidc/) or [SAML](/docs/guides/saml/) guide and do not remove a validation check to start the server.

## Report a reproducible problem

Record the Git revision, Rust version, integration mode, enabled feature names, safe error category and the step that failed. Include expected versus observed status codes. Remove passwords, SMTP/database credentials, cookies, auth headers, email tokens, authorization codes and SAML assertions before sharing diagnostics.
