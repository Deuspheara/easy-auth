---
title: Getting started
description: Run a local easy-auth server with PostgreSQL and Mailpit.
---

## Run locally

You need Rust 1.95, Docker Compose and a shell. Use source dependencies while crate names and interfaces are pre-release.

```sh
git clone https://github.com/Deuspheara/easy-auth.git
cd easy-auth
docker compose up -d --wait
cp .env.example .env
set -a
. ./.env
set +a
cargo run -p easy-auth-server --bin easy-auth
```

Open `http://127.0.0.1:58417` and request a link using a test email address. Open Mailpit at `http://127.0.0.1:8025`, then follow the email link **in the browser that requested it**. No external mailbox is needed. PostgreSQL listens on loopback port 59473; SMTP uses 1025.

The link expires after ten minutes. Requesting another replaces that browser's pending binding. Opening a link with GET does not consume it; confirmation performs the state change.

## Choose an integration

Use the standalone process above, or run the existing embedded example with the same environment:

```sh
cargo run -p easy-auth-server --example embedded
```

[Embedding in Axum](/docs/embedding/) explains the composition and notification worker. [Server configuration](/docs/guides/server-configuration/) documents settings and startup diagnostics.

## Before deployment

The example environment is for explicit loopback development. Production needs HTTPS, TLS SMTP credentials, trusted realm configuration and operational deployment preparation. Do not copy development exceptions into a public service.

OIDC and SAML require explicit provider configuration and their respective feature flags. Read [feature status](/docs/features/) and the owning guide before enabling either. Never use these instructions as evidence of a completed independent security review.
