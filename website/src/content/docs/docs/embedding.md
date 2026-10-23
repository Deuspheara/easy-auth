---
title: Embed in Axum
description: Compose the configured router and notification worker in an Axum application.
---

Use workspace/path dependencies from the repository while APIs are pre-release. Both embedded and standalone modes read the same trusted configuration and use the same core policy and PostgreSQL transactions.

## Minimal composition

The `easy-auth-server` library exports the configured application and its email notification worker:

```rust
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = easy_auth_server::configured_application().await?;
    let notifications = easy_auth_server::notification_worker(app.auth.clone());
    let listener = tokio::net::TcpListener::bind(app.bind).await?;
    let result = axum::serve(
        listener,
        app.router.into_make_service_with_connect_info::<SocketAddr>(),
    ).await;
    notifications.abort();
    result?;
    Ok(())
}
```

Keep the notification worker alive for email delivery. Your application should manage graceful shutdown for its own runtime. The repository's [embedded example](https://github.com/Deuspheara/easy-auth/blob/main/apps/auth-server/examples/embedded.rs) also merges application routes and demonstrates the authentication boundary.

From the repository, use the [local development environment](/docs/getting-started/) and run:

```sh
cargo run -p easy-auth-server --example embedded
```

## Preserve the boundaries

- Mount the configured router; do not duplicate provider or session policy in application handlers.
- Preserve connection information and the documented trusted proxy configuration.
- Keep application permissions separate from authentication and session identity.
- Do not link accounts by matching email addresses.
- Use documented provider configuration and persisted administrative registration; browser input cannot grant trust.

Read [session management](/docs/guides/sessions/) and [server configuration](/docs/guides/server-configuration/) before integrating account-sensitive actions.
