---
title: Use it in your project
description: Create a separate Axum application with explicit path dependencies and the working protected-route example.
---

This guide creates a small application beside your `easy-auth` checkout. It uses **path dependencies**, because the packages are currently unpublished. First complete the [quickstart](/docs/getting-started/) so the database and development configuration exist.

## 1. Create the application

From the `easy-auth` repository root:

```sh
cargo new ../my-auth-app
mkdir -p ../my-auth-app/src/embedded
cp apps/auth-server/examples/embedded.rs ../my-auth-app/src/main.rs
cp apps/auth-server/examples/embedded/application.rs \
  ../my-auth-app/src/embedded/application.rs
```

Your directory structure should be:

```text
parent-directory/
├── easy-auth/
└── my-auth-app/
    ├── Cargo.toml
    └── src/
        ├── main.rs
        └── embedded/
            └── application.rs
```

The copied files are the complete [protected-route example](/docs/embedding/), not an unimplemented SDK sketch. Keep the `embedded/application.rs` location: `main.rs` names it with a Rust `#[path]` attribute.

## 2. Set explicit dependencies

Replace `my-auth-app/Cargo.toml` with:

```toml
[package]
name = "my-auth-app"
version = "0.1.0"
edition = "2024"
rust-version = "1.95"

[dependencies]
easy-auth-server = { path = "../easy-auth/apps/auth-server" }
auth-core = { package = "easy-auth-core", path = "../easy-auth/crates/auth-core" }
auth-axum = { package = "easy-auth-axum", path = "../easy-auth/crates/auth-axum" }
axum = "0.8"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
```

These paths assume the layout above. If your checkout has a different name or location, adjust **all three paths**. Keep the easy-auth packages on the same source revision. Do not use `workspace = true` unless your own workspace defines those dependencies.

## 3. Export the development configuration

Stop the original server if it still owns port 58417. From your new application:

```sh
cd ../my-auth-app
set -a
. ../easy-auth/.env
set +a
export AUTH_PASSWORD_BLOCKLIST_FILE=../easy-auth/docs/examples/password-blocklist-development.txt
cargo run
```

The password list path is adjusted because the process now runs from a different working directory. PostgreSQL and Mailpit still come from the original compose stack. Your first build creates an application-specific Cargo lockfile; commit that lockfile in your application.

## 4. Verify the application

Open `http://127.0.0.1:58417/private` before sign-in: expect **401**. Complete email sign-in at the app's root page, then open `/private` again: expect **200** and the public user object. If a session from a previous tutorial is still active, log out before checking the unauthenticated case.

At this point the new process owns its routes and listener. Add business routes alongside `/private` and apply your application's permission checks after authentication. Keep the existing core, router and notification worker; do not duplicate verification or persistence rules in your handlers.

Before hosting outside loopback development, follow the [deployment checklist](/docs/deployment/).
