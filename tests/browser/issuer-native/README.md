# Owned native issuer acceptance

Use only disposable local PostgreSQL and the repository's existing pinned browser:

```sh
cargo build --locked -p easy-auth-axum --features issuer-native-web --example issuer-web-browser
DATABASE_URL=postgres://… node tests/browser/issuer-native/run.cjs
```

The runner explicitly selects the owned example's native profile, reusing its
unchanged ordinary ephemeral signer, TLS proxy and database/process lifecycle.
Default example mode remains the original online profile; unsupported/unknown mode
fails closed. Never deploy that example, inbox or native test configuration.

A separate real Node HTTP listener binds127.0.0.1:0 before authorization. Chromium
navigates through actual HTTPS email completion, protected native preview/recovery
and explicit deny/allow, then reaches that listener over real TCP. No callback is
fulfilled by browser interception, private proof cookie read or identity/session
proof construction. External destinations are blocked. The listener checks absence
of app cookies/Authorization, bounds the request and redirects to a fixed clean
completion URL with no-store/no-referrer. State/issuer/code remain in client memory.

The existing independent HTTPS client retains PKCE/state/nonce and explicitly trusts
the temporary fixture certificate with hostname checks. Wrong PKCE fails; ordinary
production ID output is verified by Node's maintained crypto implementation and
published JWK. Refresh rotates only opaque credentials in memory after success,
returns no new ID token/cookie, and replay permanently invalidates descendants.
Idempotent cleanup succeeds. Public native IDs cannot authenticate introspection;
access cannot authenticate a local session. Actual browser session/privacy remain.

Six bounded cases report only counts/normal database and TLS cleanup. Credentials
are never logged or persisted. The test's memory store is not production platform
storage; production requires protected per-user storage and serial atomic refresh
replacement as documented in the native guide. This proves the owned IPv4 native
profile, not external standards certification, Rust SDK parity, OS-vault integration,
independent review or production readiness. No adversarial XML/crypto producer,
bypass/fuzz/stress or custom signature-concurrency experiment is introduced.
