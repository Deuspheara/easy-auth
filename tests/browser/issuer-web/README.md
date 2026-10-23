# Owned signed issuer acceptance

Use only the repository's disposable local PostgreSQL fixture:

```sh
cargo build --locked -p easy-auth-axum --features issuer-web --example issuer-web-browser
DATABASE_URL=postgres://… node tests/browser/issuer-web/run.cjs
```

The existing pinned Playwright/Chromium, private TLS proxy and owned database/process
helpers are reused. Only the healthy application forwarding path is used; no token
mutation/replay proxy mode is selected. External browser requests are blocked; the
owned registered callback alone is fulfilled. No private proof cookie is read or
manufactured. Actual email completion and explicit preview/approval create the code.

A separate Node HTTPS client retains its own PKCE/state/nonce and sends no browser
cookies or Origin. It resolves only the owned hostname to loopback and explicitly
trusts the temporary fixture certificate while retaining hostname/TLS verification.
It verifies the unchanged production RS256 output with Node's established crypto
library and published JWK, then checks fixed issuer/audience/nonce/time claims.
Wrong ordinary PKCE and sequential one-use replay are refused; access credentials
cannot authenticate a local session. Output contains counts/cleanup only.

This is bounded owned browser/component integration, not an external RP certification,
independent audit, native listener/storage acceptance or production deployment. No
adversarial XML/cryptographic fixture, bypass/fuzz/stress or signature-concurrency
experiment is generated or run. Ephemeral library-generated fixture keys are not
production provisioning. Never deploy the example, inbox or fixture endpoints.
