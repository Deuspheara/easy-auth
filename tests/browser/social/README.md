# Owned social-management browser acceptance

Never deploy this fixture. With an owned disposable loopback `DATABASE_URL`, build
`cargo build --locked -p easy-auth-axum --features social-linking-web --example social-web-browser`
then separately build the feature-disabled control with
`cargo build --locked -p easy-auth-axum --features google-web --example social-source-probe`
and run `node tests/browser/social/run.cjs`. Rebuild after embedded asset changes.
Use the existing pinned Playwright dependencies under `tests/browser/passkeys`.

The runner owns a random PostgreSQL database, private TLS files and all processes.
It intercepts provider authorization navigation, reusing the existing maintained
signed producers. Local sessions come through actual email delivery/confirmation
or provider code flow. No fixture API seeds authority. The thirteen cases cover
explicit confirmation for both providers, cookie-free Apple POST, wrong signed
nonce, lost finishes, late hints/restoration, stale cancellation, switched account
views, retained-source denial removed-source session invalidation and an actual feature-disabled binary check.
The probe reads genuine local/provider sessions only over private stdin, against
the same owned database; it neither seeds authority nor logs secret values.

Optional `EASY_AUTH_SOCIAL_WEB_TEST_REPORT` writes a new receipt; optional
`EASY_AUTH_SOCIAL_WEB_SCREENSHOT` captures the linked-account page. Private raw
callbacks, keys and proof/session cookies never enter these outputs. Fixture-only
TLS exceptions do not change system trust or production transports. Real provider,
native/OS and production verification remain separate.
