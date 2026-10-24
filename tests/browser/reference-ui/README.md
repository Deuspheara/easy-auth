# Reference account browser acceptance

Use the documented loopback PostgreSQL and Mailpit development services and set
`DATABASE_URL`. Reuse the locked browser dependencies; no new package is required:

```sh
npm ci --ignore-scripts --prefix tests/browser/passkeys
cd tests/browser/passkeys && npx --no-install playwright install chromium
cd ../../..
cargo build --locked -p easy-auth-server --example passkey-recovery-browser --features experimental-passkey-recovery
python3 scripts/reference_ui_tokens.py --check
node tests/browser/reference-ui/run.cjs
```

The runner owns a disposable database and only its random Mailpit recipients.
`EASY_AUTH_MAILPIT_URL` selects a loopback Mailpit HTTP endpoint (default 8025).
The existing fixture uses actual configured SMTP, password policy, native
WebAuthn and production handlers. It creates no seeded session, credential or
proof. Normal teardown stops its exact process group, drops its exact database
and removes exact owned messages. No broad database/mail cleanup is permitted.

Focused modules cover genuine email/password, session and account lifecycle;
native signup, separate-device enrollment, rename/removal and remaining-key
sign-in through both discoverable and saved account-ID paths; contact confirmation preserving strong policy; keyboard/dialog focus,
autocomplete, busy/offline errors, navigation, temporary theme and browser storage.
Focused-view checks cover password, signup, help and account-ID access, mobile/desktop
and enlarged text in both themes, browser back, inert unknown/unavailable view
queries and direct-inbox rejection. Genuine email flow verifies the check-email
transition and explicit resend, without fabricated successful responses.
The lifecycle scenario uses a separate genuinely authenticated mailbox to respect
unchanged sensitive admission limits. Delayed requests are forwarded unchanged
or cancelled by actual navigation; successful server responses are never mocked.
Real final database observations check the expected users, proven credential and
audit counts, contact policy, provenance and absent pending signup/contact rows.

Presentation checks loaded local Inter, OS theme defaults, measured light/dark
text/control contrast, 320/390/768/1024/1280/1440px reflow, 320px/200% text and
forced-color borders. The actual account view also checks both themes at 320/1440
and 320px/200% text. Optional `EASY_AUTH_UI_SCREENSHOT_DIR` saves desktop/mobile
sign-in and owned-account screenshots locally for visual inspection. Never publish images,
trace/storage state, message bodies, proof URLs, credentials or private keys.
Failures emit finite stages/status codes/source locations, never assertion values
or raw browser call logs. The summary contains only fixed outcomes and DB counts.

Existing OIDC standalone/embedded, Google transport and actual Keycloak SAML
browser suites additionally check the reference account after their genuine
completion: text-only linked issuer, actual session, unavailable mailbox/passkey
fallback and selected provider deletion. Google uses its existing owned transport;
this is not manual real-Google registration acceptance. Existing recovery cases
remain a separate full regression suite. No physical-device, accessibility audit,
independent SAML review, protocol certification or production-readiness claim.
The compact design remains a visual candidate until the owner reviews the rendered
views. Passing tests and regenerated captures do not approve a visual baseline.
