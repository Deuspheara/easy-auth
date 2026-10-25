# Reference account browser acceptance

Use the documented loopback PostgreSQL and Mailpit development services and set
`DATABASE_URL`. Reuse the locked browser dependencies. UI preparation is documented separately in
[the modernization record](../../../docs/design/reference-ui-modernization.md):

```sh
npm ci --ignore-scripts --prefix tests/browser/passkeys
cd tests/browser/passkeys && npx --no-install playwright install chromium
cd ../../..
cargo build --locked -p easy-auth-server --example passkey-recovery-browser --features experimental-passkey-recovery
python3 scripts/reference_ui_tokens.py --check
node --experimental-vm-modules tests/browser/reference-ui/inventory-pagination.cjs
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
The focused keyboard module follows genuine email authentication through Profile,
return navigation and Sessions using Tab/Shift+Tab/Enter. Escape cancellation must
restore the enabled sign-out button and send no revocation request. A separately
labelled presentation-only close listener verifies that cleanup preserves a chosen
visible heading. The real inbox response and keyboard resend both focus the heading.
Account-access coverage uses a genuine mailbox login, observes inventory401,
checks Cancel sends no logout, creates a key normally and explicitly verifies it
through account-bound native authentication before inventory200. Aggregate facts
include the extra genuinely created owner/proven key and authentication event.
The inventory invalidation module holds and then aborts a new read after genuine
passkey verification. It checks that previous labels, actions and count disappear
while pending, stay absent on failure, and return only after an explicit successful
retry against the real inventory endpoint.
An isolated Node presentation test checks session/provider cursor invalidation
after failed reloads and preserves cursors after failed continuations. Its fixed
inventory outcomes exercise controller rendering only; it starts no server and
creates no authentication, session or proof. Genuine acceptance remains separate.
A separate genuine two-tab mailbox flow switches account through real logout and
SMTP login, then explicitly triggers the return focus event and verifies refresh clears the previous owner’s unfinished
form, returns to the overview and labels the current session without a duplicate
revoke action. The pinned headless driver reports both pages focused; the trigger is simulated,
not native-tab-focus qualification. Cookies, owner/data responses and all sign-in
operations remain genuine. It seeds no identity/session or successful response.
The lifecycle scenario uses a separate genuinely authenticated mailbox to respect
unchanged sensitive admission limits. Delayed requests are forwarded unchanged
or cancelled by actual navigation; successful server responses are never mocked.
Real final database observations check the expected users, proven credential and
audit counts, contact policy, provenance and absent pending signup/contact rows.

Presentation checks loaded local Inter, OS theme defaults, measured light/dark
text/control contrast, 320/390/768/1024/1280/1440px reflow, 320px/200% text and
forced-color borders. The actual account view also checks both themes at 320/1440
and 320px/200% text. Compact account assertions cover the 660px column, shared header, genuine initials,
long-email truncation with complete profile text, unknown versus verified key count
and contextual current-session versus dedicated bulk-session actions.
Optional `EASY_AUTH_UI_SCREENSHOT_DIR` saves desktop/mobile sign-in and owned-account
screenshots locally for visual inspection. Never publish images,
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
The owner approved the rendered design and verification journey on 2026-10-25.
That visual decision is separate from the automated verification recorded here.


The Motion module probes real Axum CSP through completion, overlapping effects,
cancellation, removal, reduced-motion changes, forced colors and missing optional
module loading. All genuine-flow contexts count CSP violations from initial load.
Persistent feedback replaces the earlier eight-second success notification; the
native account scenario asserts the accepted sign-in result remains available.

Optional screenshot review now also captures the focused account forms, search
results, add/rename/remove passkey screens and genuine email/reset/deletion
confirmations through `capture.cjs`. Set `EASY_AUTH_UI_SCREENSHOT_DIR` to an
existing local directory for this runner and the recovery runner. The helper
captures both themes at 320px and 1440px, restores the original viewport/theme,
and masks nonempty password and recovery-code fields. Capture names are fixed;
no proof URL, browser state or secret is included in the manifest or filename.
Recovery captures cover verification, preparation, masked offline-code saving,
confirmation, waiting, server-authorized replacement and completion. These are
local review artifacts, not owner approval or configured-provider coverage.
