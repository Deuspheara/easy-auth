# Chromium passkey enrollment and assertion checks

This is a test-only Node/Playwright dependency, not part of the Rust authentication
runtime. It exercises the explicit experimental Axum enrollment router, the real
core verifier and PostgreSQL transactions through `navigator.credentials.create`
and `navigator.credentials.get`. Default server composition does not enable these
experimental routes; stronger-account recovery and passkey-first enrollment remain gated.

Use the local PostgreSQL development service and set `DATABASE_URL` to its
CREATEDB-capable development connection. Only loopback database hosts are accepted.
The fixture creates and drops its own random `easy_auth_browser_<uuid>` database;
it never clears application tables or drops an input database. Do not run it as a
deployed authentication server.

```sh
docker compose up -d --wait postgres
cargo build --locked -p easy-auth-axum --example passkey-browser --features passkey-authentication
cd tests/browser/passkeys
npm ci --ignore-scripts
npm audit --audit-level=low
npx --no-install playwright install --with-deps chromium
node run.cjs
```

On macOS, install/discover OpenSSL development libraries as documented in ADR 0008.
If affected by the local proc-macro LINKEDIT issue, use the existing explicit Cargo
build-dependency strip workaround. CI uses Linux and does not need that workaround.

The runner privately passes twenty newly generated session secrets to its child
fixture through the environment. The fixture seeds verified identities/sessions
using the existing repository's one-time proof transaction; these are passkey tests,
not SMTP/signup tests. There is no test sign-in/proof endpoint. Mail is
explicitly unavailable. Each isolated browser context gets its own generated
session cookie. The real enrollment HTTP start sets the HttpOnly browser-binding
cookie, and actual browser-generated credential JSON completes registration.

After registration, twelve additional cases log out the seeded session, sign real
assertions, complete the HTTP transaction and verify the protected session. They
cover internal/USB nonresident account-bound login, modal resident discovery,
UP/UV/signature rejection, replay, missing binding, signed cross-origin iframe
context, immutable backup eligibility and an eligible backup-state update. The
iframe replaces framing headers only for its own controlled test document so core
context validation is exercised; API response protections remain unchanged. The
aggregate finish-admission count proves the signed negative cases reached core.

The final case uses CDP `signCount=-1` for real signed zero assertions. Chromium
creates a credential with counter 1 even in this setup: first, a signed reset to
zero is correctly rejected. A single private stdin command then prepares trusted
stored-zero metadata for the last seeded account's unused credential and cancels
its old retryable challenge. The fixed fixture preserves its public key and changes
no verifier, signature or session code. Two independent ceremonies then accept
real signed zero assertions and reject replay. This is explicit counterless-storage
fixture evidence, not counterless native enrollment or hardware evidence. The
fixture has no network command endpoint and cannot mint a session through stdin.

Playwright 1.64.1 pins Chromium 156.0.8078.4. The previously pinned Chromium 151
silently ignored the counter setter, confirmed in its exact source; that failed
attempt is not counted as zero-counter evidence. No virtual private key is exported.

Cases cover virtual CTAP2 platform/internal and roaming/USB registration, replay,
tampered client challenge/origin, browser RP scoping, a bad UV response with a valid
control, a real cross-origin POST, and missing binding in another browser context.
Because CORS hides a rejected cross-origin response from page JavaScript and some
Playwright response events, that test checks the actual POST status through CDP
`Network.responseReceivedExtraInfo`. Only status codes are inspected; no headers,
cookies, credential payloads or virtual private keys enter output.

The fixture reports aggregate credential/audit/pending counts, closes connections
and drops its exact owned database on normal completion or test failure. The runner
requires successful cleanup, twenty credentials/enrollment audits, thirteen
passkey sessions/authentication audits, twenty-three admitted finish attempts,
one backed-up credential, one used counterless credential and no pending state.
If forced process
termination prevents cleanup, it fails rather than claiming the database was removed.

Set `EASY_AUTH_TEST_REPORT` to an output JSON path for sanitized browser/tool versions,
named outcomes, aggregate counts, source hashes and cleanup evidence. Default local
results can live under ignored `results/local/`. Never enable browser trace/storage
state recording here: those artifacts can contain credentials. The runner does not
request or export virtual-authenticator private keys.

Only Chromium virtual authenticators are automated here. Safari, Firefox, real
hardware, Apple/Google passkey providers, conditional-autofill UI, passkey-first
accounts and recovery remain separate evidence requirements. Modal resident
discovery and assertions are now automated. The packed
attestation signature-attack corpus is covered by the Rust/software-authenticator
suite; it is not mislabeled as browser hardware attestation coverage.
