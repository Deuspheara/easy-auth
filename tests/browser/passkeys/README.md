# Chromium passkey enrollment, assertion and anonymous signup checks

This is a test-only Node/Playwright dependency, not part of the Rust authentication
runtime. It exercises the explicit experimental Axum enrollment router, the real
core verifier and PostgreSQL transactions through `navigator.credentials.create`
and `navigator.credentials.get`. Default server composition does not enable these
experimental routes; verified contact attachment and stronger-account management/recovery remain gated.

Use the local PostgreSQL development service and set `DATABASE_URL` to its
CREATEDB-capable development connection. Only loopback database hosts are accepted.
The fixture creates and drops its own random `easy_auth_browser_<uuid>` database;
it never clears application tables or drops an input database. Do not run it as a
deployed authentication server.

```sh
docker compose up -d --wait postgres
cargo build --locked -p easy-auth-axum --example passkey-browser --features passkey-signup
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
fixture through the environment. For the original enrollment/assertion cases it
seeds verified identities/sessions through the existing repository proof transaction;
those cases do not test SMTP. Their isolated contexts get distinct session cookies.
The eleven new signup cases start WITHOUT a seeded cookie, choose only a display
label and use native resident creation plus a separately signed assertion through
the real signup HTTP API. The prospective UUID is server-selected, and protected
user retrieval stays 401 until final proof. There is no test sign-in/proof endpoint;
mail transport is explicitly unavailable. Passwords are configured so native
passkey-required password-enrollment denial exercises policy rather than a disabled
feature. All actual credential JSON goes through the shared core/PostgreSQL flow.

After registration, twelve additional cases log out the seeded session, sign real
assertions, complete the HTTP transaction and verify the protected session. They
cover internal/USB nonresident account-bound login, modal resident discovery,
UP/UV/signature rejection, replay, missing binding, signed cross-origin iframe
context, immutable backup eligibility and an eligible backup-state update. The
iframe replaces framing headers only for its own controlled test document so core
context validation is exercised; API response protections remain unchanged. The
aggregate finish-admission count proves the signed negative cases reached core.

The final preexisting authentication case uses CDP `signCount=-1` for real signed zero assertions. Chromium
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
requires successful cleanup, 31 credentials, 20 enrollment audits, 11 email-free
passkey-required users/signup audits, 17 later authentication audits, 28 total
passkey sessions, 27 authentication-finish admissions and the exact per-case signup
admission total (33 for the recorded Chromium run), with zero pending state. One
backed-up and one used counterless credential belong to the preexisting cases.
If forced process
termination prevents cleanup, it fails rather than claiming the database was removed.

Set `EASY_AUTH_TEST_REPORT` to an output JSON path for sanitized browser/tool versions,
named outcomes, aggregate counts, source hashes and cleanup evidence. Default local
results can live under ignored `results/local/`. Never enable browser trace/storage
state recording here: those artifacts can contain credentials. The runner does not
request or export virtual-authenticator private keys.

Only Chromium virtual authenticators are automated here. Safari, Firefox, real
hardware, Apple/Google passkey providers, conditional-autofill UI, verified-mailbox
attachment and stronger-account recovery remain separate evidence requirements.
Anonymous resident signup and both later account-bound/modal-discovery login are
now automated for internal/platform and USB/roaming transports. Additional signup
cases cover bad registration context/RP/UV, actual assertion UP/UV/signature,
replay, existing-session/cross-browser confusion and signed cross-origin iframe
rejection. Native production options are not weakened for a software signer. The packed
attestation signature-attack corpus is covered by the Rust/software-authenticator
suite; it is not mislabeled as browser hardware attestation coverage.

The separate [native SMTP contact suite](attachment/README.md) uses the real server
SMTP adapter and local Mailpit, rather than the disabled-mail adapter in this
31-case fixture. It adds two anonymous platform/USB signup-to-contact cases with
actual email confirmation, session rotation and subsequent passkey login. CI runs
both suites sequentially with owned disposable databases; their aggregate counts
and evidence records stay separate.
