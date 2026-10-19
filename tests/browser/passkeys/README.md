# Chromium passkey enrollment checks

This is a test-only Node/Playwright dependency, not part of the Rust authentication
runtime. It exercises the explicit experimental Axum enrollment router, the real
core verifier and PostgreSQL transactions through `navigator.credentials.create`.
Default server composition does not enable those routes or provide passkey login.

Use the local PostgreSQL development service and set `DATABASE_URL` to its
CREATEDB-capable development connection. Only loopback database hosts are accepted.
The fixture creates and drops its own random `easy_auth_browser_<uuid>` database;
it never clears application tables or drops an input database. Do not run it as a
deployed authentication server.

```sh
docker compose up -d --wait postgres
cargo build --locked -p easy-auth-axum --example passkey-browser --features passkey-enrollment
cd tests/browser/passkeys
npm ci --ignore-scripts
npm audit --audit-level=low
npx --no-install playwright install --with-deps chromium
node run.cjs
```

On macOS, install/discover OpenSSL development libraries as documented in ADR 0008.
If affected by the local proc-macro LINKEDIT issue, use the existing explicit Cargo
build-dependency strip workaround. CI uses Linux and does not need that workaround.

The runner privately passes eight newly generated session secrets to its child
fixture through the environment. The fixture seeds verified identities/sessions
using the existing repository's one-time proof transaction; these are passkey tests,
not SMTP/signup tests. It exposes no fixture sign-in/proof bypass endpoint. Mail is
explicitly unavailable. Each isolated browser context gets its own generated
session cookie. The real enrollment HTTP start sets the HttpOnly browser-binding
cookie, and actual browser-generated credential JSON completes registration.

Cases cover virtual CTAP2 platform/internal and roaming/USB registration, replay,
tampered client challenge/origin, browser RP scoping, a bad UV response with a valid
control, a real cross-origin POST, and missing binding in another browser context.
Because CORS hides a rejected cross-origin response from page JavaScript and some
Playwright response events, that test checks the actual POST status through CDP
`Network.responseReceivedExtraInfo`. Only status codes are inspected; no headers,
cookies, credential payloads or virtual private keys enter output.

The fixture reports aggregate credential/audit/pending counts, closes connections
and drops its exact owned database on normal completion or test failure. The runner
requires successful cleanup and matching credential/audit counts. If forced process
termination prevents cleanup, it fails rather than claiming the database was removed.

Set `EASY_AUTH_TEST_REPORT` to an output JSON path for sanitized browser/tool versions,
named outcomes, aggregate counts, source hashes and cleanup evidence. Default local
results can live under ignored `results/local/`. Never enable browser trace/storage
state recording here: those artifacts can contain credentials. The runner does not
request or export virtual-authenticator private keys.

Only Chromium virtual authenticators are automated here. Safari, Firefox, real
hardware, Apple/Google passkey providers, discoverable/passkey-first accounts,
authentication and recovery remain separate M03 evidence requirements. The packed
attestation signature-attack corpus is covered by the Rust/software-authenticator
suite; it is not mislabeled as browser hardware attestation coverage.
