# Native recovery reference-client checks

Start documented local PostgreSQL and Mailpit and load the loopback development
`DATABASE_URL`. Use pinned Node 24/Playwright dependencies from the parent package:

```sh
npm ci --ignore-scripts --prefix tests/browser/passkeys
cd tests/browser/passkeys && npx --no-install playwright install chromium
cd ../../..
CARGO_INCREMENTAL=0 cargo build --locked -p easy-auth-server --example passkey-recovery-browser --features experimental-passkey-recovery
node tests/browser/passkeys/recovery/run.cjs
```

The optional `EASY_AUTH_RECOVERY_TEST_BINARY` selects a fixed owned copy of the
producer. `EASY_AUTH_TEST_REPORT` writes a fresh report containing versions, source/
binary hashes, named outcomes and aggregate facts. Never overwrite a published
report. No trace, browser storage state, proof, private key, code or message body is
saved or logged. The process-group lifecycle fixture currently requires Unix.

Seven cases exercise the actual opt-in reference pages: resident platform/USB
recovery for both email-free and verified-contact accounts, then browser, retained-
code and freshly authenticated key cancellation. Signup/configuration, independent
contact proof, prebinding/consent, lost start response, reload/resume, original expiry,
actual replacement create/get, rejected still-fresh old signed proof, lost finish
response/normal new-key sign-in and replacement code configuration are explicit.
Navigation clears displayed code, invalid account input clears code entry, no
mutation occurs before consumption consent, no unhandled page errors or browser
storage remain, and a modified readiness button cannot bypass the backend.

Every account/key/session comes from real native registration/assertion; contact
and fixed notices use the actual private SMTP adapter via `configured_auth` and
loopback Mailpit. Owned random DBs are dropped after child shutdown. Only exact
random recipient namespace messages are removed; an empty delete-all request is
never sent. Expected completion/cancellation/provenance/pending facts and original
source admission are asserted. Baseline 31-browser/four-SMTP suites remain separate
with all their earlier assertions intact. CI runs all three suites.

The private development example accepts a bounded local stdin timestamp command.
It requires a current consumed generation and actual worker receipt when a contact
exists, then backdates linked claim creation/receipt/not-before timing to arrange
an elapsed delay. Original expiry, delay policy, keys, sessions and receipt existence
are never changed or fabricated. A read-only stdin observation waits for real worker
acknowledgements before shutdown. There is no HTTP endpoint or production setting
for this control. Never deploy fixture executables.

This is real browser cryptography with virtual authenticators and an arranged
elapsed-time fixture, not physical-device evidence, a real 24-hour wall-clock test,
general browser interoperability, independent review or production readiness.
