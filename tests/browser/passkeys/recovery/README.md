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

Seven recovery cases exercise the actual opt-in reference pages: resident platform/USB
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
never sent. An eighth case verifies the fixture-only human signup page, actual
registration plus separate assertion, explicit consent and confirmed saved-code
configuration. Expected completion/cancellation/provenance/pending facts and original
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


## Supervised device checks

The owned development example additionally serves `/fixture/passkey-signup` and
its script. These resources are absent from library and normal server composition.
They bootstrap a disposable email-free account using the actual signup APIs and
native WebAuthn JSON methods, without injecting a key, account or session. They
share the reference client's abort/redirect/error protections and use no-store,
no-referrer, nosniff and restrictive same-origin CSP. A deliberate checkbox precedes
registration; creating a key is followed by a separate signed assertion. Unsupported
browsers fail closed. This is test UI, not a production signup design.

After building, run the owned example with the documented development database
and Mailpit available. It prints its random localhost origin. In the chosen browser:

1. Open `<origin>/fixture/passkey-signup`. The human operator accepts disposable-test
   consent and completes both actual device prompts. Record browser/OS and the
   selected credential-provider/device description without credential contents.
2. Open `/passkey-recovery/setup`. Retain the public account ID and prepared code
   privately, reenter/confirm it, and verify the display clears. Do not send the
   code to an assistant, save screenshots/console/network traces, or include it in
   an evidence report. Reauthenticate freshly if required.
3. Open `/passkey-recovery`. Explicitly sign out, enter the retained public ID/code,
   accept consumption/browser-retention consent and start. Verify that immediate
   replacement is unavailable, then reload and resume in the same browser. A second
   browser has no transferable authority merely from the public account ID.
4. For an arranged-time device run only, enter `mature-owned-claim <public-account-ID>`
   in the owned fixture's inherited stdin. It cannot fabricate a required receipt
   or extend expiry. Record this control explicitly; it is not a real 24-hour wait.
   Refresh, accept replacement consent and have the human complete actual new-key
   creation and its separate assertion. Never weaken resident-key or UV options.
5. Verify the same account is signed in, normal new-key sign-in works and a new
   offline code can be confirmed. Cancellation and contact/SMTP scenarios require
   separate accounts/evidence; one email-free success does not satisfy them.
6. Stop the owned fixture, verify its aggregate facts and database-removal result,
   and have the human remove only the localhost credential entries matching this
   disposable test's `AUTH-20 device test` label or retained account ID from their
   chosen credential manager. Stopping the server
   does not remove operating-system/cloud-synced passkeys. Never erase unrelated
   localhost entries or claim this cleanup without confirmation.

Keep observed results, operator-reported provider details, automated emulation and
independent security review distinct. Do not label synced platform credentials as
hardware-bound or treat one device/browser path as complete interoperability proof.
