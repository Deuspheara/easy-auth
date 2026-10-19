# Native signup and real SMTP contact attachment

This suite composes the real `configured_auth` server SMTP adapter with the explicit
experimental signup router. The normal server binary stays unchanged. It creates
an owned random PostgreSQL database, starts a child server using private process
environment, and drops that database after stopping the child. No HTTP fixture
mutation or seeded sessions, users or credential metadata are provided.

Requirements: the existing PostgreSQL and Mailpit Compose services, plus the pinned
Playwright/Chromium installation from the parent browser suite.

```sh
cargo build --locked -p easy-auth-server --example passkey-smtp-browser --features experimental-passkeys
DATABASE_URL=postgres://auth:auth-development-only@localhost:59473/auth \
  node tests/browser/passkeys/attachment/run.cjs
```

Use `PLAYWRIGHT_BROWSERS_PATH` if Chromium lives outside the default cache.
`SMTP_PORT` and `EASY_AUTH_MAILPIT_URL` can select different loopback ports;
nonloopback PostgreSQL, SMTP and Mailpit are rejected. `EASY_AUTH_SMTP_TEST_BINARY`
can select the prebuilt fixture binary. Optional `EASY_AUTH_TEST_REPORT` writes
only aggregate evidence, source/binary hashes and controlled case names.

Two cases use original resident/required-UV options with Chromium platform/internal
and roaming/USB virtual authenticators. Both start anonymously, complete native
registration and a genuine assertion, obtain a no-email session, receive a real
SMTP proof and explicitly confirm it in the reference page. They check independent
browser-binding rejection, no GET/page-load mutation, fragment removal, no-store/
CSP headers, preserved UUID, verified normalized email, rotated session, old-cookie
revocation, proof replay denial, weaker lifecycle/password rejection, and subsequent
account-bound plus discoverable passkey login. The USB case first proves that an
occupied target receives the same initiation response and email path but cannot
merge either independently created account.

The fixture collects only aggregate database facts after child shutdown: two
verified stronger users/credentials/signup facts/attachment facts, four later
passkey sign-ins, no weak-method sessions, no changed attachment authentication
provenance and no pending signup/attachment state. No raw proofs, cookies, private
keys, addresses, browser storage or mail bodies are logged or saved.

Mailpit reads and cleanup use its [documented v1 API](https://mailpit.axllent.org/docs/api-v1/).
The suite searches only random per-run recipients, verifies exact recipients before
reading their bodies, and deletes only those observed message IDs. An empty delete
list is never submitted because Mailpit interprets it as delete-all. It independently
checks that its owned recipient messages are absent after cleanup; unrelated mail
is retained. No real-device, other-browser or production assurance is implied.

If the runner is forcibly killed before cleanup, owned resources may remain; a
reported timeout is a failed run, not proof of cleanup. Ordinary test failures run
cleanup before returning nonzero. Neither the fixture nor these tests implement
stronger-account recovery or last-key policy; those remain AUTH-20 work.
