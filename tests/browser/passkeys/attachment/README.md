# Native signup, contact attachment and passkey management

This suite composes the real `configured_auth` server SMTP adapter with the explicit
experimental management router, including signup/contact routes and the real
notification worker. The normal server binary stays unchanged. It creates
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
verified stronger users/remaining proven credentials/signup facts/attachment facts,
eight later passkey sign-ins, two rename facts, two removal facts, zero pending
management notices, no weak-method sessions, no changed attachment authentication
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
stronger-account recovery or ordinary activation; those remain AUTH-20 work.


Each case also renames its initial key, rejects stale versions and last-working-
key removal, then enrolls an independent spare device using unmodified required-
residence/UV/exclusion options. CDP presence simulation selects which native
virtual device answers; no key is exported and no credential metadata is seeded.
The spare must actually sign in before removal succeeds. Removal clears all
browser auth/action cookies and rejects a peer's prior session. A genuine signature
from the removed key is rejected, while the same pending challenge accepts a real
surviving-key assertion. Later bound/discoverable login uses the surviving key.

The private production SMTP adapter delivers two fixed management notices per
account. The runner checks their exact owned recipients and absence of credential
links or untrusted labels. Cleanup deletes exactly seven owned messages: three
contact proofs (including the occupied-target attempt) and four management notices.
The prior published two-case records remain immutable. Their earlier four-sign-in/
three-message totals describe earlier producers, not this extended run. Safe fixed
stage names diagnose failures without reflecting assertion values or mail bodies.


Registration uses the complete original server options. To select a particular
native device, positive assertion requests narrow the returned allowed credential
IDs to the known spare; the removed-key negative deliberately requests the old
native credential ID against a server challenge whose stored state is unchanged.
Only public selection data changes, while RP/origin/challenge/UV and actual private-
key signatures remain enforced. The same pending challenge then accepts a fresh
surviving-key signature. This is explicit signed-negative fixture setup, not a
change to production verification or a private-key/metadata export.
Presence selection follows the official
[CDP WebAuthn protocol](https://raw.githubusercontent.com/ChromeDevTools/devtools-protocol/master/pdl/domains/WebAuthn.pdl).
