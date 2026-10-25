# Apple revocation engineering checkpoint — 2026-10-25

AUTH-26 remains In Progress for deferred prerequisite/registered-provider acceptance.
The opt-in engineering scope now has local qualification: protected capture/key
rotation, atomic unlink/account-erasure queueing, leased retry-safe revocation,
explicit maintenance and web capture/link composition. Nine owned Chromium cases,
a separately built feature-disabled erasure probe and real-PG upgrade coverage
supplement the final workspace/security matrix below. Registered Apple web/native,
console/key rotation, actual OS delivery and live revocation remain deferred.
No production qualification, independent approval, PR, merge or deployment follows.
AUTH-24/AUTH-25 acceptance dependencies, outbound OIDC and SAML waiver limits remain.
Earlier checkpoint sections retain their original scoped results and limitations.

## Source and behavior

Capture/ledger foundation: `8e33892ae34074afac523c91975b3e0ead9703d5`.
Separate shared-signer extraction: `bf186d4`. Separate unchanged protected-form
POST extraction: `d77ce10` (10 existing HTTPS tests passed before extension).
The subsequent worker commit is linked in the tracker; no unpublished source is
represented as hosted or registered-provider evidence.

The worker shares the protected signer with exchange, checks encrypted client and
source binding and sends only to fixed Apple HTTPS. SQL claims commit before I/O.
One60-second lease/version, a30-second attempt, at most8 attempts and capped
exponential backoff prevent immediate/concurrent retries and stale ACK/defer.
Only verified empty200 confirms completion and clears ciphertext/key ID. Provider
errors, missing keys, mismatched client and lost responses cannot become success.
No owner/session locks span remote I/O and remote availability does not prevent
local unlink/account deletion. Maintenance must run explicitly: bounded64-row
phases erase expired unconfirmed ciphertext after7 days, classify exhausted leases
and remove terminal metadata after another7 days. Expiry is never confirmation.

The server adapter uses the existing certificate/hostname checking, pinned target,
shared operation bound, no-proxy/no-redirect/no-cookie/no-retry policy. Its private
16KiB response profile admits absent Content-Type only for empty200. Ordinary
OIDC document/token profiles retain their JSON requirements. Credentials and raw
provider diagnostics are never emitted. See [ADR0045](../architecture/adr/0045-apple-grant-custody-and-revocation.md)
and the [public contract](../architecture/api-contract.md#optional-rust-apple-grant-capture-in-progress).

## Focused evidence

- 10 real PostgreSQL revocation scenarios passed, using actual captured signed
 Apple results and maintained ES256 client-secret verification. Cases cover exact
 request/hint/endpoint, disabled sign-in source, local-session preservation,
 provider/transport failure, no busy retry, source/realm isolation, concurrent
 claim, stale success, lost-response backoff, missing storage key, authenticated
 client mismatch, exhausted attempts, expiry/purge and observed lock-wait expiry.
- Crash recovery waited for the actual60-second database lease; no shortened
 policy or fake clock. The replacement worker confirmed attempt2; the original
 generation could neither acknowledge nor defer it. Leased rotation was skipped.
- 13 server transport tests passed, including3 new revocation cases using real
 private TLS. They observe actual form POST, original hostname/SNI, no cookies/Basic
 header or retry, empty200, bounded error/nonempty responses, missing/duplicate
 media type, compression/duplicate encoding, redirects, declared/chunked oversize,
 body timeout and unknown-root/wrong-hostname certificate rejection.

Focused commands used the locked offline graph:

```sh
cargo test --offline --locked -p easy-auth-postgres --features apple-grants --test lifecycle oidc::apple::grants::revocation::
cargo test --offline --locked -p easy-auth-server --all-features oidc_http::
```

`DATABASE_URL` selected only the owned disposable PostgreSQL17 container with its image-created anonymous data volume and automatic removal;
no host bind or explicitly retained named volume was used; no preview database, retained account, passkey or real provider was used.
TLS uses fresh owned private certificates/listeners, never system trust changes.
The TLS wire tests use generated fixture values; actual client-secret signatures
and captured token encoding are independently asserted by the worker fixtures.
Together these are bounded implementation evidence, not Apple interoperability.

## Workspace and security gates

The backend behavior freeze passed:

- `cargo fmt --all --check`.
- `cargo clippy --offline --locked --workspace --all-targets -- -D warnings`.
- `cargo clippy --offline --locked --workspace --all-targets --all-features -- -D warnings`.
- `cargo test --offline --locked --workspace`:128 passed,0 failed/ignored.
- `cargo test --offline --locked --workspace --all-features`:1138 primary tests
  passed,0 failed/ignored;1139 pass reports include one logging-isolation child
  rerun. Core181, HTTP211, PostgreSQL649 and server68 cases passed.
- Protocol source guard, reference UI token check, compiled-graph advisory audit,
  all-feature dependency/license policy and scoped changed-file secret scan passed.
  Cargo.lock is unchanged; the existing inactive RSA advisory entry is not an
  exception for a compiled dependency.

These runs used `CARGO_INCREMENTAL=0`, dev/test debug0 and build-override debug1,
the existing macOS SQLx build settings. Afterward, production SQL was expanded
for readability without changing its predicates or operations. Formatting, strict
PostgreSQL all-feature Clippy and all10 focused real-PG revocation scenarios were
rechecked against that representation. Exact local command receipts are retained
with the development checkout's external validation artifacts; tracker evidence
links the resulting commit. Hosted CI has not been claimed or awaited.

## Corrections and remaining work

Initial server Clippy reported unused Apple-profile symbols in examples that
include the shared response source. The profile now lives at the concrete adapter
call site; no dead-code suppression or policy relaxation. The first TLS test build
reported E0432 for its module path, corrected to the owning transport scope. The
first crash-recovery build reported E0782 for a nonexistent `Repository::session`
call, corrected to the existing `authenticate` port. One TLS run had12 passing
cases and a failed observer count (1 instead of2) after both client-side certificate
assertions had passed. The observer now waits for the actual second handshake,
keeping both certificate assertions and the working positive control.

No protocol assertion was weakened. Full default/all-feature workspace checks,
security gates and original-checkout preservation are recorded with this
checkpoint in the tracker. Final ticket completion still requires explicit web
capture/link composition, genuine owned browser acceptance, migration/disabled-
component coverage and documentation reconciliation. The remote redemption/local
commit crash gap remains an operational limitation rather than fabricated capture
or revocation success.

## Maintainability review

New core, SQL and transport responsibilities stay in owning Apple feature modules;
crate entry files only reexport. No new crate, dependency/version, cryptography,
public proof constructor or generic provider framework. Every new module remains
under300 lines. Ordered worker/SQL transactions, response-envelope validation and
scenarios retain source/lease/time checks, real waits and positive/negative controls
together as justified function-size exceptions. Published migration0038 is unchanged.
No unrelated cleanup is deferred. Development uses the isolated checkout; all73
protected original files retain exact bytes/change set and the original index is
empty.


## Explicit HTTP capture/link checkpoint

Separate completion extraction `5cb0125` passed strict Axum all-feature Clippy and
all30 preexisting Apple/social HTTP cases. Apple fixture constructor extraction
`4b09c0b` also passed those cases before adding custody selection to the fixture.
The extraction's initial compile checks found missing moved imports (`Secret`,
`PgPool`, `Mail`); they were corrected without suppression or assertion changes.

Axum `apple-grants-web` now exposes `AppleWebServices::new_with_grants` and, with
social linking selected, `SocialWebServices::new_with_apple_grants`. Private closed
selectors pair concrete authorization/commit services. Default builders retain
discard behavior; no new route/DTO/script, credential upload or worker endpoint is
introduced. Existing purpose, owner, Origin, private cookie, one-use callback,
nonce/source/realm and final database boundaries remain authoritative. Missing
vault returns503 and rolls back instead of falling back to an ordinary commit.

This HTTP selection freeze passed formatting and strict Axum all-target/all-feature
Clippy, all221 HTTP cases with real owned PostgreSQL (0 failed/ignored), and strict
Axum Clippy plus17 Apple/13 social cases with only `social-linking-web` selected,
without capture. Ten new cases verify default discard with capture compiled,
explicit signed capture including repeated grants, no-vault rejection, foreign
realm/private proof and concurrent callback isolation, signed bad nonce, actual
provider-post disable, audit rollback, link/sign-in-to-local-unlink-to-worker,
provider error/backoff visibility and retained-local-session isolation.

The first10-case increment originally contained9 tests:6 passed and3 fixture setup
failed with Unavailable. Those tests attempted a second realm registration with
the first realm's exact callback. Migration0016 intentionally makes redirect URI
globally unique. Distinct origins and separate owned SQLx databases now preserve
that boundary; the split control produces10 passing cases. No assertion, redirect
constraint, protocol policy or feature gate was relaxed. No provider code/secret
or raw diagnostics are recorded here.

New source modules stay below100 lines and fixtures below200. The longer two-path
completion methods retain original intent/proof, verified classification and
matching core commit together as reviewed function-size exceptions. These HTTP
checks supplement the earlier backend matrix; they do not replace the final
workspace/security matrix after integration. Genuine owned browser-to-worker,
migration/disabled-component coverage and live-provider qualification remain
separate outstanding gates. Ordinary startup schedules no worker/maintenance.


## Browser fixture extraction and native capture coverage

The unchanged owned browser fixture lifetime moved separately in `a29ef5c` so the
new grant journey can reuse its existing database, mail, provider and shutdown
boundaries. Strict Axum all-feature Clippy passed. The existing13 genuine Chromium
social journeys passed after rebuilding both the selected fixture and its separate
capture/linking-disabled probe. Chromium156.0.8078.4 observed normal mailbox proof,
explicit linking, actual cookie-free cross-site Apple handoff, callback privacy,
source-session behavior and cleanup. The owned database and private TLS files were
removed, with no emergency cleanup/diagnostic. This is a refactor regression;
it does not claim the new captured-grant browser-to-worker journey has run.

One additional real-PG captured native scenario passed for both Plain and Sha256Hex
nonce modes. It verifies native-only authorization inputs, actual protected code
redemption and signed proof, stored source/realm/client binding and envelope
rewrap, wrong signed nonce rejection before another envelope exists, preservation
of the original session and rejection of native linking. Strict PG all-feature
all-target Clippy passed. This is backend fixture evidence, with no actual OS
Authentication Services, registered App ID or live Apple call. Genuine captured
browser-to-worker, migration/disabled-component coverage and the final integrated
workspace/security matrix remain outstanding.


## Integrated owned browser, erasure and upgrade checkpoint

Nine captured-grant Chromium cases passed with Nodev26.0.0 and
Chromium156.0.8078.4. They use actual normal mailbox proof, cross-site
cookie-free Apple return, explicit link/sign-in confirmation, signed nonce
rejection and protected repeated capture. Retained-factor unlink immediately
invalidates only the removed-source session and queues both grants before any
provider dispatch. A real invalid_client fixture response retains ciphertext;
the other job can complete, while the original retries only after actual database
backoff. Confirmed completion erases ciphertext/key IDs, preserving the original
local session. No timestamp, policy or assertion was shortened to pass.

The separately compiled `--no-default-features` erasure probe refuses capture/
linking-selected builds and only accepts the exact random owned loopback database.
Its compiler feature graph contains no apple-grants, oidc-linking or social-linking
selection. Actual compiler-derived flags are returned with finite results. Using
a genuine second mailbox owner/session and a distinct signed Apple subject, it
runs ordinary repository deletion preparation/completion with generated bound
verifiers, checks owner/session/identity/audit-subject erasure and internally
compares the original protected ciphertext/key/source/binding bytes. One pending
grant survives; the configured worker then confirms it. The original other owner
and session stay intact. This is a feature-disabled persistence probe, not a
browser/mail deletion confirmation or public authority shortcut.

The exact final fixture counts were users1, identities0, sessions2, audit7,
pending OAuth0, Apple code posts/signatures4, Google posts/signatures0, completed
grants3, encrypted grants0 and worker attempts/calls4. Normal shutdown removed the
owned database and private TLS material, without emergency cleanup or diagnostics.
The fixture port verifies actual protected ES256 client-secret signatures and
fixed endpoint/client/token/hint, while actual production TLS has separate tests.
No real Apple token/revocation endpoint, registration or OS delivery was contacted.

Frozen browser fixture SHA256:
`61f00e81387ca5d40ad995f02d9d5e89f104e369bfef48c1643c4746412c727a`.
Frozen feature-disabled probe SHA256:
`750120fee2e03024de9d9fefbe5345b68f3f048e4edc0f8123d50f306266fe7e`.
The parent receipt's source base is `bfb79ddfcc79fc6fe58b1913f91eba122ed41e9f` plus its
recorded source-file hashes. Every recorded source file and both frozen
binaries were checked against current bytes before commit; no stale binary or
unrelated source is represented as this acceptance. Full local JSON/command
artifacts remain outside the repository; no credential/callback is published.

Original capture-unselected browser regressions also passed after this extension:
13 social cases (including a separately built linking-disabled source probe) and
11 Apple cases. Both cleaned up their owned databases/TLS. Strict Axum all-target
Clippy passed with all features and with only social-linking-web selected.

The real-PG0037-to0038 upgrade case passed: actual signed web/native existing
identities/sessions and source/policy/audit/user rows remain byte-for-byte equal
as JSON values across unchanged additive0038. No historical grant is fabricated;
old sessions still work and new explicit capture resolves the original web owner,
leaving the native realm untouched. Strict PG all-feature all-target Clippy passed.
Initial fixture Clippy rejected a private routes reexport (E0364/E0603); visibility
was limited to the common fixture parent, with no production API widened.

New modules stay below300 lines. Shared fixture lifetime was extracted separately;
new worker observations/controls, protected port and feature-disabled probe inputs/
erasure/internal comparison live in named modules. Longer trusted constructors
and ordered real browser/migration cases keep setup, original controls, actual
waits and cleanup together as size-review exceptions. No unrelated refactor,
custom cryptography, dependency change or proof seeder is introduced. Remaining
local work is the final integrated workspace/security/documentation matrix and
push. Registered-provider/production acceptance remains deferred and gated.


## Final local validation

Exact runtime/source integration commit:
`d58b596eb8e3a1c157cfb934c106e07ca2db8d95`.
The follow-up changes only this receipt and one README phrase distinguishing
browser navigation from native OS delivery; no implementation, test logic, schema,
manifest or dependency changes after the frozen code qualification.

Passed with the existing macOS build settings and owned disposable PostgreSQL:

- `cargo fmt --all --check`.
- Strict default and all-feature workspace/all-target Clippy with `-D warnings`.
- Default workspace:128 passed,0 failed/ignored.
- All-feature workspace:1150 primary passed,0 failed/ignored.1151 pass reports
  include one logging-isolation child rerun. HTTP221, core181, PostgreSQL651,
  server68, plus the existing unit/desktop/issuer integration targets.
- Nine captured-grant Chromium cases;13 capture-unselected social and11 Apple
  browser regressions. All owned database/TLS cleanup confirmed.
- SAML source guard and reference UI token check; compiled-graph advisory audit
  and all-feature dependency/license/source policy. No lockfile/version/exception
  change. These are automated checks, not independent security approval.
- Scoped integration source/doc secret scan:31 changed files, no leaks. Full
  AUTH-26 history from AUTH-25 base through the integration commit:14 commits,
  redacted secret scan, no leaks. Final receipt history is also checked before push.
- Website normal format check from its own working directory,7 source tests,
 0 Astro errors/warnings/hints,27 built pages, and genuine rendered interactions,
 search, mobile layout,26 routes/451 anchors with no runtime errors. The initial
 root-CWD formatting invocation could not resolve prettier-plugin-astro; the
 ordinary website command succeeded without changing formatting assertions.

Every required local command completed successfully. The final verification
artifacts are retained outside the repository; no provider key, token, cookie,
callback or raw diagnostic is published. The original73 protected files retain
exact bytes/change set and their original index is empty. Retained preview,
accounts/passkeys and unrelated source were not used or changed. Branch push is
the authorized next publication step after this receipt; hosted CI success is not
claimed or awaited, and main-only deployment conditions exclude this feat branch.
Live Apple acceptance and unaccepted upstream prerequisites remain tracker gates;
this evidence does not authorize closure, merge, release or deployment.


## Resource-description correction — AUTH-47 audit

The earlier phrase “no volumes” was inaccurate. Docker's PostgreSQL image creates
an anonymous data volume even without an explicit mount. Inspection confirms the
known owned test container has AutoRemove enabled, no HostConfig bind/explicit
mounts, one anonymous-labelled data volume and no other container using it. The
volume was created with this owned fixture. No retained preview/database volume
was used. This corrects resource wording, not test results or authority policy.
Docker documents [automatic anonymous-volume cleanup with --rm](https://docs.docker.com/reference/cli/docker/container/run/#clean-up---rm).
