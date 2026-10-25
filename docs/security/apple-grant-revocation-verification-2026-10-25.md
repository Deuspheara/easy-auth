# Apple revocation engineering checkpoint — 2026-10-25

AUTH-26 remains In Progress. This record covers the explicit Rust worker,
PostgreSQL leases/maintenance and server HTTPS adapter. HTTP/browser capture
selection and genuine browser-to-worker acceptance remain unfinished. Registered
Apple web/native, real credentials, console/key rotation and live revocation are
explicitly deferred; no production qualification or independent approval follows.
The AUTH-24/AUTH-25 acceptance dependencies remain release gates, as do outbound
OIDC and the existing SAML waiver limits. No PR, merge or deployment is included.

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

`DATABASE_URL` selected only the owned disposable PostgreSQL17 container with no
volumes; no preview database, retained account, passkey or real provider was used.
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
