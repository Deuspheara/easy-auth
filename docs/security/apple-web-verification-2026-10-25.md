# Apple experimental web verification — 2026-10-25

Implementation: [9706315](https://github.com/Deuspheara/easy-auth/commit/9706315),
preceded by the separate design075ff1b and unchanged producer extraction99393ff.
The subsequent literal-form escaping scenario at
[f8f4e9f](https://github.com/Deuspheara/easy-auth/commit/f8f4e9f22c14a3e122f708682d734941512840e9)
is a test-only strengthening. Its exact reviewed source also passed the browser
run; later receipt-only changes do not modify executable/test/guide source.
This records offline local transport/component evidence, not registered Apple,
physical-device, independent security approval or release qualification.
[ADR0043](../architecture/adr/0043-apple-code-flow.md) defines the boundary.

## Delivered behavior

Explicit Axum `apple-web` composition requires matching trusted persisted web-only
registration, realm and exact HTTPS origin plus `/apple/callback`. Ordinary server
startup/root capabilities remain unchanged. Native client kinds cannot select the
web router, even when their nonce convention is plain. No migration, runtime SQL,
new dependency/version, provider-grant lifecycle or credential loader is added.

Start/finish/cancel retain the exact-Origin boundary and four independent private
Secure/HttpOnly/host-only Lax operation cookies. The only cross-site exception is
bounded form delivery: it validates and attribute-escapes the actual form into an
inert handoff, reading no cookies/storage and performing no state consumption,
exchange or commit. Fixed same-origin script removes it immediately; a deliberate
confirmation then calls the existing core Apple verification/mapping/final PG
transaction. Unsigned profile is ignored; email never selects an existing owner.

Any ambient session cookie prevents start/finish. Stale or malformed callback
state cannot clear newer proof; callback cancellation also compares returned state.
Explicit cancellation retains current sessions. Logout clears Apple proofs. The
return is discarded before finish and on navigation/restoration; interrupted or
failed completion is not automatically retried. Client IP supplies abuse admission,
not an IP-pinned identity. Provider-source/current-policy checks remain mandatory.

## Local evidence

Commands use locked offline resolution and an isolated checkout. macOS build
overrides set dev/test debug and incremental off, build-dependency debug on. Real
tests use only owned disposable PostgreSQL17.11.

- Formatting and strict default/all-feature workspace/all-target Clippy: pass at
  implementation9706315. Final formatting, strict isolated Apple/all-feature
  workspace/all-target Clippy also pass after the test-only addition.
- `cargo test --offline --locked --workspace`:128 passed,0 failed/ignored.
- Same workspace command with `--all-features` at implementation9706315:1067
  reports (1066 primary cases plus the intentional logging subprocess repeat),
  including197 HTTP,169 core and606 real PostgreSQL;0 failed/ignored. The subsequent
  literal-form addition changes tests only and receives isolated/combined checks.
- Isolated `cargo test --offline --locked -p easy-auth-axum --features apple-web
  --test browser apple_web`:17 pass, with no Google/passkey unification.
- The same17 Apple HTTP scenarios also pass in combined all-feature mode after
  the test-only addition; all required negative assertions remain intact.
- `cargo build --offline --locked -p easy-auth-axum --features apple-web --example
  apple-web-browser`, then `node tests/browser/apple-web/run.cjs`:11 cases pass.
  Chromium156.0.8078.4, Playwright1.64.1, Node26.0.0, macOS/arm64. Binary SHA256
  `9dcd94db0f02bc40bf8ea3278f518d847429151134bfe32a487f41a82ae57207`.
- Actual HTTPS browser POSTs omit Lax private proofs and an existing session.
  Before confirmation, facts remain zero owners/identities/sessions/audit/token
  POSTs with one pending operation. Deliberate verified completion creates actual
  authority; final aggregate facts are one owner/identity/session/audit, zero
  pending, two token POSTs and two actual signatures (one signed nonce rejection).
- Browser cases cover cancellation/denial/unavailability, malformed forms,
  untrusted profile/XSS, restored-page discard, lost-finish non-retry, signed nonce
  rejection, wrong-browser proof, deliberate commit/replay, and existing-session
  arrival/start protection. Script errors, CSP violations, storage and reflected
  profile data are absent. The normal maintained producer independently checks
  the actual ES256 credential and one-use provider code; fixtures never construct
  a local verified proof or seed a session.
- Owned process, random database and private TLS files are removed. Final browser
  cleanup reports stopped=true, database_removed=true, emergency_cleanup=false,
  diagnostic=false. No system trust, real Apple endpoint or retained account is used.
- Compiled advisory and all-feature cargo-deny advisories/bans/licenses/sources:
  pass. Inactive optional SQLx/MySQL RSA RUSTSEC-2023-0071 stays visible, no ignore.
  SAML integrity245 files/11 patches and UI-token checks pass. Final redacted scoped
  secret scan and local documentation-target checks pass with no missing targets.
- Committed guides: website unit7/formatter/Astro0 errors/warnings/hints/static26
  pages pass. Genuine unchanged website assertions cover25 routes/423 anchors,
  search, theme/copy/navigation and mobile. Only screenshot output destinations
  were redirected to new owned temporary paths.

## Failures investigated and review

Initial HTTP fixtures reused a callback that existing persistence requires to be
globally unique. They now use distinct origins; the production invariant remains.
A denial fixture used Google-style fields unsupported by the strict Apple decoder;
it now supplies Apple's existing denial shape and separately proves unknown-field
rejection without consuming/clearing proof. An initial source-pinning assertion
misread existing OAuth policy: the final test observes committed IP admission and
rejects incorrect private proof instead of inventing IP identity binding.

The Node fixture client initially did not inherit Chromium's hostname mapping.
Bounded fixture-only HTTPS I/O now connects solely to the owned loopback proxy
with exact virtual Host and categorical errors. The production transport/trust
policy is unchanged. Strict Clippy caught a collapsible cancellation condition;
corrected without changing behavior. No protocol assertion, deadline, admission
limit, signature check, required security gate or real-provider criterion weakened.

Named production/test/example/browser modules keep HTTP delivery separate from
verification and SQL policy. Entry files compose/reexport only. New modules stay
below300 lines; ordered fixture constructors/producers/scenarios retain setup,
observations and valid/negative controls together as documented size exceptions.
The shared producer was moved byte-for-byte in a separate commit and its unchanged
ten real-PG Apple tests passed before extension. Generated OpenAPI is a deliberate
data-size exception. No unrelated cleanup is deferred.

Final preservation review verifies all73 protected original path/byte values,
the original change set and empty index unchanged. Development, execution and
staging used only the isolated checkout. Only this task's disposable PostgreSQL
container was removed; retained preview/accounts/passkeys remain untouched.

## Remaining acceptance

Real Apple registration was explicitly deferred. Registered web/native consent,
negative controls, first/later consent, relay behavior and console key rotation
remain unperformed. Native OS callback delivery, linking/unlinking and usable
provider-grant custody/revocation remain separate work/gates. AUTH-23's unfinished
provider/native qualification dependency remains recorded; AUTH-24 stays In Progress.

Local passes do not imply provider interoperability, independent approval,
production readiness or protocol compliance. SAML waiver limits and the outbound
OIDC release gate remain unchanged. Hosted CI is not awaited and is not reported
successful without exact-commit evidence. No PR, merge or deployment is authorized.
