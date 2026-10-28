# Reference UI implementation and verification

The reference client uses Basecoat 1.1.0 Vega with a compact,
open account composition. The current visual contract is
[reference-ui.md](reference-ui.md); [ADR0042](../architecture/adr/0042-reference-account-ui.md)
records the behavior and security boundary. Earlier visual candidates are superseded.

## Feature ownership

| Area | Owning modules | Authority and verification |
|---|---|---|
| Email/password/sign-up | `pages/signin.js`, `auth-screens.js` | Existing start/finish/session APIs; real email and native credential flows |
| Profile/account actions | `account-view.js`, `account.js`, companion controllers | Current account policy/owner and existing confirmations |
| Passkeys | `passkeys.js`, `passkey-row.js`, `passkey-reauth.js` | Deliberate inventory, captured versions, explicit verification and same-owner return |
| Sessions/providers | `account.js`, `inventory-rows.js` | Bounded owned inventory; no provider linking or inferred device/location |
| Search | `settings-search.js`, `account-search.js` | Fixed labels/synonyms filtered by actual capabilities and account policy |
| Feedback | `feedback.js`, `view.js` | Associated field errors and a stable persistent status node outside replaceable lists |
| Recovery | `recovery/setup.js`, `recover.js`, named view modules | Existing proofs, deadlines, browser binding, cancellation and server readiness |
| Browser operations | `browser-operations.js` | No-store/no-redirect requests, navigation abortion and sanitized native error categories |
| Appearance | `theme.js`, `presentation-motion.js` | Temporary OS-driven theme and optional cancellable presentation only |
| Provider/consent pages | Existing feature templates/controllers | Unchanged callback, trust, confirmation and transport boundaries |

Each inventory distinguishes not requested, checking/loading, confirmed empty,
loaded and failed states. Invalidation clears rows/counts. No sensitive inventory
is fetched just to decorate the overview. Unimplemented methods remain absent:
Apple, editable display names, provider linking, OTP/TOTP/MFA, device/location
inference and automatic recovery lookup.

Opening Passkeys never initiates sign-out. If the server denies fresh inventory
access, Verify access offers an explicit confirmation. After confirmed logout,
the existing account-bound sign-in form retains the public account ID. Continue
starts a new challenge/native request from a fresh click. Failed prompts retain
the account for deliberate retry; an ambiguous finish is never automatically
repeated. Only the expected account resumes management, and the inventory endpoint
still checks real authentication freshness. Adding a key does not upgrade the
current session; an accepted addition is confirmed even if the list remains gated.

Recovery setup presents verify, prepare, save/confirm and completion. Lost-access
recovery presents start/resume, waiting, replacement and completion. Essential
waiting, expiry, code-consumption, offline-storage and replacement consequences
remain beside their decisions. Labelled facts distinguish unavailable values.
Cancellation stays reachable through explicit native disclosures. No polling,
automatic retry or client-clock authorization is introduced.

## Pinned local assets

| Input | Version | License | Purpose |
|---|---|---|---|
| basecoat-css | 1.1.0 | MIT | Standalone Vega CSS, runtime and Popover controller |
| motion / framer-motion / motion-dom / motion-utils | 14.6.0 | MIT | Optional mini ESM presentation bundle |
| tslib | 2.8.1 | 0BSD | Motion transitive runtime |
| esbuild | 0.28.2 | MIT | Build-only bundling |
| Inter | 4.1 | OFL-1.1 | Existing local variable font |
| Hugeicons shield/key | Existing project asset | MIT | Header logo |

`tools/reference-ui/package-lock.json` records npm provenance and integrity.
The builder reads only fixed package files; it does not scan application sources
or documentation. Production serves fixed local assets and requires no Node
runtime, CDN, analytics, external font or frontend framework.

`pages/vendor/assets.json` records shipped sizes and SHA-256 hashes. Vega CSS is
236766 bytes, Motion mini ESM 8444 bytes and runtime/Popover 4010 bytes before
transfer compression. These are output sizes, not latency measurements. Package
notices live beside the generated assets, the logo notice is `pages/brand.LICENSE`,
and the binary serves their combined text at `/ui/licenses.txt`. Inter's existing
OFL notice retains its separate fixed route.

Regenerate from the repository root:

```sh
npm ci --ignore-scripts --prefix tools/reference-ui
npm run build --prefix tools/reference-ui
python3 scripts/reference_ui_tokens.py
python3 tools/reference-ui/style-hash.py
```

Regeneration must reproduce the committed assets and token aliases. Basecoat owns
the light/dark control palette. The JSON supplies typography, dimensions and
compatibility aliases into Vega, rather than mapping Vega back to an old palette.
The application adds only layout and documented accessibility/CSP exceptions:
local Inter, 44px targets, text wrapping, visible forced-color focus, stronger
input boundaries, native modal geometry and native checkbox indicators.

## CSP and lifecycle

CSP retains default denial, same-origin script/connect/form/font restrictions,
frame/base denial and explicit style-attribute denial. Only the exact concatenated
Vega/token/application stylesheet hash is permitted. Fixed insertion never
interpolates user data or provider claims.

Vega's checkbox data-image mask is blocked by that policy, so the app uses the
native indicator. No `data:` permission, unsafe inline style permission or remote
origin is added. Basecoat owns normal focus rings; Input Group's inner input has
no second outline. Forced colors use a system outline when shadows disappear.

Motion is not an authentication dependency. Controllers emit synchronous committed
presentation/invalidation signals. A separately loaded adapter catches missing
optional imports, skips busy operations and never moves focus. Effects use
opacity/transform only, cancel owned work before replacement/removal and respect
reduced motion and forced colors. The adapter avoids `commitStyles()` and Motion's
automatic stop/replacement paths that can write a style attribute under this CSP.
Native dialog geometry and focus restoration stay application/browser-owned.

Password/code clearing, stale-result rejection, current-owner checks, credential
versions, native WebAuthn and server proofs remain in existing feature controllers.
The visual adaptation changes no backend API, schema, verifier or recovery policy.
The read-only linked-provider inventory is documented in ADR0041.
Presentation uses the existing transport and response contracts under the same CSP.

## Reproducible verification

Run Rust/SQLx suites sequentially, using the documented development PostgreSQL
service. SQLx and browser runners own disposable databases; never point them at a
human preview's retained database. Browser runners use real SMTP and native
virtual-authenticator operations, not mocked successful authentication responses.

Required final checks:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --all-features
python3 scripts/reference_ui_tokens.py --check
python3 scripts/check_saml_source.py
python3 scripts/audit.py
cargo deny --all-features check
npm audit --prefix tools/reference-ui
cargo build --locked -p easy-auth-server --example passkey-recovery-browser --features experimental-passkey-recovery
node tests/browser/reference-ui/run.cjs
node tests/browser/passkeys/recovery/run.cjs
```

The full-feature workspace includes genuine PostgreSQL integration suites.
Relevant existing provider/native browser regressions remain separate qualification;
record exact commands, counts and blockers with the implementation commit.

Presentation coverage includes both themes, 320/390/768/1024/1280/1440px reflow,
200% text, contrast, keyboard/dialog focus, help dismissal, reduced motion,
forced colors, busy/offline failures, capability absence and account switching.
Verification continuation coverage checks no automatic challenge on confirmation,
a sanitized native rejection with the account retained, and an explicit retry
that creates a new challenge, signs it and returns the actual owned inventory.
Recovery retains request/cancellation/replacement/interruption coverage.

Set `EASY_AUTH_UI_SCREENSHOT_DIR` to an existing local directory for optional
review captures. Nonempty passwords and recovery-code values are masked; no
browser storage state, proof URL or private key is exported. Screenshot captures
settle finite animations without disabling transitions in the application.

The owner reviewed and approved the rendered UI and updated verification journey
on 2026-10-25. Final validation and ticket closure are recorded separately from
that approval. Automated virtual-authenticator results do not establish physical
device/browser interoperability, a WCAG audit, independent SAML review, provider
registration acceptance or production readiness. The ADR0032 SAML waiver and
outbound OIDC release gate are unchanged.


## Final validation — 2026-10-25

All commands in the required-check block above passed. Default workspace tests
reported 128 passed, zero failed/ignored; all-feature workspace tests reported
1022 passed, zero failed/ignored, including real PostgreSQL integration tests.
The final embedded asset check also passed:
`cargo test --locked -p easy-auth-axum --all-features --test browser reference_ui`
(two tests). Rust/database suites ran sequentially.

The genuine reference UI browser suite passed with zero external requests,
uncaught page errors or CSP violations. Existing browser regressions passed:

| Command | Passed cases |
|---|---:|
| `node tests/browser/passkeys/recovery/run.cjs` | 9 |
| `node tests/browser/passkeys/run.cjs` | 31 |
| `node tests/browser/passkeys/attachment/run.cjs` | 4 |
| `node tests/browser/google-web/run.cjs` | 13 |
| `node tests/browser/oidc/web/run.cjs` | 18 |
| `node tests/browser/saml-keycloak/run.cjs` | 10 |
| `node tests/browser/saml-keycloak/run.cjs --account-deletion` | 8 |

Fixtures were rebuilt with their documented feature flags and owned disposable
databases; browser tests used a temporary source copy excluding protected work.
The SMTP fixture's narrow feature build emitted an existing unused-import warning
in `passkeys/recovery_setup/mod.rs`; it passed, and strict default/all-feature
Clippy passed without warnings. No unrelated Rust code was changed for that warning.

Both npm dependency audits passed. The asset build reproduced all eleven shipped
asset/notice hashes, generated tokens matched, and all 41 owned JavaScript modules
passed syntax checks. Package notice line endings are normalized without changing
license text. Staged whitespace checks passed. All 73 protected working files were
unchanged; retained human-preview account/passkey counts and record IDs matched
their pre-cleanup values. No migrations or account/credential cleanup ran.

## Integration review — 2026-10-25

The fetched `origin/main` is `7bd87b405dabd501562bb392042933743b125d2d`.
Its direct comparison includes the inherited issuer delivery stack (558 files at
`a7277cc`), not just this UI. The UI starts after
`b7a2ed2d76b7f3c8013e798c51901a84b9a636b8`, the tip of
`feat/auth-37-client-acceptance`. A stacked UI PR targets that prerequisite;
integration into main still requires the prerequisite stack and final hosted gates.

Two inventory invalidation issues were corrected:

- Starting a passkey read now discards old labels, row actions and count before
  loading, so an interrupted or freshness-denied read cannot retain that snapshot.
- Reloading sessions/providers now discards the previous pagination cursor and
  hides Show more. Failed continuation reads retain the accepted page and cursor;
  failed reloads cannot skip the missing first page with an obsolete continuation.

The genuine reference browser regression failed on the original embedded passkey
module at `passkey-invalidation.cjs:16` and verified owned fixture cleanup. It passes
with the fix, including held-request loading, actual network interruption and an
explicit successful inventory retry. The separate Node presentation regression
failed on the original pagination controller at its obsolete-continuation assertion
and passes both inventory cases after correction. It uses fixed inventory outcomes
without a server, authentication, session or proof; it is not authentication evidence.

The final rebuilt genuine browser suite passes with zero external requests,
uncaught page errors or CSP violations and verified disposable database/mail cleanup.
The existing real freshness-denial, explicit native verification, account ownership,
keyboard, responsive and account lifecycle checks remain in that run.

Maintainability review keeps both fixes in the owning inventory controllers and
regressions in named feature test modules. The controllers remain at or below
150 lines, new test modules below 90 lines and functions below 50 lines. Existing
documented ordered-scenario exceptions remain; no structural refactor, new
dependency, API/schema/policy change or unrelated cleanup is introduced.

Final follow-up checks passed on both corrected controllers: formatting, strict
default/all-feature workspace/all-target Clippy, 128 default workspace tests and
1,022 all-feature test reports (1,021 primary plus one isolated child), including
181 HTTP cases and all 596 real PostgreSQL lifecycle cases. Suites ran sequentially.
The commands are the required Rust checks above, the genuine reference UI runner,
and `node --experimental-vm-modules tests/browser/reference-ui/inventory-pagination.cjs`.
Token drift, shipped asset hashes, SAML source integrity, compiled dependency audit,
cargo-deny, both npm audits, changed JavaScript syntax and scoped redacted gitleaks
also passed. No advisory ignore was added; the inactive RSA lockfile notice remains.

Initial browser execution was blocked by the restricted sandbox; permitted local
execution resolved that environment failure. Initial advisory/license invocations
could not find the existing audit/deny tools on PATH; reruns using that installation
passed. An initial pagination test lacked its diagnostic-node DOM stub; adding the
stub corrected the harness without changing controller assertions. The two expected
pre-fix regression failures remain distinct from the passing final-source checks.
Final logs use the local `/tmp/auth43-integration-` prefix. Hosted verification of
the follow-up commit is separate and must be checked before integration.

## Theme measurement correction — 2026-10-25

Fresh isolated verification of merged `06312f5ca22f0519301f5ec021bb61dab3df2f63`
found an account contrast-measurement race without optional screenshot capture.
The account scenario read colors immediately after media emulation, before the
theme handler and transitions settled. Genuine passkey requests succeeded;
the initial run failed its session-heading contrast assertion. Reusing only the
anonymous scenario's initial animation-batch wait still failed the badge check:
an inherited child color transition remained running, measuring 4.467:1 before
settling to 14.477:1. Both failed runs verified owned database/mail cleanup.

A separate structural checkpoint extracts the existing anonymous theme selection
into `tests/browser/reference-ui/theme.cjs`; all twelve real-page presentation
cases pass after extraction. The correction reuses that selection in both account
measurement loops and waits for subsequent running/pending native animations
within the existing test timeout. It changes no contrast assertion, disables no
animation and adds no fixed sleep or timeout increase. The full genuine UI journey
then passes without screenshot capture, including native signup, management,
same-owner verification, keyboard/reflow and inventory-invalidation checks, with
zero external requests, page errors or CSP violations and normal owned cleanup.
A separate full run with local masked screenshot capture enabled also passes,
including the earlier account measurement loop; each final run removes its exact
nineteen owned messages and disposable database. Captures remain local.

The helper has one presentation-synchronization responsibility and is under
twenty lines. Existing ordered scenario size exceptions remain; no unrelated
cleanup is deferred. Production Rust, JavaScript, CSS, assets, APIs, schemas,
dependencies and authentication policy are unchanged. Fresh baseline formatting,
strict default/all-feature Clippy and sequential workspace suites pass: 128 default
and 1,022 full-feature reports (one isolated child), including 181 HTTP and 596 real
PostgreSQL cases. Source integrity, token drift, compiled advisory and cargo-deny
checks also pass without advisory ignores. Local low-debug compilation initially
hit a macOS SQLx macro-library LINKEDIT loader error; retaining build-dependency
debug information resolved it without source changes.

Hosted results are separate receipts; this
correction alone establishes no hosted success, integration or production approval.
