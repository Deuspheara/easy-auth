# ADR0042: Reference account presentation and browser lifecycle

Status: accepted; implementation and owned browser/presentation checks recorded.
Date: 2026-10-24.

## Decision

Keep the reference client in Axum's owning `pages/` modules and feature pages.
Use fixed HTML, small native JavaScript modules and one fixed stylesheet. No
frontend runtime, remote font, image, analytics or new runtime package is required by
the server. The root page exposes only boolean presentation capabilities derived
from its actual selected OpenAPI composition and `Auth::passwords_enabled`.
Compiling an optional protocol does not advertise or activate it. Capabilities
describe selected interfaces, not current provider trust or authentication proof.

The authenticated session response additionally projects the existing core
`authentication_policy` string: mailbox, passkey_required or provider_required.
It is account metadata, distinct from current authentication method/freshness.
Use it to avoid offering mailbox fallback to stronger/provider accounts. Every
actual operation still calls the existing authoritative API; no SQL, cryptographic,
freshness, last-key or lifecycle rule moves into JavaScript.

Keep profile, linked issuers, passkeys and session metadata separate in the UI.
Render user/provider labels as text, never markup or issuer-derived navigation.
Use bounded API cursor pages and current credential versions. Credential inventory
is a deliberate user action, rather than a background request on every page visit.
Destructive actions require an explicit native dialog before their existing protected POST. Provider
sign-in/deletion links use fixed local pages; the existing callback scrubbing,
purpose bindings, deliberate confirmations and SAML cross-site handoff remain.
Unavailable methods never select a weaker fallback or invent an Apple adapter.

Reuse the existing recovery client's byte-identical browser request/WebAuthn
operations in `pages/browser-operations.js`; retain its original recovery URL.
They abort on navigation, reject late results, use no-store/no-redirect requests
and retain only fixed native error categories. The account UI also invalidates
old render generations, checks its current owner before sensitive actions and
discards stale metadata. Clear password inputs on completion/navigation and
recheck the session after a restored page. Never retry an ambiguous credential
completion or persist proof in browser storage. This is not a browser-wide atomic
account-switch guarantee; database bindings and current authority remain decisive.

## Account overview and verified management

Separate identity/security overview from focused management panels and developer
diagnostics. Empty provider lists do not invent linking. Sensitive key inventory
remains deliberate. A genuine inventory401 may initiate an explicit confirmation
that replaces this browser’s session through normal logout and account-bound
WebAuthn start/finish. Cancel does not log out; there is no automatic credential
completion retry or weaker fallback. Recheck owner/view before logout and require
the actual refreshed owner to match before reading inventory. Existing core/SQL
freshness and credential restrictions remain authoritative.

The subsequent owner refinement uses a 660px overview, a shared brand/theme header
and native navigation rows. Keep recovery under Security and separate current-session
sign-out from full session management. Preserve the exact all-session semantics of
bulk revocation. Show key counts only after a successful explicit inventory read;
clear them with account metadata. Long emails remain complete in accessible text
and profile details even when visually truncated in the overview.

Refresh ordinary metadata on visible-page return, coalescing return events and
avoiding active operations. Reset unfinished forms on an observed owner change.
Keep only current/other status and genuine relative activity on session rows;
raw timestamps and immutable provider/public IDs belong in advanced details.
Nonessential success feedback expires after eight seconds, while failures and
confirmation instructions remain available. No location/device inference is added.

## Style and accessibility boundary

The maintainer's revised visual direction follows the
[authentication design contract](../../design/reference-ui.md): compact centered
sign-in and flat account settings, semantic tokens, locally bundled Inter and
equal OS-driven light/dark themes. The subsequent owner correction uses one
420px sign-in column and focused password, registration and help URLs. The closed
view selector is presentation only, bounded by selected capabilities. The inbox
state follows an actual email-start response and explicit resend uses the original
in-memory input and unchanged API limits. Direct inbox navigation returns to sign-in.
Normal page navigation retains existing cancellation and password clearing. The earlier aurora candidate was rejected and
is superseded; it is not a visual acceptance baseline.

Permit only the exact combined token/control stylesheets' SHA-256 hash in CSP. Keep default-src
none, same-origin scripts/connect/forms, base denial and frame denial. Explicitly
deny style attributes; add neither unsafe-inline nor a broad stylesheet origin.
Permit same-origin font loading for the fixed licensed Inter asset; no external
font or script origin is allowed.
An existing OpenSSL dev dependency verifies the hash against the shipped bytes.
Fixed style insertion does not parse claims or interpolate unescaped data.

Use native forms/labels, visible focus, live status, semantic landmarks, responsive
reflow and system light/dark/forced-color support. Explicit POST form methods
prevent credentials becoming GET query parameters if module initialization fails;
native non-JSON submissions remain rejected by the existing API. Browser tests
must verify actual flows, keyboard/contrast/reflow, busy/errors, navigation/privacy
and selected-method absence; appearance or mocked success is insufficient.

## Evidence and limits

Record exact completed checks with AUTH-43 and the [reference guide](../../guides/reference-ui.md).
Owned PostgreSQL/SMTP/native flows, provider-account presentation, measured
contrast/reflow, keyboard/dialog focus and local desktop/mobile visual inspection
have passed. Exact source Rust/security/hosted gates are recorded separately;
this decision alone is not acceptance proof,
WCAG certification, physical-device coverage, provider registration acceptance or
production approval. Recovery remains selected only through its existing explicit
experimental composition. SAML's ADR0032 waiver does not establish independent
review or close residual assurance. No protocol/trust/lifecycle policy is relaxed.
