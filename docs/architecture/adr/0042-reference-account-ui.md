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

## Style and accessibility boundary

The maintainer's revised visual direction follows the
[authentication design contract](../../design/reference-ui.md): compact centered
sign-in and flat account settings, semantic tokens, locally bundled Inter and
equal OS-driven light/dark themes. The earlier aurora candidate was rejected and
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
