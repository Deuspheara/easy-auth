# HTTPS issuer consent verification

AUTH-38 optional consent/recovery increment, 2026-10-23. See
[ADR0036](../architecture/adr/0036-issuer-https-consent-delivery.md) and the earlier
[code transaction receipt](issuer-code-verification.md).

## Implemented and exercised

The explicit HTTPS root-origin/realm router adds fixed non-authoritative GET pages,
closed same-origin prepare/resume/approve/cancel POSTs and a deliberately limited
contract. Private browser/handle and public operation selector cookies stay Secure,
HttpOnly, host-only and Path=/. Actual session and exact displayed preview UUID are
required. Errors never redirect to unvalidated destinations. Failed decisions cannot
clear new/retryable proofs; successful decisions and session changes clear transport
state. Read-only recovery rechecks all current/original policy without authority or
expiry extension; unusable recovery clears transport, infrastructure failure retains
it. No token/discovery endpoint or normal startup activation is introduced.

Nine real HTTP/PostgreSQL cases traverse actual email proof completion and check
Origin (including duplicate/missing), cookie/media/query/body/closed input, actual
other owner/session, stale preview/private proofs, explicit code/denial, wrong actual
native port, one-use, rollback/retry, logout, default-route absence, composition and
read-only recovery/expiry. Core proof negatives now cover preview too. Existing
PostgreSQL source/transaction tests remain unchanged apart from those added checks.

Eight owned private-TLS Chromium cases pass using the actual fixed HTML/script and
actual HTTP email proof completion. The fixture inbox models EmailDelivery only;
it constructs no user/session/provider proof and reads no private browser cookie.
Cases verify query/fragment scrubbing, no web-storage data, HttpOnly proofs, explicit
preview/allow/deny, recovery after reload, actual old-tab/new-cookie UUID refusal,
restoration and duplicate input rejection. The registered callback alone is fulfilled;
other external requests are blocked. Final aggregate facts: one user, one unchanged
local session, one sector subject, two approved codes and two issuer audit events.
This is consent delivery evidence, not signed token or remote/native interoperability.

The fixture imports the existing owned database/process/TLS/mail helpers unchanged,
reports only finite facts, and removes its database and private TLS directory. Final
run:8passed, normal owned cleanup true, no emergency cleanup or diagnostic output.
No system trust setting, real provider, live service, PR, registry publication,
custom XML/signature producer, bypass/fuzz/stress or signature-concurrency experiment.

## Local verification

Rust1.95/macOS arm64 and the repository's real loopback PostgreSQL service:

- Formatting and strict locked default/all-feature workspace all-target Clippy pass.
- Default workspace115passed, all-feature853passed,0failed/0ignored, including502
  real PostgreSQL lifecycle cases and the nine additional real-DB HTTP cases.
- Isolated `issuer-consent-web` nine HTTP/DB cases pass without optional providers.
- Final owned Chromium run passes all8cases after the script's protected recovery,
  navigation/restoration and redirect-refusing fetch changes.
- Warning-free all-feature Rustdoc; compiled advisory audit and all-feature
  cargo-deny advisories/licenses/sources/bans pass. Existing inactive SQLx/MySQL
  rsa0.9.10 advisory stays visible; no ignore or dependency/version added.
- Unchanged245file/11patch source inventory and11existing source/qualification-script
  checks pass. Scoped secret/diff/link checks and protected-file hashes are checked
  before delivery; exact feature commit/hosted run are recorded in the tracker.

The core read-only preview and public cookie selector were added after owned-browser
review exposed a reload recovery gap. The same full source-aware locks and original
caps remain mandatory. No timeout, existing assertion or security gate was weakened.

## Remaining work and assurance

Concrete signed issuance/key/audience integration and its dedicated client-authenticated
token POST, discovery/JWKS, refresh/native families and actual interoperability remain
work. Consent delivery does not close those AUTH-37/38/39 requirements. A browser
abort does not undo a committed code decision; process-wide erasure and external
callback/client history are not claimed. Production operations remain supervised.
ADR0032 waived independent SAML review; no independent review/audit was performed or
outbound production approval inherited. Hosted/local tests never substitute for it.
