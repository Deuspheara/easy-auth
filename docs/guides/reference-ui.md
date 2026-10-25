# Reference account client

The server's root page uses the same authentication APIs as a custom application.
It includes email/password and selected passkey/provider entry points, public
account details, connected issuers, passkey management and active sessions.
Existing reset, contact, recovery, consent and provider pages share its fixed
light/dark presentation. This is a reference client with owned browser-flow and
presentation checks; broader device, manual provider and production assurance
remain separate.

## Selecting methods

The page follows the router actually constructed by the embedding or configured
server, not the set of compiled Cargo features. Password controls require the
existing explicit password service. Passkey and recovery controls require their
existing explicit constructors; adding this UI does not enable ordinary recovery.
Provider buttons require the selected OIDC, Google or SAML web composition.
Source disable, expired trust, account policy and current authentication still
control every API operation. A visible button is not an availability guarantee.

Use [standalone configuration](issuer-standalone.md) for the configured issuer,
[OIDC web setup](oidc-web.md), [Google](google.md), [SAML](saml.md) and
[passkey management/recovery](passkey-management.md) for their existing boundaries.
Unsupported methods have no placeholder grant or weaker fallback. In particular,
this UI does not implement the pending Apple provider work.

## Sign-in journey

Email is the primary form. **Use a password instead** opens its own view; selected
passkeys/providers remain alternatives. **Create an account** opens native passkey
registration. **Trouble signing in?** contains recovery, saved public account-ID
access and explicit stale-session sign-out. Unavailable methods stay hidden.
The `view` query selects presentation only and never enables a method or proves
identity. After successful email start, the check-email view offers deliberate
resend; links still require the initiating browser and original ten-minute expiry.
Resend remains subject to normal server admission. No address or proof is saved in
URLs or browser storage, and ambiguous credential completions are never retried.

## Account overview

The compact overview separates profile, security and the current browser session.
Profile details use labelled name/email fields and keep account deletion separate.
Account recovery explains how a saved code can help when all passkeys are lost;
save it before losing access. Recovery still requires the account ID, its waiting
period and the existing experimental composition.
Select Personal information for profile details, or a security row for password,
passkey or recovery management. A passkey count follows a successful explicit
inventory read; unknown inventory and recovery status are not guessed.
Long email addresses truncate in the overview and wrap in full in profile details.
**Manage sessions** opens the complete owned-session inventory and its contextual
actions. Current-browser **Sign out** stays beside that session in the overview;
confirmed **Sign out everywhere** is available only in session management.
Empty connected-account inventory stays hidden; provider linking is not offered.
Public account IDs, full issuers, exact session timestamps and the manual sign-in
check are available in **Account details → Advanced developer details**.

Metadata refreshes after actions and when returning to the visible page; it avoids
interrupting active operations and resets unfinished forms when an owner change is
observed. Failures expose retry; healthy views have no manual refresh control.
Success feedback remains inline until the next operation replaces it. Errors and confirmation-link
instructions remain visible. Only other sessions have an individual revoke action;
this browser’s sign-out and confirmed sign-out everywhere are separate.
Keyboard users can open Profile and Sessions and return to the account heading.
Escape cancels the sign-out dialog without sending revocation; focus returns to
the invoking control after it is enabled. Cleanup preserves another visible focus
destination and never restores a hidden control or an earlier page's focus.

## Using account controls

Email links must finish in the initiating browser. Password reset has its own
same-browser link. Setting a password is the existing one-time enrollment, not
password replacement; existing-password users can explicitly sign out and reset.
The account page starts mailbox email changes and deliberate account deletion;
complete the separate email confirmations in that same browser. Strong accounts
can request a verified contact email after fresh passkey sign-in without enabling
mailbox sign-in or weaker recovery.
Passkey creation requires the browser's native prompt; new accounts also prove
the new key in a second prompt before sign-in. Public account-ID access is
for an already retained account, never an email-to-key lookup.

`/v1/session` now includes the existing account `authentication_policy` metadata.
Mailbox account actions, passkey-only contact attachment and provider-only
reauthenticated deletion are presented separately. This string does not prove
freshness or the authentication method. Existing backend restrictions remain
authoritative, including genuine fresh passkey proof and another proven key for
key removal. Choose **Manage passkeys** to retrieve
this sensitive inventory explicitly. Opening the page never initiates sign-out.
If the server requires fresh passkey proof, use **Verify access**, then confirm
native verification: this browser signs out and opens the account-bound sign-in
form with the same public account ID. Choose **Continue with your passkey** to
open the device prompt from a fresh click. A successful same-owner sign-in returns
to management; the inventory endpoint still checks fresh authentication. Failed
prompts keep the selected account available for an explicit retry with a new
server challenge. Adding a key does not upgrade the current
session's authentication method. An accepted addition is confirmed even when
fresh verification is still needed to display the inventory. Other sessions stay
signed in; Cancel leaves
the current sign-in intact. Failed or interrupted finish is never automatically
retried. Account-bound owner checks and normal APIs remain authoritative. No weaker recovery is selected after a rejection.

Connected-provider inventory shows immutable linked issuers, not current enabled
trust, raw subjects or claims. It supports bounded pages. Session inventory lists
only owned active records, also with bounded pages. Explicitly confirm all-session
sign-out and passkey removal; both can sign out this browser. If another tab changes
the account, the return refresh rechecks it; advanced **Check sign-in** is also available. There is no cross-tab atomic
account epoch or downstream application-session revocation claim.

Messages report confirmation only after API success and the relevant session
read. Interrupted credential completion is not automatically retried. Passwords
are cleared on completion/navigation; callback and recovery proofs keep their
existing transport and lifetime rules. No browser storage or third-party resource
is added. Themes follow the OS; the root light/dark toggle is temporary for the
current page. The compact, neutral presentation uses a locally bundled Inter
font, semantic tokens and Basecoat native controls. Optional Motion provides brief
view/supporting entrances; reduced motion, forced colors or module failure retain
the static usable presentation. See the [asset and state record](../design/reference-ui-modernization.md).
See the [authentication design contract](../design/reference-ui.md) for the
adaptation and the recorded owner approval.

## Verification and limits

The [reference browser runner](../../tests/browser/reference-ui/README.md) uses
real PostgreSQL, configured SMTP and native virtual authenticators. It passes
email/password/reset, session revocation, two-address email change/deletion,
native passkey signup/enrollment/rename/removal, discoverable and account-ID sign-in,
and strong contact flows.
It also checks labels/autocomplete, keyboard/dialog focus, delayed-request busy
state, offline errors/password clearing, navigation cancellation, no false success,
temporary theme, empty browser storage and no external request or page error.
Light/dark layouts pass measured contrast and 320/390/768/1024/1280/1440px reflow;
both sign-in and account views pass 320px/200% text. Local Inter loading is checked.
Anonymous and authenticated light/dark mobile/desktop layouts were inspected
locally. The owner approved the rendered design and verification journey on 2026-10-25.
Contrast and reflow targets follow [WCAG text contrast](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html)
and [reflow](https://www.w3.org/WAI/WCAG22/Understanding/reflow.html). Those targets
are not a completed accessibility audit or assistive-device certification.

Existing browser regressions pass 31 native passkey, 4 SMTP/account-management,
9 recovery, 18 actual Keycloak OIDC standalone/embedded, 13 owned Google transport,
10 actual Keycloak SAML, 8 SAML handoff and 8 SAML deletion cases. Provider suites
check the root account after genuine completion: immutable text-only linked issuer,
active session and selected deletion controls without mailbox/passkey fallback.
Google transport checks use the existing owned provider, not manual Google
registration acceptance. Recorded browser versions: Chromium 156.0.8078.4,
Playwright 1.64.1, Node 24.21.0, Mailpit 1.27.11 and PostgreSQL 17.11. Exact full
workspace/security and hosted source evidence belongs to the implementation
commit and CI receipt; these bounded browser results do not replace those gates.

[ADR0042](../architecture/adr/0042-reference-account-ui.md) records capabilities,
account policy metadata and the exact stylesheet hash permission. Existing strict
CSP, no-store/no-referrer, Origin, HttpOnly cookies and current-source checks remain.
SAML independent review was waived under ADR0032, not performed; manual provider,
physical-device and production assurance remain separate.

## Settings search and recovery presentation

Signed-in account screens and recovery setup offer local account-settings search.
Use Cmd+K on macOS or Ctrl+K elsewhere to focus it; Escape clears results. Search
uses fixed destination labels/synonyms and current server composition/account
policy, without searching personal data or fetching credential/session inventories.
It is absent on anonymous authentication and lost-access recovery pages.

Account and recovery pages use a 660px maximum column; anonymous authentication
and password reset use 400px. Both retain responsive gutters and consistent Back
controls. Recovery setup separates verifying access,
preparing a code, saving/confirming and completion. An existing session can be
selected explicitly, but that does not establish fresh passkey authentication:
preparation still requires acceptance by the existing server policy. Lost-access
recovery separates start/resume, waiting, replacement and completion. Dates and
readiness are server facts; there is no automatic polling or timer-based authority.

Field errors appear below the input; action errors and persistent results appear
beside the relevant action. Optional information buttons expose supplementary
help; essential recovery consequences and consent remain visible. Navigation
clears stale feedback and pending recovery code display.
