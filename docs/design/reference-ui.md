# Authentication presentation

easy-auth uses a compact, neutral interface for managing identity and security.
The design must make each section’s purpose clear before asking someone to act.
Rendered owner approval remains separate from passing browser checks.

Sign-in is a borderless 420px column with a 28px heading, one brand
presence, 48px controls and 10px control corners. Email is primary, with only
selected passkey/provider alternatives. Password, passkey registration, help and
account-ID passkey access have focused presentation URLs (`/?view=…`), rather than
sign-in accordions. Query values select presentation only; unavailable/unknown
views return to sign-in and cannot enable a capability or supply authentication.
Recovery and saved account IDs are reached through help. Successful email start
replaces the form with a check-email state and explicit resend, retaining the
existing browser binding, generic response, expiry and server admission limits.
A direct inbox query cannot construct that state or supply a resend address.
The icon theme button has an accessible action label; the repeated footer is removed.

## Account hierarchy and language

The account overview uses a 660px column and a shared brand/theme header.
Use three distinct sections: **Profile** for who the account belongs to,
**Security** for sign-in and recovery, and **Sessions** for where it is active.
Section labels describe the information; row labels describe the destination.
Avoid repeating Account, Your account and Profile as competing headings.
Focused views place the return action above the page title, with the same busy
protection as account actions. The profile view has one **Profile** page title,
labelled display-name/email values under **Personal information**, and account deletion in a separate section.
Do not imply that a read-only name is editable. Contact and deletion controls remain
conditional on actual account policy and selected services.

Recovery needs a purpose, not a circular description such as “Manage recovery
options.” Explain the situation in plain language: **Save a recovery code in case
you lose access to your passkeys.** The destination first explains that the code
must be saved while sign-in still works, is used with the account ID to request a
replacement passkey, and includes a waiting period. Preserve experimental status,
secret-handling warnings, fresh-proof requirements and explicit confirmations.
Do not imply instant access, email fallback or that recovery is already configured.

Identity has its own avatar/name/email row; long email addresses truncate visually while
remaining intact in accessible text and the wrapping profile view. Security uses
quiet navigation rows for passkeys, password and account recovery. Recovery is not
labelled a sign-in method. A passkey count appears only after an explicit successful
inventory read and clears with account metadata; no recovery status is invented.
The current session and its sign-out share one row. Other sessions, contextual
revocation and confirmed sign-out everywhere live in a separate management view;
the existing all-session API is never relabelled as other-session-only.
Empty provider inventory is hidden;
unsupported linking is never presented as a connect action. Detailed passkey and
password management and account changes use focused panels. Passkeys remain an
explicit sensitive read; **Manage passkeys** requests inventory and, only after an
authoritative freshness denial, offers confirmed native verification. It explains
that this browser will sign out, preserves other sessions and binds the new prompt
to the previously confirmed owner. Cancel preserves the existing session. An
ambiguous credential finish is never retried; only inventory is read after a
successfully verified same-owner session. No backend freshness or policy changes.

Name and email are separate text nodes. Public IDs, full provider identifiers,
manual checks and exact timestamps live under advanced developer details. Session
rows show only actual current status and activity derived from returned timestamps;
no invented device/location/method. Current-session sign-out and confirmed sign-out
everywhere remain distinct; only other sessions have an individual revoke button.
Metadata refreshes after mutations and visible-page return, with overlapping return
refreshes suppressed and active operations left alone. An observed owner change
clears unfinished account forms and returns to the overview. Every sensitive action
still rechecks its owner; this is not a cross-tab atomic account-switch guarantee.

Nonessential success feedback is a small eight-second live notification; errors and
confirmation instructions persist. The same native layout supports both themes,
mobile and enlarged text. No sidebar, marketing hero, ambient effect, decorative
image or new runtime dependency is added. Conditional WebAuthn mediation remains
outside this presentation change. Rendered owner approval is still pending.

The selected semantic roles live in [reference-ui-tokens.json](reference-ui-tokens.json).
`python3 scripts/reference_ui_tokens.py` generates the committed `pages/tokens.css`;
`--check` rejects drift. `reference.css` owns shared native controls and feature
geometry, using those aliases. Both fixed CSS inputs form one hash-allowed style
block; changes require updating its CSP digest and passing the exact-hash check.
Native forms, details and the existing modal dialog retain their behavior;
no new frontend framework or primitive library is required for this adaptation.
Both themes follow the OS until the temporary page toggle is used.
The shared native dialog retains a fixed black 50% backdrop; that native-overlay
effect and the feature's computed column widths are explicit presentation
exceptions, not additional screen palettes or shadow recipes.

Inter 4.1 upright variable WOFF2 is bundled unmodified under SIL OFL 1.1, with its
license at `/ui/fonts/OFL.txt`. The 352240-byte asset has SHA-256
`693b77d4f32ee9b8bfc995589b5fad5e99adf2832738661f5402f9978429a8e3`, matching the
[pinned official distribution](https://github.com/rsms/inter/tree/v4.1/docs/font-files).
It is served from one fixed local asset route; CSP adds same-origin font loading,
retaining every script/connect/form/frame/base restriction. No runtime CDN is used.
System UI is the explicit fallback; browser evidence checks that local Inter loaded.
The font adds 352240 source bytes, without a JS runtime dependency. No latency or
production performance qualification is inferred from these asset sizes.

The [browser runner](../../tests/browser/reference-ui/README.md) exercises genuine
authentication/account flows, keyboard/dialogs, local font loading, measured
contrast, six widths from 320–1440px, 320px/200% text and both themes. Rendered owner
approval and manual assistive-device qualification remain separate. Existing
protocol, current-source, freshness, tenant and lifecycle policy remains decisive.
