# Authentication presentation

This adapts the maintainer-supplied `engineering-workspace-ui-v1` contract to
authentication. It is a visual candidate awaiting the owner's review, not an
approval inherited from another application or from passing browser checks.

The sign-in view is a narrow, borderless column with an 18px title. Email is its
primary local action; selected password, passkey and provider methods remain
secondary. Retained IDs, signup, recovery and stale-sign-in cleanup use contextual
disclosure. Available methods come from the actual selected router, not fixtures.
The account view uses flat settings sections and aligned session/provider rows.
Key management and destructive actions reveal their relevant fields and warnings.
There is no workspace sidebar, marketing hero, ambient effect or decorative mark.

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
