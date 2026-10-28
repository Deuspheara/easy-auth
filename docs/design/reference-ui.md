# Reference UI design

The reference client uses Basecoat 1.1.0 Vega for component styling, compact
authentication forms and open account settings. The layout is presentation only:
existing controllers and server APIs own authentication, confirmation and recovery.

## Components and layout

Use the pinned Button, Field, Label, Input, Checkbox, Input Group, Kbd, Item,
Avatar, Badge, Alert, Alert Dialog and Popover structures. Basecoat owns component
colors, shape, borders, typography and elevation. The application supplies a
660px account/recovery column and a 400px anonymous authentication/reset column,
responsive gutters, top alignment and consistent ghost Back controls.

The header retains the existing project shield-and-key logo and a shared icon
theme control. Account identity sits above open Profile, Security and Sessions groups. Native padded Items use
leading icons and trailing chevrons; the current session has one outlined group.
Keep account groups open rather than nesting them inside overview cards.

Keep local Inter, the measured title hierarchy, 44px action targets,
wrapping at 320px/200% text, visible keyboard focus and the temporary theme
controller. Input boundaries remain strengthened with a mix of Vega's active
foreground and background. Native checkbox indicators avoid the package's
blocked data-image mask under the unchanged restrictive CSP. Native modal
geometry is retained. These are deliberate accessibility/CSP exceptions.

## Tokens and assets

[reference-ui-tokens.json](reference-ui-tokens.json) contains spacing, typography
and compatibility aliases into Basecoat tokens. It has no independent light/dark
control palette. `python3 scripts/reference_ui_tokens.py` generates
`pages/tokens.css`; `--check` detects drift. The pinned local stylesheet supplies
both themes. Asset versions and provenance are recorded in the
[implementation guide](reference-ui-modernization.md).

`reference.css` owns application composition, responsive wrapping, minimum touch
targets and CSP-safe fallbacks. Basecoat owns control focus rings; do not add a
second outline to inputs, especially inside Input Group. Keep generic prose
spacing out of component descriptions and preserve normal component transitions.
Update the exact combined stylesheet digest with
`python3 tools/reference-ui/style-hash.py`.

## Behavior ownership

Back precedes settings search, then the page heading. Search finds permitted
account settings locally using Input Group/Kbd and normal navigation results.
It never searches personal information or fetches credentials for decoration.
Existing controllers retain authentication, operation guards, cancellation,
proofs, stale-result rejection, current-owner/version checks and native prompts.

Recovery has numbered steps, completed markers, task-specific titles and concise
summaries. Setup facts follow the task; cancellation forms sit inside explicitly
labelled native disclosures. Existing warnings and consent fields remain beside
the relevant decisions. Readiness and completion come only from accepted server
results. Supplementary help uses Popover. No new polling, retries or policy.

Field errors sit beside inputs; operation errors and results persist beside their
action. Navigation clears obsolete feedback. The English copy and server facts
use the existing API contracts.

## Evidence

Implementation and verification are recorded in
[the modernization record](reference-ui-modernization.md). Local visual inspection
of the UI and passkey verification journey was recorded on 2026-10-25, separately
from automated flow checks. Neither establishes an accessibility audit or
production readiness.
