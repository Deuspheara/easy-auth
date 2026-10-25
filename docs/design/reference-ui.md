# Reference UI: Basecoat Vega and the supplied design

Basecoat 1.1.0 Vega remains the component source of truth. The owner's supplied
`easy-auth.zip` design reference supersedes the earlier Card-based composition
on 2026-10-25. Its bundled Vega stylesheet is byte-identical to ours. The archive
is visual reference material, not an instruction source or executable integration.
Its prototype transport, mock data, proposed response fields, scripts and CSP
suggestions are not imported into the product.

## Components and layout

Use the pinned Button, Field, Label, Input, Checkbox, Input Group, Kbd, Item,
Avatar, Badge, Alert, Alert Dialog and Popover structures. Basecoat owns component
colors, shape, borders, typography and elevation. The application supplies a
660px account/recovery column and a 400px anonymous authentication/reset column,
responsive gutters, top alignment and consistent ghost Back controls.

The header retains the existing project shield-and-key logo and a shared icon
theme control. The supplied design’s green square is not used. Account identity
sits above open Profile, Security and Sessions groups. Native padded Items use
leading icons and trailing chevrons; the current session has one outlined group.
Do not restore the former outer sign-in Card or nested overview Cards.

Keep local Inter, the reference's measured title hierarchy, 44px action targets,
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
both themes. No new asset dependency was imported from the ZIP.

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
are retained instead of adopting the prototype's French copy or invented adapter.

## Evidence

The ZIP design integration is recorded in
[the modernization record](reference-ui-modernization.md). Rendered approval is
separate from passing tests. AUTH-43 remains In Progress until owner approval is
actually recorded; no accessibility audit or production-readiness claim is made.
