# ADR0033: Static project website and curated developer guides

Status: Accepted; GitHub Pages publishing authorized by the maintainer.

## Context

The project needs a public landing page and navigable, searchable guides alongside
its Rust source. Runtime authentication policy stays in the existing crates.
Private local assurance packets and unfinished research must never enter a public
website build. Capability claims must reflect documented implementation scope.

## Decision

Use Astro and Starlight to build a static site in `website/`, with an original
landing page and documentation under `/docs/`. Starlight supplies accessible docs
navigation, syntax rendering, theme selection and Pagefind search. No new backend,
provider demo, accounts, telemetry, external fonts or runtime API is introduced.
Pin dependencies and commit the npm lockfile. CI validates branches and deploys a verified static artifact from `main` to
GitHub Pages, using job-scoped Pages/OIDC permissions and no personal token.

An explicit source manifest selects public `docs/guides` files. The publisher reads
regular-file Git objects at the build revision, not working copies or directory
globs. Provenance records exact source hashes. The Markdown renderer rewrites
relative links to selected local routes or committed GitHub paths; uncommitted
references cannot become public links. Authored website pages remain normal source
files subject to review. This boundary does not replace reviewing committed public
content for secrets or inaccurate claims.

Feature availability has one website data source. Provider guides retain detailed
contracts. SAML follows ADR0032's explicit maintainer waiver; the site must not
represent it as an independent audit. Outbound OIDC issuer functionality remains
unreleased. The public project-site target is `https://deuspheara.github.io/easy-auth/`.
One base-path helper serves Astro and Markdown links; browser checks exercise
that prefix, assets and search. Repository administrators must enable the Pages
GitHub Actions source before first deployment.

## Alternatives and consequences

Buildless HTML would minimize dependencies but require maintaining docs navigation,
search indexing and code rendering ourselves. A server-rendered framework adds a
hosting runtime the content does not need. Static Astro/Starlight adds build-time
npm dependencies, requiring ordinary advisory and upgrade maintenance, while
leaving production authentication and Rust dependency graphs unchanged.

RustAuth's public documentation-site structure informed the landing-plus-guides
shape; its source, branding and authentication implementation were not copied.
The visual design, content selection and implementation are specific to easy-auth.
Later maintainer feedback informed the monochrome layout using Better Auth and
Auth.js as references. Hugeicons Free supplies MIT-licensed SVG icons, rendered
at build time with its notice included; no Pro icon or new browser framework.

Guides distinguish quickstart, complete Axum composition, a separate application
Cargo example, same-origin browser usage, concepts, deployment and troubleshooting.
The two full Rust example listings come from allowlisted committed source, keeping
them tied to code compilation rather than hand-maintained pseudo-APIs.
