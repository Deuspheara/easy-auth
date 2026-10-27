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

## Search writer completion (AUTH-60, 2026-10-27)

An observed successful build emitted empty Pagefind runtime/entry files and failed
real browser search. A bounded owned reproduction found3 incomplete outputs in12
upstream writer/close runs. The pinned
[Pagefind1.5.2 writer](https://github.com/Pagefind/pagefind/blob/v1.5.2/pagefind/src/output/mod.rs)
awaits Tokio file writes without flushing; the Node close routine terminates its
backend. [Tokio documents](https://docs.rs/tokio/latest/tokio/fs/struct.File.html)
that pending file operations can outlive a file's scope without flush. The source
and reproduction support a writer-shutdown race; this is not a disk-durability claim.

Use Pagefind's documented [in-memory file API](https://pagefind.app/docs/node-api/)
and Node-owned awaited writes instead. A small Astro integration adapter replaces
only Starlight's writer hook, retaining every other hook and its normal UI/indexing
configuration. It does not patch node_modules, disable search, upgrade dependencies,
duplicate indexing or introduce a second search provider. Pagefind1.5.2 becomes an
exact direct build dependency with no change to the resolved lockfile package set.
Review this deliberate hook adaptation on future Starlight upgrades.

Validate the complete response, fixed version/entry/language assets, compressed
payloads and safe distinct paths before writing. Write into a fresh owned staging
directory, await closes and compare every emitted file byte-for-byte before rename.
Keep staging private until validation; normalize public file/directory modes to
0644/0755 before publication, even under a restrictive umask.
Missing/empty/altered/unexpected output, an existing destination or a write fault
fails the build; remove only owned staging. This completion boundary needs neither
sleep nor retry nor a new assertion waiver. Existing real browser controls stay
required and additionally exercise selecting a result under the project base.

The [verification record](../../security/website-search-verification-2026-10-27.md)
records exact implementation revisions, root-cause evidence, failure controls,
public permissions, Node24/26 browser qualification and unchanged backend gates.
