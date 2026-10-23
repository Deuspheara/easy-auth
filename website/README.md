# easy-auth website

Original landing page and searchable developer documentation for the pre-release
Rust project. Astro and Starlight produce static files; hosting needs no Node
server, database, account or authentication credentials.

## Local development

Use Node 24 (at least 22.23.4) and npm. Run from this directory:

```sh
npm ci --ignore-scripts
npm test
npm run check
npm run build
npx playwright install chromium
npm run test:browser
npm run preview
```

Open the loopback URL printed by Astro. `npm run dev` rebuilds during editing.
Browser checks own a programmatic preview on an ephemeral port and stop it on exit.
Screenshots go to the operating system temporary directory, outside public assets.

## Public content boundary

`scripts/docs-manifest.mjs` explicitly selects committed public guides. The build
reads their Git objects at HEAD, never their working copies. Uncommitted research,
private review packets and tracker exports are not inputs. Generated guides and
`public/docs-provenance.json` are ignored; each build records its source revision
and hashes. Relative links resolve to other selected guides or exact committed
GitHub sources; unpublished references are removed, or rejected for definitions.

Keep feature labels in `src/data/features.ts` consistent with the owning guides.
Maintainer-directed SAML activation is not independent security approval. The
outbound OIDC issuer remains unreleased. Do not add testimonials, usage statistics,
provider availability or production-readiness claims without evidence.

## Hosting

The public target is `https://deuspheara.github.io/easy-auth/`. Astro's canonical
origin and `/easy-auth` base are defined in `scripts/site-path.mjs`. Both Astro
markup and Markdown links use that base; the browser suite runs under it too.

The Website workflow validates builds for branches/PRs. Only a successful build
on `main` can upload `website/dist` and deploy with GitHub Pages. Deployment uses
job-scoped `pages: write` and `id-token: write`, not a personal access token.
Enable **Settings → Pages → Build and deployment → Source: GitHub Actions** once
as a repository administrator. No authentication backend runs on Pages.
The workflow can also be dispatched manually from `main` after configuration.

Astro/Starlight/Pagefind provide documentation rendering, themes and local search.
No analytics, remote fonts, backend login demo or third-party runtime API is used.
Dependency licenses remain governed by their individual packages and the lockfile;
our code uses the repository's MIT OR Apache-2.0 license.

## Dependency review

At implementation, `npm audit` reported zero vulnerabilities (2026-10-23).
Astro, Starlight, Pagefind, Shiki and Expressive Code use MIT licenses;
Playwright uses Apache-2.0. The build graph also includes ISC/BSD/CC0/BlueOak
packages and Python-2.0-licensed argparse. Sharp's optional libvips distributions
carry LGPL-3.0-or-later terms and Lightning CSS carries MPL-2.0: these are build
platform tools, not a new Rust runtime dependency. Distribute static `dist/`
assets for hosting; redistributing build tool binaries or a build image requires
preserving those packages' own notices and applicable source obligations.
Keep bundled browser-code notices when transforming/minifying output and recheck
advisories/licenses when updating the lockfile. Do not describe the entire npm
dependency graph as solely MIT/Apache licensed.

Hugeicons Free `@hugeicons/core-free-icons` is MIT-licensed. The Astro icon
component emits only selected SVG shapes at build time, without a client icon
runtime. Its copyright/license notice is shipped in `public/hugeicons-license.txt`
and linked in the footer. No Pro icons are included. Complete Axum code examples
are read from two explicitly allowlisted committed source files; they never read
an arbitrary path or local research.
