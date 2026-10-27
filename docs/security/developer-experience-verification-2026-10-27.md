# Developer experience acceptance audit — 2026-10-27

AUTH-42/M08 requires runnable protected-route examples, reference UI, OpenAPI and
accurate deployment/provider guides, with the child tickets' tests and evidence.
This audit establishes that developer-experience delivery scope. Feature-complete
release still requires all six authentication categories and the outbound issuer
release gate; registered-provider, OS, independent-assurance and production work
remain separate. No PR, merge or deployment is part of this audit.

Audit changes are documentation/presentation metadata only:
`6d587a3d5e5ff9722f7c961554d296ac42db17ac` corrects current component descriptions;
`542dfb2cd78f148c5bb73c96e8de409c39c8c266` adds the explicit committed issuer guide
to the website's named public-source allowlist. The branch is
`feat/auth-42-developer-experience-audit`, based on validatedc73f82d.

## Requirement and evidence map

| Requirement | Actual evidence and scope |
| --- | --- |
| Runnable protected route | Existing [embedded example](../../apps/auth-server/examples/embedded.rs) and [application handler](../../apps/auth-server/examples/embedded/application.rs) compiled and exercised on clean6d587a3 with fresh PostgreSQL/SMTP; actual ownership, realm isolation and stale-cookie rejection below |
| Independent Rust/browser integration | Existing independently locked [Rust consumer](../../examples/clients/rust/Cargo.toml) freshly built and executed against that embedded app; existing [TypeScript module](../../examples/clients/browser.ts) strictly compiled; AUTH-45's genuine TS/container/backup evidence retains its exact source/image scope |
| Reference UI | AUTH-43's owner-approved design, original exact merged hosted acceptance, separately corrected transition measurement and fresh current reference-browser runs with/without captures; genuine SMTP/native WebAuthn/owner/session/account assertions, not scaffold presence |
| OpenAPI | Published [default contract](../openapi.json), opt-in snapshots and live-contract assertions passed in the latest full workspace/real-PG suite; their implementation and JSON inputs are unchanged in this audit |
| Deployment and provider guidance | AUTH-44's exact hosted/local setup acceptance and AUTH-45's exact container/client evidence; current descriptions distinguish implemented components, explicit composition and remaining release/registration gates |
| Searchable documentation | AUTH-60's completed writer fix and new full website qualification on542dfb2, including the reviewed explicit issuer setup route |

All four native children AUTH-43, AUTH-44, AUTH-45 and AUTH-60 were independently
read as Done; child evidence and actual artifacts were inspected rather than
using those labels as the proof. AUTH-42 has no native blocker. Its feature-complete
release condition is retained as the project-wide release gate, not a claim that
M08 completion supplies provider/production acceptance.

## Exact historical hosted reconciliation

Fresh read-only GitHub API responses confirmed these completed runs:

- AUTH-43 source `06312f5ca22f0519301f5ec021bb61dab3df2f63`:
  [CI40194541133](https://github.com/Deuspheara/easy-auth/actions/runs/40194541133)
  and [Website40194541221](https://github.com/Deuspheara/easy-auth/actions/runs/40194541221)
  both success. The website job passed and its deployment job was skipped.
- AUTH-44 source `5aeeb6a3ba5fc9e53b7dc75e59e6ef7c6a8d3705`:
  [CI40201250616](https://github.com/Deuspheara/easy-auth/actions/runs/40201250616)
  and [Website40201250607](https://github.com/Deuspheara/easy-auth/actions/runs/40201250607)
  both success. Its deployment job was also skipped.

These satisfy the child-specific historical hosted requirements. They do not
qualify newer unmerged sources or establish any current deployment. The original
single-merge waiver is not reused. No new hosted run was waited for or declared
successful based on local execution.

AUTH-45's [container/client evidence](container-client-verification-2026-10-26.md)
records exact source de7c5e2, image IDs/scans, owned real browser/SMTP/TS/Rust behavior,
quarantined backup and required backend gates. Named container/client/fixture
inputs are byte-unchanged from that source. This audit does not relabel its schema38
snapshot or old image scan as a fresh schema39/current-image test. Later
[operational recovery evidence](retention-verification-2026-10-27.md) and
[incident controls](incident-recovery-verification-2026-10-27.md) keep their own scope.

## Fresh current-source runtime observations

The existing embedded and experimental passkey-recovery examples were frozen-built
on clean6d587a3. The independent Rust example was frozen-built under its own locked
manifest in a separate owned target directory. Strict TypeScript compilation used
the documented ES2022/DOM/module settings. No authentication implementation,
workspace manifest/lock, schema, feature policy or example source changed.

Two current genuine reference-UI runs used fresh owned PostgreSQL/Mailpit and
separately created/disposed databases. Without captures,18 exact owned messages
were removed; with local masked captures,19 were removed. Both passed the same
five-user/two-key, one strongly verified owner, provenance/audit and absent pending
signup/contact invariants. Both reported zero external requests, page errors and
CSP violations, with exact database removal. Current versions were Node26.0.0,
Playwright1.64.1, Chromium156.0.8078.4, PostgreSQL17.11 and Mailpit1.27.11.
This is headless native WebAuthn fixture evidence, not physical-device or
independent accessibility certification. Capture files stay local/private.

A separate fresh schema39 database ran two actual embedded instances with distinct
realms. Anonymous `/private` returned401. An owner signed in through real SMTP and
the shared production email completion; `/private` then returned200, the exact
same owner/realm and `Cache-Control: no-store`. The same cookie failed against the
other realm while the original session stayed usable. After actual logout, replay
of the saved original cookie through a fresh client returned401, proving server
revocation rather than merely clearing the browser jar. The independent Rust
process remained anonymous before, during and after owner authentication.

The embedded database was dropped only after its processes and actual backends
stopped; absence was checked. Exactly its one owned message was removed. All owned
containers/exclusive anonymous volumes and private service settings were removed;
a subsequent inventory found no remaining AUTH-42 fixture containers. No retained
preview, existing account/passkey, unrelated Docker project or original private
file was used as a fixture. Credentials/cookies/private responses stayed in memory
or owned temporary process inputs and were not included in receipts.

## Documentation reconciliation and verification

The website now describes implemented signed issuer/native/introspection components
while retaining **Not released**. Label definitions distinguish implementation
scope from release availability. Provider selection documents explicit protected
Apple grant composition/worker requirements and keeps registered-provider gates.
CLI guidance separates finite retention maintenance from startup diagnostics and
links its recorded local qualification.

The first new website crawl on6d587a3 correctly failed404 for the newly authored
issuer-guide link. The committed guide was reviewed and confirmed outside the73
protected paths, then only its named manifest entry was added. No route assertion,
private-content boundary or release gate was weakened. On clean542dfb2, Node24
format,22 unit tests, type/build and genuine Chromium all passed:34 routes/557
anchors,35 HTML files and50 complete verified search assets. All earlier search,
result navigation, theme, keyboard and mobile checks remain; previous fixed
screenshot bytes were restored.

The latest full required backend checkpoint remains cleanfc1aa20 from AUTH-60:
format, strict default/all-feature workspace/all-target Clippy, default167 and
all-feature1193 reported passes (one isolated logging child;1192 primary), zero
failures/ignored, including676 real-PG lifecycle cases. Audit and all-feature deny
passed with inactive RSA/RUSTSEC-2023-0071 retained. Rust/Cargo/schema/root-script/
workflow/OpenAPI inputs are byte-identical through this documentation-only audit;
those exact results retain their scope. Fresh runtime checks above supplement,
not replace or relabel, the full suite and child-specific historical evidence.

Changed files preserve feature ownership and existing modules. The explicit guide
manifest still reads committed regular Git objects; no security/research glob or
new implementation framework was added. SAML's maintainer waiver remains a waiver
of independent review, not a performed approval. The outbound release gate and
real provider/OS/production acceptance remain open. M08 delivery acceptance does
not establish a feature-complete or production-ready authentication release.
