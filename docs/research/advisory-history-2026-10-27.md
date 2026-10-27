# Published advisory history at the M00 source pins — 2026-10-27

This closes the missing **published repository advisory inventory**, with unresolved applicability stated explicitly. It does not clear any project for adoption or establish a comprehensive vulnerability history, independent review, protocol compliance or production readiness. The seven revisions remain the historical [source snapshots](source-snapshots.json); no source pin or authentication dependency changes.

## Collection and interpretation

Each public GitHub repository advisory API was requested with `state=published&per_page=100`. All seven returned HTTP 200, fewer than 100 records and no pagination Link header on 2026-10-27. The [machine-readable inventory](advisory-history-2026-10-27.json) records retrieval times, exact URLs, response SHA-256, all 52 published advisory identities/dates and all 74 package/range rows. No observed record was withdrawn. Raw descriptions, authors, PoCs and private tracker content are excluded. Response hashes identify collected bytes; mutable feeds can change after this date.

All seven commit identities and normalized committer timestamps were freshly checked against the primary GitHub commit API and match the recorded snapshots. Pinned manifests establish the version labels below. Better Auth maps each affected package to its own pinned manifest. Stable Better Auth/Rauthy comparisons use npm-semver 7.8.5 (ISC), joining comma-separated comparators with spaces; invalid ranges must remain unresolved. This is a comparison with maintainer-declared ranges, not a source or exploit assessment. Blank package/ecosystem fields remain blank in the inventory.

| Repository | Pinned manifest version | Published advisories / range rows | Assessment |
| --- | --- | --- | --- |
| [better-auth/better-auth](https://github.com/better-auth/better-auth/tree/d0ca6d538db47547b0a842cfa44ca92a8ea9bba0) | [1.7.10](https://raw.githubusercontent.com/better-auth/better-auth/d0ca6d538db47547b0a842cfa44ca92a8ea9bba0/packages/better-auth/package.json) | 37 / 57 | 56 outside declared ranges; one matches, configuration review required |
| [better-auth-rs/better-auth-rs](https://github.com/better-auth-rs/better-auth-rs/tree/9f91cd7fdb8a5f73a9c69d5c56d363468a7dc281) | [1.0.0-alpha.3](https://raw.githubusercontent.com/better-auth-rs/better-auth-rs/9f91cd7fdb8a5f73a9c69d5c56d363468a7dc281/Cargo.toml) | 0 / 0 | Empty public repository feed; no clearance |
| [salasebas/rustauth](https://github.com/salasebas/rustauth/tree/b55e9ce3c9f375a66d8ae7ef40afe0cbd041ec1e) | [0.3.2](https://raw.githubusercontent.com/salasebas/rustauth/b55e9ce3c9f375a66d8ae7ef40afe0cbd041ec1e/Cargo.toml) | 0 / 0 | Empty feed; pinned README declares unmaintained |
| [lucid-softworks/auth](https://github.com/lucid-softworks/auth/tree/d16c16bfa2050e5ac08cf7e18521576f41a214f0) | [0.1.0](https://raw.githubusercontent.com/lucid-softworks/auth/d16c16bfa2050e5ac08cf7e18521576f41a214f0/Cargo.toml) | 0 / 0 | Empty feed; historical compiled RSA finding remains |
| [sebadob/rauthy](https://github.com/sebadob/rauthy/tree/ea587538b35c886ea602ab918853d8500d3b92bd) | [0.37.1](https://raw.githubusercontent.com/sebadob/rauthy/ea587538b35c886ea602ab918853d8500d3b92bd/Cargo.toml) | 3 / 3 | Three outside declared project-version ranges; no exact-fix proof |
| [kanidm/kanidm](https://github.com/kanidm/kanidm/tree/f76b7ee9fdd28f123bb57d26351afef1515857d6) | [1.12.0-dev](https://raw.githubusercontent.com/kanidm/kanidm/f76b7ee9fdd28f123bb57d26351afef1515857d6/Cargo.toml) | 10 / 11 | Eleven unresolved development-pin rows; exact-fix review required |
| [ory/kratos](https://github.com/ory/kratos/tree/b86338da04a040247a07f46100a86dcfb3875909) | [source pin; no root semantic version](https://raw.githubusercontent.com/ory/kratos/b86338da04a040247a07f46100a86dcfb3875909/go.mod) | 2 / 3 | Three rows: source descends from both advertised fixed release tags |

## Findings and adoption consequences

**Better Auth:** version 1.7.10 matches the `>=1.6.14` row of [GHSA-fmh4-wcc4-5jm3](https://github.com/better-auth/better-auth/security/advisories/GHSA-fmh4-wcc4-5jm3); that row supplies no patched version. The advisory concerns organization invitations and verified-email/configuration assumptions. An adoption assessment must review the documented verified-email/invitation access controls; upgrading alone cannot establish protection for affected configurations. This does not establish exploitability of every installation. The other 56 rows are outside their declared ranges at the corresponding 1.7.10 package versions. Organization business authorization is deliberately outside easy-auth core.

**Rauthy:** the 0.37.1 workspace label is outside the three declared ranges. Two records omit a registry ecosystem/package identity, so this is a project-version comparison only. Verify exact source fixes and deployment configuration before adoption; a version label alone is insufficient.

**Kanidm:** the workspace declares 1.12.0-dev. Published fields include `HEAD of master`, `none`, blank patched versions and the ambiguous `<1.9.3, 1.10.1`. Do not treat those as an ordinary portable semantic-version range or infer component release versions from a workspace label. All 11 rows remain **exact-fix-review-required**. Source ancestry, the affected component and configuration need individual review before adoption. The inventory exposes this research limit rather than assigning an unsupported unaffected status.

**Kratos:** the Go module has no root semantic version and the source pin is not an exact release tag. Primary GitHub comparisons show that the pinned source descends from the advertised fixed releases [v1.3.0](https://github.com/ory/kratos/compare/v1.3.0...b86338da04a040247a07f46100a86dcfb3875909) (868 commits ahead) and [v26.2.0](https://github.com/ory/kratos/compare/v26.2.0...b86338da04a040247a07f46100a86dcfb3875909) (202 ahead), with zero commits behind and merge base equal to each fixed-tag commit. Exact base hashes are retained. This establishes ancestry, not absence of regressions.

**Empty feeds:** Better Auth RS, RustAuth and lucid-auth returned no published repository advisories. This cannot cover private reports, transitive dependencies, native components or future maintenance. [RustAuth’s pinned maintenance notice](https://github.com/salasebas/rustauth/blob/b55e9ce3c9f375a66d8ae7ef40afe0cbd041ec1e/README.md) explicitly disclaims planned releases, bug fixes and security updates. The [native comparison](adoption-comparison.md) separately records RSA 0.9.10 / RUSTSEC-2023-0071 compiled in the historical lucid probe; its empty project feed does not erase that finding. Do not execute old dependency graphs merely to refresh this inventory.

## Complete observed advisory index

Each row below is one published advisory; all package ranges, patched-version fields and per-range assessments are retained in the JSON. Counts aggregate advisory rows separately from package ranges.

| Repository | Advisory | Severity | Package-range assessments |
| --- | --- | --- | --- |
| better-auth/better-auth | [GHSA-44jh-23m7-hpcf](https://github.com/better-auth/better-auth/security/advisories/GHSA-44jh-23m7-hpcf) | low | 3 outside-declared-range |
| better-auth/better-auth | [GHSA-965c-763c-88jm](https://github.com/better-auth/better-auth/security/advisories/GHSA-965c-763c-88jm) | critical | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-mx9r-x6ww-qjw9](https://github.com/better-auth/better-auth/security/advisories/GHSA-mx9r-x6ww-qjw9) | high | 2 outside-declared-range |
| better-auth/better-auth | [GHSA-r4xp-prcw-77qf](https://github.com/better-auth/better-auth/security/advisories/GHSA-r4xp-prcw-77qf) | high | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-8c5h-wx78-2cfg](https://github.com/better-auth/better-auth/security/advisories/GHSA-8c5h-wx78-2cfg) | high | 3 outside-declared-range |
| better-auth/better-auth | [GHSA-qq9h-g4jm-xgf3](https://github.com/better-auth/better-auth/security/advisories/GHSA-qq9h-g4jm-xgf3) | high | 2 outside-declared-range |
| better-auth/better-auth | [GHSA-q84f-53jg-9ppm](https://github.com/better-auth/better-auth/security/advisories/GHSA-q84f-53jg-9ppm) | high | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-prpr-5gj3-qqhg](https://github.com/better-auth/better-auth/security/advisories/GHSA-prpr-5gj3-qqhg) | high | 2 outside-declared-range |
| better-auth/better-auth | [GHSA-h3rm-78g3-j7cp](https://github.com/better-auth/better-auth/security/advisories/GHSA-h3rm-78g3-j7cp) | high | 2 outside-declared-range |
| better-auth/better-auth | [GHSA-rjg6-39jm-rgg4](https://github.com/better-auth/better-auth/security/advisories/GHSA-rjg6-39jm-rgg4) | critical | 2 outside-declared-range |
| better-auth/better-auth | [GHSA-j8v8-g9cx-5qf4](https://github.com/better-auth/better-auth/security/advisories/GHSA-j8v8-g9cx-5qf4) | high | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-p2fr-6hmx-4528](https://github.com/better-auth/better-auth/security/advisories/GHSA-p2fr-6hmx-4528) | medium | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-86j7-9j95-vpqj](https://github.com/better-auth/better-auth/security/advisories/GHSA-86j7-9j95-vpqj) | medium | 2 outside-declared-range |
| better-auth/better-auth | [GHSA-gv74-j8m3-fg5f](https://github.com/better-auth/better-auth/security/advisories/GHSA-gv74-j8m3-fg5f) | high | 2 outside-declared-range |
| better-auth/better-auth | [GHSA-392p-2q2v-4372](https://github.com/better-auth/better-auth/security/advisories/GHSA-392p-2q2v-4372) | high | 2 outside-declared-range |
| better-auth/better-auth | [GHSA-7w99-5wm4-3g79](https://github.com/better-auth/better-auth/security/advisories/GHSA-7w99-5wm4-3g79) | high | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-5rr4-8452-hf4v](https://github.com/better-auth/better-auth/security/advisories/GHSA-5rr4-8452-hf4v) | critical | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-g38m-r43w-p2q7](https://github.com/better-auth/better-auth/security/advisories/GHSA-g38m-r43w-p2q7) | high | 2 outside-declared-range |
| better-auth/better-auth | [GHSA-2vg6-77g8-24mp](https://github.com/better-auth/better-auth/security/advisories/GHSA-2vg6-77g8-24mp) | low | 2 outside-declared-range |
| better-auth/better-auth | [GHSA-xr8f-h2gw-9xh6](https://github.com/better-auth/better-auth/security/advisories/GHSA-xr8f-h2gw-9xh6) | medium | 2 outside-declared-range |
| better-auth/better-auth | [GHSA-cq3f-vc6p-68fh](https://github.com/better-auth/better-auth/security/advisories/GHSA-cq3f-vc6p-68fh) | high | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-wxw3-q3m9-c3jr](https://github.com/better-auth/better-auth/security/advisories/GHSA-wxw3-q3m9-c3jr) | medium | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-9h47-pqcx-hjr4](https://github.com/better-auth/better-auth/security/advisories/GHSA-9h47-pqcx-hjr4) | high | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-pw9m-5jxm-xr6h](https://github.com/better-auth/better-auth/security/advisories/GHSA-pw9m-5jxm-xr6h) | medium | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-p6v2-xcpg-h6xw](https://github.com/better-auth/better-auth/security/advisories/GHSA-p6v2-xcpg-h6xw) | high | 2 outside-declared-range |
| better-auth/better-auth | [GHSA-xg6x-h9c9-2m83](https://github.com/better-auth/better-auth/security/advisories/GHSA-xg6x-h9c9-2m83) | high | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-x732-6j76-qmhm](https://github.com/better-auth/better-auth/security/advisories/GHSA-x732-6j76-qmhm) | high | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-4vcf-q4xf-f48m](https://github.com/better-auth/better-auth/security/advisories/GHSA-4vcf-q4xf-f48m) | high | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-569q-mpph-wgww](https://github.com/better-auth/better-auth/security/advisories/GHSA-569q-mpph-wgww) | medium | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-wmjr-v86c-m9jj](https://github.com/better-auth/better-auth/security/advisories/GHSA-wmjr-v86c-m9jj) | low | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-99h5-pjcv-gr6v](https://github.com/better-auth/better-auth/security/advisories/GHSA-99h5-pjcv-gr6v) | high | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-fmh4-wcc4-5jm3](https://github.com/better-auth/better-auth/security/advisories/GHSA-fmh4-wcc4-5jm3) | high | 1 outside-declared-range; 1 matches-declared-range |
| better-auth/better-auth | [GHSA-36rg-gfq2-3h56](https://github.com/better-auth/better-auth/security/advisories/GHSA-36rg-gfq2-3h56) | medium | 2 outside-declared-range |
| better-auth/better-auth | [GHSA-vp58-j275-797x](https://github.com/better-auth/better-auth/security/advisories/GHSA-vp58-j275-797x) | high | 2 outside-declared-range |
| better-auth/better-auth | [GHSA-hjpm-7mrm-26w8](https://github.com/better-auth/better-auth/security/advisories/GHSA-hjpm-7mrm-26w8) | high | 2 outside-declared-range |
| better-auth/better-auth | [GHSA-9x4v-xfq5-m8x5](https://github.com/better-auth/better-auth/security/advisories/GHSA-9x4v-xfq5-m8x5) | medium | 1 outside-declared-range |
| better-auth/better-auth | [GHSA-8jhw-6pjj-8723](https://github.com/better-auth/better-auth/security/advisories/GHSA-8jhw-6pjj-8723) | medium | 1 outside-declared-range |
| sebadob/rauthy | [GHSA-wx92-7mmw-5x82](https://github.com/sebadob/rauthy/security/advisories/GHSA-wx92-7mmw-5x82) | high | 1 outside-declared-range |
| sebadob/rauthy | [GHSA-7qh2-3hc5-2vqp](https://github.com/sebadob/rauthy/security/advisories/GHSA-7qh2-3hc5-2vqp) | medium | 1 outside-declared-range |
| sebadob/rauthy | [GHSA-x8jp-v2j6-6vjf](https://github.com/sebadob/rauthy/security/advisories/GHSA-x8jp-v2j6-6vjf) | medium | 1 outside-declared-range |
| kanidm/kanidm | [GHSA-2pm5-6m23-h692](https://github.com/kanidm/kanidm/security/advisories/GHSA-2pm5-6m23-h692) | high | 1 exact-fix-review-required |
| kanidm/kanidm | [GHSA-qcrp-p3rq-pffr](https://github.com/kanidm/kanidm/security/advisories/GHSA-qcrp-p3rq-pffr) | high | 1 exact-fix-review-required |
| kanidm/kanidm | [GHSA-hh34-7jqq-3f73](https://github.com/kanidm/kanidm/security/advisories/GHSA-hh34-7jqq-3f73) | low | 1 exact-fix-review-required |
| kanidm/kanidm | [GHSA-j4gj-f54h-56j5](https://github.com/kanidm/kanidm/security/advisories/GHSA-j4gj-f54h-56j5) | low | 1 exact-fix-review-required |
| kanidm/kanidm | [GHSA-x8cg-3c8h-gw55](https://github.com/kanidm/kanidm/security/advisories/GHSA-x8cg-3c8h-gw55) | low | 1 exact-fix-review-required |
| kanidm/kanidm | [GHSA-xxwr-vvr3-2g9f](https://github.com/kanidm/kanidm/security/advisories/GHSA-xxwr-vvr3-2g9f) | critical | 1 exact-fix-review-required |
| kanidm/kanidm | [GHSA-gpxg-fx2g-qxj2](https://github.com/kanidm/kanidm/security/advisories/GHSA-gpxg-fx2g-qxj2) | medium | 1 exact-fix-review-required |
| kanidm/kanidm | [GHSA-53hj-r94p-8c8f](https://github.com/kanidm/kanidm/security/advisories/GHSA-53hj-r94p-8c8f) | low | 1 exact-fix-review-required |
| kanidm/kanidm | [GHSA-r5fr-9gmv-jggh](https://github.com/kanidm/kanidm/security/advisories/GHSA-r5fr-9gmv-jggh) | high | 2 exact-fix-review-required |
| kanidm/kanidm | [GHSA-84jc-3hj2-hwc7](https://github.com/kanidm/kanidm/security/advisories/GHSA-84jc-3hj2-hwc7) | medium | 1 exact-fix-review-required |
| ory/kratos | [GHSA-hgx2-28f8-6g2r](https://github.com/ory/kratos/security/advisories/GHSA-hgx2-28f8-6g2r) | high | 1 includes-fixed-tag-ancestry |
| ory/kratos | [GHSA-wc43-73w7-x2f5](https://github.com/ory/kratos/security/advisories/GHSA-wc43-73w7-x2f5) | medium | 2 includes-fixed-tag-ancestry |

## Decision boundary

The M00 comparison now has an explicit dated inventory for every project, including positive findings and unresolved applicability. It is not a complete transitive/native vulnerability audit. No scanner policy, advisory exemption, adoption recommendation or independent-alpha build decision changes. Before adopting any candidate, repeat the assessment for the selected source, resolved feature graph, maintained support and actual configuration; resolve the outstanding source applicability. Easy-auth’s compiled-graph gates, SAML maintainer-waiver limits and outbound OIDC release gate remain unchanged.
