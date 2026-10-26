# Migration recovery and software upgrade verification — 2026-10-26

AUTH-49 implementation `34c204f9127a2e3d9ced4a31a550cec43b71c7e2` qualifies a
selected schema37→38 recovery and actual prior/current software transition on
unchanged schema38. It follows the [schema/role](database-role-verification-2026-10-26.md)
and [encrypted archive](encrypted-backup-verification-2026-10-26.md) increments.
Retention and stale-session/key/token incident reconciliation remain incomplete;
AUTH-49 is In Progress. No production, independent approval or compliance follows.

## Selected revisions and artifacts

| Role | Source revision | Actual local binary SHA256 |
| --- | --- | --- |
| Schema37 ancestor | `0783ff48b6409d362fbcae527f46a483ca66fb55` | `32cfba80f916366854ae2a67d6f96b634db7e9d19709f988f58c41d275fb1c83` |
| Prior schema38 software | `e6a061f9e6804eda323ce1af78b0369c73cdd021` | `ee1edee9ae6b54ac1500b09c3a74677e766dd264795cb858111e2b773129854c` |
| Current restricted-runtime software | 34c204f; unchanged Rust implementation from a6507c2 | `974b9046d9a7c246df0487de41c5336e924cdb904d819d5cd3d9a6409e1dc2a4` |

The pinned Git trees are respectively
`ca9e75a6510e485094a110c74cfa05af74d552a1` and
`5e615d2567c94ea930a962bd0a270266f07ed13c`.
Each export is an ancestor of the current source. Workspace Cargo.toml/Cargo.lock,
rust-toolchain.toml/.cargo/config.toml and all37/38 published migrations match the
current inputs exactly. Per-crate manifests/software intentionally belong to their
selected revisions; they are not claimed identical. Frozen builds use Rust1.95.0,
separate targets and private temporary paths. All exported source files remain
unchanged; receipt aggregates are:

- Schema37: `e359d4e8947c66bf0a16d60149393db5197365dd1d1c4ae968ceb5d17bda17ee`.
- Prior schema38: `bee755640b26d152b0796443ff3d5e3549fa359deff57f54e03fcbb74595d704`.

These are observed artifact hashes, not a bit-identical cross-directory/host build
claim. Current source is clean34c204f,2339 files, aggregate
`612553b074c8dff97000842997b3be091800c831cc022484eeebbcb13f081466`.

Default server normal/build dependency packages and unified feature lists were
compared for all three sources on aarch64-apple-darwin, excluding the intentionally
different workspace source packages. All193 entries match, aggregate
`da5cadcfd9eceb713e93cf614aad59f89fa6fbc4429a74a4bdde2def90287327`.
No new package version, migration, crypto or application/runtime dependency was added.

## Exact committed local verification

Three unchanged CI run blocks were extracted and executed on clean34c204f with
matching GITHUB_SHA: existing schema/role regression; preparation of both immutable
fixtures; actual failed-migration/recovery/software-replacement drill. All passed.
The unchanged assessed age tool from the prior exact cc10b5c replay was reused;
an exact input/implementation diff and actual binary hashes establish that reuse.
No fresh Go assessment or hosted CI result is implied. This local run is macOS arm64.

| Check | Observed result |
| --- | --- |
| Source/artifact admission unit tests | Four passed: altered migration/artifact refusal, existing-directory preservation and unrelated build-override rejection |
| Availability probe controls | Two passed with real owned loopback HTTP: actual progress/thread shutdown and changed-owner refusal |
| Existing role regression | Four HTTP/receipt tests and complete real-PG/SMTP/role/realm/logout drill passed after the exact migration diagnostic extension |
| Fresh source37/source38 preparation | Both frozen builds passed ancestry/tree/input/compiler/full-file-stability checks |
| Real failed migration | Required exact `database migration failed` diagnostic; earlier ALTER/CREATE effects rolled back, legacy rows/history unchanged,37 successes and no remaining migration lock |
| Recovery paths | Selected encrypted backup restored to a new quarantined DB then migrated; inspected owned source conflict removed and original migration rerun successfully |
| Version/schema refusal | Current verification refuses37 without changing data; schema37 executable refuses future38 without changing data |
| Actual software upgrade | Prior e6a061f and current executables both served original sessions during overlap; one-at-a-time replacement succeeded on unchanged38 |
| Concurrent request control | 27 actual availability-probe responses; zero failures or ownership changes while peers started/stopped |
| Scope/revocation | Foreign-realm use refused; logout propagated to a surviving replica; other realm's session remained valid |
| Cleanup | Exactly two owned messages, every owned child/container/exclusive volume and entire private key/archive directory removed |
| Website | Format/seven unit/type/build/genuine Chromium passed:31 routes/520 anchors, retaining mobile/search/theme/keyboard checks |
| Source checks | Formatting, local Markdown targets, source secret scan and YAML/shell passed; every preceding CI step and other job preserved |

Existing fixture image IDs remained PostgreSQL17
`sha256:25a89970a83255ae96484d709005bb35aa71f7455f941bc1634514f31c5d5c62`
and Mailpit
`sha256:32a9262f9b8b7cc97130cddf9d17fb3f467cafa622e4427fb2159fe7282b3cad`.
There was no unexpected validation failure in the final replay. Negative conditions
are required controls; no existing assertion/security policy was weakened.

## What the drill actually does

Three owned legacy schema37 replicas bootstrap one new database using their old
administration-capable startup. Two real SMTP/HTTP accounts in distinct realms sign
in; another same-realm replica accepts the original session. This does not qualify
old startup as a restricted-runtime profile. All old writers are stopped and actual
database connections observed gone before DDL. Current verify startup rejects37
without creating history/applying DDL or changing private rows.

The encrypted pre-failure snapshot contains complete stable legacy data. A deliberately
owned probe index occupies migration38's later index name. The real current migration
command fails after its earlier unique-constraint/table creation statements. Catalog
inspection proves those earlier effects absent, the preexisting conflict retained,
and no new history row or advisory lock. Complete private public-table values equal
the before snapshot. No history/checksum is edited.

Recovery first decrypts/restores into a newly created never-served database, denies
runtime CONNECT and applies the original migration there. Legacy rows/history prefix
are preserved and the new grant table is empty. Separately inspect/remove only the
known owned conflict on the source and rerun the same migration. Both reach38. The
schema37 executable then fails against38 without changing upgraded data. The clone
has no runtime/notification/provider worker connected and is never promoted.

The validated pre-operations schema38 software is then started on that unchanged
schema and replaced instance by instance by the current explicit-verification,
restricted-runtime software. Continuous independent clients reuse actual issued
session cookies and check original owner/realm while peers start/stop. An additional
current-replica replacement runs, followed by realm isolation and shared logout.
Probe clients own their cookie jars/threads and refuse redirects; neither raw
headers/tokens nor private database rows appear in receipts.

The populated fixture contains two mailbox accounts/sessions and owned probe rows.
Other credential/provider/issuer tables are included in full comparisons but are
not populated interoperability cases here; their separate backend/protocol evidence
is not replaced by this operational drill.

## Boundaries and remaining work

The schema-changing step has a deliberate writer-drain window and fresh connections
after DDL, preserving [ADR0038](../architecture/adr/0038-native-token-lifecycle.md).
The selected prior/current software overlap is qualified only on unchanged schema38.
This is not arbitrary mixed-version DDL, downgrade, zero-downtime, load-balancer/
controller, all in-flight draining, RTO/RPO or production TLS qualification.

No Rust app/crate/build input changed relative to the recorded schema/role baseline.
Its required backend gate results retain their original scope; they were not rerun
for this qualification-only increment. New frozen default builds, actual operational
tests and the checks above were run. Complete required gates remain before final
ticket completion and after subsequent backend changes. The prior inactive RSA,
unimported Go OpenPGP and native/SAML assessment risks remain recorded.

The new feature modules separate source construction/admission, catalog/atomicity,
journey composition and concurrent availability observation. New handwritten files
are below300 lines and functions at most50. The existing small subprocess owner gains
closed exact connection/migration failure profiles; its previous role journey is
retested. No generic migration engine, plugin framework, new crate, HTTP admin route
or structural refactor was introduced. Original73 protected bytes/change set/index
and retained preview/accounts/passkeys remain preserved.

[ADR0049](../architecture/adr/0049-owned-migration-upgrade-qualification.md) and the
[operator guide](../guides/upgrades.md) record the selected procedure. Retention and
stale-session/key/token incident reconciliation remain AUTH-49 work. AUTH-48/AUTH-47
release prerequisites, real provider/OS/production acceptance, SAML waiver limits and
the outbound OIDC release gate remain open. No PR, merge, public deployment,
independent approval or protocol compliance is established.
