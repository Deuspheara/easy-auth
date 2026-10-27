# Encrypted backup and quarantine verification — 2026-10-26

This records AUTH-49's offline encrypted-archive increment at
`cc10b5c5a08e7c82f2e633cd7e92c1552d9b2663`, following the separate
[schema/role increment](database-role-verification-2026-10-26.md).
AUTH-49 remains In Progress for retention, actual failed-DDL recovery/upgrades
and incident stale-session/key/token qualification. This is local implementation
evidence, not production recovery, independent security/legal approval or compliance.

## Commands and dependency boundary

`scripts/prepare_backup_tool.py` prepares a new private external directory from
checksum-pinned Go1.27.3, original age1.3.2 source and govulncheck1.9.0. The build-only
Go module selects x/crypto0.56.0 for the two recorded SSH fixes without changing
upstream age source. Binary metadata preserves its actual version/module sum;
the command version suffix identifies the dependency selection. Read-only builds
and unchanged lock inputs are enforced. No Go source/runtime dependency is added
to authentication packages; no new cipher, envelope or signature is implemented.

The scanner's source/binary inventories must cover the exact expected modules and
toolchain. Affected imported packages fail even when symbols are uncalled.
GO-2026-5932 remains reported for unimported OpenPGP code; package-graph evidence
classifies it as an inactive module finding, without an ignore. Selected source,
all three binaries,12 module notice sets and Go LICENSE/PATENTS are assessed.
See [ADR0048](../architecture/adr/0048-encrypted-backup-quarantine.md) for primary
contracts, source/advisory links and exact scope.

`scripts/backup_archive.py` provides explicit native-key generation, stdin
encryption and full decryption to a new private quarantine file. It never starts
PostgreSQL. Inputs/output files have owner/permission/regular-file checks;
existing files are preserved. Each age operation has a90second limit and archive
input/output has a1GiB bound. Protected native identities and an isolated PATH
select no plugin/agent/passphrase fallback. The reviewed tool validates key
checksums and performs crypto. CLI errors omit foreign argument values; normal
output contains only public recipient/digest/status metadata.

Decryption requires a separately protected selected ciphertext digest and full
age success before returning the plaintext file. Failed/partial plaintext is
removed. A digest is not a signature, and public recipients let others create
valid encrypted files: neither mechanism authenticates the sender or selects the
latest trusted backup. Archive SQL still requires trusted provenance. File unlink
does not promise physical erasure, and protected local files do not establish
production key custody or disk encryption.

## Exact committed local CI replay

Both new CI run blocks were extracted unchanged and executed on clean cc10b5c
with matching GITHUB_SHA. This used macOS arm64; the pinned Linux amd64 path is
configured for hosted CI but is not established by this local result. No hosted
success is inferred and no new CI result was awaited.

| Check | Observed result |
| --- | --- |
| Preparation/admission suite | 10 passed: unsafe archive/link/duplicate/traversal rejection, checksum-before-extraction, environment hook isolation, exact scanner coverage and affected-package rejection |
| Fresh pinned preparation | Passed compiler/source/binary/lock/notice assessment; every finding retained |
| Real-age archive suite | Nine passed: multichunk round trip, wrong/missing keys, digest mismatch, tamper/truncation after valid chunks, rotation, existing-file preservation, restricted profiles/permissions, changed binary, output/deadline cleanup and non-PG content |
| Genuine CLI subprocess suite | Three passed: configuration-free help, non-reflecting invalid arguments and metadata-only key/encrypt/decrypt output |
| Real PostgreSQL/SMTP restore drill | Two realms/accounts,38 migrations, two snapshots/reading keys and two transactional never-served restore databases; all public table contents equal their selected snapshots |
| Invalid decryption | Ten cases; zero PostgreSQL input operations; no retained partial plaintext |
| Quarantine/source controls | Restored runtime CONNECT refused; no live clone connections; live source remained logged out |
| Cleanup | Exactly two owned messages; all owned children/containers/exclusive volume and entire private key/archive/plaintext directory removed |
| Workflow | Valid YAML/shell; all preceding CI steps and other jobs preserved |
| Website | Format, seven unit tests, zero type/build diagnostics and genuine Chromium passed:30 routes/505 anchors with mobile/search/theme/keyboard checks |
| Source/security/organization | Changed-source secret scan, local documentation targets and formatting passed; new handwritten Python files below300 lines/functions at most50 lines |

The source receipt records2326 files, clean cc10b5c and aggregate SHA256
`4f0ad6810495ecd118f6f5a2376210f69eaf5ce25679fcd8edf34ba2c443e8e0`.
The default server binary SHA256 remained
`974b9046d9a7c246df0487de41c5336e924cdb904d819d5cd3d9a6409e1dc2a4`.
Actual fixture image IDs remained:

- PostgreSQL17: `sha256:25a89970a83255ae96484d709005bb35aa71f7455f941bc1634514f31c5d5c62`.
- Mailpit: `sha256:32a9262f9b8b7cc97130cddf9d17fb3f467cafa622e4427fb2159fe7282b3cad`.

The verified Darwin arm64 Go archive SHA256 was
`dd3908cf20959d798c1e06ebe5b72213f0505ce01373b40ce3110975a6cd99c2`.
Final prepared binaries:

| Binary | SHA256 |
| --- | --- |
| age | `075c2200b8c3d1bba382ffaaa3e768735682509da87107d6308ede695ff18448` |
| age-keygen | `b9b2e57a9d567c008db05f9797da429952c0d34535ff5bdb9841708966871432` |
| govulncheck | `7b48a24bb2bd96a5c2303b6fa13d244b6b30d6546d5585ea3f267e654f191407` |

All four scanner assessments reported database modification
2026-10-21T00:27:29Z. Age/keygen/source retained the inactive OpenPGP finding;
the scanner binary had none. No affected imported package or called-symbol
finding was accepted.

The drill used ordinary real HTTP clients/SMTP, not a genuine auth browser or live
provider. Incompressible owned probe rows made actual archives cross authenticated
chunk boundaries. Initial runtimes were stopped for stable complete table snapshots.
A later real logout separates the old and current snapshots. Decryption/listing
completes before new-database creation and transactional restoration; wrong keys,
wrong trusted digests, tampering and truncation cannot even invoke archive listing.
Existing ciphertext preservation is also checked before another dump starts.

Every public table is compared privately in memory using one SQL snapshot, including
the exact migration history, session revocation, identities and probe payloads.
This is not evidence about cluster roles/tablespaces, external configuration/keys,
all sequences under future writes, cross-major upgrades or an RTO/RPO. The older
restored snapshot deliberately retains its pre-logout session row. It was never
served; no incident reconciliation or safe promotion is implied. Both target DBs
deny runtime CONNECT and have no app/notification/revocation worker selected.

## Failures and review corrections

- Initial upstream age metadata retained x/crypto0.55.0 and exposed two uncalled
  SSH package advisories plus the unimported OpenPGP module advisory. Minimal
  fixed-dependency selection removes the former; the latter stays visible.
- A verified Go archive has a root `go` directory. Initial admission rejected it;
  exact root-directory admission was added while traversal, links, duplicates,
  nonregular entries and size bounds stay rejected.
- An initial prototype source scan selected system Go1.25.4 and failed the
  dependency's minimum version. All Go/scanner subprocesses now use the pinned
  toolchain/PATH, private caches/temp paths, disabled owner cache hooks, explicit
  module/checksum services and no insecure/VCS fallback.
- The first build-only driver lacked command-specific go.sum inputs. Explicit
  command resolution produced the committed lock; final builds retain read-only
  mode rather than fetching around an incomplete lock.
- The first complete preparation replay failed its inventory check: the pinned
  scanner spells source stdlib versions `v1.27.3` and binary versions `go1.27.3`.
  Exact mode-specific spellings are now required, with positive/negative coverage;
  module coverage and vulnerability assertions remain intact.
- Cleanup ownership was reviewed so an existing archive/quarantine file is not
  deleted after creation is refused. Unit and real-dump preservation controls
  exercise the resulting behavior. No existing assertion or security policy was
  relaxed to obtain a pass.

## Existing backend gates and remaining work

An exact diff against the schema/role implementation proves unchanged Rust apps,
crates, migrations, Cargo manifests/lock, Cargo configuration and toolchain inputs.
The prior required fmt/default+all strict Clippy/workspace/real-PG/security results
therefore retain their recorded scope:139 default tests,1161 primary all-feature
passes plus one logging child,659 PG cases and a separate96-test server recheck.
Those suites were not rerun for this Python/tooling-only increment; fresh formatting,
the new actual Go/CLI/PG/security checks and the website checks above were run.
The required complete gates remain before final ticket completion and after later
backend changes. Existing inactive RSA and native/SAML release risks are unchanged.

The feature tree separates Go toolchain/assessment/provenance, archive input and
crypto-command lifetime, PostgreSQL dump/restore, and owned account/snapshot fixtures.
There is no generic plugin/framework or speculative application crate. No structural
refactor is mixed into behavior; the existing small evidence module gains only the
shared exact-CI-source check. Original73 protected file hashes/change set/empty
index were reverified unchanged; retained preview accounts/passkeys were untouched.

Retention, failed-DDL recovery/upgrade and stale-session/key/token incident policy
remain AUTH-49 work. AUTH-48/AUTH-47 release prerequisites, real provider/OS/production
verification, the SAML waiver limits and outbound OIDC release gate remain open.
No PR, merge, public deployment, independent approval or protocol compliance is
established by this increment.
