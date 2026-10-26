# Database schema and role verification — 2026-10-26

This records AUTH-49's schema/role increment, not completion of operational recovery
or production qualification. Structural extraction
`909e892e91640e1ace661cc2364c2caa9e39119d` precedes behavior commit
`a6507c27e6bc1b5b7f2464568d61a0e40c9715d1` on
`feat/auth-49-operational-recovery`. No PR, merge or deployment was performed.

## Implemented boundary

`easy-auth migrate` applies the unchanged embedded SQLx migrations using only the
privately configured administration connection, then exits without a listener or
notification worker. Shared configured runtime accepts exact `run|verify`, default
`run`. Explicit verification performs no DDL/history repair and rejects missing,
dirty, unknown or checksum-mismatched history. Separately provisioned runtime
credentials retain ordinary auth DML, with no schema/history-write authority.

Dedicated schema connections close on success/error/cancellation. Verification
has a five-second overall budget and two-second server statement/lock limits;
administration bounds lock waits at two seconds without that short DDL execution
limit. SQLx retains migration transactions, checksums and serialization. This is
history verification, not arbitrary schema drift detection or a privilege audit.
The [role procedure](../guides/database-roles.md) describes grants and limits.

## Local validation

Rust/Cargo1.95.0; real owned PostgreSQL17. No retained preview database, mailbox,
account or passkey was used. The original protected checkout's73 file hashes,
modified/untracked set and empty index were reverified unchanged.

| Command/check | Observed result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | Passed |
| Same strict Clippy with `--all-features` | Passed |
| `cargo test --locked --workspace` | 139 passed; zero failed/ignored |
| Same workspace tests with `--all-features` | 1161 primary passes plus one isolated logging-child pass; zero failed/ignored; includes659 real PostgreSQL cases |
| `cargo test --locked -p easy-auth-server --all-features` | Separate sequential recheck:96 passed; zero failed/ignored |
| `python3 scripts/audit.py` | Compiled graph passed; inactive resolver-only rsa0.9.10/RUSTSEC-2023-0071 still reported |
| `cargo deny --all-features check` | Advisory/bans/licenses/sources passed with existing warnings; no policy exemption added |
| New operational HTTP/receipt tests | Four passed using a real owned loopback HTTP server |
| Exact committed role CI run block | Passed on clean a6507c2 source; complete owned-service cleanup verified |
| Website format/unit/check/build/browser | All passed:7 unit tests, zero check errors/warnings,30 routes/499 anchors in genuine Chromium; mobile/search/theme/keyboard checks retained |
| Workflow verification | Valid YAML/shell; all preceding CI steps and other jobs preserved |
| Documentation/source checks | 180 changed-document local targets verified; changed-source and two-commit secret scans passed |

The extra sequential server run removes binary-artifact ambiguity after a default
server build overlapped the all-feature workspace run. PostgreSQL/core/HTTP test
executables were unchanged. A fresh default binary was used for the exact role CI
block; binary SHA256:
`974b9046d9a7c246df0487de41c5336e924cdb904d819d5cd3d9a6409e1dc2a4`.
Its receipt records clean source revision a6507c2 and2302 source-file hashes aggregated
as `da8eecd55dc779cb687473473f623fb1e0ebcd7d2486554ef6fdb11b60fc6915`.
These are local replays, not hosted CI results or cross-platform qualification.

Eight new real-PG cases cover untouched empty/history refusal, checksum/dirty/
future/missing rows, observed advisory-lock waiting, bounded/cancelled verification,
failed administration and cancelled administration. Tests preserve history before/
after refused verification and exercise working controls after the refusal. The
separate extraction previously passed the existing migration and17 HTTP/PG cases.

The role drill provisions two actual TCP-password LOGIN principals in a new
database. It checks restricted runtime role attributes and SQLSTATE42501 for
permanent DDL, temporary objects, history writes and migration-role switching.
Wrong administration/runtime passwords fail. Administration is idempotent;
automatic-migration runtime startup fails while explicit verification succeeds.
Two distinct realms perform real email initiation, actual SMTP delivery and HTTP
completion. Cross-realm session use fails without damaging the original session;
logout revokes it. Exactly two owned messages are deleted, the mailbox is checked
empty, and both runtime processes, containers and exclusive anonymous volume are
removed. This uses ordinary HTTP clients, not browser or live-provider acceptance.

Fixture images were recorded by actual image ID:

- PostgreSQL: `sha256:25a89970a83255ae96484d709005bb35aa71f7455f941bc1634514f31c5d5c62`.
- Mailpit: `sha256:32a9262f9b8b7cc97130cddf9d17fb3f467cafa622e4427fb2159fe7282b3cad`.

## Failures retained and corrected

- Initial test compilation used the wrong integration-crate alias; corrected to
  the existing `easy_auth_postgres` name, with no added dependency.
- The spawned migration future exposed SQLx's documented Acquire lifetime issue.
  Use its existing `run_direct` after explicit pool acquisition; preserve engine
  checks/transactions rather than replacing migration behavior.
- An unchanged cancellation assertion failed:7 schema cases passed and one failed
  because the backend remained an advisory-lock waiter after client close. The
  two-second server administration lock limit corrected this; all eight passed.
- A formatter difference was applied. All-feature Clippy then caught unused
  administration composition in the owned OIDC example's configuration inclusion.
  A separate command module reuses the same crate-only pool factory; no warning
  suppression or assertion relaxation was added.
- The first role fixture failed with an unlocalized PostgreSQL-operation error;
  its resources were removed. Later diagnostics identify stage/SQLSTATE without
  SQL or credentials, and readiness now requires the actual TCP server. The cause
  of that first failure was not proven.
- The next role run failed with JSONDecodeError after auth operations. Mailpit's
  DELETE success is plain text. Explicit non-JSON deletion handling retains the
  status and empty-mailbox checks; JSON GETs remain strict. Subsequent runs passed.
- Restricted-environment attempts could not access Docker/bind a loopback test
  listener. The complete checks were rerun with owned-fixture access; these were
  environment failures, not skipped acceptance checks.

No credential-bearing SQL/output, DSN, raw email token or mail body is retained in
public evidence. Child logs/receipt files are private; receipt creation refuses
overwriting an existing file. Cleanup is attempted for services even when process
cleanup fails. The source/binary must remain stable throughout the role drill.

## Maintainability and remaining work

New handwritten modules remain below300 lines and Python functions below50.
PostgreSQL schema handling, server configuration/administration, test history/locks
and Python service/role/process/mail/evidence responsibilities remain distinct.
Entry files contain declarations/reexports/dispatch. No migration or Cargo.lock
version changed, SQL moved into HTTP/core, new crypto or generic framework was added.
[ADR0047](../architecture/adr/0047-schema-administration-and-runtime-verification.md)
records this increment and its separate structural commit.

AUTH-49 stays In Progress. Encrypted backup/restoration, retention, failed-migration
recovery/upgrade procedure and stale-key/token incident drills are still required;
checksum refusal is not a complete failed-DDL recovery exercise. AUTH-48/AUTH-47
release prerequisites, real provider/OS/production verification, SAML waiver limits
and the outbound OIDC release gate remain open. No independent security approval,
protocol compliance, production readiness or arbitrary rolling-upgrade guarantee
is claimed.
