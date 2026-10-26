# Bounded realm retention verification — 2026-10-27

AUTH-49 runtime revision `99f4dd84f8471b73a8c9b9dc6938e26a7e9bce6e` implements
explicit finite realm maintenance. The following are local macOS arm64 results,
not hosted CI, production qualification, independent approval or compliance.
AUTH-49 remains In Progress for incident revocation and restored-snapshot
reconciliation. No PR, merge or deployment is included.

## Implementation and exact backend gates

Index-only migration checkpoint `9209a2ae495b4fce4bfdfae33d7f65138e9e9119` precedes
behavioral implementation `db04fc3771656fbf5c03589fdcc4887aff5c3630`. Structural
configuration ownership correction `053de73ec2dcf6d2dc0b95e44cd649ec4ba8e72c` and
query-plan fixture qualification `99f4dd84f8471b73a8c9b9dc6938e26a7e9bce6e` follow.
Earlier migrations1–38 are unchanged. Migration39 adds37 supporting indexes,
without changing stored rows or foreign keys. No dependency or crypto was added.

On clean99f4dd8, these commands passed (completed 2026-10-26 UTC, recorded at
23:04:53 UTC; 2026-10-27 Europe/Paris):

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo test --locked --workspace --all-features
```

Both test suites used actual disposable PostgreSQL, not skipped DB cases. Default
reported167 passes; all-feature reported1191 including one isolated logging child
(1190 primary). Neither reported a failure or ignored test. The main all-feature
PostgreSQL lifecycle target alone passed674 cases; this is not the total database
coverage count. Additional targets include two actual query-plan tests, two real
migration tests and two actual CLI/database maintenance tests. Advisory and
all-feature license/source/bans checks passed; inactive `rsa0.9.10` advisory
`RUSTSEC-2023-0071` remains reported rather than ignored.

Tests cover the28 closed categories,64-row bounds, explicit audit/notice choices,
live/expired/foreign state, cancellation, concurrent skip-locked batches, partial
commit reporting and rollback/retry. Fresh post-lock dependency checks use explicit
Read Committed even with a repeatable-read pool default. A real elapsed native
grant/family graph preserves audit references and spent-refresh history through
original caps before leaf-first pruning. Existing genuine refresh-reuse, OIDC and
signed-SAML lifecycle rejection assertions remain and run after maintenance.
Serialized proof fixtures in storage-cap tests are not protocol-interoperability
claims. Existing23 Apple grant tests passed; expiry is not remote revocation.

Real migration tests preserve complete47-table values/history/constraints across
38→39 and prove transactional rollback of earlier39 DDL on an owned final-index
conflict, then successful retry after correcting only that fixture conflict.
Normal-planner tests require actual realm/expiry index conditions without planner
forcing, including retained-audit lookups and both deterministic UUID orderings.

## Fresh operational qualification on the exact runtime

The default server was rebuilt on clean99f4dd8. Observed SHA256:
`31b00a3ed3d9ffc1994924bd22fa33487ce98750d72521488e58e4f312c3bb6d`.
Source receipt:2370 tracked files, aggregate
`6b86b51737e521f113eab4545e1281268dadecc0d0e223220fba2c2ad9904484`.
All three commands below passed with matching GITHUB_SHA and source/binary stability
checks. Each owns fresh PostgreSQL/mail services and removes its owned resources.

```sh
python3 scripts/smoke_database_roles.py
python3 scripts/smoke_encrypted_backup.py
python3 scripts/smoke_upgrade_recovery.py
```

| Drill | Actual observed result |
| --- | --- |
| Restricted runtime maintenance | Separate TCP/password roles; DDL, migration-history writes, temporary objects and migration-role switching refused; actual SMTP/HTTP sessions in two realms |
| Exact retention effect | With both horizons `keep`, one expired email proof in the selected realm deleted; foreign expired proof retained; every other public-table value preserved; second pass all zero; both actual sessions still valid |
| Encrypted restore | Schema39, two realms/accounts and two snapshots under separate reading keys; two never-served quarantined restores exactly matched every public-table value; runtime CONNECT refused |
| Archive negative controls | Ten invalid archives rejected before PostgreSQL input; no retained plaintext; live-source logout remained rejected |
| Failed migration recovery | Real migration38 conflict during37→39 administration; earlier DDL rolled back, history/legacy values unchanged, no abandoned schema lock; restore-then-migrate and inspected-conflict roll-forward both succeeded |
| Selected software replacement | Actual pre-retention schema39 and current binaries both used restricted runtime roles and verification; original sessions survived overlap and another current-replica replacement |
| Concurrent availability | 27 actual session responses, zero failures or ownership changes during peer starts/stops; foreign realm refused, logout shared, other realm preserved |
| Cleanup | Each drill removed its two owned messages and owned processes/containers/exclusive volumes; backup/upgrade private archive/key directories removed |

The schema37 binary was the previously admitted immutable artifact from source
`0783ff48b6409d362fbcae527f46a483ca66fb55`, SHA256
`32cfba80f916366854ae2a67d6f96b634db7e9d19709f988f58c41d275fb1c83`.
Its source aggregate, immutable inputs and artifact hash were rechecked before reuse.
The prior schema39 binary was freshly frozen-built from9209a2a, tree
`a61024f985c198e2eac1d4abdfdc5068ccce1ef9`, SHA256
`723204c2be8d46d13f39a19ea49a57cb5f29891983a94be52f9e1e8f2ff4ac72`.
This qualifies only the selected unchanged-schema software pair. Schema-changing
administration still drains writers and requires fresh connections. Old37 refuses
future39; no arbitrary mixed-version DDL or zero-downtime claim follows.

The previously assessed age/keygen/scanner artifacts were admitted and reused,
not rebuilt or newly assessed for this increment. Their hashes and risk boundaries
are recorded in the [encrypted-backup evidence](encrypted-backup-verification-2026-10-26.md).
PostgreSQL image ID remained
`sha256:25a89970a83255ae96484d709005bb35aa71f7455f941bc1634514f31c5d5c62`;
Mailpit ID remained
`sha256:32a9262f9b8b7cc97130cddf9d17fb3f467cafa622e4427fb2159fe7282b3cad`.
The operational fixture populates mailbox sessions/probe rows; empty provider and
issuer tables in its complete comparisons are not populated interoperability cases.

## Failures investigated without weakening assertions

- A source-export build sharing the current target left old core/PostgreSQL
  artifacts; initial Clippy reported15 missing-API errors. Only owned package
  artifacts were cleaned and rebuilt. Fresh comparison builds use separate targets.
- The actual repeatable-read pool regression failed before explicit transaction
  isolation selection. Selecting Read Committed fixed the unchanged assertion.
- All-feature Clippy found three unused operator parsers through an existing
  example's broad configuration graph. A separate structural commit moved them
  into the retention component; no lint suppression was added.
- An initial planner fixture and a later balanced-realm fixture selected the old
  global expiry index. The assertion was preserved and strengthened to require
  actual index conditions. The fixture now represents a sparse target beside a
  larger foreign expired backlog and verifies both UUID orderings under normal
  planner settings. This does not promise every possible distribution's plan.
- Local operational/probe tests initially could not bind loopback in the sandbox.
  Rerunning with the required fixture permission passed four operational tests
  and two probe tests. Four source/admission unit tests also passed.

The final complete backend run passed after these fixes. No assertion, security
policy, required check or dependency advisory was waived.

## Maintainability and remaining scope

Core owns policy; PostgreSQL owns SQL and transactions; the one-shot server merely
composes configuration, schema verification and the shared use case. Existing
feature modules/tests were extended. Apple lifecycle ownership was extracted in
separate previously tested4855fa7 before behavior changes. Parsers live only with
the operator command. Visibility is narrow; no generic SQL/plugin framework or new
crate was introduced. Closed category matching, Apple's atomic three stages and
ordered integration scenarios justify their size where review triggers apply;
transaction boundaries were not scattered to satisfy mechanical line limits.

The [operator guide](../guides/retention.md), [table inventory](../design/retention-cleanup.md)
and [ADR0050](../architecture/adr/0050-bounded-realm-retention.md) describe bounded
commits, retained references, cancellation, notice-lease semantics and exclusions.
Maintenance does not revoke live authority, reconcile an old snapshot for promotion,
delete external backups/logs or establish a legal retention policy. Incident
session/key/token revocation and post-restore reconciliation remain required work.
AUTH-47/AUTH-48 prerequisites, deferred real provider/OS/production verification,
SAML waiver limits and the outbound OIDC release gate remain open.

The subsequent [incident qualification](incident-recovery-verification-2026-10-27.md)
records the new populated native/session/key snapshot regression and its own exact
workspace/security gates. It does not relabel the runtime or operational runs above.
