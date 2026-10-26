# Migration recovery and replica upgrades

Schema changes use the separate [administration command](database-roles.md).
Runtime verification checks complete embedded SQLx history, never migrates as a
fallback and does not audit arbitrary schema drift. This guide records the bounded
owned schema37→39 procedure and its limits; it is not production orchestration,
arbitrary-version interoperability, downgrade or zero-downtime qualification.

## Review the revision pair and isolate recovery

Identify the exact old/new source and binary revisions, migration prefix/checksums,
dependency/toolchain inputs, roles, configuration, external key references and
rollback/roll-forward options. Published migrations remain immutable. Do not edit
history/checksums, ignore a failed migration or run an old binary against a future
schema to force service back online. A database backup cannot recover configuration
or lost reading/signing/provider keys by itself.

Take a selected [encrypted backup](backups.md) with separately protected provenance
and reading keys before schema administration. Restoration executes trusted archive
SQL. Restore only into a new quarantined DB with runtime CONNECT denied and no
app/notification/provider-revocation worker using it. A successful restored schema
does not reconcile revoked/deleted credentials or pending side effects; incident
policy must run before any promotion. Keep production recovery decisions separate
from disposable test success.

## Schema-changing upgrade window

1. Stop admitting work to old replicas and drain/stop their writers and workers.
   Observe the actual database connections and in-flight work gone before DDL.
   Retained prepared statements and old query shapes are not qualified across
   in-place DDL; [ADR0038](../architecture/adr/0038-native-token-lifecycle.md) requires
   fresh connections after schema change.
2. Run `easy-auth migrate` with privately delivered migration-role DATABASE_URL and
   the reviewed new binary. Keep runtime credentials separate. No CLI credential
   argument is accepted. Coordinate administration because server lock waits are
   bounded; investigate contention rather than repeatedly forcing it.
3. On failure, keep writers stopped. Privately inspect actual catalog/history and
   error stage, transaction effects, remaining locks and the selected backup.
   Never assume all DDL rolled back without checking. The recorded migration38
   case is transactional; this is not a guarantee for arbitrary SQL or future
   nontransactional migrations.
4. Choose a reviewed recovery path. Restore the pre-failure snapshot into a new
   quarantined target and apply the new migration there, or inspect and correct
   the exact source conflict before rerunning the original migration. The test
   conflict is a deliberately owned fixture index; its removal does not authorize
   deleting an unexpected production object or changing migration history.
5. Verify migration history, catalog/data invariants and exact runtime grants. Start
   matching new replicas on fresh connections with `AUTH_DATABASE_MIGRATIONS=verify`.
   Require actual authentication, original ownership/realm scope and revocation
   behavior. Readiness alone does not prove SMTP, provider or session continuity.

This schema-changing step has a deliberate writer-drain window. The owned evidence
does not establish an old/new mixed-writer overlap or an automatic database switch.
An old executable that does not know a future applied migration must fail startup.

## Replica replacement on unchanged schema

After schema administration succeeds, keep at least one matching current replica
serving while starting a replacement with the same reviewed configuration, database,
realm and current verified schema. Check its readiness and real session/identity
behavior before removing the old instance from that current pool. Stop the selected
old instance, confirm another replica still serves, and check shared logout/revocation
and realm isolation through the survivors. Keep workers bound to the intended live
database; do not repoint them at a restored snapshot as a readiness shortcut.

The reference drill qualifies the selected pre-retention schema39 software revision
to the current restricted-runtime software on unchanged schema39, after the actual
37→39 data upgrade. Both versions serve original sessions during overlap. Continuous
owned probes check request/identity progress while peers start/stop, and an additional
current-replica replacement runs. Other revision pairs, load balancers, full in-flight
request draining, deployment controllers, failover/RTO/RPO and production TLS require
their own selected qualification.

## Run the owned recovery drill

Build the current default server and prepare the [backup tool](backups.md). The
drill also builds pinned public schema37 and prior schema39 ancestors in separate
source/target directories. Their ancestry/trees, all37/39 immutable migration files and Cargo dependency/toolchain
inputs must match; all exported files must stay unchanged during the frozen build.
It rejects existing build directories, altered artifacts and unrelated compiler/
native/cache/SQLx database overrides. It does not execute the protected original
checkout or reuse preview accounts, databases, passkeys or mailboxes.

```sh
cargo build --locked -p easy-auth-server --bin easy-auth
python3 -m unittest discover -s scripts -p test_upgrade_source.py -v
python3 -m unittest discover -s scripts -p test_upgrade_probe.py -v
python3 scripts/prepare_upgrade_fixture.py --destination /private/tmp/easy-auth-upgrade-fixture
python3 scripts/prepare_upgrade_fixture.py --profile schema39 --destination /private/tmp/easy-auth-upgrade-prior
export EASY_AUTH_UPGRADE_FIXTURE_DIRECTORY=/private/tmp/easy-auth-upgrade-fixture
export EASY_AUTH_UPGRADE_PRIOR_DIRECTORY=/private/tmp/easy-auth-upgrade-prior
# Set this to the directory prepared using the backup guide:
export EASY_AUTH_BACKUP_TOOL_DIRECTORY=/private/tmp/easy-auth-backup-tool
python3 scripts/smoke_upgrade_recovery.py
```

The Git checkout must contain the ancestor and full ancestry. CI deepens its shallow
checkout with a read-only fetch before preparation. No PR, merge, release or public
deployment is part of this drill. `EASY_AUTH_UPGRADE_REPORT` optionally chooses a new
private sanitized receipt; an existing receipt is preserved. Receipts bind source,
old/current binaries, backup-tool binaries, fixed inputs and observed cleanup.

The old schema37 binary starts with its legacy administration-capable role. This
does not make old startup a restricted-runtime profile or add support for new
configuration fields to an old executable. Current schema verification refuses37
without DDL. Actual old accounts sign in through SMTP/HTTP in two realms; another
old replica serves the same session. After drain, an owned index conflicts with
migration38's later CREATE INDEX. The real command must fail, earlier ALTER/CREATE
effects must roll back, and all legacy rows/history and the conflict must remain.

Both recovery paths then run: decrypt/restore the pre-failure snapshot into a new
disconnected clone and migrate it; inspect/remove the owned source conflict and
rerun migration38 and apply39. Compare complete legacy table contents and actual successful
history. The old binary must refuse schema39; current replicas must preserve the
original identities/sessions, replace prior software with current software while
continuous real session requests succeed, replace a current instance, refuse
foreign-realm cookies and share logout without affecting the other realm. Remove
only the run's two messages and all owned processes/containers/volume/private files.

See [ADR0049](../architecture/adr/0049-owned-migration-upgrade-qualification.md).
The [schema39 retention qualification](../security/retention-verification-2026-10-27.md)
records the selected current revisions and results. Stale-session/key/token incident
reconciliation remains separate AUTH-49 work. Real provider/OS/production acceptance, SAML waiver limits and the
outbound OIDC release gate remain open.
