# Schema administration and runtime database roles

The server supports separate migration and runtime PostgreSQL connections. These
are deployment principals; they confer no application authorization. This procedure
does not qualify production permissions, backup restoration or rolling upgrades.
Release prerequisites and provider/OS acceptance remain open.

## Installation and grants

Provision distinct, privately authenticated PostgreSQL LOGIN roles. Neither should
be a superuser or have CREATEDB, CREATEROLE, REPLICATION or BYPASSRLS. The runtime role
must have no membership allowing it to assume the migration role, database owner or
another privileged role. Use NOINHERIT as defense in depth, not as a substitute for
removing such membership. Keep migration credentials out of runtime processes.

Use the migration role as the dedicated database owner. Revoke PUBLIC database
privileges, explicitly grant runtime CONNECT, and restrict the public schema. A
database administrator provisions roles and credentials outside this application;
the executable never creates roles. Configure PostgreSQL authentication/TLS and
credential delivery separately. Avoid password-bearing SQL in logged scripts and
connection URLs in shell arguments, shell tracing or diagnostic output.

With the migration role's `DATABASE_URL` delivered privately:

```sh
./target/debug/easy-auth migrate
```

The command requires only that setting, uses one connection and exits. It does not
read runtime realm, SMTP or provider configuration. Existing immutable SQLx
migrations retain their transactions, checksums and database advisory lock.

Before starting runtime writers, apply the following through a protected psql
session connected to the dedicated database as its migration owner. The psql
identifier variables `database_name`, `migration_role` and `runtime_role` designate
the provisioned principals/database, never passwords. Review the current schema
before granting all auth-table DML. These grants authorize the trusted auth backend
to mutate authentication records; this is not a read-only or untrusted client role.

```sql
BEGIN;
REVOKE ALL ON DATABASE :"database_name" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"database_name" TO :"runtime_role";
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO :"runtime_role";
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO :"runtime_role";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO :"runtime_role";
REVOKE INSERT, UPDATE, DELETE ON _sqlx_migrations FROM :"runtime_role";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migration_role" IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :"runtime_role";
ALTER DEFAULT PRIVILEGES FOR ROLE :"migration_role" IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO :"runtime_role";
COMMIT;
```

The runtime role can SELECT migration history but cannot change it or create
permanent/temporary objects. Recheck privileges after migrations and role changes;
default privileges apply only to future objects created by the named migration
role. Alternate schemas, preexisting role memberships and additional grants need
their own assessment. The application does not audit or repair privileges.

Then deliver only the runtime role's connection setting to each server/embedded
process and select:

```sh
export AUTH_DATABASE_MIGRATIONS=verify
./target/debug/easy-auth
```

Supply the usual realm, transport and SMTP settings from the
[startup contract](server-cli.md). Verification checks every embedded up migration's
version/checksum, rejects missing/dirty/future history, and applies no DDL. It does
not detect arbitrary manual changes to table definitions with unchanged history.
No failed verification selects `run`. The default `run` exists for compatibility;
forgetting `verify` under restricted runtime credentials fails instead of granting
privileges or skipping migration checks.

## Contention, failure and upgrades

Schema verification has a five-second overall budget including pool acquisition,
with two-second database statement/lock limits. Administration bounds database
lock waits at two seconds, without a short statement-execution limit on migration
DDL. Both close the dedicated schema connection on success, error and future
cancellation, preventing a session advisory lock or timeout setting returning to
the authentication pool. Server-side limits also bound a cancelled backend still
waiting for a lock. Contention fails; coordinate administration and retry only
after investigating the competing operation.

Stop writers and take a separately protected backup before an upgrade. Run the
reviewed migration revision once through administration, validate the result, then
start matching binaries with fresh connections and `verify`. Do not edit published
migrations, delete history or substitute a checksum to make startup pass. Restore
or roll forward through a reviewed procedure after investigating a failure. This
guide does not establish a tested downgrade or arbitrary mixed-version operation.
[ADR0038](../architecture/adr/0038-native-token-lifecycle.md) preserves the existing
fresh-connection boundary after DDL. Encrypted recovery, retention, incident drills
and a qualified upgrade procedure remain AUTH-49 work.

## Disposable qualification

After building the current default server, run:

```sh
python3 -m unittest discover -s scripts -p test_operational_recovery.py -v
python3 scripts/smoke_database_roles.py
```

The drill requires locally cached `postgres:17-alpine` and `axllent/mailpit:v1.27`
images and Docker. It creates fresh labelled containers on random loopback ports,
an exclusive anonymous volume, random credentials, and a new database. It uses
actual TCP password authentication, the administration executable and two ordinary
runtime processes. Wrong credentials, runtime DDL/history writes/temporary objects/
role switching and automatic-migration startup must fail. Both real SMTP sign-ins,
realm isolation and logout must succeed. It then removes its child processes,
exact messages, containers and volume. It never connects to an existing database
or mailbox and uses no retained account or passkey.

`EASY_AUTH_DATABASE_ROLE_REPORT` optionally selects a new private receipt path.
An existing receipt is never overwritten. The receipt records binary SHA256,
source revision/clean state/source digest, fixture image IDs, bounded observations
and cleanup result; it contains no connection URL, password, email token or mail
body. Source/binary changes during the drill invalidate it. A dirty source receipt
is development evidence, not exact-commit validation. Ordinary HTTP clients are
used; this drill is not genuine-browser or real-provider acceptance.

PostgreSQL integration cases separately cover empty/dirty/future/missing/checksum
history and actual observed advisory-lock contention/cancellation. See
[ADR0047](../architecture/adr/0047-schema-administration-and-runtime-verification.md).
