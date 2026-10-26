# Database backups and isolated restore checks

Use the [container walkthrough](containers.md) first; the commands below use its
explicit `container_project`, `container_source` and private `container_environment`. They target only that owned
development database. Production backup/restore, migration rollback, key loss,
rolling upgrades and incident recovery still require separate qualification.

## Capture a protected archive

A database backup contains identity/contact data, credential verifiers, sessions,
pending proofs, audits and possibly encrypted Apple grants. Keep it outside source
trees and build contexts, with restricted access, encryption and a retention policy.
Protect configuration and required retained envelope/signing keys separately;
the database archive is not a complete application recovery package.

```sh
umask 077
backup_directory=$(mktemp -d "${TMPDIR:-/tmp}/easy-auth-backup.XXXXXX")
docker compose --env-file "$container_environment" --project-name "$container_project" \
  --file "$container_source/deploy/local/compose.yaml" exec -T postgres \
  pg_dump --username=auth --format=custom --no-owner --no-acl auth \
  > "$backup_directory/auth.dump"
test -s "$backup_directory/auth.dump"
```

Check the command's exit status and warnings before treating the archive as usable.
Record its SHA-256 checksum with your platform's `sha256sum` or `shasum -a 256`,
plus source revision, PostgreSQL/tool versions, migration state and protected key
references. A checksum detects changed bytes; it does not prove recoverability.

`pg_dump` takes a consistent single-database snapshot while ordinary transactions
continue. It does not back up cluster roles/tablespaces or external keys/config.
Use tooling compatible with the deployed PostgreSQL major and inspect its
[documented limitations](https://www.postgresql.org/docs/17/app-pgdump.html).
Do not copy a live PostgreSQL data directory as a substitute for a supported backup.

## Restore into a new, isolated database

Create a fresh destination; creation must fail if the name already exists.
Do not point the running app or a notification/revocation worker at it.

```sh
docker compose --env-file "$container_environment" --project-name "$container_project" \
  --file "$container_source/deploy/local/compose.yaml" exec -T postgres \
  createdb --username=auth auth_restore_check
docker compose --env-file "$container_environment" --project-name "$container_project" \
  --file "$container_source/deploy/local/compose.yaml" exec -T postgres \
  pg_restore --username=auth --dbname=auth_restore_check --no-owner --no-acl \
  --single-transaction --exit-on-error < "$backup_directory/auth.dump"
docker compose --env-file "$container_environment" --project-name "$container_project" \
  --file "$container_source/deploy/local/compose.yaml" exec -T postgres \
  psql --username=auth --dbname=auth_restore_check --set=ON_ERROR_STOP=1 \
  --command='SELECT count(*) FROM auth_users; SELECT count(*) FROM _sqlx_migrations WHERE NOT success;'
```

Compare expected identities, schema/migration state, constraints and operational
invariants without dumping private rows into logs. Restore only trusted archives:
[pg_restore](https://www.postgresql.org/docs/17/app-pgrestore.html) executes the
archive's SQL in the destination. This example avoids `--clean` and never overwrites
the running database. It checks archive/schema usability, not full disaster recovery.

A point-in-time snapshot can resurrect revoked sessions, deleted identities,
one-use credentials or pending side effects. Quarantine restoration from public
traffic, SMTP and providers until revocation, key/configuration and incident policy
are reconciled. Do not automatically run migrations, notices or Apple revocation
jobs against an old snapshot. A worker job or local erasure is not proof of remote
provider revocation. The SAML waiver and outbound issuer release gate still apply.

After checking this newly created disposable clone:

```sh
docker compose --env-file "$container_environment" --project-name "$container_project" \
  --file "$container_source/deploy/local/compose.yaml" exec -T postgres \
  dropdb --username=auth auth_restore_check
```

Remove only the private archive directory you created when its retention is over.
For production, define recovery objectives, backup encryption/access/retention,
tested restore isolation, least-privilege roles, key custody and rotation, and
cross-version migration/recovery procedures before any release claim.
