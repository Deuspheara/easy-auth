# Database backups and isolated restore checks

## Encrypted archive workflow

The offline Python 3.12+ commands use prepared age 1.3.2 with a fixed dependency
selection, native X25519 recovery identities and no plugin/agent/passphrase fallback.
They add no runtime server dependency or public administration route. This bounded
workflow and its disposable restoration drill do not qualify production recovery.
Use [ADR0048](../architecture/adr/0048-encrypted-backup-quarantine.md) and the
[tool inputs](../../tools/backup-encryption/README.md) for exact source, license,
advisory and remaining acceptance details.

Prepare a new tool directory; the script refuses existing directories. It downloads
only pinned upstream inputs into private build/module caches, checks compiler and
binary metadata, source/binary scan coverage and exact license notices. Imported
affected packages fail, including uncalled ones. An unimported OpenPGP module
finding stays visible in the receipt. Keep the prepared notices with its binaries.

```sh
umask 077
backup_tool_directory=/private/tmp/easy-auth-backup-tool
python3 scripts/prepare_backup_tool.py --destination "$backup_tool_directory"
recovery_key_directory=$(mktemp -d "${TMPDIR:-/tmp}/easy-auth-recovery-key.XXXXXX")
python3 scripts/backup_archive.py keygen --tool-directory "$backup_tool_directory" \
  --identity "$recovery_key_directory/archive.key" > "$recovery_key_directory/recipient.json"
backup_recipient=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["recipient"])' \
  < "$recovery_key_directory/recipient.json")
```

Protect the private recovery identity separately from backups. The recipient is
public; the identity never belongs in command arguments, source, logs or a database.
Identity files must be owned, private regular files containing one native identity.
This reference profile uses protected local files; hardware custody, encrypted
identity files and production key management need separate qualification. Unlinking
a file is not a physical-erasure guarantee.

Use a Bash script and a PostgreSQL17-compatible `pg_dump`. Select its source and
authentication through privately provisioned PostgreSQL service/password files or
environment; do not put a password-bearing URL in arguments or enable shell tracing.
The following uses the current private PostgreSQL connection settings. Both pipeline
exits must succeed. Its output directory is newly created, so failure cleanup only
removes this capture's file; do not reuse an existing backup directory/name.

```bash
backup_directory=$(mktemp -d "${TMPDIR:-/tmp}/easy-auth-encrypted-backup.XXXXXX")
if ! (
  set -o pipefail
  pg_dump --format=custom --no-owner --no-acl |
    python3 scripts/backup_archive.py encrypt --tool-directory "$backup_tool_directory" \
      --recipient "$backup_recipient" --output "$backup_directory/auth.dump.age"
) > "$backup_directory/capture.json"; then
  rm -f -- "$backup_directory/auth.dump.age"
  echo 'Encrypted backup capture failed' >&2
  exit 1
fi
```

The command streams plaintext directly into age and writes a new 0600 ciphertext.
Its JSON output contains the ciphertext SHA256. Record that digest with source,
schema, PostgreSQL/tool versions and protected key references in separately protected
inventory before storing the archive. Encryption success alone does not establish
that `pg_dump` succeeded or that restoration works. The wrapper currently bounds
ciphertext/plaintext to 1 GiB and each age operation to 90 seconds; larger databases need
a separately qualified resource profile.

Select a trusted snapshot and load `expected_ciphertext_sha256` from its separately
protected inventory. A digest is not a signature. Anyone with the public recipient
can create a new encrypted file; age integrity does not authenticate its sender,
select the latest snapshot or make archive SQL trustworthy.

```bash
quarantine_directory=$(mktemp -d "${TMPDIR:-/tmp}/easy-auth-restore-quarantine.XXXXXX")
if ! python3 scripts/backup_archive.py decrypt --tool-directory "$backup_tool_directory" \
  --identity "$recovery_key_directory/archive.key" --input "$backup_directory/auth.dump.age" \
  --expected-sha256 "$expected_ciphertext_sha256" --output "$quarantine_directory/auth.dump"; then
  echo 'Archive decryption refused' >&2
  exit 1
fi
pg_restore --list < "$quarantine_directory/auth.dump" > "$quarantine_directory/contents.txt"
```

Decryption verifies the selected digest and full authenticated input before releasing
the private quarantine file. Wrong/missing keys, tampering, truncation, output bounds
and expired operations remove partial output. Existing key/archive/plaintext files
are never overwritten. Do not pipe decryption directly into PostgreSQL: age can emit
authenticated earlier chunks before a later failure. Review successful listing and
the selected snapshot's provenance. Pass `$quarantine_directory/auth.dump` to the
reviewed new-database restore procedure, using the transactional/error-stopping
flags illustrated below. The separate container exercise captures its own archive
and uses its own connection variables.
Keep apps, SMTP and provider-revocation workers disconnected from restoration until
incident/key/configuration and pending-job policy is reconciled. Old snapshots can
revive revoked sessions, deleted accounts and one-use proofs.

Generate a new identity/recipient for future backup encryption when rotating. Retain
old reading identities in protected custody for every still-retained old archive.
The new identity cannot recover an old archive; missing keys select no fallback.
Retention/retirement and production key-loss procedures remain separate work.

The owned drill requires cached PostgreSQL/Mailpit images and a freshly built
default server, using the same isolated resources as the [role drill](database-roles.md):

```sh
export EASY_AUTH_BACKUP_TOOL_DIRECTORY="$backup_tool_directory"
python3 -m unittest discover -s scripts -p test_backup_tool.py -v
python3 -m unittest discover -s scripts -p test_encrypted_archives.py -v
python3 -m unittest discover -s scripts -p test_backup_archive_cli.py -v
python3 scripts/smoke_encrypted_backup.py
```

It encrypts two real PostgreSQL snapshots with different recovery keys, before and
after live logout, and compares every public table's contents after separate
transactional restorations. Runtime CONNECT is denied and no app/worker serves the
clones. Ten invalid-archive cases must reach no PostgreSQL input operation; the live
source must retain its logout. All owned accounts, messages, processes, databases,
volume, archives, plaintext and disposable keys are removed. Optional
`EASY_AUTH_ENCRYPTED_BACKUP_REPORT` selects a new private sanitized receipt path.
This establishes the recorded local workflow, not full AUTH-49 or production acceptance.

## Container archive exercise

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
