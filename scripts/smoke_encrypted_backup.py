#!/usr/bin/env python3
"""Owned real-PG encrypted archives, key rotation and never-served restorations."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

from operational_recovery import mailbox, restore_fixture
from operational_recovery.archive_postgres import ArchivePostgres
from operational_recovery.encrypted_archives.cipher import ArchiveCipher
from operational_recovery.evidence import ci_source_identity, source_identity, write_receipt
from operational_recovery.processes import Processes
from operational_recovery.roles import Roles
from operational_recovery.services import Services

ROOT = Path(__file__).resolve().parents[1]
MINIMUM_ENCRYPTED_DRILL_BYTES = 128 * 1024


def refuse_replacement(pg, cipher, recipient, archive, expected):
    try:
        pg.encrypted_dump(cipher, recipient, archive)
    except FileExistsError:
        if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
            raise ValueError("existing encrypted snapshot changed")
    else:
        raise ValueError("existing encrypted snapshot was replaced")


def refuse_invalid_archives(pg, cipher, archive, identity, other_identity, directory):
    before = pg.input_operations
    original = archive.read_bytes()
    changed = bytearray(original)
    changed[-1] ^= 1
    cases = [(archive, other_identity, hashlib.sha256(original).hexdigest()),
             (archive, directory / "missing.key", hashlib.sha256(original).hexdigest()),
             (archive, identity, "0" * 64)]
    for data in (original[:-1], bytes(changed)):
        path = directory / (uuid.uuid4().hex + ".age")
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            output.write(data)
        cases.append((path, identity, hashlib.sha256(data).hexdigest()))
    for stored, key, digest in cases:
        try:
            pg.restore_selected(cipher, stored, key, digest)
        except (ValueError, FileNotFoundError):
            pass
        else:
            raise ValueError("invalid encrypted archive unexpectedly restored")
        if pg.input_operations != before or list(directory.glob("quarantine-*.dump")):
            raise ValueError("failed decryption reached PostgreSQL or retained plaintext")
    return len(cases)


def exercise(services, initial, live, cipher, directory):
    roles = Roles(services)
    services.stage = "backup-fixture-provision"
    roles.provision()
    initial.one_shot(roles.url(roles.migration, roles.migration_password), expected_success=True)
    roles.runtime_grants()
    realms, users, messages = restore_fixture.sign_in_realms(services, roles, initial)
    restore_fixture.seed_probe(services, roles, realms)
    initial.close()
    old = restore_fixture.snapshot(services, roles.database)
    pg = ArchivePostgres(services, roles, directory)
    old_key, new_key = directory / "old.key", directory / "new.key"
    old_recipient, new_recipient = cipher.new_identity(old_key), cipher.new_identity(new_key)
    first, second = directory / "old.dump.age", directory / "current.dump.age"
    services.stage = "encrypted-old-snapshot"
    first_digest = pg.encrypted_dump(cipher, old_recipient, first)
    refuse_replacement(pg, cipher, old_recipient, first, first_digest)
    if first.stat().st_size <= MINIMUM_ENCRYPTED_DRILL_BYTES:
        raise ValueError("real encrypted archive did not cross authenticated chunk boundaries")
    origin = live.start(roles.url(roles.runtime, roles.runtime_password), realms[0])
    restore_fixture.revoke_live_session(users[0], origin)
    current = restore_fixture.snapshot(services, roles.database)
    restore_fixture.assert_snapshots(old, current, realms, users[0])
    services.stage = "encrypted-current-snapshot"
    second_digest = pg.encrypted_dump(cipher, new_recipient, second)
    refused = refuse_invalid_archives(pg, cipher, first, old_key, new_key, directory)
    refused += refuse_invalid_archives(pg, cipher, second, new_key, old_key, directory)
    services.stage = "quarantined-restoration"
    for archive, key, expected, content in [(first, old_key, first_digest, old), (second, new_key, second_digest, current)]:
        clone = pg.restore_selected(cipher, archive, key, expected)
        if restore_fixture.snapshot(services, clone) != content:
            raise ValueError("quarantined restoration changed private table contents")
        pg.assert_quarantined(clone)
    if mailbox.request(users[0][0], origin + "/v1/session")[0] != 401:
        raise ValueError("restoration damaged live-source revocation")
    mailbox.remove_messages(services.mail_origin, messages)
    return dict(realms=2, users=2, migrations=restore_fixture.CURRENT_MIGRATION_COUNT, restored_databases=len(pg.clones),
        all_public_table_contents_preserved=True, old_snapshot_precedes_live_revocation=True,
        live_revocation_preserved=True, cloned_runtime_connect_refused=True, clones_never_served=True,
        rejected_archives=refused, invalid_decryption_postgres_invocations=0, retained_plaintext_files=0,
        key_rotation=True, old_archive_requires_retained_old_key=True, owned_messages_removed=2,
        ciphertext_sha256=[first_digest, second_digest])


def main():
    report = os.environ.get("EASY_AUTH_ENCRYPTED_BACKUP_REPORT")
    if report and (Path(report).exists() or Path(report).is_symlink()):
        raise ValueError("encrypted backup receipt already exists")
    selected = os.environ.get("EASY_AUTH_BACKUP_TOOL_DIRECTORY")
    if not selected:
        raise ValueError("a prepared backup tool directory is required")
    cipher = ArchiveCipher(selected)
    source = ci_source_identity(ROOT)
    binary = ROOT / "target/debug/easy-auth"
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    failure, result = None, {}
    with tempfile.TemporaryDirectory(prefix="easy-auth-encrypted-restore-") as temporary:
        directory = Path(temporary)
        for phase in ("initial", "live"):
            (directory / phase).mkdir(mode=0o700)
        services = Services(directory)
        processes = [Processes(binary, directory / phase, 0) for phase in ("initial", "live")]
        try:
            services.start()
            result["fixture_images"] = services.verify()
            for process in processes:
                process.smtp_port = services.smtp_port
            result["checks"] = exercise(services, *processes, cipher, directory)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            failure = dict(stage=services.stage, category=type(error).__name__)
            if type(error) is ValueError:
                failure["reason"] = str(error)
        finally:
            for process in reversed(processes):
                try:
                    process.close()
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    failure = failure or dict(stage="owned-process-cleanup", category=type(error).__name__)
            try:
                services.close()
                result["owned_resources_removed"] = True
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                failure = failure or dict(stage="owned-service-cleanup", category=type(error).__name__)
    if source_identity(ROOT) != source or hashlib.sha256(binary.read_bytes()).hexdigest() != binary_hash:
        failure = dict(stage="source-stability", category="changed-during-drill")
    result.update(suite="encrypted-backup-drill", status="failed" if failure else "passed", source=source,
        binary_sha256=binary_hash, tool_binaries=cipher.receipt["binaries"], production_acceptance=False,
        owned_private_directory_removed=not directory.exists())
    if failure:
        result["failure"] = failure
    if report:
        write_receipt(report, result)
    print(json.dumps(result))
    raise SystemExit(bool(failure))


if __name__ == "__main__":
    main()
