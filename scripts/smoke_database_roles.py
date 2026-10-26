#!/usr/bin/env python3
"""Distinct owned DB roles plus actual CLI, runtime HTTP/SMTP and realm isolation."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

from operational_recovery import mailbox
from operational_recovery.processes import Processes
from operational_recovery.roles import Roles
from operational_recovery.services import Services
from operational_recovery.evidence import source_identity, write_receipt

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MIGRATION_COUNT = 38


def journey(services, processes):
    roles = Roles(services)
    services.stage = "role-provision"
    roles.provision()
    services.stage = "migration-administration"
    processes.one_shot(roles.url(roles.migration, roles.migration_password), expected_success=True)
    processes.one_shot(roles.url(roles.migration, "invalid-owned-password"), expected_success=False)
    processes.one_shot(roles.url(roles.migration, roles.migration_password), expected_success=True)
    roles.runtime_grants()
    services.stage = "privilege-refusals"
    privileges = roles.assert_privileges()
    runtime_url = roles.url(roles.runtime, roles.runtime_password)
    services.stage = "runtime-startup"
    processes.start(roles.url(roles.runtime, "invalid-owned-password"), uuid.uuid4(), expected_success=False)
    processes.start(runtime_url, uuid.uuid4(), mode="run", expected_success=False)
    first_realm, second_realm = uuid.uuid4(), uuid.uuid4()
    first_origin = processes.start(runtime_url, first_realm)
    second_origin = processes.start(runtime_url, second_realm)
    services.stage = "actual-http-and-mail"
    first, first_message = mailbox.sign_in(first_origin, services.mail_origin)
    second, second_message = mailbox.sign_in(second_origin, services.mail_origin)
    if first[2]["realm_id"] != str(first_realm) or second[2]["realm_id"] != str(second_realm) \
            or first[2]["id"] == second[2]["id"]:
        raise ValueError("role-backed realm identity mismatch")
    mailbox.isolation_and_logout(first, second_origin, first_origin)
    services.stage = "owned-message-cleanup"
    mailbox.remove_messages(services.mail_origin, [first_message, second_message])
    if services.sql(roles.database, "SELECT count(*) FROM _sqlx_migrations WHERE success") != str(EXPECTED_MIGRATION_COUNT):
        raise ValueError("role schema migration count mismatch")
    return dict(privileges=privileges, actual_smtp=True, actual_http_authentication=True,
                realm_isolation=True, logout_revoked=True, administration_idempotent=True,
                wrong_migration_password_refused=True, runtime_ddl_startup_refused=True,
                wrong_runtime_password_refused=True,
                verified_runtime_startup=True, migration_count=EXPECTED_MIGRATION_COUNT, owned_messages_removed=2)


def main():
    failure, result = None, {}
    destination = os.environ.get("EASY_AUTH_DATABASE_ROLE_REPORT")
    if destination and (Path(destination).exists() or Path(destination).is_symlink()):
        raise SystemExit("operational receipt destination already exists")
    binary = ROOT / "target/debug/easy-auth"
    source = source_identity(ROOT)
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="easy-auth-role-drill-") as directory:
        services = Services(directory)
        processes = Processes(binary, directory, 0)
        try:
            services.start()
            processes.smtp_port = services.smtp_port
            result["fixture_images"] = services.verify()
            result["checks"] = journey(services, processes)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            failure = dict(stage=services.stage, category=type(error).__name__)
            if type(error) is ValueError:
                failure["reason"] = str(error)
        finally:
            try:
                processes.close()
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                result["process_cleanup_failed"] = True
                failure = failure or dict(stage="owned-process-cleanup", category=type(error).__name__)
            try:
                services.close()
                result["owned_resources_removed"] = True
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                result["service_cleanup_failed"] = True
                failure = failure or dict(stage="owned-service-cleanup", category=type(error).__name__)
    if source != source_identity(ROOT) or binary_hash != hashlib.sha256(binary.read_bytes()).hexdigest():
        failure = dict(stage="source-stability", category="changed-during-drill")
    result.update(suite="database-role-drill", status="failed" if failure else "passed",
                  production_acceptance=False, binary_sha256=binary_hash, source=source)
    if failure:
        result["failure"] = failure
    if destination:
        write_receipt(destination, result)
    print(json.dumps(result))
    raise SystemExit(bool(failure))


if __name__ == "__main__":
    main()
