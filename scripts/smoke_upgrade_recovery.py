#!/usr/bin/env python3
"""Actual owned old/current binaries, failed published DDL and recovery/replica drill."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from operational_recovery.encrypted_archives.cipher import ArchiveCipher
from operational_recovery.evidence import ci_source_identity, source_identity, write_receipt
from operational_recovery.services import Services
from operational_recovery.upgrade_journey import UpgradeJourney
from operational_recovery.upgrade_source import prepared_binary

ROOT = Path(__file__).resolve().parents[1]


def run_owned(old_binary, prior_binary, current_binary, cipher):
    result, failure = {}, None
    with tempfile.TemporaryDirectory(prefix="easy-auth-upgrade-recovery-") as temporary:
        directory = Path(temporary)
        services = Services(directory)
        journey = UpgradeJourney(services, directory, old_binary, prior_binary, current_binary, cipher)
        try:
            services.start()
            result["fixture_images"] = services.verify()
            services.stage = "legacy-schema37"
            journey.bootstrap_legacy()
            services.stage = "failed-migration-and-recovery"
            result["recovery"] = journey.failure_and_recovery()
            services.stage = "current-replica-replacement"
            result["replicas"] = journey.rolling_replacement()
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            failure = dict(stage=services.stage, category=type(error).__name__)
            if type(error) is ValueError:
                failure["reason"] = str(error)
        finally:
            failures = journey.close()
            if failures:
                result["process_cleanup_failures"] = failures
                failure = failure or dict(stage="owned-process-cleanup", category="incomplete")
            try:
                services.close()
                result["owned_resources_removed"] = True
            except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
                failure = failure or dict(stage="owned-service-cleanup", category=type(error).__name__)
    result["owned_private_directory_removed"] = not directory.exists()
    return result, failure


def main():
    report = os.environ.get("EASY_AUTH_UPGRADE_REPORT")
    if report and (Path(report).exists() or Path(report).is_symlink()):
        raise ValueError("upgrade receipt already exists")
    old_directory = os.environ.get("EASY_AUTH_UPGRADE_FIXTURE_DIRECTORY")
    prior_directory = os.environ.get("EASY_AUTH_UPGRADE_PRIOR_DIRECTORY")
    tool_directory = os.environ.get("EASY_AUTH_BACKUP_TOOL_DIRECTORY")
    if not old_directory or not prior_directory or not tool_directory:
        raise ValueError("both prepared upgrade fixtures and backup tool directories are required")
    old_binary, old_receipt = prepared_binary(old_directory)
    prior_binary, prior_receipt = prepared_binary(prior_directory, "schema39")
    cipher = ArchiveCipher(tool_directory)
    source = ci_source_identity(ROOT)
    current = ROOT / "target/debug/easy-auth"
    binaries = (old_binary, prior_binary, current)
    hashes = [hashlib.sha256(path.read_bytes()).hexdigest() for path in binaries]
    result, failure = run_owned(*binaries, cipher)
    if source_identity(ROOT) != source or hashes != [hashlib.sha256(path.read_bytes()).hexdigest() for path in binaries]:
        failure = dict(stage="source-stability", category="changed-during-drill")
    result.update(suite="migration-upgrade-recovery", status="failed" if failure else "passed",
        source=source, old_source=old_receipt["pin"], old_binary_sha256=hashes[0],
        prior_source=prior_receipt["pin"], prior_binary_sha256=hashes[1], current_binary_sha256=hashes[2],
        tool_binaries=cipher.receipt["binaries"], production_acceptance=False)
    if failure:
        result["failure"] = failure
    if report:
        write_receipt(report, result)
    print(json.dumps(result))
    raise SystemExit(bool(failure))


if __name__ == "__main__":
    main()
