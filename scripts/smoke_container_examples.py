#!/usr/bin/env python3
"""Owned default container + independent client + basic backup documentation smoke."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from container_examples import backup
from container_examples.compose import ROOT, Stack


def client_acceptance(stack):
    environment = dict(os.environ, EASY_AUTH_CONTAINER_ORIGIN=stack.origin,
                       EASY_AUTH_CONTAINER_MAIL_ORIGIN=stack.mail_origin)
    environment.pop("DEBUG", None)
    environment.pop("PWDEBUG", None)
    result = subprocess.run(["node", "tests/browser/container-clients/run.cjs"], cwd=ROOT,
                            env=environment, capture_output=True, check=True, timeout=120)
    clients = json.loads(result.stdout)
    if clients.get("status") != "passed" or result.stderr:
        raise ValueError("client acceptance/diagnostics failed")
    return clients


def source_provenance():
    paths = ["Dockerfile", ".dockerignore", "deploy/local/compose.yaml", "deploy/local/nginx.conf",
             "examples/clients/rust/Cargo.toml", "examples/clients/rust/Cargo.lock",
             "examples/clients/rust/src/main.rs", "examples/clients/rust/src/probe.rs",
             "examples/clients/rust/src/probe/tests.rs", "examples/clients/browser.ts",
             "scripts/smoke_container_examples.py", "scripts/container_examples/compose.py",
             "scripts/container_examples/backup.py", "tests/browser/container-clients/run.cjs",
             "tests/browser/container-clients/mail.cjs", "scripts/container_examples/settings.py",
             "scripts/write_local_container_environment.py"]
    return {
        "source_base_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip(),
        "source_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in paths},
        "client_binary_sha256": hashlib.sha256((ROOT / "target/debug/easy-auth-http-probe-example").read_bytes()).hexdigest(),
        "browser_module_sha256": hashlib.sha256((ROOT / "target/client-example/browser.js").read_bytes()).hexdigest(),
    }


def write_report(report):
    destination = os.environ.get("EASY_AUTH_CONTAINER_TEST_REPORT")
    if destination:
        with open(destination, "x", encoding="utf-8") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    print(json.dumps(report))


def main():
    stage, failure, report = "owned-startup", None, {}
    with tempfile.TemporaryDirectory(prefix="easy-auth-container-smoke-") as directory:
        stack = Stack(Path(directory))
        try:
            stack.start()
            report["image_ids"] = stack.verify()
            stage = "independent-clients"
            report["clients"] = client_acceptance(stack)
            stage = "isolated-backup-restore"
            report["backup"] = backup.check(stack)
        except (OSError, ValueError, KeyError, AssertionError, subprocess.SubprocessError) as error:
            failure = {"stage": stage, "category": type(error).__name__}
            if type(error) is ValueError:
                failure["reason"] = str(error)
        finally:
            try:
                stack.close()
                report["owned_resources_removed"] = True
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                failure = {"stage": "owned-cleanup", "category": type(error).__name__}
    report.update(suite="default-container-examples", status="failed" if failure else "passed",
                  production_acceptance=False)
    report.update(source_provenance())
    if failure:
        report["failure"] = failure
    write_report(report)
    return 1 if failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
