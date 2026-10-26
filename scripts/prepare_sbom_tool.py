#!/usr/bin/env python3
"""Python 3.12+: build the pinned official generator with a reviewed tooling lock."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / "tools/supply-chain"
ARCHIVE_LIMIT = 2 * 1024 * 1024


def run_check(name, arguments, directory):
    environment = dict(os.environ, CARGO_TARGET_DIR=str(directory / "cargo-cyclonedx-0.5.9/target"),
                       CARGO_INCREMENTAL="0")
    with (directory / (name + ".log")).open("x") as output:
        result = subprocess.run(arguments, cwd=ROOT, stdout=output,
                                stderr=subprocess.STDOUT, env=environment, timeout=600)
    if result.returncode:
        raise ValueError("SBOM tool " + name + " failed")


def validate_members(archive, prefix):
    for member in archive.getmembers():
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not path.parts \
                or path.parts[0] != prefix or not (member.isfile() or member.isdir()):
            raise ValueError("unexpected SBOM tool archive member")


def tool_source(destination, pin):
    expected_url = "https://static.crates.io/crates/cargo-cyclonedx/cargo-cyclonedx-0.5.9.crate"
    if pin["name"] != "cargo-cyclonedx" or pin["version"] != "0.5.9" \
            or pin["archive_url"] != expected_url:
        raise ValueError("unreviewed SBOM generator source")
    with urlopen(Request(expected_url, headers={"User-Agent": "easy-auth-supply-chain/1"}), timeout=30) as response:
        if response.status != 200 or response.url != expected_url:
            raise ValueError("unexpected SBOM generator download")
        data = response.read(ARCHIVE_LIMIT + 1)
    if len(data) > ARCHIVE_LIMIT or hashlib.sha256(data).hexdigest() != pin["archive_sha256"]:
        raise ValueError("SBOM generator archive identity mismatch")
    archive_path = destination / "source.crate"
    archive_path.write_bytes(data)
    with tarfile.open(archive_path) as archive:
        validate_members(archive, "cargo-cyclonedx-0.5.9")
        archive.extractall(destination, filter="data")
    source = destination / "cargo-cyclonedx-0.5.9"
    lock = INPUTS / "cargo-cyclonedx.Cargo.lock"
    if hashlib.sha256(lock.read_bytes()).hexdigest() != pin["lock_sha256"]:
        raise ValueError("SBOM generator tooling lock identity mismatch")
    shutil.copyfile(lock, source / "Cargo.lock")
    return source


def prepare(destination):
    if sys.version_info < (3, 12):
        raise ValueError("Python 3.12 or later is required")
    if destination.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError("choose a new tool directory outside source")
    destination.mkdir(mode=0o700)  # Refuse reuse, including symlinks and old builds.
    pin = json.loads((INPUTS / "cargo-cyclonedx.json").read_text())
    source = tool_source(destination, pin)
    manifest = str(source / "Cargo.toml")
    run_check("fetch", ["cargo", "fetch", "--locked", "--manifest-path", manifest], destination)
    with (destination / "audit.json").open("x") as output:
        audited = subprocess.run(["cargo", "audit", "--json", "--file", str(source / "Cargo.lock")],
                                 stdout=output, stderr=subprocess.PIPE, timeout=120)
    audit = json.loads((destination / "audit.json").read_text())
    if audited.returncode or audit.get("error") or "vulnerabilities" not in audit \
            or audit["vulnerabilities"].get("list") or any(audit.get("warnings", {}).values()):
        raise ValueError("SBOM generator audit has findings or is unavailable")
    run_check("deny", ["cargo", "deny", "--manifest-path", manifest, "--all-features",
                       "--config", str(INPUTS / "deny.toml"), "check"], destination)
    run_check("build", ["cargo", "build", "--release", "--frozen", "--manifest-path", manifest,
                        "--bin", "cargo-cyclonedx", "--jobs", "2"], destination)
    binary = source / "target/release/cargo-cyclonedx"
    if hashlib.sha256((source / "Cargo.lock").read_bytes()).hexdigest() != pin["lock_sha256"]:
        raise ValueError("SBOM generator tooling lock changed")
    receipt = dict(source=pin, binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                   audit_sha256=hashlib.sha256((destination / "audit.json").read_bytes()).hexdigest(),
                   tooling_policy_sha256=hashlib.sha256((INPUTS / "deny.toml").read_bytes()).hexdigest(),
                   bootstrap_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   rustc=subprocess.check_output(["rustc", "-vV"]).decode().strip(),
                   cargo_audit_version=subprocess.check_output(["cargo", "audit", "--version"]).decode().strip(),
                   cargo_deny_version=subprocess.check_output(["cargo", "deny", "--version"]).decode().strip(),
                   advisory_database=audit.get("database"),
                   advisory_and_license_checks_passed=True, production_security_approval=False)
    (destination / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return binary, receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    binary, receipt = prepare(parser.parse_args().destination.absolute())
    print(json.dumps(dict(status="built", binary=str(binary), sha256=receipt["binary_sha256"],
                          production_security_approval=False)))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(json.dumps(dict(status="failed", category=type(error).__name__)), file=sys.stderr)
        raise SystemExit(1) from None
