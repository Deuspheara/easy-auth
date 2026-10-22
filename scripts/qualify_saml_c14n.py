#!/usr/bin/env python3
"""Run existing SAML/core and C14N tests with the selected shipped graph.

Only a lock-verified unchanged registry archive is copied into a disposable
workspace. No XML/crypto fixtures, native probes or cryptographic code are added.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile

if __package__:
    from . import qualify_saml_dependency as qualification
else:
    import qualify_saml_dependency as qualification

ROOT = qualification.ROOT
PACKAGE = "bergshamra-c14n"
VERSION = "0.9.2"
CHECKSUM = "f9ea63f9d7b6cceeeef8ad96da61325c6ed6397e342377b552a0bf9917e266a9"


def archive_source(destination, lock):
    records = [entry for entry in lock.decode().split("[[package]]")
               if re.search(r'^name = "bergshamra-c14n"$', entry, re.MULTILINE)]
    if len(records) != 1 or f'version = "{VERSION}"' not in records[0] \
            or f'checksum = "{CHECKSUM}"' not in records[0]:
        raise ValueError("unexpected selected C14N source")
    registry = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))) / "registry/cache"
    archives = list(registry.glob(f"*/{PACKAGE}-{VERSION}.crate"))
    if len(archives) != 1 or hashlib.sha256(archives[0].read_bytes()).hexdigest() != CHECKSUM:
        raise ValueError("C14N archive identity mismatch")
    files = {}
    with tarfile.open(archives[0]) as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if not member.isfile() or path.is_absolute() or ".." in path.parts \
                    or path.parts[0] != f"{PACKAGE}-{VERSION}" or len(path.parts) < 2:
                raise ValueError("unexpected C14N archive member")
            target = destination.joinpath(*path.parts[1:])
            target.parent.mkdir(parents=True, exist_ok=True)
            data = archive.extractfile(member).read()
            target.write_bytes(data)
            files["/".join(path.parts[1:])] = hashlib.sha256(data).hexdigest()
    return files


def stage_workspace(staged, lock):
    qualification.stage_workspace(staged, lock)
    files = archive_source(staged / f"third-party/{PACKAGE}", lock)
    manifest = (staged / "Cargo.toml").read_text()
    if "[patch.crates-io]" in manifest:
        raise ValueError("review existing registry patches before qualification")
    manifest = manifest.replace("members = [", f'members = ["third-party/{PACKAGE}", ', 1)
    manifest += f'\n[patch.crates-io]\n{PACKAGE} = {{ path = "third-party/{PACKAGE}" }}\n'
    (staged / "Cargo.toml").write_text(manifest)
    return files


def verification_sources(root):
    folder = root / "crates/auth-core/src/saml/verification"
    paths = sorted(folder.rglob("*.rs"))
    if not paths or any(p.is_symlink() for p in paths):
        raise ValueError("unexpected verification source inventory")
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in paths}


def qualify():
    qualification.check()
    lock = (ROOT / "Cargo.lock").read_bytes()
    inventory = (ROOT / "third-party/saml-rs-source.json").read_bytes()
    verification = verification_sources(ROOT)
    graph_arguments = ["tree", "-p", "easy-auth-core", "--features", "saml-verification",
                       *qualification.TREE]
    shipped = qualification.saml_subtree(qualification.cargo(
        [*graph_arguments, "--locked"], ROOT))
    with tempfile.TemporaryDirectory(prefix="easy-auth-c14n-qualification-") as directory:
        staged = Path(directory)
        files = stage_workspace(staged, lock)
        actual = qualification.saml_subtree(qualification.cargo(graph_arguments, staged))
        if actual != shipped:
            raise ValueError("C14N qualification changed shipped normal/build graph")
        metadata = json.loads(qualification.cargo(
            ["metadata", "--locked", "--format-version", "1"], staged))
        packages = [p for p in metadata["packages"] if p["name"] == PACKAGE]
        if len(packages) != 1 or Path(packages[0]["manifest_path"]).resolve() != (staged / f"third-party/{PACKAGE}/Cargo.toml").resolve():
            raise ValueError("C14N archive copy is not the selected package")
        environment = dict(os.environ, CARGO_INCREMENTAL="0")
        environment.setdefault("CARGO_TARGET_DIR", str(ROOT / "target"))
        result = subprocess.run(
            ["cargo", "test", "--locked", "-p", "easy-auth-core", "-p", "saml-rs",
             "-p", PACKAGE, "--no-default-features", "--features", "easy-auth-core/saml-verification"],
            cwd=staged, env=environment, capture_output=True, text=True)
        if (ROOT / "Cargo.lock").read_bytes() != lock \
                or (ROOT / "third-party/saml-rs-source.json").read_bytes() != inventory \
                or (ROOT / ".cargo/config.toml").read_bytes() != (staged / ".cargo/config.toml").read_bytes():
            raise ValueError("application inputs changed during C14N qualification")
        if verification_sources(ROOT) != verification or verification_sources(staged) != verification:
            raise ValueError("verification sources changed during qualification")
        for name, checksum in files.items():
            if hashlib.sha256((staged / f"third-party/{PACKAGE}" / name).read_bytes()).hexdigest() != checksum:
                raise ValueError("C14N archive source changed during qualification")
        report = qualification.test_report(result, staged, lock, inventory, actual)
        report.update(test_packages=["easy-auth-core", "saml-rs", PACKAGE],
                      reproducer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      report_helper_sha256=hashlib.sha256(Path(qualification.__file__).read_bytes()).hexdigest(),
                      core_verification_source_sha256=verification,
                      c14n_source=dict(package=PACKAGE, version=VERSION, archive_sha256=CHECKSUM,
                                       copied_archive_files=len(files), source_modified=False,
                                       archive_file_sha256=files))
        destination = ROOT / "target/saml-c14n-qualification.json"
        destination.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k: v for k, v in report.items() if k != "normal_build_packages"}))
        if result.returncode or not report["test_groups"] or report["failed"] or report["ignored"]:
            raise ValueError("existing SAML/C14N tests did not pass")
    qualification.check()


if __name__ == "__main__":
    try:
        qualify()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError) as error:
        print("Shipped-graph established SAML/C14N qualification: FAIL")
        print(json.dumps({"error_kind": type(error).__name__,
                          "reason": str(error) if type(error) is ValueError else "runner failure"}))
        raise SystemExit(1) from None
