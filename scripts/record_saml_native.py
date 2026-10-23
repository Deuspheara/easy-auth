#!/usr/bin/env python3
"""Record ordinary build/native provenance, not security or resource testing.

Run after the documented combined SAML/OIDC server build and C14N qualification.
No signatures, XML fixtures, network calls, load or native execution probes.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
from datetime import datetime, timezone

if __package__:
    from .qualify_saml_c14n import ROOT, verification_sources
else:
    from qualify_saml_c14n import ROOT, verification_sources


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(arguments):
    result = subprocess.run(arguments, cwd=ROOT, capture_output=True, text=True)
    if result.returncode:
        raise ValueError("native inventory command failed")
    return result.stdout.strip()


def aws_lc_source(report):
    packages = [p for p in report["normal_build_packages"] if p["name"] == "aws-lc-sys"]
    if len(packages) != 1:
        raise ValueError("unexpected selected AWS-LC source")
    version = packages[0]["version"]
    records = [r for r in (ROOT / "Cargo.lock").read_text().split("[[package]]")
               if 'name = "aws-lc-sys"' in r and f'version = "{version}"' in r]
    if len(records) != 1:
        raise ValueError("AWS-LC lock identity missing")
    checksum = re.search(r'^checksum = "([a-f0-9]{64})"$', records[0], re.MULTILINE).group(1)
    registry = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))) / "registry/cache"
    archives = list(registry.glob(f"*/aws-lc-sys-{version}.crate"))
    if len(archives) != 1 or digest(archives[0]) != checksum:
        raise ValueError("AWS-LC archive identity mismatch")
    with tarfile.open(archives[0]) as archive:
        data = archive.extractfile(f"aws-lc-sys-{version}/aws-lc/CMakeLists.txt").read()
    software = re.search(rb'set\(SOFTWARE_VERSION\s+"?([0-9.]+)', data).group(1).decode()
    return dict(sys_version=version, archive_sha256=checksum,
                cmake_sha256=hashlib.sha256(data).hexdigest(), software_version=software,
                scope="bundled source identity; not native certification")


def native_libraries(binary):
    system = platform.system()
    if system == "Darwin":
        output = command(["otool", "-L", str(binary)])
        paths = [line.strip().split(" (", 1)[0] for line in output.splitlines()[1:]]
    elif system == "Linux":
        output = command(["ldd", str(binary)])
        paths = re.findall(r'=>\s+(/\S+)', output)
    else:
        raise ValueError("native inventory platform not supported")
    libraries = []
    for name in paths:
        path = Path(name)
        if not re.match(r"lib(?:ssl|crypto)[.-]", path.name):
            continue
        actual = path.resolve(strict=True)
        libraries.append(dict(load_name=path.name, resolved_name=actual.name,
                              sha256=digest(actual), bytes=actual.stat().st_size))
    if {"ssl", "crypto"} != {"ssl" if x["load_name"].startswith("libssl") else "crypto"
                                for x in libraries}:
        raise ValueError("expected linked OpenSSL artifacts missing")
    return libraries


def record():
    report_path = ROOT / "target/saml-c14n-qualification.json"
    report = json.loads(report_path.read_text())
    sources = verification_sources(ROOT)
    if report["exit_code"] or report["failed"] or report["ignored"] \
            or report["features"] != ["crypto-aws-lc"] \
            or report["application_lock_sha256"] != digest(ROOT / "Cargo.lock") \
            or report["source_inventory_sha256"] != digest(ROOT / "third-party/saml-rs-source.json") \
            or report["core_verification_source_sha256"] != sources \
            or report["reproducer_sha256"] != digest(ROOT / "scripts/qualify_saml_c14n.py") \
            or report["report_helper_sha256"] != digest(ROOT / "scripts/qualify_saml_dependency.py"):
        raise ValueError("native inventory does not match qualified sources")
    binary = ROOT / "target/debug/easy-auth"
    if not binary.is_file():
        raise ValueError("build the combined server before recording inventory")
    prefix = Path(command(["pkg-config", "--variable=prefix", "openssl"]))
    executable = prefix / "bin/openssl"
    openssl = command([str(executable) if executable.is_file() else "openssl", "version"])
    clean = subprocess.run(["git", "diff", "--quiet", "HEAD", "--", "crates", "apps", "third-party", "Cargo.lock"], cwd=ROOT).returncode
    if clean not in (0, 1):
        raise ValueError("source state unavailable")
    inventory = dict(
        recorded_at=datetime.now(timezone.utc).isoformat(),
        source_base_commit=command(["git", "rev-parse", "HEAD"]),
        implementation_state="commit" if clean == 0 else "working-tree",
        source_inventory_sha256=report["source_inventory_sha256"],
        application_lock_sha256=report["application_lock_sha256"],
        qualification_report_sha256=digest(report_path),
        saml_activation_configuration_sha256=digest(ROOT / "apps/auth-server/src/configuration/saml/settings.rs"),
        reproducer_sha256=digest(Path(__file__)),
        system=platform.system(), release=platform.release(), machine=platform.machine(),
        rustc=command(["rustc", "-vV"]),
        ci_image={k: os.environ[k] for k in ("ImageOS", "ImageVersion") if k in os.environ},
        declared_build="cargo build --locked -p easy-auth-server --bin easy-auth --example embedded --features saml-web,oidc-web",
        binary=dict(path="target/debug/easy-auth", sha256=digest(binary), bytes=binary.stat().st_size),
        openssl_pkg_config_version=command(["pkg-config", "--modversion", "openssl"]),
        openssl_executable_version=openssl, linked_openssl_artifacts=native_libraries(binary),
        aws_lc_source=aws_lc_source(report), core_verification_source_sha256=sources,
        scope="observed development/CI build only; not a selected production deployment, independent audit, FIPS certification or resource envelope",
        production_security_approval=False)
    (ROOT / "target/saml-native-inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
    print(json.dumps(inventory))


if __name__ == "__main__":
    try:
        record()
    except (OSError, ValueError, KeyError, AttributeError, tarfile.TarError) as error:
        print(json.dumps({"status": "failed", "kind": type(error).__name__,
                          "reason": str(error) if type(error) is ValueError else "inventory unavailable"}))
        raise SystemExit(1) from None
