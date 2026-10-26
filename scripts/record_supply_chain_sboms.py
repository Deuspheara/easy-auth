#!/usr/bin/env python3
"""Generate reviewed source SBOMs using a prepared official tool and pinned scanner."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from supply_chain import rust_sbom, trivy_sbom, sources

ROOT = Path(__file__).resolve().parents[1]
IMAGE_NAMES = {"default", "default-proxy", "saml", "saml-proxy"}
PROFILES = (
    ("default", "apps/auth-server/Cargo.toml", []),
    ("saml", "apps/auth-server/Cargo.toml", ["--features", "saml-web,oidc-web"]),
    ("all-features", "Cargo.toml", ["--all-features"]),
    ("consumer", "examples/clients/rust/Cargo.toml", ["--all-features"]),
)
NPM = (("website", "website/package-lock.json"),
       ("reference-ui", "tools/reference-ui/package-lock.json"),
       ("browser-tests", "tests/browser/passkeys/package-lock.json"))


def prepared_tool(directory):
    receipt = json.loads((directory / "receipt.json").read_text())
    pin = json.loads((ROOT / "tools/supply-chain/cargo-cyclonedx.json").read_text())
    binary = directory / "cargo-cyclonedx-0.5.9/target/release/cargo-cyclonedx"
    if receipt["source"] != pin or not receipt["advisory_and_license_checks_passed"] \
            or receipt["binary_sha256"] != hashlib.sha256(binary.read_bytes()).hexdigest() \
            or receipt["tooling_policy_sha256"] != hashlib.sha256((ROOT / "tools/supply-chain/deny.toml").read_bytes()).hexdigest() \
            or receipt["bootstrap_sha256"] != hashlib.sha256((ROOT / "scripts/prepare_sbom_tool.py").read_bytes()).hexdigest():
        raise ValueError("prepared SBOM generator identity/checks mismatch")
    return binary, receipt


def image_reports(arguments):
    reports = {}
    for value in arguments:
        name, separator, path = value.partition("=")
        if not separator or name not in IMAGE_NAMES or name in reports:
            raise ValueError("use distinct known image-report names")
        reports[name] = Path(path).resolve(strict=True)
    return reports


def generate(destination, directory, reports):
    binary, receipt = prepared_tool(directory)
    destination.mkdir(mode=0o700)
    revision = sources.committed_revision(ROOT)
    epoch = subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=ROOT).decode().strip()
    with tempfile.TemporaryDirectory(prefix="easy-auth-sbom-export-") as temporary:
        source = Path(temporary) / "source"
        source.mkdir()
        archive = Path(temporary) / "source.tar"
        with archive.open("xb") as output:
            subprocess.run(["git", "archive", revision], cwd=ROOT, stdout=output, check=True)
        subprocess.run(["tar", "-xf", str(archive), "-C", str(source)], check=True)
        rust = [rust_sbom.generate(source, destination, binary, revision, epoch, *profile)
                for profile in PROFILES]
        npm = [trivy_sbom.npm(source, destination, name, lock) for name, lock in NPM]
    images = [trivy_sbom.image(path, destination, name) for name, path in sorted(reports.items())]
    report = dict(source_base_revision=revision, source_date_epoch=epoch, rust=rust, npm=npm,
                  images=images, generator=receipt, scanner_image=trivy_sbom.SCANNER,
                  image_upload=False, scanner_network="none", production_security_approval=False,
                  generator_sha256=sources.tracked_hashes(ROOT, ["scripts/record_supply_chain_sboms.py", "scripts/supply_chain"]),
                  scope="Source and exact-image package inventories; resolver-only packages retained; not binary reachability, license approval or protocol compliance")
    (destination / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tool-directory", type=Path, required=True)
    parser.add_argument("--image-report", action="append", default=[])
    args = parser.parse_args()
    report = generate(args.output.absolute(), args.tool_directory.absolute(), image_reports(args.image_report))
    print(json.dumps(dict(status="recorded", rust_profiles=len(report["rust"]),
                          npm_profiles=len(report["npm"]), image_sboms=len(report["images"]),
                          production_security_approval=False)))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps(dict(status="failed", category=type(error).__name__)), file=sys.stderr)
        raise SystemExit(1) from None
