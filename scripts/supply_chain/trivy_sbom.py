"""Offline standard npm/image SBOMs from explicit public inputs only."""
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

if __package__ == "scripts.supply_chain":
    from ..saml_release import docker
    from ..saml_release.advisories import SCANNER
    from ..saml_release.inventory import snapshot
else:
    from saml_release import docker
    from saml_release.advisories import SCANNER
    from saml_release.inventory import snapshot
from .rust_sbom import components, verify_references

COPYRIGHT = {
    "libgcc-s1": "usr/share/doc/gcc-14-base/copyright",
    "libgomp1": "usr/share/doc/gcc-14-base/copyright",
    "libstdc++6": "usr/share/doc/gcc-14-base/copyright",
    "libcrypt1": "usr/share/doc/libcrypt1/copyright",
}


def publish(document, destination, name, expected, *, use_purls=False):
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.7":
        raise ValueError("unexpected pinned scanner SBOM format")
    verify_references(document)
    libraries = [c for c in components(document) if c.get("type") == "library"]
    if use_purls:
        observed = {c["purl"] for c in libraries}
    else:
        observed = {((c["group"] + "/" if c.get("group") else "") + c["name"], c.get("version"))
                    for c in libraries}
    if not expected or expected - observed:
        raise ValueError("scanner SBOM omitted inventoried package identities")
    data = (json.dumps(document, indent=2) + "\n").encode()
    if any(marker in data for marker in (b"/Users/", b"/private/tmp/")):
        raise ValueError("local filesystem path in scanner SBOM")
    target = destination / (name + ".cdx.json")
    with target.open("xb") as output:
        output.write(data)
    return dict(path=target.name, sha256=hashlib.sha256(data).hexdigest(),
                expected_package_identities=len(expected), missing_package_identities=[],
                identity_comparison="full package URL" if use_purls else "scoped name and version",
                additional_identities=sorted(observed - expected),
                components_without_reported_license=sum(not c.get("licenses") for c in libraries),
                scope="Package SBOM, no license/security approval; missing license fields remain explicit")


def scanner(directory, arguments, source=None):
    (directory / "empty-config.yaml").write_text("{}\n")
    mounts = ["--mount", f"type=bind,src={directory},dst=/owned"]
    if source:
        mounts += ["--mount", f"type=bind,src={source},dst=/source,readonly"]
    operation, *options = arguments
    docker.run(["run", "--rm", "--network", "none", *mounts, SCANNER, operation,
                "--config", "/owned/empty-config.yaml", "--ignorefile", "/dev/null", *options], timeout=120)


def npm(source, destination, name, lock):
    packages = json.loads((source / lock).read_text())["packages"]
    expected = {(location.rsplit("node_modules/", 1)[-1], p["version"])
                for location, p in packages.items() if location}
    with tempfile.TemporaryDirectory(prefix="easy-auth-npm-sbom-") as temporary:
        directory = Path(temporary)
        inputs = directory / "source"
        inputs.mkdir()
        for filename in ("package-lock.json", "package.json"):
            shutil.copyfile((source / lock).parent / filename, inputs / filename)
        scanner(directory, ["fs", "--disable-telemetry", "--offline-scan", "--skip-db-update",
                            "--scanners", "license", "--include-dev-deps", "--format", "cyclonedx",
                            "--output", "/owned/bom.json", "/source"], inputs)
        document = json.loads((directory / "bom.json").read_text())
    return publish(document, destination, name, expected)


def retained_copyright(report, image_id):
    missing = [p for result in report["Results"] for p in result.get("Packages", [])
               if not p.get("Licenses")]
    if any(p["Name"] not in COPYRIGHT for p in missing):
        raise ValueError("new image license-metadata gap needs review")
    notices = []
    if missing:
        packages = {p["Name"]: p for result in report["Results"] for p in result.get("Packages", [])}
        for package in missing:
            if package["Name"] != "libcrypt1" and package["ID"].split("@", 1)[1] \
                    != packages["gcc-14-base"]["ID"].split("@", 1)[1]:
                raise ValueError("GCC runtime and retained notice package versions differ")
        wanted = {COPYRIGHT[p["Name"]] for p in missing}
        files, _, _ = snapshot(image_id, wanted)
        for path, data in sorted(files.items()):
            notices.append(dict(path=path, sha256=hashlib.sha256(data).hexdigest(), bytes=len(data),
                                related_packages=[p["Identifier"]["PURL"] for p in missing
                                                  if COPYRIGHT[p["Name"]] == path]))
    return notices


def image(report_path, destination, name):
    report = json.loads(report_path.read_text())
    image_id = report["Metadata"]["ImageID"]
    if report.get("ArtifactType") != "container_image" or not image_id.startswith("sha256:"):
        raise ValueError("image SBOM input lacks actual scanned image identity")
    # Trivy's Version field can omit Debian epoch/revision. Its full package URL
    # retains both, plus architecture/distro; compare that identity unchanged.
    expected = {p["Identifier"]["PURL"] for r in report["Results"] for p in r.get("Packages", [])}
    with tempfile.TemporaryDirectory(prefix="easy-auth-image-sbom-") as temporary:
        directory = Path(temporary)
        shutil.copyfile(report_path, directory / "input.json")
        scanner(directory, ["convert", "--format", "cyclonedx", "--output", "/owned/bom.json",
                            "/owned/input.json"])
        document = json.loads((directory / "bom.json").read_text())
    record = publish(document, destination, name, expected, use_purls=True)
    notices = retained_copyright(report, image_id)
    record.update(image_id=image_id, scanner_image=SCANNER,
                  input_report_sha256=hashlib.sha256(report_path.read_bytes()).hexdigest(),
                  retained_copyright_for_metadata_gaps=notices,
                  license_expression_inferred=False,
                  scope="Only packages in exact image scan; statically linked Rust/native source requires separate inventory")
    return record
