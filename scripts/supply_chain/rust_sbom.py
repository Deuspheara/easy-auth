"""Official Rust SBOM generation, explicit source-ref normalization and coverage."""
import hashlib
import json
from pathlib import Path
import subprocess
import os


def components(document):
    result = []

    def visit(component):
        result.append(component)
        for child in component.get("components", []):
            visit(child)

    if "component" in document.get("metadata", {}):
        visit(document["metadata"]["component"])
    for component in document.get("components", []):
        visit(component)
    return result


def verify_references(document):
    references = [c["bom-ref"] for c in components(document)]
    if len(references) != len(set(references)):
        raise ValueError("duplicate SBOM component reference")
    for node in document.get("dependencies", []):
        if node["ref"] not in references or not set(node.get("dependsOn", [])).issubset(references):
            raise ValueError("dangling SBOM dependency reference")


def normalize_source_refs(value, source_uri, revision):
    if isinstance(value, dict):
        return {key: normalize_source_refs(item, source_uri, revision) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_source_refs(item, source_uri, revision) for item in value]
    if isinstance(value, str) and source_uri in value:
        prefix = "path+" + source_uri
        if not value.startswith(prefix) or value[len(prefix):len(prefix) + 1] not in ("/", "#"):
            raise ValueError("unexpected absolute source path in SBOM")
        return "path+file:///source/" + revision + value[len(prefix):]
    return value


def selected_packages(source, manifest, features):
    arguments = ["cargo", "tree", "--locked", "--offline", "--target", "all",
                 "--edges", "normal,build", "--prefix", "none", "--format", "{p}",
                 "--no-dedupe", "--manifest-path", str(source / manifest), *features]
    tree = subprocess.run(arguments, cwd=source, capture_output=True, text=True, check=True, timeout=120)
    selected = set()
    for line in tree.stdout.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 2 or not fields[1].startswith("v"):
            raise ValueError("unexpected selected SBOM graph output")
        selected.add((fields[0], fields[1][1:]))
    if not selected:
        raise ValueError("empty selected SBOM graph")
    return selected


def export_document(path, source, destination, revision, profile, root_licenses):
    raw = path.read_bytes()
    document = json.loads(raw)
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.5":
        raise ValueError("unexpected official Rust SBOM format")
    verify_references(document)
    normalized = normalize_source_refs(document, source.as_uri(), revision)
    verify_references(normalized)
    root = normalized["metadata"]["component"]
    expression = root_licenses[root["name"]]
    if not expression:
        raise ValueError("source root license declaration missing")
    license_added = not root.get("licenses")
    if license_added:
        root["licenses"] = [{"expression": expression}]
    elif root["licenses"] != [{"expression": expression}]:
        raise ValueError("SBOM root license differs from Cargo metadata")
    # Nested metadata components are Cargo targets (lib.rs/bin), not separately
    # licensed packages. The generator's flat dependency list holds package data.
    package_components = [root, *normalized.get("components", [])]
    if any(not c.get("licenses") for c in package_components):
        raise ValueError("Rust SBOM component license missing")
    identities = {(c["name"], c.get("version")) for c in package_components}
    data = (json.dumps(normalized, indent=2) + "\n").encode()
    if any(marker in data for marker in (b"/Users/", b"/private/tmp/", str(source).encode())):
        raise ValueError("local filesystem path remains in Rust SBOM")
    target = destination / (profile + "-" + document["metadata"]["component"]["name"] + ".cdx.json")
    with target.open("xb") as output:
        output.write(data)
    record = dict(path=target.name, sha256=hashlib.sha256(data).hexdigest(),
                  raw_generator_sha256=hashlib.sha256(raw).hexdigest(),
                  root_license_from_cargo_metadata=expression if license_added else None)
    return record, identities, document["metadata"]["component"]["name"]


def generate(source, destination, binary, revision, epoch, profile, manifest, features):
    expected = selected_packages(source, manifest, features)
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version", "1",
         "--manifest-path", str(source / manifest), *features], cwd=source))
    roots = {p["name"] for p in metadata["packages"] if p["id"] in metadata["workspace_members"]}
    root_licenses = {p["name"]: p["license"] for p in metadata["packages"] if p["name"] in roots}
    before_locks = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in (source / "Cargo.lock", source / "examples/clients/rust/Cargo.lock")}
    name = "supply-chain-" + profile
    environment = dict(os.environ, CARGO_NET_OFFLINE="true", SOURCE_DATE_EPOCH=epoch)
    with (destination / (profile + ".log")).open("x") as output:
        subprocess.run([str(binary), "cyclonedx", "--manifest-path", str(source / manifest),
                        "--target", "all", "--format", "json", "--spec-version", "1.5",
                        "--override-filename", name, "--license-strict", *features],
                       cwd=source, env=environment, stdout=output, stderr=subprocess.STDOUT,
                       check=True, timeout=120)
    records, observed, generated_roots = [], set(), set()
    for path in sorted(source.rglob(name + ".json")):
        record, identities, package = export_document(path, source, destination, revision, profile, root_licenses)
        records.append(record)
        observed.update(identities)
        generated_roots.add(package)
    if generated_roots != roots or len(records) != len(roots) or expected - observed:
        raise ValueError("Rust SBOM omits selected normal/build package identities")
    if any(hashlib.sha256((source / name).read_bytes()).hexdigest() != checksum
           for name, checksum in before_locks.items()):
        raise ValueError("SBOM generator changed source lock inputs")
    return dict(profile=profile, records=records, selected_normal_build_packages=len(expected),
                observed_source_package_identities=len(observed), missing_selected_packages=[],
                resolver_overapproximation=sorted(observed - expected),
                normalization="Exported absolute path+file source refs map to file:///source/<commit>; missing own-root license is supplied from exact Cargo metadata. Dependency PURLs/licenses/versions/hashes are unchanged",
                scope="Feature/target-aware source SBOM; resolver-only components retained, dev dependencies excluded, not observed binary linkage")
