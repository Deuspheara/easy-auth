"""Normalize Cargo's actual resolved graph without publishing local cache paths."""
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def identity(package):
    return package["name"], package["version"], package.get("source")


def checksum(package):
    value = package.get("checksum")
    if package.get("source") != REGISTRY or not isinstance(value, str) \
            or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("unreviewed registry or missing lock checksum")
    return value


def package_record(package, locked, root):
    source = package["source"]
    if not package.get("license"):
        raise ValueError("resolved Cargo package has no declared license expression")
    result = dict(name=package["name"], version=package["version"],
                  license_expression=package["license"], source=source)
    if source:
        result["declared_archive_sha256"] = checksum(locked)
    else:
        manifest = Path(package["manifest_path"])
        if manifest.is_symlink():
            raise ValueError("symlinked local Cargo manifest")
        manifest = manifest.resolve(strict=True)
        relative = manifest.relative_to(root.resolve())
        if relative.name != "Cargo.toml":
            raise ValueError("local Cargo package manifest outside source")
        tracked = subprocess.run(["git", "ls-files", "--error-unmatch", "--", relative.as_posix()],
                                 cwd=root, capture_output=True)
        if tracked.returncode:
            raise ValueError("uncommitted local Cargo package manifest")
        result.update(source="path:" + relative.parent.as_posix(),
                      manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest())
    return result


def normalize(metadata, lock, root):
    locked = {identity(p): p for p in lock["package"]}
    if len(locked) != len(lock["package"]):
        raise ValueError("duplicate Cargo lock identity")
    packages, references = [], {}
    for package in metadata["packages"]:
        record = package_record(package, locked[identity(package)], root)
        reference = record["name"] + "@" + record["version"] + " (" + record["source"] + ")"
        record["ref"] = reference
        references[package["id"]] = reference
        packages.append(record)
    if len(references) != len(packages) or len({p["ref"] for p in packages}) != len(packages):
        raise ValueError("ambiguous resolved Cargo identity")
    nodes = metadata["resolve"]["nodes"]
    if {n["id"] for n in nodes} != set(references) or len(nodes) != len(references):
        raise ValueError("incomplete resolved Cargo graph")
    graph = []
    for node in nodes:
        dependencies = [dict(ref=references[d["pkg"]], kinds=d["dep_kinds"])
                        for d in node["deps"]]
        graph.append(dict(ref=references[node["id"]], features=sorted(node["features"]),
                          dependencies=sorted(dependencies, key=lambda d: d["ref"])))
    resolved = {identity(p) for p in metadata["packages"]}
    inactive = [dict(name=p["name"], version=p["version"], source=p["source"],
                     declared_archive_sha256=checksum(p))
                for p in lock["package"] if identity(p) not in resolved]
    return dict(packages=sorted(packages, key=lambda p: p["ref"]),
                metadata_graph=sorted(graph, key=lambda p: p["ref"]),
                workspace_members=sorted(references[p] for p in metadata["workspace_members"]),
                lock_entries_outside_metadata=sorted(inactive, key=lambda p: (p["name"], p["version"])))


def selected_references(tree, packages):
    references = {}
    for package in packages:
        key = package["name"], "v" + package["version"]
        if key in references:
            raise ValueError("ambiguous Cargo tree package identity")
        references[key] = package["ref"]
    selected = set()
    for line in tree.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) < 2 or (fields[0], fields[1]) not in references:
            raise ValueError("Cargo tree differs from metadata inventory")
        selected.add(references[fields[0], fields[1]])
    if not selected:
        raise ValueError("empty selected Cargo graph")
    return sorted(selected)


def record(root, manifest):
    manifest = root / manifest
    result = subprocess.run(["cargo", "metadata", "--locked", "--offline", "--all-features",
                             "--format-version", "1", "--manifest-path", str(manifest)],
                            cwd=root, capture_output=True, check=True, timeout=120)
    lock_path = manifest.parent / "Cargo.lock"
    report = normalize(json.loads(result.stdout), tomllib.loads(lock_path.read_text()), root)
    tree = subprocess.run(["cargo", "tree", "--locked", "--offline", "--workspace", "--target", "all",
                           "--all-features", "--edges", "normal,build,dev", "--prefix", "none",
                           "--format", "{p}", "--no-dedupe", "--manifest-path", str(manifest)],
                          cwd=root, capture_output=True, text=True, check=True, timeout=120)
    selected = selected_references(tree.stdout, report["packages"])
    report.update(manifest=manifest.relative_to(root).as_posix(),
                  manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
                  lock_sha256=hashlib.sha256(lock_path.read_bytes()).hexdigest(),
                  selected_all_target_feature_refs=selected,
                  unselected_metadata_refs=sorted(p["ref"] for p in report["packages"] if p["ref"] not in selected),
                  scope="Metadata is a resolver overapproximation; selected refs independently derive from all-feature/all-target normal/build/dev cargo tree. Neither proves all-target compilation, license approval or verified cache bytes")
    return report
