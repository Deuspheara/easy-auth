"""Inventory explicit committed npm inputs and shipped notices/assets only."""
import base64
import hashlib
import json
import os
from pathlib import PurePosixPath
import subprocess
from urllib.parse import urlsplit

NPM_LOCKS = ("website/package-lock.json", "tools/reference-ui/package-lock.json",
             "tests/browser/passkeys/package-lock.json")
ASSETS = ("docs/security/third-party-licenses", "crates/auth-axum/src/pages/vendor",
          "crates/auth-axum/src/pages/fonts", "LICENSE-MIT", "LICENSE-APACHE")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def committed_revision(root):
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip()
    if os.environ.get("GITHUB_SHA") and os.environ["GITHUB_SHA"] != revision:
        raise ValueError("inventory checkout differs from CI revision")
    return revision


def npm_record(root, name):
    lock = json.loads((root / name).read_text())
    if lock.get("lockfileVersion") != 3:
        raise ValueError("unsupported npm lock format")
    packages = []
    for location, package in lock["packages"].items():
        if not location:
            continue
        if ".." in PurePosixPath(location).parts or not location.startswith("node_modules/"):
            raise ValueError("unexpected npm package location")
        source = urlsplit(package["resolved"])
        if source.scheme != "https" or source.hostname != "registry.npmjs.org" \
                or source.username or source.password or source.query or source.fragment \
                or source.port not in (None, 443):
            raise ValueError("unreviewed npm source")
        integrity = package["integrity"]
        if not integrity.startswith("sha512-"):
            raise ValueError("npm archive integrity missing")
        if len(base64.b64decode(integrity[7:], validate=True)) != 64:
            raise ValueError("invalid npm archive integrity")
        packages.append(dict(location=location, version=package["version"],
                             source=package["resolved"], integrity=integrity,
                             license_expression=package.get("license"),
                             development=package.get("dev", False),
                             optional=package.get("optional", False)))
    return dict(lockfile=name, lock_sha256=digest(root / name),
                packages=sorted(packages, key=lambda p: p["location"]),
                missing_license_declarations=sum(not p["license_expression"] for p in packages),
                scope="Declared locked npm inventory including development/optional packages; not installed bytes or license approval")


def tracked_records(root, prefixes):
    names = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", "HEAD", "--", *prefixes],
                                    cwd=root).decode().splitlines()
    if not names:
        raise ValueError("commit reviewed inventory inputs first")
    result = []
    for name in names:
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("unexpected shipped asset path")
        result.append(dict(path=name, sha256=digest(path), bytes=path.stat().st_size))
    return result


def assets(root):
    result = tracked_records(root, ASSETS)
    if not any(item["path"].endswith("MPL-2.0.txt") for item in result):
        raise ValueError("shipped notice inventory missing")
    return result


def tracked_hashes(root, prefixes):
    return {item["path"]: item["sha256"] for item in tracked_records(root, prefixes)}
