#!/usr/bin/env python3
"""Check the exact packaged SAML qualification source, including public vectors.

This is a source-integrity check, not XML/signature verification or approval.
Run before compiling the opt-in candidate or applying public-vector scan exceptions.
"""
from pathlib import Path, PurePosixPath
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "third-party/saml-rs"
MANIFEST = ROOT / "third-party/saml-rs-source.json"
REVISION = "3b289001a7a84d5a7ff7af2671991ab7098090bd"
PATCHES = (
    "0001-extract-verified-profile.patch",
    "0002-exact-sha256-profile.patch",
    "0003-reject-unclosed-document.patch",
)


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("expected a regular source file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check():
    manifest = json.loads(MANIFEST.read_text())
    if (manifest.get("format_version") != 1
            or manifest["revision"] != REVISION
            or manifest["package_version"] != "0.6.1"):
        raise ValueError("unexpected source revision/version")
    patches = manifest["existing_qualification_patches"]
    if set(patches) != set(PATCHES):
        raise ValueError("unexpected qualification patch set")
    for name in PATCHES:
        path = ROOT / "tests/provider/saml/rust-policy/patches" / name
        if digest(path) != patches[name]:
            raise ValueError("qualification patch hash mismatch")
    entries = manifest["files"]
    expected = {entry["path"]: entry["sha256"] for entry in entries}
    if len(expected) != len(entries):
        raise ValueError("duplicate source inventory path")
    if not expected:
        raise ValueError("empty source inventory")
    actual = set()
    for path in SOURCE.rglob("*"):
        if path.is_symlink():
            raise ValueError("source symlinks are unsupported")
        if path.is_file():
            actual.add(path.relative_to(SOURCE).as_posix())
    if actual != set(expected):
        raise ValueError("source file inventory mismatch")
    for name, fingerprint in expected.items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("invalid source inventory path")
        if digest(SOURCE / name) != fingerprint:
            raise ValueError("source file hash mismatch")
    provenance = json.loads((SOURCE / ".cargo_vcs_info.json").read_text())
    if provenance["git"] != {"sha1": REVISION, "dirty": True}:
        raise ValueError("unexpected packaged source provenance")
    print(f"SAML candidate source integrity: PASS ({len(actual)} files, three recorded patches)")
    print("Production dependency/security approval remains pending.")


if __name__ == "__main__":
    try:
        check()
    except (OSError, ValueError, KeyError, TypeError):
        # Do not print source lines, certificates, keys or unexpected input values.
        print("SAML candidate source integrity: FAIL", file=sys.stderr)
        sys.exit(1)
