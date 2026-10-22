#!/usr/bin/env python3
"""Record exact build input bytes inside the controlled release build context."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def record():
    files = [ROOT / name for name in ("Cargo.toml", "Cargo.lock", ".cargo/config.toml")]
    for folder in ("apps", "crates", "third-party", "tests/support",
                   "tests/provider/saml/rust-policy/patches", "scripts", "deploy/saml"):
        files.extend(path for path in (ROOT / folder).rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc")
    hashes = {}
    for path in sorted(files):
        if path.is_symlink():
            raise ValueError("build source symlinks are not supported")
        hashes[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    print(json.dumps(dict(source_files=[dict(path=name, sha256=checksum)
                                      for name, checksum in hashes.items()],
                         scope="Build-context source identity; not reproducible-build proof or security approval")))


if __name__ == "__main__":
    record()
