"""Source identity and exclusive private receipt output, never runtime credentials."""
import hashlib
import json
import os
from pathlib import Path
import subprocess


def source_identity(root):
    paths = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root,
    ).decode().split("\0")
    records = []
    for name in sorted(set(paths) - {""}):
        path = root / name
        records.append([name, hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None])
    return dict(
        revision=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip(),
        clean=not bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=root)),
        file_count=len(records),
        files_sha256=hashlib.sha256(json.dumps(records, separators=(",", ":")).encode()).hexdigest(),
    )


def write_receipt(destination, result):
    with os.fdopen(os.open(Path(destination), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        json.dump(result, output, indent=2)


def ci_source_identity(root):
    source = source_identity(root)
    expected = os.environ.get("GITHUB_SHA")
    if expected and (expected != source["revision"] or not source["clean"]):
        raise ValueError("CI source must be the exact clean commit")
    return source
