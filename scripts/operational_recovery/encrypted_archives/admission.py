"""Admit the protected prepared tool, native identities and private archive files."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from ..backup_tool.build import load_inputs

MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
KEY_FILE_LIMIT = 4096
CHUNK_BYTES = 64 * 1024


def private_directory(path):
    value = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.getuid() or value.st_mode & 0o077:
        raise ValueError("archive directory must be private and owned")


def private_file(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        value = os.fstat(descriptor)
        if not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid() or value.st_mode & 0o077:
            raise ValueError("archive input must be an owned private regular file")
        os.set_blocking(descriptor, True)
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def digest(stream, limit=MAX_ARCHIVE_BYTES):
    result, count = hashlib.sha256(), 0
    while block := stream.read(CHUNK_BYTES):
        count += len(block)
        if count > limit:
            raise ValueError("archive input exceeds size bound")
        result.update(block)
    return result.hexdigest()


def native_recipient(value):
    # Only choose the native profile here; age validates the actual key/checksum.
    if not re.fullmatch(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}", value):
        raise ValueError("an explicit native age recipient is required")
    return value


def native_identity(path):
    with private_file(path) as stream:
        data = stream.read(KEY_FILE_LIMIT + 1)
    lines = [line for line in data.splitlines() if line and not line.startswith(b"#")]
    if len(data) > KEY_FILE_LIMIT or len(lines) != 1 \
            or not re.fullmatch(rb"AGE-SECRET-KEY-1[023456789ACDEFGHJKLMNPQRSTUVWXYZ]{58}", lines[0]):
        raise ValueError("one protected native age identity is required")


def prepared_tool(path):
    path = Path(path).absolute()
    private_directory(path)
    with private_file(path / "receipt.json") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("backup tool receipt exceeds bound")
    receipt = json.loads(raw)
    if receipt["pin"] != load_inputs()[0] or receipt["production_security_approval"] is not False \
            or set(receipt["assessment"]) != {"age", "age-keygen", "govulncheck", "source"} \
            or not all(entry["imported_package_gate_passed"] is True for entry in receipt["assessment"].values()):
        raise ValueError("prepared backup tool assessment mismatch")
    value = (path / "bin").stat(follow_symlinks=False)
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.getuid() or value.st_mode & 0o022:
        raise ValueError("backup tool binary directory is writable by another principal")
    for name in ("age", "age-keygen", "govulncheck"):
        binary = path / "bin" / name
        value = binary.stat(follow_symlinks=False)
        if not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid() or value.st_mode & 0o022:
            raise ValueError("backup tool binary is not a protected regular file")
        with binary.open("rb") as stream:
            if digest(stream, 64 * 1024 * 1024) != receipt["binaries"][name]:
                raise ValueError("prepared backup tool binary changed")
    return path, receipt
