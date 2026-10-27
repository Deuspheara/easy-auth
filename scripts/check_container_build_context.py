#!/usr/bin/env python3
"""Exercise the default Docker allowlist using only owned, non-secret markers."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "Cargo.toml", "Cargo.lock", ".cargo/config.toml", "LICENSE-MIT", "LICENSE-APACHE",
    "apps/auth-server/src/main.rs", "crates/auth-core/src/lib.rs",
    "third-party/saml-rs/Cargo.toml", "docs/security/third-party-licenses/notice.txt",
)
EXCLUDED = (
    ".env", ".env.example", ".cargo/credentials.toml", ".git/config",
    ".aws/credentials", "docs/security/private-review.md", "docs/research/private.md",
    "docs/planning/private.md", "website/private.txt", "scripts/private.py",
    "apps/auth-server/.env.local", "apps/auth-server/private.key",
    "apps/auth-server/local-settings.env",
    "apps/auth-server/apple-private.p8",
    "crates/auth-core/private.pem", "crates/auth-core/target/private.txt",
    "apps/auth-server/node_modules/private.txt",
)


def check():
    rules = (ROOT / ".dockerignore").read_bytes()
    with tempfile.TemporaryDirectory(prefix="easy-auth-default-context-") as directory:
        temporary = Path(directory)
        source = temporary / "source"
        source.mkdir()
        for name in REQUIRED + EXCLUDED:
            marker = source / name
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text("ordinary owned build-context marker\n")
        (source / ".dockerignore").write_bytes(rules)
        # Scratch + local export exercises Docker filtering without executing a
        # copied file, pulling a base image or reading the user's working copy.
        (source / "Dockerfile").write_text("FROM scratch\nCOPY . /context\n")
        output = temporary / "export"
        result = subprocess.run(
            ["docker", "build", "--progress=plain", "--output", f"type=local,dest={output}",
             str(source)], capture_output=True, timeout=180,
        )
        if result.returncode:
            raise ValueError("owned Docker context export failed")
        if any(not (output / "context" / name).is_file() for name in REQUIRED):
            raise ValueError("required default build marker excluded")
        if any((output / "context" / name).exists() for name in EXCLUDED):
            raise ValueError("private marker admitted to default build context")
    return {"rules_sha256": hashlib.sha256(rules).hexdigest(),
            "required_markers_present": len(REQUIRED),
            "private_markers_excluded": len(EXCLUDED),
            "private_files_read": False, "copied_files_executed": False}


if __name__ == "__main__":
    try:
        print(json.dumps(check()))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "failed", "category": type(error).__name__}))
        raise SystemExit(1) from None
