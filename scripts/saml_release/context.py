"""Build-filter regression using owned ordinary text markers, never private files."""
import hashlib
from pathlib import Path
import shutil
import tempfile

from . import docker

ROOT = Path(__file__).resolve().parents[2]
BASE = "debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad"
REQUIRED = ("Cargo.toml", ".cargo/config.toml", "apps/auth-server/Cargo.toml",
            "tests/support/fixture.rs", "third-party/saml-rs/README.md",
            "tests/provider/saml/rust-policy/patches/fixture.patch",
            "docs/security/third-party-licenses/fixture.txt", "deploy/saml/nginx.conf")
EXCLUDED = ("docs/security/saml-review-request.md", "docs/security/saml-independent-review-packet.md",
            "tests/provider/saml/rust-policy/bounds_fixtures.py",
            "tests/provider/saml/comparison/profile_control.rs", ".cargo/credentials.toml",
            "deploy/saml/runtime.env", "deploy/saml/private.key", "scripts/unapproved.py")


def check():
    results = []
    for name in ("Dockerfile.dockerignore", "proxy.Dockerfile.dockerignore"):
        rules = ROOT / "deploy/saml" / name
        with tempfile.TemporaryDirectory(prefix="easy-auth-context-") as directory:
            folder = Path(directory)
            for item in REQUIRED + EXCLUDED:
                path = folder / item
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("ordinary non-secret build-context marker\n")
            shutil.copyfile(rules, folder / "Dockerfile.dockerignore")
            checks = [f"test -f /context/{path}" for path in REQUIRED]
            checks += [f"test ! -e /context/{path}" for path in EXCLUDED]
            recipe = "# syntax=docker/dockerfile:1\nFROM " + BASE + "\n"
            recipe += "RUN --mount=type=bind,source=.,target=/context,readonly "
            recipe += " && ".join(checks) + "\n"
            (folder / "Dockerfile").write_text(recipe)
            docker.run(["build", "--progress=plain", "-f", str(folder / "Dockerfile"),
                        str(folder)], timeout=180)
        results.append(dict(rules=name, rules_sha256=hashlib.sha256(rules.read_bytes()).hexdigest(),
                            required_markers_present=len(REQUIRED), private_markers_excluded=len(EXCLUDED)))
    return dict(checks=results, private_files_read=False, private_files_executed=False,
                scope="Ordinary owned-text build-filter regression; no XML/crypto/resource probe")
