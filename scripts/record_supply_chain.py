#!/usr/bin/env python3
"""Python 3.11+: create exclusive source inventory; no private tree scan or upload."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from supply_chain import cargo, sources

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ("Cargo.toml", "Cargo.lock", ".cargo", "apps", "crates", "third-party",
          "examples/clients/rust", *sources.NPM_LOCKS, "tools/reference-ui/package.json",
          "website/package.json", "tests/browser/passkeys/package.json",
          "scripts/record_supply_chain.py", "scripts/supply_chain",
          "docs/security/third-party-licenses", "tools/supply-chain", "LICENSE-MIT", "LICENSE-APACHE")


def record():
    clean = subprocess.run(["git", "diff", "--quiet", "HEAD", "--", *INPUTS], cwd=ROOT)
    if clean.returncode:
        raise ValueError("commit reviewed source inputs before recording inventory")
    inventory = dict(
        source_base_revision=sources.committed_revision(ROOT),
        cargo=[cargo.record(ROOT, name) for name in ("Cargo.toml", "examples/clients/rust/Cargo.toml")],
        npm=[sources.npm_record(ROOT, name) for name in sources.NPM_LOCKS],
        shipped_notices_and_assets=sources.assets(ROOT),
        maintained_saml_inventory_sha256=sources.digest(ROOT / "third-party/saml-rs-source.json"),
        tooling_inputs_sha256=sources.tracked_hashes(ROOT, ["tools/supply-chain"]),
        generator_sha256=sources.tracked_hashes(ROOT, ["scripts/record_supply_chain.py", "scripts/supply_chain"]),
        python_version=sys.version.split()[0],
        scope="Source identity and declared licenses; separate exact image/native artifacts and advisory/license decisions required",
        production_security_approval=False,
    )
    return inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    destination = parser.parse_args().output
    if destination.exists():
        raise ValueError("inventory destination already exists")
    inventory = record()
    data = (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode()
    with destination.open("xb") as output:
        output.write(data)
    print(json.dumps(dict(status="recorded", sha256=hashlib.sha256(data).hexdigest(),
                          cargo_packages=[len(p["packages"]) for p in inventory["cargo"]],
                          npm_packages=[len(p["packages"]) for p in inventory["npm"]],
                          production_security_approval=False)))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps(dict(status="failed", category=type(error).__name__)), file=sys.stderr)
        raise SystemExit(1) from None
