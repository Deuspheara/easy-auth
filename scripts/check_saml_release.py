#!/usr/bin/env python3
"""Verify the disabled release artifact using ordinary startup and metadata only."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

from saml_release import docker, inventory, proxy, runtime


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--proxy-image", required=True)
    parser.add_argument("--output", type=Path, default=Path("target/saml-release-inventory.json"))
    arguments = parser.parse_args()
    record = inventory.record(arguments.image)
    image = record["image_id"]
    proxy_image = inventory.proxy_record(arguments.proxy_image)
    for option in ("--version", "--help"):
        output = docker.run(["run", "--rm", "--network", "none", "--read-only", image, option])
        if "easy-auth" not in output:
            raise ValueError("release CLI check failed")
    record.update(recorded_at=datetime.now(timezone.utc).isoformat(),
                  cli_checks_passed=2, activation_refused=runtime.activation_refused(image),
                  startup=runtime.compose_check(image, proxy_image["image_id"]),
                  proxy={**proxy_image, **proxy.check(proxy_image["image_id"])},
                  production_security_approval=False)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({key: record[key] for key in ("image_id", "architecture", "source_revision",
          "binary_sha256", "cli_checks_passed", "activation_refused", "startup",
          "production_security_approval")}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "failed", "kind": type(error).__name__,
                          "reason": str(error) if type(error) is ValueError else "release check unavailable"}))
        raise SystemExit(1) from None
