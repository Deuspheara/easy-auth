#!/usr/bin/env python3
"""Assess all image advisory severities; fail on any high/critical finding."""
import argparse
import json
from pathlib import Path
import subprocess

from saml_release.advisories import assess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--proxy-image", required=True)
    parser.add_argument("--output", type=Path, default=Path("target/saml-release-advisories"))
    args = parser.parse_args()
    summary = assess(args.image, args.proxy_image, args.output)
    print(json.dumps({"images": summary["images"], "production_security_approval": False}))
    if not all(item["high_critical_gate_passed"] for item in summary["images"].values()):
        raise ValueError("release image high/critical advisory gate failed; full findings retained")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "failed", "kind": type(error).__name__,
                          "reason": str(error) if type(error) is ValueError else "advisory assessment unavailable"}))
        raise SystemExit(1) from None
