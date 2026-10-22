#!/usr/bin/env python3
"""Check app/proxy build filtering with ordinary owned non-secret text markers."""
import json
from pathlib import Path
import subprocess

from saml_release.context import check


if __name__ == "__main__":
    try:
        record = check()
        Path("target").mkdir(exist_ok=True)
        Path("target/saml-build-context.json").write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps(record))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "failed", "kind": type(error).__name__,
                          "reason": str(error) if type(error) is ValueError else "context check unavailable"}))
        raise SystemExit(1) from None
