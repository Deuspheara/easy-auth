#!/usr/bin/env python3
"""Build a selected pinned public ancestor for the owned operational upgrade drill."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tarfile

from operational_recovery.upgrade_source import prepare


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--profile", choices=("schema37", "schema38"), default="schema37")
    try:
        options = parser.parse_args()
        receipt = prepare(options.destination.absolute(), options.profile)
        print(json.dumps(dict(status="prepared", revision=receipt["pin"]["revision"],
            binary_sha256=receipt["binary_sha256"], production_acceptance=False)))
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(json.dumps(dict(status="failed", category=type(error).__name__)), file=sys.stderr)
        raise SystemExit(1) from None
