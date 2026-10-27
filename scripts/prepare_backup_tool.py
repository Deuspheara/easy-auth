#!/usr/bin/env python3
"""Python3.12+: prepare the pinned age backup commands in a new private directory."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tarfile

from operational_recovery.backup_tool.build import prepare


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    options = parser.parse_args()
    receipt = prepare(options.destination.absolute())
    print(json.dumps(dict(status="prepared", binaries=receipt["binaries"],
                          production_security_approval=False)))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(json.dumps(dict(status="failed", category=type(error).__name__)), file=sys.stderr)
        raise SystemExit(1) from None
