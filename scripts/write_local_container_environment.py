#!/usr/bin/env python3
"""Create an exclusive private settings file; never print generated credentials."""
import os
from pathlib import Path
import sys

from container_examples.settings import development_settings


def main():
    if len(sys.argv) != 2:
        raise ValueError("one new private destination required")
    destination = Path(sys.argv[1])
    if destination.resolve().is_relative_to(Path(__file__).resolve().parents[1]):
        raise ValueError("choose a private destination outside the source tree")
    values = development_settings()
    with os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        output.write("".join(name + "=" + value + "\n" for name, value in values.items()))
    print("Created private local container settings; retain them for this project's restarts.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        reason = str(error) if type(error) is ValueError else type(error).__name__
        print("Local settings creation failed: " + reason, file=sys.stderr)
        raise SystemExit(1) from None
