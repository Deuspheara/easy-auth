"""Run unchanged upstream assertions; preserve their exit status."""
import argparse
import json
import os
from pathlib import Path

IGNORED_POSITIVE = "idp::tests::test_accept_signed_with_correct_key_idp"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=("default", "ignored-positive"), default="default")
    arguments = parser.parse_args()
    artifacts = [
        json.loads(line)
        for line in Path("/work/compiler-artifacts.json").read_text().splitlines()
    ]
    binaries = [
        item["executable"]
        for item in artifacts
        if item.get("reason") == "compiler-artifact"
        and item.get("profile", {}).get("test")
        and item.get("executable")
    ]
    if len(binaries) != 1:
        raise SystemExit("Expected exactly one upstream library test binary")
    options = ["--test-threads=1"]
    if arguments.case == "ignored-positive":
        options += ["--ignored", "--exact", IGNORED_POSITIVE]
    os.execv(binaries[0], [binaries[0], *options])


if __name__ == "__main__":
    main()
