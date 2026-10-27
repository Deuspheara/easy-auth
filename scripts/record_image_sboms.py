#!/usr/bin/env python3
"""Offline CycloneDX image inventories from already assessed exact image reports."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from record_supply_chain_sboms import image_reports
from supply_chain.trivy_sbom import image, SCANNER


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image-report", action="append", required=True)
    args = parser.parse_args()
    reports = image_reports(args.image_report)
    args.output.mkdir(mode=0o700)
    records = [image(path, args.output, name) for name, path in sorted(reports.items())]
    report = dict(images=records, scanner_image=SCANNER, image_upload=False,
                  scanner_network="none", production_security_approval=False)
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(status="recorded", image_sboms=len(records), production_security_approval=False)))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps(dict(status="failed", category=type(error).__name__)), file=sys.stderr)
        raise SystemExit(1) from None
