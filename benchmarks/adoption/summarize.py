#!/usr/bin/env python3
"""Print medians from saved native comparison reports."""
import argparse
import json
from pathlib import Path
import statistics


def summarize(directory):
    print("| Probe | Compiled packages | Binary MiB | Session RSS MiB | 1 worker validations/s | 8 workers validations/s |")
    print("| --- | ---: | ---: | ---: | ---: | ---: |")
    for project in ("easy", "rustauth", "lucid"):
        reports = [json.loads(path.read_text()) for path in sorted(directory.glob(f"measure-{project}-*.json"))]
        if not reports:
            raise SystemExit(f"No measurements for {project}")
        if not all(report["post_revoke_rejections"] == 64 and report["other_user_still_valid"] for report in reports):
            raise SystemExit(f"Revocation acceptance failed for {project}")
        dependencies = json.loads((directory / f"dependencies-{project}.json").read_text())
        trials = [trial for report in reports for trial in report["trials"]]
        rates = [statistics.median(trial["requests_per_second"] for trial in trials if trial["workers"] == workers)
                 for workers in (1, 8)]
        rss = statistics.median(report["sampled_session_peak_rss_kib"] for report in reports) / 1024
        print(f"| {project} | {dependencies['compiled_packages_including_probe']} | "
              f"{dependencies['binary_bytes'] / 1024**2:.2f} | {rss:.2f} | {rates[0]:.0f} | {rates[1]:.0f} |")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    summarize(parser.parse_args().directory)
