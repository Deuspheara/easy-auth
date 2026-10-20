"""Fail closed on cargo-deny infrastructure errors, even with tool exit0."""
import argparse
import json
from pathlib import Path

CHECKS = {"advisories", "licenses", "sources"}


def assess(records, exit_code):
    logs = [row.get("fields", {}) for row in records if row.get("type") == "log"]
    if any(row.get("level") == "ERROR" for row in logs):
        return {"status": "infrastructure_failed", "reason": "tool_logged_error"}
    summaries = [row.get("fields", {}) for row in records if row.get("type") == "summary"]
    if len(summaries) != 1 or set(summaries[0]) != CHECKS:
        return {"status": "infrastructure_failed", "reason": "missing_or_ambiguous_summary"}
    summary = summaries[0]
    for counts in summary.values():
        if (set(counts) != {"errors", "warnings", "notes", "helps"} or
                any(type(value) is not int or value < 0 for value in counts.values())):
            return {"status": "infrastructure_failed", "reason": "invalid_summary_counts"}
    passed = exit_code == 0 and not any(row["errors"] for row in summary.values())
    diagnostics = [{"code": row["fields"].get("code"),
                    "severity": row["fields"].get("severity")}
                   for row in records if row.get("type") == "diagnostic"]
    return {"status": "checks_passed" if passed else "checks_failed",
            "summary": summary, "diagnostics": diagnostics,
            "tool_exit_code": exit_code, "production_gate_open": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--tool-exit-code", required=True, type=int)
    args = parser.parse_args()
    try:
        records = [json.loads(line) for line in args.report.read_text().splitlines()]
        report = assess(records, args.tool_exit_code)
    except (OSError, ValueError, TypeError, KeyError):
        report = {"status": "infrastructure_failed", "reason": "invalid_report"}
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report["status"] == "checks_passed" else
                     2 if report["status"] == "infrastructure_failed" else 1)


if __name__ == "__main__":
    main()
