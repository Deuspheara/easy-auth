"""Assess finite engine outcomes; failed controls never become signature denials."""
import json
import os
from pathlib import Path
import signal
import subprocess

POSITIVES = {"healthy-before", "second-healthy", "healthy-after"}
DENIALS = {"wrong-key", "missing-key", "untrusted-keyinfo", "weak-digest",
           "tampered-subject", "duplicate-id", "unsigned", "altered-signature"}
WRAPPERS = {"forged-sibling-before", "forged-sibling-after"}
SYNTAX = {"doctype", "malformed", "multiple-roots"}
CASES = POSITIVES | DENIALS | WRAPPERS | SYNTAX | {"rollover"}
MODES = {"rooted", "predigest"}
ERRORS = {"none", "invalid_signature", "invalid_encoding", "duplicate_id",
          "invalid_id", "xml_parse", "reference_rejected", "engine_error"}
KNOWN_DENIALS = ERRORS - {"none", "engine_error"}


class InfrastructureFailure(Exception):
    pass


def capture():
    artifacts = [json.loads(line) for line in
                 Path("/work/signature-artifacts.json").read_text().splitlines()]
    binaries = [item["executable"] for item in artifacts
                if item.get("reason") == "compiler-artifact"
                and item.get("target", {}).get("name") == "auth32_signature_probe"
                and item.get("executable")]
    if len(binaries) != 1:
        raise InfrastructureFailure("signature_fixture_missing")
    process = subprocess.Popen(binaries, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate(timeout=2)
        raise InfrastructureFailure("signature_fixture_timeout") from None
    if process.returncode != 0:
        raise InfrastructureFailure("signature_fixture_unavailable")
    return [json.loads(line) for line in stdout.splitlines()], bool(stderr)


def validate(rows):
    seen = set()
    fields = {"case", "mode", "accepted", "trusted_subject", "attacker_marker",
              "wrapper_marker", "error_class"}
    for row in rows:
        if not isinstance(row, dict) or set(row) != fields:
            raise InfrastructureFailure("invalid_engine_ipc")
        pair = row["case"], row["mode"]
        if (pair in seen or pair[0] not in CASES or pair[1] not in MODES
                or row["error_class"] not in ERRORS
                or any(type(row[key]) is not bool for key in
                       ("accepted", "trusted_subject", "attacker_marker", "wrapper_marker"))
                or row["accepted"] != (row["error_class"] == "none")
                or (not row["accepted"] and any(row[key] for key in
                    ("trusted_subject", "attacker_marker", "wrapper_marker")))):
            raise InfrastructureFailure("invalid_engine_ipc")
        seen.add(pair)
    if seen != {(case, mode) for case in CASES for mode in MODES}:
        raise InfrastructureFailure("engine_cases_incomplete")


def safe_content(row):
    return (row["accepted"] and row["trusted_subject"]
            and not row["attacker_marker"] and not row["wrapper_marker"])


def assess(row):
    if not row["accepted"] and row["error_class"] == "engine_error":
        return "requires_engine_error_review"
    if row["case"] in DENIALS | SYNTAX:
        return "rejected" if row["error_class"] in KNOWN_DENIALS else "policy_gap"
    if row["case"] in WRAPPERS and row["error_class"] in KNOWN_DENIALS:
        return "rejected"
    return "verified_content_only" if safe_content(row) else "policy_gap"


def run():
    rows, diagnostics = capture()
    validate(rows)
    if any(not safe_content(row) for row in rows if row["case"] in POSITIVES):
        raise InfrastructureFailure("signed_positive_control_failed")
    for row in rows:
        row["assessment"] = assess(row)
    gaps = [row for row in rows if row["assessment"] == "policy_gap"]
    unresolved = [row for row in rows if row["assessment"] == "requires_engine_error_review"]
    return {
        "status": "candidate_controls_incomplete" if gaps or unresolved else "engine_controls_passed",
        "execution_completed": True, "candidate_controls_passed": not (gaps or unresolved),
        "scope": "signed Response engine only; no SAML profile or authentication acceptance",
        "positive_control_rows": sum(row["case"] in POSITIVES for row in rows),
        "policy_gap_rows": len(gaps), "unresolved_engine_rows": len(unresolved),
        "native_diagnostics_emitted": diagnostics, "rows": rows,
    }


if __name__ == "__main__":
    try:
        result = run()
        print(json.dumps(result, sort_keys=True))
        raise SystemExit(0 if result["candidate_controls_passed"] else 1)
    except InfrastructureFailure as error:
        print(json.dumps({"status": "infrastructure_failed", "stage": str(error)}))
        raise SystemExit(2) from None
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps({"status": "infrastructure_failed", "stage": "engine_observer_unavailable"}))
        raise SystemExit(2) from None
