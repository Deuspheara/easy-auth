"""Observe the complete exact-policy Rust flow; never publish XML or raw errors."""
from base64 import b64decode, b64encode
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import threading
from http.server import HTTPServer

import parser_observe as parser
from comparison_run import rows as transport_rows

STRACE = "strace"
BINARY = "/work/rust-target/debug/examples/auth32_policy"
EXPORTER = "/work/target/debug/examples/auth32_corpus_export"
PROFILE = "/work/target/debug/examples/auth32_profile_export"
REFERENCES = {"profile-file-reference", "profile-http-reference", "profile-path-reference"}
POSITIVE = {"profile-healthy-response", "profile-healthy-assertion"}
DENIALS = {"xml_rejected", "trust_rejected", "coverage_rejected", "signature_rejected",
           "reference_rejected", "algorithm_rejected", "protocol_profile_rejected",
           "subject_confirmation_rejected", "time_rejected"}
NONPOLICY = {f"profile-{target}-{kind}{bits}" for target in ("response", "assertion")
             for kind in ("signature", "digest") for bits in (384, 512)}


def capture(command, data=None):
    result = subprocess.run(command, input=data, capture_output=True, timeout=30)
    if result.returncode:
        raise parser.InfrastructureFailure("child_or_observer_failed")
    return result.stdout, bool(result.stderr)


def corpus(port):
    values = []
    for command in ([EXPORTER], [EXPORTER, str(port)], [PROFILE, "--exact-policy"]):
        output, _diagnostics = capture(command)
        values.extend(transport_rows(output))
    values.extend(reference_inputs(values, port))
    keys = {(row["case"], row["mode"]) for row in values}
    if len(values) != 106 or len(keys) != 106:
        raise parser.InfrastructureFailure("incomplete_or_duplicate_corpus")
    data = "".join("\t".join([row["case"], row["mode"], row["xml_b64"],
                            ",".join(row["certs_b64"])]) + "\n" for row in values).encode()
    if len(data) >= 2 * 1024 * 1024:
        raise parser.InfrastructureFailure("transport_limit_exceeded")
    return data, keys


def reference_inputs(values, port):
    # Negative fixture mutation only, never input sanitization or a parser
    # boundary. Changing SignedInfo invalidates the signature; these cases
    # specifically test external-reference preflight before any resource use.
    originals = [row for row in values if row["case"] == "profile-healthy-response"]
    if len(originals) != 2:
        raise parser.InfrastructureFailure("reference_fixture_unavailable")
    result = []
    for original in originals:
        xml = b64decode(original["xml_b64"])
        prefix = b'<ds:Reference URI="'
        start = xml.index(prefix) + len(prefix)
        end = xml.index(b'"', start)
        for case, uri in [
            ("profile-file-reference", f"file://{parser.SENTINEL}"),
            ("profile-http-reference", f"http://127.0.0.1:{port}/reference"),
            ("profile-path-reference", str(parser.SENTINEL)),
        ]:
            altered = xml[:start] + uri.encode() + xml[end:]
            result.append({**original, "case": case, "xml_b64": b64encode(altered).decode()})
    return result


def validate_rows(values, keys, api):
    expected = {"case", "mode", "api", "accepted", "trusted_subject",
                "attacker_marker", "wrapper_marker", "error_class"}
    if len(values) != len(keys) or {(row["case"], row["mode"]) for row in values} != keys:
        raise parser.InfrastructureFailure("incomplete_result_rows")
    for row in values:
        if (set(row) != expected or row["api"] != api or
                any(type(row[key]) is not bool for key in
                    ("accepted", "trusted_subject", "attacker_marker", "wrapper_marker"))):
            raise parser.InfrastructureFailure("invalid_result_schema")


def observe(data, keys, directory):
    trace = directory / "exact.trace"
    before = parser.Trap.requests
    output, diagnostics = capture([
        STRACE, "-f", "-e", "trace=%file,%network", "-o", str(trace), BINARY,
    ], data)
    values = [json.loads(line) for line in output.splitlines()]
    validate_rows(values, keys, "exact-flow")
    lines = trace.read_text().splitlines()
    if not any("execve(" in line and BINARY in line for line in lines):
        raise parser.InfrastructureFailure("trace_execution_not_confirmed")
    return values, {
        "sentinel_file_calls": sum(str(parser.SENTINEL) in line for line in lines),
        "connect_calls": sum("connect(" in line for line in lines),
        "http_requests": parser.Trap.requests - before,
        "diagnostics_emitted": diagnostics,
        "traced_execution_confirmed": True,
    }


def policy_passed(exact, broad, counts, positive_cases=POSITIVE):
    valid_subject = lambda row: (row["trusted_subject"] and not row["attacker_marker"]
                                 and not row["wrapper_marker"])
    return (all(row["accepted"] == (row["case"] in positive_cases) for row in exact)
            and all(valid_subject(row) for row in exact if row["accepted"])
            and all(row["error_class"] in DENIALS for row in exact if not row["accepted"])
            and all(row["error_class"] == "algorithm_rejected" for row in exact
                    if row["case"] in NONPOLICY)
            and all(row["error_class"] == "reference_rejected" for row in exact
                    if row["case"] in REFERENCES)
            and sum(row["case"] in NONPOLICY and row["accepted"] and valid_subject(row)
                    for row in broad) == 16
            and not any(counts[key] for key in
                        ("sentinel_file_calls", "connect_calls", "http_requests")))


def run(corpus_builder=corpus, positive_cases=POSITIVE):
    parser.SENTINEL.write_bytes(parser.MARKER)
    trap = HTTPServer(("127.0.0.1", 0), parser.Trap)
    thread = threading.Thread(target=trap.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="auth32-exact-policy-") as value:
            directory = Path(value)
            before = parser.controls(parser.executable(), trap.server_port, directory, "before")
            data, keys = corpus_builder(trap.server_port)
            output, _diagnostics = capture([BINARY, "--strict"], data)
            broad = [row for line in output.splitlines()
                     if (row := json.loads(line))["api"] == "strict-flow"]
            validate_rows(broad, keys, "strict-flow")
            exact, counts = observe(data, keys, directory)
            after = parser.controls(parser.executable(), trap.server_port, directory, "after")
            passed = policy_passed(exact, broad, counts, positive_cases)
            return {"status": "controls_passed" if passed else "candidate_controls_failed",
                    "candidate_controls_passed": passed, "input_rows": len(keys),
                    "transport_sha256": hashlib.sha256(data).hexdigest(),
                    "controls_before": before, "controls_after": after,
                    "aggregate_exact_child": counts, "exact_rows": exact,
                    "broad_profile_rows": broad, "production_gate_open": False,
                    "scope": "bounded aggregate exact-flow child, not exhaustive XXE assurance"}
    finally:
        trap.shutdown()
        trap.server_close()
        thread.join(timeout=2)
        parser.SENTINEL.unlink(missing_ok=True)
        if thread.is_alive():
            raise parser.InfrastructureFailure("trap_shutdown_unconfirmed")


def main(run_report=run):
    try:
        value = run_report()
        print(json.dumps(value, sort_keys=True))
        raise SystemExit(0 if value["candidate_controls_passed"] else 1)
    except parser.InfrastructureFailure as error:
        print(json.dumps({"status": "infrastructure_failed", "stage": str(error)}))
        raise SystemExit(2) from None
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps({"status": "infrastructure_failed", "stage": "observer_unavailable"}))
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
