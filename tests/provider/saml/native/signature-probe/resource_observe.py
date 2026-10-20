"""Trace the signature child with the existing independent parser I/O controls."""
import json
from pathlib import Path
import subprocess
import tempfile
import threading
from http.server import HTTPServer

import parser_observe as parser
import signature_observe as signature

POSITIVES = {f"resource-healthy-{kind}-{when}" for kind in ("response", "assertion")
             for when in ("before", "after")}
FORBIDDEN = {f"resource-{case}" for case in ("doctype", "internal-entity", "file-entity",
                                           "http-entity", "external-dtd", "parameter-entity")}
CASES = POSITIVES | FORBIDDEN


def executable():
    artifacts = [json.loads(line) for line in
                 Path("/work/resource-artifacts.json").read_text().splitlines()]
    binaries = [item["executable"] for item in artifacts
                if item.get("reason") == "compiler-artifact"
                and item.get("target", {}).get("name") == "auth32_signature_resources"
                and item.get("executable")]
    if len(binaries) != 1:
        raise parser.InfrastructureFailure("signature_resource_executable_missing")
    return binaries[0]


def observe(binary, port, directory):
    trace = directory / "signature.trace"
    before = parser.Trap.requests
    result, diagnostics = parser.capture([
        "strace", "-f", "-e", "trace=%file,%network", "-o", str(trace), binary, str(port),
    ])
    if not isinstance(result, dict) or set(result) != {"rows"}:
        raise parser.InfrastructureFailure("invalid_signature_resource_ipc")
    rows = result["rows"]
    signature.validate(rows, CASES)
    if any(not signature.safe_content(row) for row in rows if row["case"] in POSITIVES):
        raise parser.InfrastructureFailure("signed_positive_control_failed")
    lines = trace.read_text().splitlines()
    return rows, {
        "sentinel_file_calls": sum(str(parser.SENTINEL) in line for line in lines),
        "connect_calls": sum("connect(" in line for line in lines),
        "http_requests": parser.Trap.requests - before,
        "native_diagnostics_emitted": diagnostics,
    }


def run():
    binary = executable()
    parser_binary = parser.executable()
    parser.SENTINEL.write_bytes(parser.MARKER)
    trap = HTTPServer(("127.0.0.1", 0), parser.Trap)
    thread = threading.Thread(target=trap.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="auth32-signature-resource-") as directory:
            directory = Path(directory)
            before = parser.controls(parser_binary, trap.server_port, directory, "before")
            rows, counts = observe(binary, trap.server_port, directory)
            after = parser.controls(parser_binary, trap.server_port, directory, "after")
            return report(rows, counts, before, after)
    finally:
        trap.shutdown()
        trap.server_close()
        thread.join(timeout=2)
        parser.SENTINEL.unlink(missing_ok=True)
        if thread.is_alive():
            raise parser.InfrastructureFailure("trap_shutdown_unconfirmed")


def report(rows, counts, before, after):
    gaps = [row for row in rows if row["case"] in FORBIDDEN and row["accepted"]]
    unresolved = [row for row in rows if not row["accepted"]
                  and row["error_class"] not in signature.KNOWN_DENIALS]
    resource_calls = any(counts[key] for key in
                         ("sentinel_file_calls", "connect_calls", "http_requests"))
    passed = not (gaps or unresolved or resource_calls)
    return {
        "status": "resource_controls_passed" if passed else "candidate_controls_incomplete",
        "execution_completed": True, "candidate_controls_passed": passed,
        "scope": "aggregate child observations across bounded signed XML inputs; no SAML authority",
        "controls_before": before, "rows": rows, "aggregate_signature_child": counts,
        "controls_after": after, "policy_gap_rows": len(gaps),
        "unresolved_engine_rows": len(unresolved),
    }


if __name__ == "__main__":
    try:
        result = run()
        print(json.dumps(result, sort_keys=True))
        raise SystemExit(0 if result["candidate_controls_passed"] else 1)
    except (parser.InfrastructureFailure, signature.InfrastructureFailure) as error:
        print(json.dumps({"status": "infrastructure_failed", "stage": str(error)}))
        raise SystemExit(2) from None
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps({"status": "infrastructure_failed", "stage": "observer_unavailable"}))
        raise SystemExit(2) from None
