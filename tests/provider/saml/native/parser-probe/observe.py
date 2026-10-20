"""Observe bounded synthetic parser calls; never infer SAML authority."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

MARKER = b"auth32-owned-marker"
SENTINEL = Path("/tmp/auth32-owned-sentinel")
CASES = (
    "doctype", "internal-entity", "file-entity", "http-entity",
    "external-dtd", "parameter-entity", "malformed", "multiple-roots",
)


class InfrastructureFailure(Exception):
    pass


class Trap(BaseHTTPRequestHandler):
    requests = 0

    def setup(self):
        super().setup()
        self.connection.settimeout(2)

    def do_GET(self):
        Trap.requests += 1
        body = b"<!ELEMENT probe (#PCDATA)>" if self.path == "/dtd" else MARKER
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def executable():
    artifacts = [json.loads(line) for line in
                 Path("/work/parser-artifacts.json").read_text().splitlines()]
    binaries = [item["executable"] for item in artifacts
                if item.get("reason") == "compiler-artifact"
                and item.get("target", {}).get("name") == "auth32_parser_probe"
                and item.get("executable")]
    if len(binaries) != 1:
        raise InfrastructureFailure("probe_executable_missing")
    return binaries[0]


def capture(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate(timeout=2)
        raise InfrastructureFailure("probe_timeout") from None
    if process.returncode != 0:
        raise InfrastructureFailure("probe_or_observer_failed")
    return json.loads(stdout), bool(stderr)


def observe(binary, port, directory, case, label):
    trace = directory / f"{label}.trace"
    before = Trap.requests
    value, diagnostics = capture([
        "strace", "-f", "-e", "trace=%file,%network", "-o", str(trace),
        binary, case, str(port),
    ])
    expected = {"case", "parse_accepted", "marker_matches"}
    if (not isinstance(value, dict) or set(value) != expected
            or value.get("case") != case or type(value.get("marker_matches")) is not bool):
        raise InfrastructureFailure("unexpected_probe_result")
    parsed = value["parse_accepted"]
    if ((case.endswith("-control") and parsed is not None)
            or (not case.endswith("-control") and type(parsed) is not bool)):
        raise InfrastructureFailure("unexpected_probe_result")
    lines = trace.read_text().splitlines()
    return {
        **value,
        "sentinel_file_calls": sum(str(SENTINEL) in line for line in lines),
        "connect_calls": sum("connect(" in line for line in lines),
        "http_requests": Trap.requests - before,
        "diagnostics_emitted": diagnostics,
    }


def controls(binary, port, directory, label):
    healthy = observe(binary, port, directory, "healthy", f"{label}-healthy")
    file = observe(binary, port, directory, "file-control", f"{label}-file")
    http = observe(binary, port, directory, "http-control", f"{label}-http")
    if not (healthy["parse_accepted"] and healthy["marker_matches"]
            and not any(healthy[key] for key in
                        ("sentinel_file_calls", "connect_calls", "http_requests"))
            and file["marker_matches"] and file["sentinel_file_calls"] > 0
            and file["connect_calls"] == 0 and file["http_requests"] == 0
            and http["marker_matches"] and http["connect_calls"] > 0
            and http["http_requests"] == 1 and http["sentinel_file_calls"] == 0):
        raise InfrastructureFailure("positive_control_failed")
    return {"healthy_parser": healthy, "file_observer": file, "http_observer": http}


def run():
    binary = executable()
    SENTINEL.write_bytes(MARKER)
    trap = HTTPServer(("127.0.0.1", 0), Trap)
    thread = threading.Thread(target=trap.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="auth32-observers-") as directory:
            directory = Path(directory)
            before = controls(binary, trap.server_port, directory, "before")
            cases = [observe(binary, trap.server_port, directory, case, case)
                     for case in CASES]
            after = controls(binary, trap.server_port, directory, "after")
            gaps = [case["case"] for case in cases if case["parse_accepted"]
                    or case["sentinel_file_calls"] or case["connect_calls"]
                    or case["http_requests"]]
            return {
                "status": "candidate_policy_gaps_observed" if gaps else "parser_controls_passed",
                "execution_completed": True, "candidate_parser_policy_passed": not gaps,
                "scope": "upstream parser defaults only; no signature or SAML acceptance",
                "controls_before": before, "cases": cases, "controls_after": after,
                "policy_gap_cases": gaps,
            }
    finally:
        trap.shutdown()
        trap.server_close()
        thread.join(timeout=2)
        SENTINEL.unlink(missing_ok=True)
        if thread.is_alive():
            raise InfrastructureFailure("trap_shutdown_unconfirmed")


if __name__ == "__main__":
    try:
        result = run()
        print(json.dumps(result, sort_keys=True))
        raise SystemExit(0 if result["candidate_parser_policy_passed"] else 1)
    except InfrastructureFailure as error:
        print(json.dumps({"status": "infrastructure_failed", "stage": str(error)}))
        raise SystemExit(2) from None
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        print(json.dumps({"status": "infrastructure_failed", "stage": "observer_unavailable"}))
        raise SystemExit(2) from None
