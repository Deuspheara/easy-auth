"""Run inside a disposable probe container with the matching Clippy component.

Retain upstream lint failures separately from strict lint of owned source. No
upstream source changes or warning exemptions. Cargo dependencies stay offline.
"""
import json
from pathlib import Path
import subprocess
import sys


def run():
    full = subprocess.run(
        ["cargo", "clippy", "--locked", "--offline", "--features", "xmlsec",
         "--example", "auth32_signature_probe", "--message-format=json", "--", "-D", "warnings"],
        capture_output=True, text=True, timeout=180,
    )
    diagnostics = [item for line in full.stdout.splitlines()
                   if (item := json.loads(line)).get("reason") == "compiler-message"
                   and item["message"]["level"] in {"error", "warning"}]
    deps = Path("/work/target/debug/deps")
    command = ["clippy-driver", "/work/source/examples/auth32_signature_probe/main.rs",
               "--edition=2021", "--crate-type=bin", "--emit=metadata",
               "-L", f"dependency={deps}", "-o", "/tmp/auth32-signature-lint.rmeta",
               "-W", "clippy::all", "-D", "warnings"]
    for dependency in ("libxml", "samael"):
        artifacts = list(deps.glob(f"lib{dependency}-*.rlib"))
        if len(artifacts) != 1:
            raise RuntimeError("ambiguous_dependency_artifact")
        command += ["--extern", f"{dependency}={artifacts[0]}"]
    owned = subprocess.run(command, capture_output=True, timeout=60)
    if owned.returncode:
        sys.stderr.buffer.write(owned.stderr)
    return {"full_upstream_exit_code": full.returncode,
            "full_upstream_diagnostic_count": len(diagnostics),
            "full_upstream_diagnostic_codes": sorted({
                item["message"]["code"]["code"] for item in diagnostics
                if item["message"].get("code")}),
            "owned_diagnostics_in_full_run": sum(any(
                span["file_name"].startswith("examples/auth32_signature_probe/")
                for span in item["message"]["spans"]) for item in diagnostics),
            "owned_strict_clippy_exit_code": owned.returncode,
            "owned_diagnostics_emitted": bool(owned.stderr),
            "upstream_modified": False, "warning_exemptions_added": False}


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["owned_strict_clippy_exit_code"] == 0 else 1)
