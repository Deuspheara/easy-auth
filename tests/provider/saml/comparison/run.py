"""Replay identical private synthetic bytes through two unchanged verifier pins.

Requires the documented prebuilt native image and Rust example. Emits finite
outcomes only. XML/public certificates remain in memory; private keys never leave
the signer process. This comparison is not a resource-access observer.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def execute(command, data=None):
    result = subprocess.run(command, input=data, capture_output=True, timeout=180)
    if result.returncode:
        raise RuntimeError("comparison_process_failed")
    return result.stdout


def rows(output):
    # Existing scenario composition owns the array framing; exporter emits JSONL.
    try:
        return json.loads(output)["rows"]
    except (json.JSONDecodeError, TypeError):
        return [json.loads(line) for line in output.splitlines() if line.strip()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-image", required=True)
    parser.add_argument("--rust-example", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    docker = ["docker", "run", "--rm", "-i", "--network", "none", "--read-only",
              "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
              "--pids-limit", "128", "--cpus", "2", "--memory", "3g",
              "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m", "--entrypoint"]

    def native(example, arguments=(), data=None):
        return execute(docker + [f"/work/target/debug/examples/{example}",
                                 args.native_image, *arguments], data)

    corpus = rows(native("auth32_corpus_export"))
    corpus += rows(native("auth32_corpus_export", ["38117"]))
    corpus += rows(native("auth32_profile_export"))
    keys = {(row["case"], row["mode"]) for row in corpus}
    if len(corpus) != 84 or len(keys) != 84:
        raise RuntimeError("incomplete_or_duplicate_corpus")
    transport = "".join("\t".join([
        row["case"], row["mode"], row["xml_b64"], ",".join(row["certs_b64"])
    ]) + "\n" for row in corpus).encode()
    if len(transport) >= 2 * 1024 * 1024:
        raise RuntimeError("transport_limit_exceeded")
    native_rows = [json.loads(line) for line in native(
        "auth32_native_replay", ["--replay"], transport).splitlines()]
    rust_rows = [json.loads(line) for line in execute(
        [str(args.rust_example.resolve())], transport).splitlines()]
    if {(r["case"], r["mode"]) for r in native_rows} != keys or len(native_rows) != 84:
        raise RuntimeError("incomplete_native_results")
    for api in ("raw-signature", "strict-flow"):
        selected = [r for r in rust_rows if r["api"] == api]
        if {(r["case"], r["mode"]) for r in selected} != keys or len(selected) != 84:
            raise RuntimeError("incomplete_rust_results")
    if len(rust_rows) != 168:
        raise RuntimeError("unexpected_rust_results")
    # Findings, including security failures, are retained rather than made green.
    args.output.write_text(json.dumps({
        "transport_sha256": hashlib.sha256(transport).hexdigest(),
        "input_rows": len(corpus), "native": native_rows, "rust": rust_rows,
        "resource_observer": False,
    }, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
