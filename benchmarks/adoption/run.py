#!/usr/bin/env python3
"""Reproduce native session probes on the repository's loopback PostgreSQL stack."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import subprocess
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent
PROJECTS = ("easy", "rustauth", "lucid")


def cargo_arguments(project):
    return ["--manifest-path", str(ROOT / "Cargo.toml"), "--locked",
            "--no-default-features", "--features", project]


def compose(*arguments, capture=False):
    return subprocess.run(["docker", "compose", "-f", str(REPO / "compose.yaml"),
                           "exec", "-T", "postgres", *arguments], check=True,
                          text=True, capture_output=capture)


def dependencies(project):
    command = ["cargo", "tree", *cargo_arguments(project), "--edges", "normal,build",
               "--prefix", "none", "--format", "{p}|{f}"]
    output = subprocess.check_output(command, text=True)
    entries = set()
    for line in output.splitlines():
        # Remove machine-specific local paths; retain upstream Git source references.
        entry = re.sub(r" \(/[^)]*\)", "", line).removesuffix(" (*)")
        entries.add(entry)
    packages = {entry.split("|", 1)[0].removesuffix(" (proc-macro)") for entry in entries}
    return {"command": "cargo tree --locked --no-default-features --features " + project
            + " --edges normal,build --prefix none --format '{p}|{f}'",
            "includes_measurement_harness": True, "compiled_packages_including_probe": len(packages),
            "package_features": sorted(entries)}


def build(project, destination):
    command = ["cargo", "build", "--release", *cargo_arguments(project), "--bin", f"probe-{project}",
               "--target-dir", str(ROOT / "target"), "-j", "2"]
    started = time.monotonic()
    with (destination / f"build-{project}.log").open("w") as log:
        subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
    binary = ROOT / "target" / "release" / f"probe-{project}"
    report = dependencies(project)
    report.update(binary_bytes=binary.stat().st_size, build_seconds=time.monotonic() - started)
    (destination / f"dependencies-{project}.json").write_text(json.dumps(report, indent=2) + "\n")


def observe(process):
    ready = threading.Event()
    lines = []

    def read():
        for line in process.stdout:
            lines.append(line)
            if '"phase":"ready"' in line:
                ready.set()

    reader = threading.Thread(target=read)
    reader.start()
    setup_rss, measured_rss = [], []
    deadline = time.monotonic() + 180
    while process.poll() is None:
        if time.monotonic() > deadline:
            process.kill()
            process.wait()
            reader.join()
            raise RuntimeError("probe exceeded 180 seconds")
        sample = subprocess.run(["ps", "-o", "rss=", "-p", str(process.pid)],
                                capture_output=True, text=True, check=False)
        if sample.returncode == 0 and sample.stdout.strip():
            (measured_rss if ready.is_set() else setup_rss).append(int(sample.stdout.strip()))
        time.sleep(0.1)
    reader.join()
    if process.returncode != 0:
        raise RuntimeError(f"probe exited with status {process.returncode}; inspect local stderr log")
    results = [json.loads(line) for line in lines if line.startswith("{")]
    result = next(item for item in results if item.get("phase") == "result")
    if not measured_rss:
        raise RuntimeError("no post-provisioning RSS samples recorded")
    result.update(sampled_setup_peak_rss_kib=max(setup_rss, default=None),
                  sampled_session_peak_rss_kib=max(measured_rss),
                  sampled_session_min_rss_kib=min(measured_rss),
                  session_rss_sample_count=len(measured_rss))
    return result


def measure(project, destination, repetition):
    database = "easy_auth_compare_" + uuid.uuid4().hex
    compose("createdb", "-U", "auth", database)
    try:
        environment = os.environ.copy()
        environment["DATABASE_URL"] = (
            "postgres://auth:auth-development-only@127.0.0.1:59473/" + database)
        # Explicit configuration; inherited application settings cannot alter this comparison.
        for key in list(environment):
            if key.startswith(("RUSTAUTH_", "BETTER_AUTH_")):
                del environment[key]
        binary = ROOT / "target" / "release" / f"probe-{project}"
        with (destination / f"stderr-{project}-{repetition}.log").open("w") as errors:
            process = subprocess.Popen([str(binary)], env=environment, stdout=subprocess.PIPE,
                                       stderr=errors, text=True)
            try:
                result = observe(process)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        result.update(repetition=repetition, binary_bytes=binary.stat().st_size)
        (destination / f"measure-{project}-{repetition}.json").write_text(json.dumps(result, indent=2) + "\n")
        print(f"{project} repetition {repetition}: verified revocation; result saved", flush=True)
    finally:
        # Only the database created by this invocation is removed.
        compose("dropdb", "--force", "-U", "auth", database)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("build", "measure", "all"))
    parser.add_argument("--output", type=Path, default=ROOT / "results" / "local")
    parser.add_argument("--project", choices=PROJECTS, action="append")
    parser.add_argument("--repetitions", type=int, default=3)
    arguments = parser.parse_args()
    if not 1 <= arguments.repetitions <= 10:
        parser.error("repetitions must be between 1 and 10")
    destination = arguments.output.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    projects = arguments.project or list(PROJECTS)
    if arguments.phase in ("build", "all"):
        for project in projects:
            build(project, destination)
    if arguments.phase in ("measure", "all"):
        version = compose("psql", "-U", "auth", "-d", "auth", "-Atc", "SELECT version()", capture=True).stdout.strip()
        source_files = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", ROOT / "run.py", *sorted((ROOT / "src").glob("*.rs"))]
        metadata = {"rustc": subprocess.check_output(["rustc", "-vV"], text=True),
                    "platform": platform.system(), "release": platform.release(),
                    "architecture": platform.machine(), "host_logical_cpus": os.cpu_count(),
                    "docker_vm_cpu_and_memory_bytes": subprocess.check_output(
                        ["docker", "info", "--format", "{{json .NCPU}} {{json .MemTotal}}"], text=True).strip(),
                    "postgres": version,
                    "source_revision": subprocess.check_output(["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip(),
                    "memory_sampling_interval_seconds": 0.1, "order_seed": 20261019,
                    "harness_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                       for path in source_files}}
        (destination / "environment.json").write_text(json.dumps(metadata, indent=2) + "\n")
        rng = random.Random(20261019)
        for repetition in range(1, arguments.repetitions + 1):
            order = list(projects)
            rng.shuffle(order)
            for project in order:
                measure(project, destination, repetition)


if __name__ == "__main__":
    main()
