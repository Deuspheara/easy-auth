"""Check stored AUTH-5 provenance/accounting without running upstream code or SQL."""

import hashlib
import json
import math
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PRODUCER = "34ed2e9e9e2255f6b32b25bf18db99b0cca94565"
RESULTS = ROOT / "benchmarks/adoption/results/2026-10-19-under-load"
PRODUCER_FILES = {
    "Cargo.toml", "Cargo.lock", "run.py", "src/easy.rs", "src/lib.rs",
    "src/lucid.rs", "src/revocation.rs", "src/rustauth.rs",
}
EXPECTED_TOTALS = {
    "timed_validations": 27648,
    "post_revoke_rejections": 576,
    "background_validations": 2532,
    "other_owner_controls": 9,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_result(name):
    return json.loads((RESULTS / name).read_text())


def verify_provenance():
    environment = read_result("environment.json")
    require(environment["source_revision"] == PRODUCER, "unexpected producer")
    hashes = environment["harness_sha256"]
    require(set(hashes) == PRODUCER_FILES, "incomplete producer file inventory")
    changed = []
    for name, expected in sorted(hashes.items()):
        source = subprocess.check_output(
            ["git", "show", f"{PRODUCER}:benchmarks/adoption/{name}"], cwd=ROOT
        )
        require(hashlib.sha256(source).hexdigest() == expected, f"producer hash: {name}")
        current = (ROOT / "benchmarks/adoption" / name).read_bytes()
        if hashlib.sha256(current).hexdigest() != expected:
            changed.append(name)
    return changed


def verify_project(project, totals):
    paths = sorted(RESULTS.glob(f"measure-{project}-*.json"))
    require(len(paths) == 3, f"process count: {project}")
    dependencies = read_result(f"dependencies-{project}.json")
    identities = {
        entry.split("|", 1)[0].removesuffix(" (proc-macro)")
        for entry in dependencies["package_features"]
    }
    require(len(identities) == dependencies["compiled_packages_including_probe"],
            f"compiled package count: {project}")
    for path in paths:
        report = json.loads(path.read_text())
        require(report["background_load_sustained"] is True, "load not sustained")
        require(report["background_workers"] == 7, "background worker count")
        require(report["other_user_still_valid"] is True, "other owner control")
        require(report["post_revoke_rejections"] == 64, "post-revoke rejection count")
        require(report["session_count"] == 8 and report["pool_max"] == 10, "fixture size")
        require(report["background_validations"] >= 7, "missing worker activity")
        require(report["session_rss_sample_count"] > 0, "missing RSS samples")
        require(report["sampled_session_peak_rss_kib"] >=
                report["sampled_session_min_rss_kib"] > 0, "invalid RSS range")
        require(report["binary_bytes"] == dependencies["binary_bytes"], "binary size")
        require(sorted(t["workers"] for t in report["trials"]) == [1, 1, 1, 8, 8, 8],
                "trial worker counts")
        for trial in report["trials"]:
            require(trial["requests"] == 512 and trial["seconds"] > 0, "trial size/time")
            require(math.isclose(trial["seconds"] * trial["requests_per_second"],
                                 512, rel_tol=1e-9), "throughput arithmetic")
            require(0 <= trial["p50_ms"] <= trial["p95_ms"] < math.inf, "percentiles")
            totals["timed_validations"] += trial["requests"]
        totals["post_revoke_rejections"] += report["post_revoke_rejections"]
        totals["background_validations"] += report["background_validations"]
        totals["other_owner_controls"] += 1


def main():
    changes = verify_provenance()
    totals = dict.fromkeys(EXPECTED_TOTALS, 0)
    for project in ("easy", "rustauth", "lucid"):
        verify_project(project, totals)
    require(totals == EXPECTED_TOTALS, "stored aggregate accounting differs")
    print(json.dumps({
        "producer": PRODUCER,
        "producer_hashes_checked": len(PRODUCER_FILES),
        "totals": totals,
        "current_files_differ_from_producer": changes,
        "scope": "stored arithmetic and Git-object checks; no new runtime execution",
    }, indent=2))


if __name__ == "__main__":
    main()
