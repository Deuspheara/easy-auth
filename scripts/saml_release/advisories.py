"""Local image-archive assessment; never upload images or suppress findings."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import tempfile

from . import docker

SCANNER = "aquasec/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"
SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def scan(image, name, destination, cache):
    details = docker.inspect(image)
    image_id = details["Id"]
    output = destination / (name + ".json")
    (destination / "empty-config.yaml").write_text("{}\n")
    with tempfile.TemporaryDirectory(prefix="easy-auth-image-scan-") as directory:
        archive = Path(directory) / "image.tar"
        docker.run(["save", "--output", str(archive), image_id])
        docker.run(["run", "--rm", "--mount", f"type=bind,src={archive},dst=/image.tar,readonly",
                    "--mount", f"type=bind,src={destination},dst=/output",
                    "--mount", f"type=bind,src={cache},dst=/root/.cache/trivy", SCANNER,
                    "image", "--disable-telemetry", "--scanners", "vuln",
                    "--ignorefile", "/dev/null", "--config", "/output/empty-config.yaml",
                    "--format", "json", "--output", "/output/" + name + ".json",
                    "--input", "/image.tar"], timeout=600)
    report = json.loads(output.read_text())
    if report.get("ArtifactType") != "container_image" \
            or report.get("Metadata", {}).get("ImageID") != image_id \
            or report.get("Metadata", {}).get("OS", {}).get("Family") != "debian" \
            or not any(result.get("Type") == "debian" for result in report.get("Results", [])):
        raise ValueError("advisory report does not identify the selected image")
    findings = [finding for result in report.get("Results", [])
                for finding in result.get("Vulnerabilities", [])]
    counts = Counter(finding["Severity"] for finding in findings)
    if not set(counts).issubset(SEVERITIES):
        raise ValueError("unknown advisory severity")
    return dict(image_id=image_id, report=str(output),
                report_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
                severity_counts=dict(counts), total_findings=len(findings),
                high_critical_gate_passed=not any(counts[level] for level in ("HIGH", "CRITICAL")),
                remaining_disposition_required=bool(findings),
                findings_ignored=0, ignore_unfixed=False)


def assess(image, proxy_image, destination):
    destination = destination.resolve()
    cache = destination / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    results = {name: scan(value, name, destination, cache)
               for name, value in [("auth", image), ("proxy", proxy_image)]}
    database = cache / "db/metadata.json"
    if not database.is_file():
        raise ValueError("scanner database provenance missing")
    summary = dict(scanner_image=SCANNER,
                   scanner_version=docker.run(["run", "--rm", "--network", "none", SCANNER, "--version"]),
                   database=json.loads(database.read_text()),
                   database_metadata_sha256=hashlib.sha256(database.read_bytes()).hexdigest(),
                   images=results, telemetry_disabled=True, image_upload=False,
                   scope="Known image-package advisories; not independent review or complete reachability proof",
                   production_security_approval=False)
    (destination / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary
