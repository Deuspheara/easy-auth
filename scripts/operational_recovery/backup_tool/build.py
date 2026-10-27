"""Build original upstream commands with a pinned, fixed transitive dependency."""
import hashlib
import json
from pathlib import Path
import shutil
import sys

from ..evidence import ci_source_identity, source_identity, write_receipt
from .assessment import assess
from .provenance import capture_notices, metadata
from .toolchain import GoToolchain, fetch_go

ROOT = Path(__file__).resolve().parents[3]
INPUTS = ROOT / "tools/backup-encryption"


def load_inputs():
    pin = json.loads((INPUTS / "age.json").read_text())
    if pin["schema_version"] != 1 or pin["go"]["version"] != "1.27.3" \
            or pin["age"]["version"] != "v1.3.2" or pin["age"]["crypto_version"] != "v0.56.0" \
            or pin["scanner"]["version"] != "v1.9.0":
        raise ValueError("unreviewed backup tool versions")
    if set(pin["inputs"]) != {"go.mod", "go.sum", "notice-policy.json"}:
        raise ValueError("incomplete backup tool input identity")
    for name, digest in pin["inputs"].items():
        if hashlib.sha256((INPUTS / name).read_bytes()).hexdigest() != digest:
            raise ValueError("backup tool input identity mismatch")
    return pin, json.loads((INPUTS / "notice-policy.json").read_text())


def compile_commands(tool, pin):
    driver = tool.directory / "driver"
    driver.mkdir(mode=0o700)
    for name in ("go.mod", "go.sum"):
        shutil.copyfile(INPUTS / name, driver / name)
    tool.check("go-version", [tool.go, "version"])
    tool.check("install-scanner", [tool.go, "install", "-trimpath", "golang.org/x/vuln/cmd/govulncheck@" + pin["scanner"]["version"]])
    tool.check("download-driver", [tool.go, "mod", "download"], cwd=driver)
    for name in ("age", "age-keygen"):
        tool.check("build-" + name, [tool.go, "build", "-mod=readonly", "-trimpath",
            "-ldflags=-X main.Version=" + pin["age"]["tool_version"],
            "-o", str(tool.directory / "bin" / name), "filippo.io/age/cmd/" + name], cwd=driver)
        tool.check("version-" + name, [str(tool.directory / "bin" / name), "--version"])
    for name in ("go.mod", "go.sum"):
        if (driver / name).read_bytes() != (INPUTS / name).read_bytes():
            raise ValueError("backup command lock changed during build")
    return driver


def qualify_commands(tool, pin, driver):
    inventory, evaluations, per_binary = {}, {}, {}
    for name in ("age", "age-keygen", "govulncheck"):
        binary = tool.directory / "bin" / name
        path = tool.check("metadata-" + name, [tool.go, "version", "-m", str(binary)])
        selected = metadata(path.read_text(), pin, name)
        for module, entry in selected.items():
            if module in inventory and inventory[module] != entry:
                raise ValueError("backup binaries disagree on a module identity")
            inventory[module] = entry
        versions = {module: entry["version"] for module, entry in selected.items()}
        per_binary[name] = versions
        cwd, patterns = (driver, ["filippo.io/age/cmd/" + name]) if name != "govulncheck" else \
            (tool.directory / "modules" / ("golang.org/x/vuln@" + pin["scanner"]["version"]), ["./cmd/govulncheck"])
        graph = tool.check("packages-" + name, [tool.go, "list", "-mod=readonly", "-deps", *patterns], cwd=cwd)
        packages = set(graph.read_text().splitlines())
        if not packages:
            raise ValueError("backup tool package graph missing")
        path = tool.check("audit-" + name, [str(tool.directory / "bin/govulncheck"),
            "-json", "-db", "https://vuln.go.dev", "-mode=binary", str(binary)])
        evaluations[name] = assess(path.read_text(), packages, pin["scanner"]["version"], "binary", versions)
    source = tool.check("source-audit", [str(tool.directory / "bin/govulncheck"), "-json", "-db",
        "https://vuln.go.dev", "filippo.io/age/cmd/age", "filippo.io/age/cmd/age-keygen"], cwd=driver)
    graph = tool.check("source-packages", [tool.go, "list", "-mod=readonly", "-deps",
        "filippo.io/age/cmd/age", "filippo.io/age/cmd/age-keygen"], cwd=driver)
    evaluations["source"] = assess(source.read_text(), set(graph.read_text().splitlines()),
        pin["scanner"]["version"], "source", per_binary["age"])
    return inventory, evaluations


def prepare(destination):
    if sys.version_info < (3, 12) or destination.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError("Python 3.12+ and a new external tool directory are required")
    pin, policy = load_inputs()
    source = ci_source_identity(ROOT)
    destination.mkdir(mode=0o700)
    for name in ("logs", "notices"):
        (destination / name).mkdir(mode=0o700)
    archive = fetch_go(destination, pin["go"])
    tool = GoToolchain(destination)
    driver = compile_commands(tool, pin)
    inventory, evaluations = qualify_commands(tool, pin, driver)
    notices = capture_notices(destination, policy, inventory)
    if load_inputs()[0] != pin or source_identity(ROOT) != source:
        raise ValueError("backup tool source changed during preparation")
    receipt = dict(source=source, pin=pin, go_archive=archive, assessment=evaluations,
        notices=notices, production_security_approval=False,
        binaries={name: hashlib.sha256((destination / "bin" / name).read_bytes()).hexdigest()
                  for name in ("age", "age-keygen", "govulncheck")},
        logs={path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (destination / "logs").iterdir()})
    write_receipt(destination / "receipt.json", receipt)
    return receipt
