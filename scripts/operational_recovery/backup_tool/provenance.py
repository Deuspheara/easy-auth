"""Verify embedded Go module identities and exact reviewed license-notice inputs."""
import hashlib
import re


def metadata(raw, pin, name):
    if not raw.splitlines()[0].endswith(": go" + pin["go"]["version"]) \
            or "\tbuild\tCGO_ENABLED=0\n" not in raw:
        raise ValueError("backup binary compiler or native linkage mismatch")
    modules = {}
    for module, version, checksum in re.findall(r"^\t(?:mod|dep)\t([^\t]+)\t([^\t]+)\t(h1:[^\n]+)", raw, re.M):
        if module in modules:
            raise ValueError("ambiguous backup binary module")
        modules[module] = dict(version=version, module_sum=checksum)
    module, configuration = ("golang.org/x/vuln", pin["scanner"]) if name == "govulncheck" \
        else ("filippo.io/age", pin["age"])
    if modules.get(module) != dict(version=configuration["version"], module_sum=configuration["module_sum"]):
        raise ValueError("backup binary upstream identity mismatch")
    if name != "govulncheck" and modules.get("golang.org/x/crypto", {}).get("version") != pin["age"]["crypto_version"]:
        raise ValueError("backup binary fixed dependency missing")
    return modules


def capture_notices(directory, policy, modules):
    expected = {entry["module"]: dict(version=entry["version"], module_sum=entry["module_sum"])
                for entry in policy["modules"]}
    if modules != expected or policy["legal_approval"] is not False:
        raise ValueError("backup tool notice policy does not cover the selected modules")
    records = []
    for entry in policy["modules"]:
        if entry["license"] != "BSD-3-Clause":
            raise ValueError("unreviewed backup tool license")
        source = directory / "modules" / (entry["module"] + "@" + entry["version"])
        target = directory / "notices" / (entry["module"].replace("/", "__") + "@" + entry["version"])
        target.mkdir(mode=0o700)
        copy_notices(source, target, entry["notices"])
        records.append(entry)
    if policy["go_version"] != "go1.27.3" or policy["go_license"] != "BSD-3-Clause":
        raise ValueError("unreviewed Go license policy")
    target = directory / "notices" / "Go1.27.3"
    target.mkdir(mode=0o700)
    copy_notices(directory / "go", target, policy["go_notices"])
    return dict(modules=records, go_notices=policy["go_notices"], legal_approval=False)


def copy_notices(source, target, entries):
    if not any(entry["name"] == "LICENSE" for entry in entries):
        raise ValueError("backup tool license notice missing")
    for entry in entries:
        if entry["name"] not in ("LICENSE", "PATENTS", "NOTICE"):
            raise ValueError("unexpected backup tool notice name")
        path = source / entry["name"]
        if path.is_symlink() or not path.is_file():
            raise ValueError("backup tool notice is not a regular file")
        data = path.read_bytes()
        if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("backup tool notice identity mismatch")
        destination = target / entry["name"]
        with destination.open("xb") as output:
            output.write(data)
        destination.chmod(0o600)
