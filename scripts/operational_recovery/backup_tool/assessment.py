"""Keep every finding; reject affected imported packages as well as called symbols."""
import json


def messages(raw):
    decoder, values = json.JSONDecoder(), []
    while raw.strip():
        value, end = decoder.raw_decode(raw.lstrip())
        if not isinstance(value, dict) or len(value) != 1:
            raise ValueError("invalid backup scanner message")
        values.append(value)
        raw = raw.lstrip()[end:]
    return values


def scan_identity(values, scanner_version, mode, versions):
    configurations = [value["config"] for value in values if "config" in value]
    if len(configurations) != 1:
        raise ValueError("backup scanner configuration missing or ambiguous")
    config = configurations[0]
    expected = dict(protocol_version="v1.0.0", scanner_name="govulncheck",
                    scanner_version=scanner_version, db="https://vuln.go.dev",
                    scan_level="symbol", scan_mode=mode)
    if any(config.get(key) != value for key, value in expected.items()) or not config.get("db_last_modified"):
        raise ValueError("backup scanner identity or database mismatch")
    inventories = [value["SBOM"] for value in values if "SBOM" in value]
    if len(inventories) != 1 or inventories[0].get("go_version") != "go1.27.3":
        raise ValueError("backup scanner inventory missing or wrong toolchain")
    entries = inventories[0]["modules"]
    observed = {entry["path"]: entry.get("version", "") for entry in entries}
    # Source scans may report the build-only driver, which supplies no code.
    observed.pop("easy-auth.invalid/backup-encryption-tools", None)
    # The pinned scanner uses module-semver spelling for source stdlib entries,
    # and toolchain spelling in binary entries. Require the exact mode's form.
    stdlib = "v1.27.3" if mode == "source" else "go1.27.3"
    if len(entries) != len({entry["path"] for entry in entries}) \
            or observed != dict(versions, stdlib=stdlib) or not inventories[0].get("roots"):
        raise ValueError("backup scanner inventory does not cover the expected modules")
    return config


def assess(raw, packages, scanner_version, mode, versions):
    values = messages(raw)
    config = scan_identity(values, scanner_version, mode, versions)
    advisories = {value["osv"]["id"]: value["osv"] for value in values if "osv" in value}
    residual = set()
    for value in values:
        if "finding" not in value:
            continue
        finding = value["finding"]
        trace = finding["trace"]
        if not trace or finding["osv"] not in advisories:
            raise ValueError("unclassifiable backup vulnerability finding")
        if any(frame.get("package") or frame.get("function") for frame in trace):
            raise ValueError("backup tool has an affected imported package")
        module = trace[0]["module"]
        affected = [item for item in advisories[finding["osv"]]["affected"]
                    if item["package"]["ecosystem"] == "Go" and item["package"]["name"] == module]
        imports = [entry["path"] for item in affected for entry in item.get("ecosystem_specific", {}).get("imports", [])]
        if not imports or any(path in packages for path in imports):
            raise ValueError("backup module finding is active or lacks package scope")
        residual.add((finding["osv"], module))
    return dict(database_modified=config["db_last_modified"], imported_package_gate_passed=True,
                inactive_module_findings=[dict(advisory=advisory, module=module)
                                          for advisory, module in sorted(residual)])
