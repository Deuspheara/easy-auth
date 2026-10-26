"""Fail-closed archive admission and scanner coverage, without network/downloads."""
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from operational_recovery.backup_tool.assessment import assess
from operational_recovery.backup_tool.toolchain import GoToolchain, fetch_go, validate_members


def scan(*, package=None, imports=None):
    configuration = dict(protocol_version="v1.0.0", scanner_name="govulncheck", scanner_version="v1.9.0",
        db="https://vuln.go.dev", db_last_modified="2026-10-21T00:27:29Z", scan_level="symbol", scan_mode="binary")
    inventory = dict(go_version="go1.27.3", roots=["example.test/tool"],
        modules=[dict(path="example.test/tool", version="v1.0.0"), dict(path="stdlib", version="go1.27.3")])
    affected = dict(package=dict(name="example.test/tool", ecosystem="Go"),
                    ecosystem_specific=dict(imports=imports if imports is not None else [dict(path="example.test/tool/unused")]))
    trace = dict(module="example.test/tool", version="v1.0.0")
    if package:
        trace["package"] = package
    return [dict(config=configuration), {"SBOM": inventory},
        dict(osv=dict(id="GO-fixture", affected=[affected])), dict(finding=dict(osv="GO-fixture", trace=[trace]))]


def evaluate(values, packages):
    return assess("\n".join(json.dumps(value) for value in values), packages, "v1.9.0", "binary",
                  {"example.test/tool": "v1.0.0"})


class ScannerCoverageTests(unittest.TestCase):
    def test_imported_uncalled_finding_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "affected imported package"):
            evaluate(scan(package="example.test/tool"), {"example.test/tool"})

    def test_module_only_finding_cannot_hide_an_imported_affected_package(self):
        with self.assertRaisesRegex(ValueError, "active or lacks package scope"):
            evaluate(scan(), {"example.test/tool", "example.test/tool/unused"})

    def test_inactive_module_findings_remain_visible_without_an_ignore(self):
        result = evaluate(scan(), {"example.test/tool"})
        self.assertEqual(result["inactive_module_findings"], [dict(advisory="GO-fixture", module="example.test/tool")])

    def test_unknown_scope_is_not_treated_as_inactive(self):
        with self.assertRaisesRegex(ValueError, "active or lacks package scope"):
            evaluate(scan(imports=[]), {"example.test/tool"})

    def test_source_inventory_requires_the_scanners_source_version_form(self):
        values = scan()
        values[0]["config"]["scan_mode"] = "source"
        raw = lambda: "\n".join(json.dumps(value) for value in values)
        with self.assertRaisesRegex(ValueError, "inventory does not cover"):
            assess(raw(), {"example.test/tool"}, "v1.9.0", "source", {"example.test/tool": "v1.0.0"})
        values[1]["SBOM"]["modules"][1]["version"] = "v1.27.3"
        result = assess(raw(), {"example.test/tool"}, "v1.9.0", "source", {"example.test/tool": "v1.0.0"})
        self.assertTrue(result["imported_package_gate_passed"])

    def test_scan_requires_correct_identity_and_complete_inventory(self):
        original = scan()
        variants = [[original[0]], original + [original[0]]]
        for key, replacement in [("scanner_version", "v0.0.0"), ("db", "http://untrusted.test")]:
            variant = deepcopy(original)
            variant[0]["config"][key] = replacement
            variants.append(variant)
        missing = deepcopy(original)
        missing[1]["SBOM"]["modules"] = [dict(path="stdlib", version="go1.27.3")]
        variants.append(missing)
        for variant in variants:
            with self.subTest(variant=variants.index(variant)), self.assertRaises(ValueError):
                evaluate(variant, {"example.test/tool"})


class ArchiveAdmissionTests(unittest.TestCase):
    def test_build_environment_cannot_select_owner_cache_hooks_or_insecure_fetch(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ,
                {"GOCACHEPROG": "private-owner-cache-hook", "GOINSECURE": "*", "GOFLAGS": "-mod=mod"}):
            tool = GoToolchain(Path(directory))
            self.assertEqual(tool.environment["GOCACHEPROG"], "")
            self.assertEqual(tool.environment["GOINSECURE"], "")
            self.assertNotIn("GOFLAGS", tool.environment)
            self.assertEqual(tool.environment["GOVCS"], "*:off")
            self.assertEqual(Path(tool.environment["GOTMPDIR"]).parent, Path(directory))
            self.assertEqual((Path(tool.environment["TEST_TELEMETRY_DIR"]) / "mode").read_text(), "off\n")

    def validate(self, entries):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            for name, kind in entries:
                entry = tarfile.TarInfo(name)
                entry.type = kind
                if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    entry.linkname = "/outside"
                archive.addfile(entry)
        data.seek(0)
        with tarfile.open(fileobj=data) as archive:
            return validate_members(archive)

    def test_root_directory_and_regular_go_members_are_accepted(self):
        entries = self.validate([("go", tarfile.DIRTYPE), ("go/bin/go", tarfile.REGTYPE)])
        self.assertEqual(len(entries), 2)

    def test_traversal_links_duplicates_and_other_roots_are_rejected(self):
        for entries in [[("../go", tarfile.DIRTYPE)], [("/go", tarfile.DIRTYPE)],
                        [("other/go", tarfile.REGTYPE)], [("go/../outside", tarfile.REGTYPE)],
                        [("go/bin/go", tarfile.SYMTYPE)], [("go/bin/go", tarfile.LNKTYPE)],
                        [("go", tarfile.REGTYPE)], [("go/a", tarfile.REGTYPE)] * 2]:
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                self.validate(entries)

    def test_checksum_failure_never_extracts_the_download(self):
        response = io.BytesIO(b"not the pinned archive")
        response.status, response.url = 200, "https://dl.google.com/go/go1.27.3.darwin-arm64.tar.gz"
        pin = dict(version="1.27.3", archives={"Darwin-arm64": dict(file="go1.27.3.darwin-arm64.tar.gz", sha256="0" * 64)})
        with tempfile.TemporaryDirectory() as directory, patch("operational_recovery.backup_tool.toolchain.platform.system", return_value="Darwin"), \
                patch("operational_recovery.backup_tool.toolchain.platform.machine", return_value="arm64"), \
                patch("operational_recovery.backup_tool.toolchain.urlopen", return_value=response):
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                fetch_go(Path(directory), pin)
            self.assertFalse((Path(directory) / "go").exists())


if __name__ == "__main__":
    unittest.main()
