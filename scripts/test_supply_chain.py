"""Evidence must distinguish resolution from selection and reject false identity."""
import copy
import json
import os
from pathlib import Path
import tempfile
import io
import tarfile
import subprocess
import unittest
from unittest.mock import patch

from .supply_chain import cargo, sources, rust_sbom, trivy_sbom
from .prepare_sbom_tool import validate_members


class CargoInventory(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="easy-auth-inventory-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.package = dict(id="registry+cache/path#example@1.0.0", name="example",
                            version="1.0.0", source=cargo.REGISTRY, license="MIT",
                            manifest_path="/private/cache/not-for-publication/Cargo.toml")
        self.locked = dict(name="example", version="1.0.0", source=cargo.REGISTRY,
                           checksum="a" * 64)
        self.metadata = dict(packages=[self.package], workspace_members=[],
                             resolve=dict(nodes=[dict(id=self.package["id"], features=[], deps=[])]))

    def record(self, metadata=None, locked=None):
        return cargo.normalize(metadata or self.metadata,
                               dict(package=[locked or self.locked]), self.root)

    def test_public_graph_retains_license_checksum_without_cache_path(self):
        report = self.record()
        self.assertEqual(report["packages"][0]["license_expression"], "MIT")
        self.assertEqual(report["packages"][0]["declared_archive_sha256"], "a" * 64)
        self.assertNotIn("/private", json.dumps(report))
        self.assertNotIn("cache/path", json.dumps(report))

    def test_unreviewed_registry_and_missing_checksum_fail(self):
        for changed in [dict(self.locked, source="registry+https://unreviewed.example"),
                        dict(self.locked, checksum=None)]:
            with self.subTest(source=changed["source"]), self.assertRaises((ValueError, KeyError)):
                self.record(locked=changed)

    def test_missing_license_and_dangling_edge_fail(self):
        missing = copy.deepcopy(self.metadata)
        missing["packages"][0]["license"] = None
        with self.assertRaises(ValueError):
            self.record(metadata=missing)
        dangling = copy.deepcopy(self.metadata)
        dangling["resolve"]["nodes"][0]["deps"] = [dict(pkg="unrecorded", dep_kinds=[])]
        with self.assertRaises(KeyError):
            self.record(metadata=dangling)

    def test_absent_or_duplicate_graph_nodes_fail(self):
        for nodes in ([], self.metadata["resolve"]["nodes"] * 2):
            changed = dict(self.metadata, resolve=dict(nodes=nodes))
            with self.subTest(count=len(nodes)), self.assertRaises(ValueError):
                self.record(metadata=changed)

    def test_selected_tree_does_not_promote_resolver_only_packages(self):
        packages = self.record()["packages"]
        packages.append(dict(name="resolver-only", version="2.0.0", ref="resolver-only"))
        selected = cargo.selected_references("\nexample v1.0.0\n\n", packages)
        self.assertEqual(selected, [packages[0]["ref"]])
        self.assertNotIn("resolver-only", selected)
        with self.assertRaises(ValueError):
            cargo.selected_references("unknown v1.0.0", packages)
        with self.assertRaises(ValueError):
            cargo.selected_references("\n", packages)

    def test_local_manifest_cannot_escape_source(self):
        outside = self.root / "outside" / "Cargo.toml"
        outside.parent.mkdir()
        outside.write_text('[package]\nname="owned-test"\n')
        source = self.root / "source"
        source.mkdir()
        package = dict(self.package, source=None, manifest_path=str(outside))
        with self.assertRaises(ValueError):
            cargo.package_record(package, {}, source)


class NpmInventory(unittest.TestCase):
    def record(self, package):
        with tempfile.TemporaryDirectory(prefix="easy-auth-npm-inventory-test-") as directory:
            root = Path(directory)
            (root / "package-lock.json").write_text(json.dumps(dict(
                lockfileVersion=3, packages={"node_modules/example": package})))
            return sources.npm_record(root, "package-lock.json")

    def package(self, **changes):
        return dict(version="1.0.0", resolved="https://registry.npmjs.org/example/-/example-1.0.0.tgz",
                    integrity="sha512-" + "A" * 86 + "==", license="MIT", **changes)

    def test_registry_credentials_mirror_or_invalid_integrity_fail(self):
        for changes in [dict(resolved="https://user:password@registry.npmjs.org/example.tgz"),
                        dict(resolved="https://mirror.example/example.tgz"),
                        dict(integrity="sha512-invalid")]:
            package = self.package()
            package.update(changes)
            with self.subTest(fields=sorted(changes)), self.assertRaises(ValueError):
                self.record(package)

    def test_missing_license_is_visible_not_silently_approved(self):
        package = self.package()
        package.pop("license")
        report = self.record(package)
        self.assertEqual(report["missing_license_declarations"], 1)
        self.assertIsNone(report["packages"][0]["license_expression"])


class ToolArchive(unittest.TestCase):
    def archive(self, name, kind=tarfile.REGTYPE):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            member = tarfile.TarInfo(name)
            member.type = kind
            archive.addfile(member)
        data.seek(0)
        return tarfile.open(fileobj=data)

    def test_expected_regular_source_is_admitted(self):
        with self.archive("cargo-cyclonedx-0.5.9/src/main.rs") as archive:
            validate_members(archive, "cargo-cyclonedx-0.5.9")

    def test_traversal_other_root_absolute_and_links_are_rejected(self):
        for name, kind in [("cargo-cyclonedx-0.5.9/../escape", tarfile.REGTYPE),
                           ("other-package/Cargo.toml", tarfile.REGTYPE),
                           ("/absolute", tarfile.REGTYPE),
                           ("cargo-cyclonedx-0.5.9/link", tarfile.SYMTYPE),
                           ("cargo-cyclonedx-0.5.9/link", tarfile.LNKTYPE)]:
            with self.subTest(kind=kind, name=name), self.archive(name, kind) as archive:
                with self.assertRaises(ValueError):
                    validate_members(archive, "cargo-cyclonedx-0.5.9")


class PublicSourceInputs(unittest.TestCase):
    def test_only_committed_paths_are_read(self):
        with tempfile.TemporaryDirectory(prefix="easy-auth-committed-inputs-") as directory:
            root = Path(directory)
            command = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                       "-c", "commit.gpgsign=false", "-c", "user.name=Owned fixture",
                       "-c", "user.email=fixture@example.test"]
            for arguments in (["init", "--quiet"],):
                subprocess.run(command + arguments, cwd=root, capture_output=True, check=True)
            (root / "public.txt").write_text("ordinary committed marker\n")
            subprocess.run(command + ["add", "public.txt"], cwd=root, capture_output=True, check=True)
            subprocess.run(command + ["commit", "--quiet", "-m", "owned fixture"], cwd=root,
                           capture_output=True, check=True)
            (root / "untracked.txt").write_text("owned marker that must not be read\n")
            records = sources.tracked_records(root, ["."])
            self.assertEqual([p["path"] for p in records], ["public.txt"])

    def test_checkout_revision_must_match_ci(self):
        with patch.object(sources.subprocess, "check_output", return_value=b"abc123\n"):
            with patch.dict(os.environ, {"GITHUB_SHA": "abc123"}):
                self.assertEqual(sources.committed_revision(Path(".")), "abc123")
            with patch.dict(os.environ, {"GITHUB_SHA": "different"}):
                with self.assertRaises(ValueError):
                    sources.committed_revision(Path("."))


class SbomReferences(unittest.TestCase):
    def document(self):
        root = "path+file:///private/owned-export/app#app@1.0.0"
        return dict(metadata=dict(component={"bom-ref": root, "name": "app", "version": "1.0.0"}),
                    components=[{"bom-ref": "registry-package", "name": "example", "version": "2.0.0",
                                 "licenses": [{"expression": "MIT OR Apache-2.0"}]}],
                    dependencies=[dict(ref=root, dependsOn=["registry-package"])])

    def test_normalization_changes_only_source_refs_and_retains_graph_and_license(self):
        original = self.document()
        before = copy.deepcopy(original)
        normalized = rust_sbom.normalize_source_refs(original, "file:///private/owned-export", "abc123")
        rust_sbom.verify_references(normalized)
        self.assertEqual(original, before)
        self.assertEqual(normalized["components"], original["components"])
        reference = "path+file:///source/abc123/app#app@1.0.0"
        self.assertEqual(normalized["metadata"]["component"]["bom-ref"], reference)
        self.assertEqual(normalized["dependencies"][0]["ref"], reference)
        self.assertNotIn("/private/", json.dumps(normalized))

    def test_prefix_collision_or_unexpected_path_field_is_not_silently_rewritten(self):
        for value in ("path+file:///private/owned-export-lookalike/app", "file:///private/owned-export/app"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                rust_sbom.normalize_source_refs(value, "file:///private/owned-export", "abc123")

    def test_dangling_and_duplicate_refs_fail(self):
        dangling = self.document()
        dangling["dependencies"][0]["dependsOn"].append("missing")
        with self.assertRaises(ValueError):
            rust_sbom.verify_references(dangling)
        duplicate = self.document()
        duplicate["components"].append(copy.deepcopy(duplicate["components"][0]))
        with self.assertRaises(ValueError):
            rust_sbom.verify_references(duplicate)

    def test_scoped_package_coverage_retains_namespace_and_rejects_missing_identity(self):
        document = dict(bomFormat="CycloneDX", specVersion="1.7", components=[{
            "bom-ref": "scoped", "type": "library", "group": "@scope", "name": "example",
            "version": "1.0.0", "licenses": [{"expression": "MIT"}]}])
        with tempfile.TemporaryDirectory(prefix="easy-auth-sbom-coverage-") as directory:
            destination = Path(directory)
            record = trivy_sbom.publish(document, destination, "valid", {("@scope/example", "1.0.0")})
            self.assertEqual(record["missing_package_identities"], [])
            with self.assertRaises(ValueError):
                trivy_sbom.publish(document, destination, "missing", {("other", "1.0.0")})

    def test_debian_epoch_revision_and_architecture_remain_part_of_identity(self):
        purl = "pkg:deb/debian/example@1%3A2.0-3?arch=arm64&distro=debian-13"
        document = dict(bomFormat="CycloneDX", specVersion="1.7", components=[{
            "bom-ref": "debian", "type": "library", "name": "example", "version": "1:2.0-3",
            "purl": purl, "licenses": [{"expression": "MIT"}]}])
        with tempfile.TemporaryDirectory(prefix="easy-auth-debian-sbom-") as directory:
            destination = Path(directory)
            record = trivy_sbom.publish(document, destination, "valid", {purl}, use_purls=True)
            self.assertEqual(record["missing_package_identities"], [])
            with self.assertRaises(ValueError):
                trivy_sbom.publish(document, destination, "wrong-revision",
                                   {purl.replace("-3?", "-4?")}, use_purls=True)

    def test_own_root_license_comes_from_metadata_without_changing_dependencies(self):
        document = dict(self.document(), bomFormat="CycloneDX", specVersion="1.5")
        with tempfile.TemporaryDirectory(prefix="easy-auth-root-license-") as directory:
            folder = Path(directory)
            raw = folder / "input.json"
            raw.write_text(json.dumps(document))
            record, _, _ = rust_sbom.export_document(raw, Path("/private/owned-export"), folder,
                                                     "abc123", "test", {"app": "MIT OR Apache-2.0"})
            result = json.loads((folder / record["path"]).read_text())
            self.assertEqual(result["components"], document["components"])
            self.assertEqual(result["metadata"]["component"]["licenses"], [{"expression": "MIT OR Apache-2.0"}])
            document["metadata"]["component"]["licenses"] = [{"expression": "Apache-2.0"}]
            raw.write_text(json.dumps(document))
            with self.assertRaises(ValueError):
                rust_sbom.export_document(raw, Path("/private/owned-export"), folder,
                                           "abc123", "conflict", {"app": "MIT OR Apache-2.0"})

    def test_new_license_gap_or_mismatched_gcc_version_requires_review(self):
        unknown = dict(Results=[dict(Packages=[dict(Name="new-gap", Licenses=[])])])
        mismatch = dict(Results=[dict(Packages=[
            dict(Name="libgcc-s1", ID="libgcc-s1@15.0-1", Licenses=[]),
            dict(Name="gcc-14-base", ID="gcc-14-base@14.2-19", Licenses=["GPL-3.0"])])])
        with patch.object(trivy_sbom, "snapshot") as snapshot:
            for report in (unknown, mismatch):
                with self.assertRaises(ValueError):
                    trivy_sbom.retained_copyright(report, "unused-owned-image")
            snapshot.assert_not_called()


if __name__ == "__main__":
    unittest.main()
