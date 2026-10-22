"""Ordinary source-inventory regressions; no XML or cryptographic probes."""
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import shutil
import tempfile
import unittest
import json
from unittest.mock import patch

from scripts import check_saml_source as source


class SourceIntegrity(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="easy-auth-source-check-")
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        shutil.copytree(source.SOURCE, root / "source")
        shutil.copyfile(source.MANIFEST, root / "manifest.json")
        target = root / "tests/provider/saml/rust-policy/patches"
        target.mkdir(parents=True)
        for name in source.PATCHES:
            shutil.copyfile(source.ROOT / "tests/provider/saml/rust-policy/patches" / name, target / name)
        self.root = root
        self.scope = patch.multiple(source, ROOT=root, SOURCE=root / "source", MANIFEST=root / "manifest.json")
        self.scope.start()
        self.addCleanup(self.scope.stop)

    def test_exact_source_passes(self):
        with redirect_stdout(StringIO()):
            source.check()

    def test_changed_document_fails(self):
        (source.SOURCE / "README.md").write_text("ordinary source-integrity fixture\n")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            source.check()

    def test_extra_source_file_fails(self):
        (source.SOURCE / "unexpected.txt").write_text("ordinary source-integrity fixture\n")
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            source.check()

    def test_changed_patch_fails(self):
        path = self.root / "tests/provider/saml/rust-policy/patches" / source.PATCHES[0]
        path.write_text("ordinary source-integrity fixture\n")
        with self.assertRaisesRegex(ValueError, "patch hash mismatch"):
            source.check()

    def test_changed_maintenance_patch_fails(self):
        path = self.root / "tests/provider/saml/rust-policy/patches" / source.PATCHES[-1]
        path.write_text("ordinary source-integrity fixture\n")
        with self.assertRaisesRegex(ValueError, "patch hash mismatch"):
            source.check()

    def test_duplicate_patch_scope_fails(self):
        manifest = json.loads(source.MANIFEST.read_text())
        name = source.PATCHES[0]
        manifest["maintenance_patches"][name] = manifest["existing_qualification_patches"][name]
        source.MANIFEST.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "duplicate patch inventory path"):
            source.check()


if __name__ == "__main__":
    unittest.main()
