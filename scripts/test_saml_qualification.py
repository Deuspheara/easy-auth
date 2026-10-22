"""Check qualification graph selection without running protocol/crypto scenarios."""
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import qualify_saml_dependency as qualification

from scripts.qualify_saml_dependency import saml_subtree


class QualificationGraph(unittest.TestCase):
    def test_selects_only_saml_descendants_and_preserves_features(self):
        graph = saml_subtree("""0easy-auth-core v0.1.0 features=saml-verification
1other v1.0.0 features=default
1saml-rs v0.6.1 (/temporary/source) features=crypto-aws-lc
2backend v2.0.0 features=std,aws-lc
1unrelated v3.0.0 features=default
""")
        self.assertEqual(graph, {
            ("saml-rs", "0.6.1"): ("crypto-aws-lc",),
            ("backend", "2.0.0"): ("aws-lc", "std"),
        })

    def test_versions_and_feature_changes_are_distinct(self):
        before = saml_subtree("0saml-rs v0.6.1 features=crypto-aws-lc\n1backend v1.0.0 features=aws-lc")
        changed_version = saml_subtree("0saml-rs v0.6.1 features=crypto-aws-lc\n1backend v2.0.0 features=aws-lc")
        changed_features = saml_subtree("0saml-rs v0.6.1 features=crypto-aws-lc\n1backend v1.0.0 features=rustcrypto")
        self.assertNotEqual(before, changed_version)
        self.assertNotEqual(before, changed_features)

    def test_broader_or_missing_crypto_features_cannot_qualify(self):
        for features in ["", "crypto-rustcrypto", "crypto-aws-lc,crypto-rustcrypto"]:
            with self.subTest(features=features):
                with self.assertRaisesRegex(ValueError, "unexpected SAML"):
                    saml_subtree("0saml-rs v0.6.1 features=" + features)

    def test_missing_saml_cannot_establish_graph_equality(self):
        with self.assertRaisesRegex(ValueError, "SAML package missing"):
            saml_subtree("0unrelated v1.0.0 features=default")


class QualificationRun(unittest.TestCase):
    def test_full_report_path_passes_and_ignored_tests_fail(self):
        graph = "0saml-rs v0.6.1 features=crypto-aws-lc"
        with tempfile.TemporaryDirectory(prefix="easy-auth-report-test-") as directory:
            root = Path(directory)
            (root / "third-party").mkdir()
            (root / ".cargo").mkdir()
            (root / ".cargo/config.toml").write_text('[env]\nRUST_TEST_THREADS = "4"\n')
            (root / "Cargo.lock").write_bytes(b"ordinary lock fixture")
            (root / "third-party/saml-rs-source.json").write_bytes(b"ordinary inventory fixture")

            def stage(destination, lock):
                (destination / "Cargo.lock").write_bytes(lock)
                (destination / ".cargo").mkdir()
                (destination / ".cargo/config.toml").write_bytes(
                    (root / ".cargo/config.toml").read_bytes())

            result = SimpleNamespace(returncode=0, stderr="", stdout=(
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"))
            with patch.object(qualification, "ROOT", root), \
                 patch.object(qualification, "check"), \
                 patch.object(qualification, "cargo", return_value=graph), \
                 patch.object(qualification, "stage_workspace", side_effect=stage), \
                 patch.object(qualification.subprocess, "check_output", return_value="rustc fixture"), \
                 patch.object(qualification.subprocess, "run", return_value=result), \
                 redirect_stdout(StringIO()):
                qualification.qualify()
                self.assertTrue((root / "target/saml-dependency-qualification.json").is_file())
                result.stdout = result.stdout.replace("0 ignored", "1 ignored")
                with self.assertRaisesRegex(ValueError, "tests did not pass"):
                    qualification.qualify()
