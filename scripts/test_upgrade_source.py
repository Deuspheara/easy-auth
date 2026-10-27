"""Immutable published inputs and artifact admission for the owned upgrade fixture."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from operational_recovery import upgrade_source


class UpgradeSourceTests(unittest.TestCase):
    def test_prepared_binary_change_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "target/debug").mkdir(parents=True)
            (root / "target/debug/easy-auth").write_bytes(b"not an executable")
            receipt = root / "receipt.json"
            receipt.write_text(json.dumps(dict(pin=upgrade_source.load_pin(), production_acceptance=False,
                                               preserved_inputs={str(i): "owned" for i in range(41)},
                                               source_files_sha256="0" * 64, compiler="rustc 1.95.0 fixture",
                                               binary_sha256="0" * 64)))
            receipt.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "binary changed"):
                upgrade_source.prepared_binary(root)

    def test_existing_preparation_directory_and_bytes_survive_refusal(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            marker = root / "keep"
            marker.write_bytes(b"owned bytes")
            with self.assertRaises(FileExistsError):
                upgrade_source.prepare(root)
            self.assertEqual(marker.read_bytes(), b"owned bytes")

    def test_modified_published_migration_is_not_accepted_as_legacy_input(self):
        with tempfile.TemporaryDirectory() as name:
            root, old = Path(name) / "current", Path(name) / "old"
            for directory in (root, old):
                migrations = directory / "crates/auth-postgres/migrations"
                migrations.mkdir(parents=True)
                (directory / ".cargo").mkdir()
                for file in ("Cargo.lock", "Cargo.toml", "rust-toolchain.toml", ".cargo/config.toml"):
                    (directory / file).write_text("owned matching fixture\n")
                for version in range(1, 38):
                    (migrations / (str(version).zfill(4) + "_fixture.sql")).write_text("SELECT 1;\n")
            with patch.object(upgrade_source, "ROOT", root):
                accepted = upgrade_source.verify_inputs(old, upgrade_source.load_pin())
                self.assertEqual(len(accepted), 41)
                (old / "crates/auth-postgres/migrations/0037_fixture.sql").write_text("SELECT 2;\n")
                with self.assertRaisesRegex(ValueError, "input differs"):
                    upgrade_source.verify_inputs(old, upgrade_source.load_pin())

    def test_build_ignores_owner_wrappers_and_database_overrides(self):
        with patch.dict(os.environ, {"RUSTC_WRAPPER": "owner-private-hook", "CC": "owner-private-cc",
                                     "DATABASE_URL": "private-marker", "SQLX_OFFLINE_DIR": "private-path"}):
            environment = upgrade_source.build_environment(Path("/owned/fixture"))
        self.assertEqual(environment["RUSTC_WRAPPER"], "")
        self.assertEqual(environment["SQLX_OFFLINE"], "true")
        self.assertNotIn("DATABASE_URL", environment)
        self.assertNotIn("SQLX_OFFLINE_DIR", environment)
        self.assertNotIn("CC", environment)


if __name__ == "__main__":
    unittest.main()
