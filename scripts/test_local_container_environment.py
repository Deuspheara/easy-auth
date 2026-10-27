"""Exercise exclusive private settings creation without emitting its values."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from urllib.parse import urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]


class LocalSettings(unittest.TestCase):
    def invoke(self, destination):
        return subprocess.run(["python3", str(ROOT / "scripts/write_local_container_environment.py"),
                               str(destination)], capture_output=True, text=True, check=False)

    def test_private_consistent_values_and_existing_bytes_preserved(self):
        with tempfile.TemporaryDirectory(prefix="easy-auth-settings-") as directory:
            destination = Path(directory) / "settings.env"
            first = self.invoke(destination)
            self.assertEqual(first.returncode, 0)
            content = destination.read_bytes()
            self.assertEqual(destination.stat().st_mode & 0o077, 0)
            values = dict(line.split("=", 1) for line in content.decode().splitlines())
            self.assertEqual(uuid.UUID(values["EASY_AUTH_LOCAL_REALM_ID"]).version, 4)
            password = values["EASY_AUTH_LOCAL_DB_PASSWORD"]
            connection = urlsplit(values["EASY_AUTH_LOCAL_DATABASE_URL"])
            self.assertTrue(connection.password == password, "paired credentials must agree")
            self.assertEqual((connection.hostname, connection.path), ("postgres", "/auth"))
            self.assertTrue(password not in first.stdout + first.stderr, "no credential output")
            second = self.invoke(destination)
            self.assertNotEqual(second.returncode, 0)
            self.assertTrue(destination.read_bytes() == content, "existing private bytes preserved")
            self.assertTrue(password not in second.stdout + second.stderr, "no credential output on refusal")

    def test_source_tree_destination_is_refused_without_creating_a_file(self):
        destination = ROOT / "target" / ("refuse-settings-" + uuid.uuid4().hex + ".env")
        self.assertFalse(destination.exists())
        try:
            self.assertNotEqual(self.invoke(destination).returncode, 0)
            self.assertFalse(destination.exists())
        finally:
            destination.unlink(missing_ok=True)
