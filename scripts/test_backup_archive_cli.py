"""Genuine archive subprocesses keep credentials/plaintext out of command output."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BackupCommandTests(unittest.TestCase):
    def run_command(self, *arguments, input=None):
        return subprocess.run([sys.executable, str(ROOT / "scripts/backup_archive.py"), *arguments],
            input=input, capture_output=True, cwd=ROOT, timeout=30)

    def test_help_needs_no_tool_or_private_configuration(self):
        output = self.run_command("--help")
        self.assertEqual(output.returncode, 0)
        self.assertEqual(output.stderr, b"")
        self.assertIn(b"keygen", output.stdout)

    def test_bad_arguments_never_reflect_pasted_private_values(self):
        for arguments in [("AGE-SECRET-KEY-private-marker",),
                          ("encrypt", "--unknown", "private-marker"),
                          ("decrypt", "--identity", "private-marker")]:
            output = self.run_command(*arguments)
            self.assertNotEqual(output.returncode, 0)
            self.assertEqual(output.stdout, b"")
            self.assertNotIn(b"private-marker", output.stderr)
            self.assertEqual(json.loads(output.stderr), dict(status="failed", category="ValueError"))

    def test_actual_key_encrypt_decrypt_outputs_metadata_only(self):
        tool = os.environ.get("EASY_AUTH_BACKUP_TOOL_DIRECTORY")
        if not tool:
            self.fail("prepare EASY_AUTH_BACKUP_TOOL_DIRECTORY before archive CLI qualification")
        with tempfile.TemporaryDirectory(prefix="easy-auth-archive-cli-") as name:
            directory = Path(name)
            key, encrypted, decrypted = (directory / name for name in ("owned.key", "owned.age", "plain.dump"))
            generated = self.run_command("keygen", "--tool-directory", tool, "--identity", str(key))
            self.assertEqual(generated.returncode, 0)
            self.assertEqual(generated.stderr, b"")
            recipient = json.loads(generated.stdout)["recipient"]
            plaintext = b"PGDMP" + b"private-marker-plaintext" * 100
            output = self.run_command("encrypt", "--tool-directory", tool, "--recipient", recipient,
                                      "--output", str(encrypted), input=plaintext)
            self.assertEqual(output.returncode, 0)
            expected = json.loads(output.stdout)["ciphertext_sha256"]
            released = self.run_command("decrypt", "--tool-directory", tool, "--identity", str(key),
                "--input", str(encrypted), "--output", str(decrypted), "--expected-sha256", expected)
            self.assertEqual(released.returncode, 0)
            self.assertEqual(json.loads(released.stdout), dict(status="decrypted_quarantine", plaintext_released_to_database=False))
            self.assertTrue(decrypted.read_bytes() == plaintext)
            for result in (generated, output, released):
                self.assertNotIn(b"AGE-SECRET-KEY", result.stdout + result.stderr)
                self.assertNotIn(b"private-marker", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
