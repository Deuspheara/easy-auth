"""Real pinned-age archive/rotation negatives; no database or provider credentials."""
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest
import uuid
from unittest.mock import patch

from operational_recovery.encrypted_archives.admission import prepared_tool
from operational_recovery.encrypted_archives.cipher import ArchiveCipher


def write_private(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(data)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class EncryptedArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tool = os.environ.get("EASY_AUTH_BACKUP_TOOL_DIRECTORY")
        if not tool:
            raise ValueError("prepare and select EASY_AUTH_BACKUP_TOOL_DIRECTORY before this suite")
        cls.temporary = tempfile.TemporaryDirectory(prefix="easy-auth-age-cases-")
        cls.directory = Path(cls.temporary.name)
        cls.cipher = ArchiveCipher(tool)
        cls.old_key, cls.new_key = cls.directory / "old.key", cls.directory / "new.key"
        cls.old_recipient = cls.cipher.new_identity(cls.old_key)
        cls.new_recipient = cls.cipher.new_identity(cls.new_key)
        cls.source = cls.directory / "synthetic.dump"
        write_private(cls.source, b"PGDMP" + os.urandom(150000))
        cls.archive = cls.directory / "old.dump.age"
        with cls.source.open("rb") as stream:
            cls.archive_digest = cls.cipher.encrypt(stream, cls.archive, cls.old_recipient)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def output(self):
        return self.directory / uuid.uuid4().hex

    def test_full_multichunk_round_trip_is_private(self):
        target = self.output()
        self.cipher.decrypt(self.archive, target, self.old_key, self.archive_digest)
        self.assertEqual(sha(target), sha(self.source))
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.archive.stat().st_mode & 0o777, 0o600)

    def test_wrong_key_missing_key_and_wrong_trusted_digest_release_no_plaintext(self):
        for key, digest in [(self.new_key, self.archive_digest),
                            (self.directory / "absent.key", self.archive_digest),
                            (self.old_key, "0" * 64)]:
            target = self.output()
            with self.subTest(key=key.name), self.assertRaises((ValueError, FileNotFoundError)):
                self.cipher.decrypt(self.archive, target, key, digest)
            self.assertFalse(target.exists())

    def test_tamper_and_truncation_after_valid_chunks_remove_partial_plaintext(self):
        original = self.archive.read_bytes()
        changed = bytearray(original)
        changed[-1] ^= 1
        for data in (original[:-1], original[:70000], bytes(changed)):
            damaged, target = self.output(), self.output()
            write_private(damaged, data)
            # Deliberately supply the damaged digest too: the age full-length
            # integrity check must reject it independently of snapshot selection.
            with self.assertRaises(ValueError):
                self.cipher.decrypt(damaged, target, self.old_key, sha(damaged))
            self.assertFalse(target.exists())

    def test_new_key_only_reads_new_archives_and_old_key_is_retained_for_old(self):
        archive = self.output()
        with self.source.open("rb") as stream:
            digest = self.cipher.encrypt(stream, archive, self.new_recipient)
        target = self.output()
        with self.assertRaises(ValueError):
            self.cipher.decrypt(archive, target, self.old_key, digest)
        self.assertFalse(target.exists())
        for stored, key, expected in [(archive, self.new_key, digest),
                                      (self.archive, self.old_key, self.archive_digest)]:
            target = self.output()
            self.cipher.decrypt(stored, target, key, expected)
            self.assertEqual(sha(target), sha(self.source))

    def test_existing_archive_plaintext_and_identity_are_never_overwritten(self):
        target = self.output()
        write_private(target, b"owned bytes to preserve")
        before = sha(target)
        with self.source.open("rb") as stream, self.assertRaises(FileExistsError):
            self.cipher.encrypt(stream, target, self.old_recipient)
        self.assertEqual(sha(target), before)
        with self.assertRaises(FileExistsError):
            self.cipher.decrypt(self.archive, target, self.old_key, self.archive_digest)
        self.assertEqual(sha(target), before)
        key_before = sha(self.old_key)
        with self.assertRaises(FileExistsError):
            self.cipher.new_identity(self.old_key)
        self.assertEqual(sha(self.old_key), key_before)

    def test_public_identity_permissions_and_other_profiles_are_rejected(self):
        copied = self.output()
        shutil.copyfile(self.old_key, copied)
        copied.chmod(0o644)
        with self.assertRaises(ValueError):
            self.cipher.recipient(copied)
        for recipient in ("ssh-ed25519 synthetic", "age1plugin1synthetic", "", self.old_recipient + "\n"):
            target = self.output()
            with self.source.open("rb") as stream, self.assertRaises(ValueError):
                self.cipher.encrypt(stream, target, recipient)
            self.assertFalse(target.exists())

    def test_changed_prepared_binary_is_rejected_before_use(self):
        root = self.output()
        root.mkdir(mode=0o700)
        (root / "bin").mkdir(mode=0o700)
        shutil.copyfile(self.cipher.directory / "receipt.json", root / "receipt.json")
        (root / "receipt.json").chmod(0o600)
        for name in ("age", "age-keygen", "govulncheck"):
            shutil.copyfile(self.cipher.directory / "bin" / name, root / "bin" / name)
        with (root / "bin/age").open("r+b") as binary:
            binary.seek(-1, 2)
            value = binary.read(1)[0]
            binary.seek(-1, 2)
            binary.write(bytes([value ^ 1]))
        with self.assertRaisesRegex(ValueError, "binary changed"):
            prepared_tool(root)

    def test_output_size_and_expired_budget_remove_the_partial_file(self):
        for name, value in [("MAX_ARCHIVE_BYTES", 1000), ("OPERATION_SECONDS", 0)]:
            target = self.output()
            with patch("operational_recovery.encrypted_archives.cipher." + name, value):
                with self.source.open("rb") as source, self.assertRaises(ValueError):
                    self.cipher.encrypt(source, target, self.old_recipient)
            self.assertFalse(target.exists())

    def test_authenticated_non_archive_content_is_not_released(self):
        source, archive, output = self.output(), self.output(), self.output()
        write_private(source, b"owned data that is not a PostgreSQL archive")
        with source.open("rb") as stream:
            expected = self.cipher.encrypt(stream, archive, self.old_recipient)
        with self.assertRaisesRegex(ValueError, "not a PostgreSQL custom archive"):
            self.cipher.decrypt(archive, output, self.old_key, expected)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
