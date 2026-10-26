"""Use the reviewed age command; never release partial decryption to PostgreSQL."""
import os
from pathlib import Path
import re
import selectors
import subprocess
import time

from .admission import (CHUNK_BYTES, MAX_ARCHIVE_BYTES, digest, native_identity,
                        native_recipient, prepared_tool, private_directory, private_file)

OPERATION_SECONDS = 90


class ArchiveCipher:
    def __init__(self, directory):
        self.directory, self.receipt = prepared_tool(directory)
        # Explicit native identities plus an isolated PATH supply no plugin/agent
        # selection or ambient credentials to the offline command.
        self.environment = dict(PATH=str(self.directory / "bin"), LANG="C")

    def new_identity(self, path):
        path = Path(path)
        private_directory(path.parent)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as output:
                result = subprocess.run([str(self.directory / "bin/age-keygen")],
                    env=self.environment, stdin=subprocess.DEVNULL, stdout=output,
                    stderr=subprocess.PIPE, timeout=OPERATION_SECONDS)
            if result.returncode:
                raise ValueError("backup identity generation failed")
            return self.recipient(path)
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def recipient(self, identity):
        identity = Path(identity)
        native_identity(identity)
        result = subprocess.run([str(self.directory / "bin/age-keygen"), "-y", str(identity)],
            env=self.environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=OPERATION_SECONDS)
        if result.returncode or result.stderr:
            raise ValueError("backup identity could not be parsed")
        return native_recipient(result.stdout.decode("ascii").removesuffix("\n"))

    def encrypt(self, source, destination, recipient):
        recipient = native_recipient(recipient)
        command = [str(self.directory / "bin/age"), "--encrypt", "--recipient", recipient]
        self._write_output(command, source, Path(destination))
        try:
            with private_file(Path(destination)) as stream:
                return digest(stream)
        except BaseException:
            Path(destination).unlink(missing_ok=True)
            raise

    def decrypt(self, archive, destination, identity, expected_sha256):
        archive, destination, identity = Path(archive), Path(destination), Path(identity)
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise ValueError("trusted archive digest is required")
        native_identity(identity)
        with private_file(archive) as source:
            if digest(source) != expected_sha256:
                raise ValueError("archive differs from the selected trusted snapshot")
            source.seek(0)
            command = [str(self.directory / "bin/age"), "--decrypt", "--identity", str(identity)]
            self._write_output(command, source, destination)
        try:
            with private_file(destination) as plaintext:
                if plaintext.read(5) != b"PGDMP":
                    raise ValueError("decrypted content is not a PostgreSQL custom archive")
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        return destination

    def _write_output(self, command, source, destination):
        private_directory(destination.parent)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as output:
                child = subprocess.Popen(command, env=self.environment, stdin=source,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                try:
                    deadline = time.monotonic() + OPERATION_SECONDS
                    drain_output(child, output, deadline)
                    if child.wait(timeout=max(0.001, deadline - time.monotonic())):
                        raise ValueError("archive cryptographic operation failed")
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=5)
                    child.stdout.close()
        except BaseException:
            destination.unlink(missing_ok=True)
            raise


def drain_output(child, output, deadline):
    count = 0
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise ValueError("archive operation exceeded its deadline")
            block = os.read(child.stdout.fileno(), CHUNK_BYTES)
            if not block:
                if count == 0:
                    raise ValueError("archive operation produced no output")
                return
            count += len(block)
            if count > MAX_ARCHIVE_BYTES:
                raise ValueError("archive output exceeds size bound")
            output.write(block)
