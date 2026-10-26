"""Dump/restore only this drill's owned cluster and newly created quarantined DBs."""
import os
from pathlib import Path
import subprocess
import time
import uuid

from .services import inspect


class ArchivePostgres:
    def __init__(self, services, roles, directory):
        self.services, self.roles, self.directory = services, roles, Path(directory)
        self.clones = []
        self.input_operations = 0
        self.restore_operations = 0

    def _command(self, program, database):
        self.services.verify()
        value = inspect("container", self.services.ids["postgres"])
        address = next(iter(value["NetworkSettings"]["Networks"].values()))["IPAddress"]
        environment = dict(os.environ, PGPASSWORD=self.roles.migration_password)
        command = ["docker", "exec", "-i", "--env", "PGPASSWORD", value["Id"], program,
                   "--host=" + address, "--username=" + self.roles.migration]
        if database is not None:
            command += ["--dbname=" + database]
        return command, environment

    def encrypted_dump(self, cipher, recipient, destination):
        if Path(destination).exists() or Path(destination).is_symlink():
            raise FileExistsError("encrypted archive destination already exists")
        command, environment = self._command("pg_dump", self.roles.database)
        child = subprocess.Popen(command + ["--format=custom", "--no-owner", "--no-acl"],
            env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        encrypted = False
        try:
            expected = cipher.encrypt(child.stdout, destination, recipient)
            encrypted = True
            child.stdout.close()
            _, diagnostic = child.communicate(timeout=30)
            if child.returncode or diagnostic:
                raise ValueError("owned PostgreSQL encrypted dump failed")
            return expected
        except BaseException:
            if encrypted:
                Path(destination).unlink(missing_ok=True)
            raise
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            child.stdout.close()
            child.stderr.close()

    def restore_selected(self, cipher, archive, identity, expected):
        plaintext = self.directory / ("quarantine-" + uuid.uuid4().hex + ".dump")
        decrypted = False
        try:
            cipher.decrypt(archive, plaintext, identity, expected)
            decrypted = True
            return self._restore(plaintext)
        finally:
            if decrypted:
                plaintext.unlink(missing_ok=True)

    def _restore(self, plaintext):
        command, environment = self._command("pg_restore", None)
        # Listing parses the fully decrypted archive but executes no archive SQL.
        self.input_operations += 1
        with plaintext.open("rb") as source:
            listed = subprocess.run(command + ["--list"], env=environment, stdin=source,
                capture_output=True, timeout=90)
        if listed.returncode or listed.stderr or b"_sqlx_migrations" not in listed.stdout:
            raise ValueError("owned decrypted archive listing failed")
        clone = "auth49_restore_" + uuid.uuid4().hex
        self.services.sql("fixture_admin", "CREATE DATABASE " + clone + " OWNER " + self.roles.migration
                          + " ALLOW_CONNECTIONS false", label="quarantine-create")
        self.clones.append(clone)
        self.services.sql("fixture_admin", "REVOKE ALL ON DATABASE " + clone + " FROM PUBLIC; "
                          "ALTER DATABASE " + clone + " ALLOW_CONNECTIONS true", label="quarantine-connect")
        command, environment = self._command("pg_restore", clone)
        self.input_operations += 1
        self.restore_operations += 1
        with plaintext.open("rb") as source:
            restored = subprocess.run(command + ["--no-owner", "--no-acl", "--single-transaction", "--exit-on-error"],
                env=environment, stdin=source, capture_output=True, timeout=90)
        if restored.returncode or restored.stderr:
            raise ValueError("owned quarantined restoration failed")
        self.assert_quarantined(clone)
        return clone

    def assert_quarantined(self, clone):
        if clone not in self.clones:
            raise ValueError("unknown restore destination")
        privilege = self.services.sql("fixture_admin", "SELECT has_database_privilege('"
            + self.roles.runtime + "','" + clone + "','CONNECT')", label="quarantine-privilege")
        if privilege != "f":
            raise ValueError("runtime role can connect to quarantined restoration")
        deadline = time.monotonic() + 5
        while self.services.sql("fixture_admin", "SELECT count(*) FROM pg_stat_activity WHERE datname='"
                                + clone + "'", label="quarantine-connections") != "0":
            if time.monotonic() >= deadline:
                raise ValueError("quarantined restore has a live connection")
            time.sleep(0.1)
