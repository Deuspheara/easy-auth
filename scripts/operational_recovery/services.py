"""Exclusive PostgreSQL/Mailpit fixture lifetime, including anonymous-volume cleanup."""
import json
import os
from pathlib import Path
import secrets
import re
import subprocess
import time
import uuid


def docker(arguments, *, environment=None, input=None):
    result = subprocess.run(["docker", *arguments], env=environment, input=input,
                            capture_output=True, timeout=120)
    if result.returncode:
        raise ValueError("owned operational Docker command failed")
    return result.stdout.decode().strip()


def inspect(kind, identifier):
    result = subprocess.run(["docker", kind, "inspect", identifier], capture_output=True, timeout=15)
    if result.returncode:
        if b"no such" in result.stderr.lower():
            return None
        raise ValueError("owned operational resource inspection failed")
    records = json.loads(result.stdout)
    if len(records) != 1:
        raise ValueError("ambiguous operational resource")
    return records[0]


class Services:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.owner = "auth49-" + uuid.uuid4().hex
        self.names = {name: "easy-auth-" + self.owner + "-" + name for name in ("postgres", "mail")}
        self.admin_password = secrets.token_urlsafe(32)
        self.ids = {}
        self.volumes = set()
        self.stage = "owned-services"

    def start(self):
        if any(inspect("container", name) for name in self.names.values()):
            raise ValueError("operational fixture already exists")
        settings = self.directory / "postgres.env"
        with os.fdopen(os.open(settings, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
            output.write("POSTGRES_USER=auth\nPOSTGRES_DB=fixture_admin\nPOSTGRES_PASSWORD=" + self.admin_password + "\n")
        for service, image, options in [
            ("postgres", "postgres:17-alpine", ["--publish", "127.0.0.1::5432", "--env-file", str(settings)]),
            ("mail", "axllent/mailpit:v1.27", ["--publish", "127.0.0.1::1025", "--publish", "127.0.0.1::8025"]),
        ]:
            command = ["run", "--detach", "--rm", "--pull=never", "--name", self.names[service],
                       "--label", "easy-auth.owner=" + self.owner, *options, image]
            if service == "postgres":
                command += ["-c", "log_statement=none", "-c", "log_min_error_statement=panic",
                            "-c", "log_min_messages=panic", "-c", "log_parameter_max_length_on_error=0"]
            self.ids[service] = docker(command)
        self.verify()
        value = inspect("container", self.ids["postgres"])
        address = next(iter(value["NetworkSettings"]["Networks"].values()))["IPAddress"]
        deadline = time.monotonic() + 60
        # The entrypoint's temporary initialization server accepts Unix sockets
        # before the final TCP server is ready. Require the actual TCP listener.
        while subprocess.run(["docker", "exec", self.ids["postgres"], "pg_isready", "--host", address, "-U", "auth",
                              "-d", "fixture_admin"], capture_output=True).returncode:
            if time.monotonic() >= deadline:
                raise ValueError("owned PostgreSQL readiness deadline")
            time.sleep(0.1)

    def verify(self):
        values = {name: inspect("container", identifier) for name, identifier in self.ids.items()}
        if set(values) != {"postgres", "mail"}:
            raise ValueError("operational fixture incomplete")
        for value in values.values():
            if not value or not value["State"]["Running"] or not value["HostConfig"]["AutoRemove"] \
                    or value["Config"]["Labels"].get("easy-auth.owner") != self.owner \
                    or value["HostConfig"].get("Binds"):
                raise ValueError("operational fixture ownership mismatch")
            if any(b["HostIp"] != "127.0.0.1" for entries in value["NetworkSettings"]["Ports"].values()
                   if entries for b in entries):
                raise ValueError("operational fixture nonloopback listener")
            for mount in value["Mounts"]:
                if mount["Type"] != "volume":
                    raise ValueError("unexpected operational fixture mount")
                volume = inspect("volume", mount["Name"])
                users = docker(["ps", "-aq", "--filter", "volume=" + mount["Name"]]).split()
                if "com.docker.volume.anonymous" not in volume["Labels"] or users != [value["Id"][:12]]:
                    raise ValueError("operational fixture volume is not exclusive")
                self.volumes.add(mount["Name"])
        self.pg_port = int(values["postgres"]["NetworkSettings"]["Ports"]["5432/tcp"][0]["HostPort"])
        self.smtp_port = int(values["mail"]["NetworkSettings"]["Ports"]["1025/tcp"][0]["HostPort"])
        self.mail_origin = "http://127.0.0.1:" + values["mail"]["NetworkSettings"]["Ports"]["8025/tcp"][0]["HostPort"]
        return {name: value["Image"] for name, value in values.items()}

    def sql(self, database, statement, *, user="auth", password=None, expected_error=False, label="command"):
        environment = dict(os.environ)
        arguments = ["exec", "-i"]
        if password is not None:
            environment["PGPASSWORD"] = password
            arguments += ["--env", "PGPASSWORD"]
        arguments += [self.ids["postgres"], "psql", "-XqAt", "--set=ON_ERROR_STOP=1",
                      "--set=VERBOSITY=sqlstate", "--username=" + user, "--dbname=" + database]
        if password is not None:
            value = inspect("container", self.ids["postgres"])
            address = next(iter(value["NetworkSettings"]["Networks"].values()))["IPAddress"]
            arguments += ["--host=" + address]
        result = subprocess.run(["docker", *arguments], env=environment, input=statement.encode(),
                                capture_output=True, timeout=20)
        matched = re.search(rb"(?:ERROR|FATAL):\s*([0-9A-Z]{5})(?:\s|$)", result.stderr)
        state = matched.group(1).decode() if matched else "unavailable"
        if expected_error:
            if result.returncode == 0 or b"42501" not in result.stderr:
                raise ValueError("expected PostgreSQL privilege refusal not observed: " + label + "/" + state)
            return ""
        if result.returncode:
            raise ValueError("owned PostgreSQL operation failed: " + label + "/" + state)
        return result.stdout.decode().strip()

    def close(self):
        volumes = set(self.volumes)
        for name in reversed(list(self.names.values())):
            value = inspect("container", name)
            if value is None:
                continue
            if value["Config"]["Labels"].get("easy-auth.owner") != self.owner \
                    or not value["HostConfig"]["AutoRemove"] or value["HostConfig"].get("Binds"):
                raise ValueError("refusing unknown operational cleanup")
            for mount in value["Mounts"]:
                if mount["Type"] != "volume":
                    raise ValueError("unexpected operational mount")
                volume = inspect("volume", mount["Name"])
                users = docker(["ps", "-aq", "--filter", "volume=" + mount["Name"]]).split()
                if "com.docker.volume.anonymous" not in volume["Labels"] or users != [value["Id"][:12]]:
                    raise ValueError("operational volume is not exclusive")
                volumes.add(mount["Name"])
            docker(["stop", "--time", "5", value["Id"]])
        deadline = time.monotonic() + 10
        while any(inspect("container", name) for name in self.names.values()) \
                or any(inspect("volume", name) for name in volumes):
            if time.monotonic() >= deadline:
                raise ValueError("owned operational resources remain")
            time.sleep(0.1)
