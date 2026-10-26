"""Lifetime and ownership of one disposable local Compose project."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
from urllib.request import urlopen
import uuid

from .settings import development_settings

ROOT = Path(__file__).resolve().parents[2]
SERVICES = {"app", "mailpit", "postgres", "proxy"}
RESOURCE_LIMITS = {"app": (512 * 1024 * 1024, 128), "proxy": (64 * 1024 * 1024, 64)}


def unused_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class Stack:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.project = "easy-auth-smoke-" + uuid.uuid4().hex
        self.http_port, self.mail_port = unused_port(), unused_port()
        if self.http_port == self.mail_port:
            raise ValueError("owned listener collision")
        self.origin = f"http://127.0.0.1:{self.http_port}"
        self.mail_origin = f"http://127.0.0.1:{self.mail_port}"
        self.environment = dict(os.environ, **development_settings(),
                                EASY_AUTH_HTTP_PORT=str(self.http_port),
                                EASY_AUTH_MAIL_HTTP_PORT=str(self.mail_port))
        for name in ("deploy/local/compose.yaml", "deploy/local/nginx.conf",
                     "docs/examples/password-blocklist-development.txt"):
            target = self.directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        self.command = ["docker", "compose", "--env-file", "/dev/null", "--project-name",
                        self.project, "--file", str(self.directory / "deploy/local/compose.yaml")]
        self.started = False

    def run(self, arguments, **options):
        return subprocess.run(self.command + arguments, env=self.environment,
                              capture_output=True, check=True, timeout=120, **options)

    def start(self):
        for kind in ("container", "volume", "network"):
            command = ["docker", "ps", "-aq"] if kind == "container" else ["docker", kind, "ls", "-q"]
            if subprocess.check_output(command + ["--filter", "label=com.docker.compose.project=" + self.project]).strip():
                raise ValueError("owned project already exists")
        self.started = True
        self.run(["up", "--detach", "--wait", "--wait-timeout", "90"])
        self.verify()
        deadline = time.monotonic() + 90
        while True:
            try:
                with urlopen(self.origin + "/readyz", timeout=3) as response:
                    if response.status == 200:
                        return
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise ValueError("actual owned HTTP readiness deadline")
            time.sleep(0.2)

    def containers(self):
        ids = self.run(["ps", "--all", "--quiet"]).stdout.decode().splitlines()
        if not ids:
            return {}
        values = json.loads(subprocess.check_output(["docker", "inspect", *ids]))
        for value in values:
            labels = value["Config"]["Labels"]
            if labels["com.docker.compose.project"] != self.project or labels["com.docker.compose.service"] not in SERVICES:
                raise ValueError("unexpected container ownership")
        return {v["Config"]["Labels"]["com.docker.compose.service"]: v for v in values}

    def verify(self):
        containers = self.containers()
        if set(containers) != SERVICES or not all(v["State"]["Running"] for v in containers.values()):
            raise ValueError("owned stack incomplete")
        ports = containers["mailpit"]["NetworkSettings"]["Ports"]
        bindings = [binding for values in ports.values() if values for binding in values]
        if {v["HostPort"] for v in bindings} != {str(self.http_port), str(self.mail_port)} or any(v["HostIp"] != "127.0.0.1" for v in bindings):
            raise ValueError("non-owned or nonloopback listener")
        for service in ("app", "proxy"):
            value = containers[service]
            host = value["HostConfig"]
            if host["NetworkMode"] != "container:" + containers["mailpit"]["Id"] or not host["ReadonlyRootfs"] or value["Config"]["User"] != "65532:65532":
                raise ValueError("private namespace/filesystem invariant")
            if "ALL" not in host["CapDrop"] or "no-new-privileges:true" not in host["SecurityOpt"]:
                raise ValueError("container privilege invariant")
            if (host["Memory"], host["PidsLimit"]) != RESOURCE_LIMITS[service]:
                raise ValueError("container resource limit invariant")
            if any(m["Type"] == "bind" and (m["RW"] or not Path(m["Source"]).resolve().is_relative_to(self.directory.resolve())) for m in value["Mounts"]):
                raise ValueError("unexpected bind mount")
        return {name: value["Image"] for name, value in containers.items()}

    def close(self):
        if not self.started:
            return
        self.containers()  # Refuse unknown ownership before any removal.
        volumes = subprocess.check_output(["docker", "volume", "ls", "-q", "--filter",
                                           "label=com.docker.compose.project=" + self.project]).decode().splitlines()
        for name in volumes:
            value = json.loads(subprocess.check_output(["docker", "volume", "inspect", name]))[0]
            if value["Labels"].get("com.docker.compose.volume") != "postgres_data":
                raise ValueError("unexpected owned volume")
        self.run(["down", "--volumes"])
        if self.containers() or any(subprocess.run(["docker", "volume", "inspect", name], capture_output=True).returncode == 0 for name in volumes):
            raise ValueError("owned resources remain")
        if subprocess.check_output(["docker", "network", "ls", "-q", "--filter", "label=com.docker.compose.project=" + self.project]).strip():
            raise ValueError("owned network remains")
