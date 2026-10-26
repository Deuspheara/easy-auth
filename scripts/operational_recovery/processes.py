"""Own only the explicitly launched administration/runtime child processes."""
import os
from pathlib import Path
import socket
import subprocess
import time
from urllib.request import ProxyHandler, build_opener
from urllib.parse import unquote, urlsplit


def unused_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class Processes:
    def __init__(self, binary, directory, smtp_port):
        self.binary = Path(binary)
        self.directory = Path(directory)
        self.smtp_port = smtp_port
        self.children = []
        self.logs = []
        self.private_values = set()

    def protect_url(self, database_url):
        self.private_values.add(database_url.encode())
        password = unquote(urlsplit(database_url).password or "")
        if password:
            self.private_values.add(password.encode())

    def one_shot(self, database_url, *, expected_success, failure_kind="connection"):
        expected_failures = {"connection": b'Error: "database connection failed"\n',
                             "migration": b'Error: "database migration failed"\n'}
        if failure_kind not in expected_failures:
            raise ValueError("unknown owned migration failure profile")
        self.protect_url(database_url)
        environment = {"PATH": os.environ.get("PATH", ""), "DATABASE_URL": database_url,
                       "AUTH_REALM_ID": "unused-invalid-runtime-setting",
                       "SMTP_PASSWORD": "unused-invalid-runtime-setting"}
        child = subprocess.Popen([str(self.binary), "migrate"], env=environment,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.children.append(child)
        output, diagnostic = child.communicate(timeout=20)
        if any(value in output or value in diagnostic for value in self.private_values):
            raise ValueError("administration output exposed fixture credentials")
        if expected_success:
            if child.returncode != 0 or output != b"database migrations completed\n" or diagnostic:
                raise ValueError("owned migration administration did not complete cleanly")
        elif child.returncode == 0 or output or diagnostic != expected_failures[failure_kind]:
            raise ValueError("owned migration refusal did not match its exact profile")

    def start(self, database_url, realm, *, mode="verify", expected_success=True):
        self.protect_url(database_url)
        origin = "http://127.0.0.1:" + str(unused_port())
        environment = {"PATH": os.environ.get("PATH", ""), "DATABASE_URL": database_url,
                       "AUTH_DEVELOPMENT": "true", "AUTH_REALM_ID": str(realm),
                       "AUTH_PUBLIC_URL": origin, "AUTH_BIND": origin.removeprefix("http://"),
                       "AUTH_DATABASE_MIGRATIONS": mode, "SMTP_HOST": "127.0.0.1",
                       "SMTP_PORT": str(self.smtp_port), "SMTP_FROM": "auth@example.test"}
        path = self.directory / ("server-" + str(len(self.logs)) + ".log")
        log = os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
        self.logs.append(log)
        child = subprocess.Popen([str(self.binary)], env=environment, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=log)
        self.children.append(child)
        if not expected_success:
            child.wait(timeout=10)
            if child.returncode == 0:
                raise ValueError("unprivileged migration startup unexpectedly succeeded")
            return origin
        opener = build_opener(ProxyHandler({}))
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise ValueError("owned runtime exited before readiness")
            try:
                with opener.open(origin + "/readyz", timeout=2) as response:
                    if response.status == 200:
                        return origin
            except OSError:
                pass
            time.sleep(0.1)
        raise ValueError("owned runtime readiness deadline")

    def close(self):
        for child in reversed(self.children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        for log in self.logs:
            log.close()
        for log in self.directory.glob("server-*.log"):
            if any(value in log.read_bytes() for value in self.private_values):
                raise ValueError("runtime output exposed fixture credentials")
