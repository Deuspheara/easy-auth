#!/usr/bin/env python3
"""Local transport check: an owned queue fixture through the real SMTP worker.

This checks delivery, not saved-code configuration or all-keys-lost recovery.
Use the documented Docker PostgreSQL/Mailpit services and a freshly built server.
Only this run's disposable database and exact random recipient are removed.
"""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
MAILPIT = "http://127.0.0.1:8025"


def psql(database):
    container = os.environ.get("EASY_AUTH_SMOKE_POSTGRES_CONTAINER")
    if container:
        assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", container), "explicit test PostgreSQL container"
        command = ["docker", "exec", "-i", container]
    else:
        command = ["docker", "compose", "exec", "-T", "postgres"]
    return command + ["psql", "-U", "auth", "-d", database, "-v", "ON_ERROR_STOP=1"]


def sql(statement):
    subprocess.run(
        psql("auth") + ["-c", statement],
        cwd=ROOT, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def mail_request(path, ids=None):
    data = None if ids is None else json.dumps({"IDs": ids}).encode()
    request = urllib.request.Request(
        MAILPIT + path, data=data, method="GET" if ids is None else "DELETE",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        body = response.read()
        if ids is not None:
            return None  # Mailpit DELETE may return non-JSON success text.
        return json.loads(body) if body else None


def owned_messages(address):
    result = mail_request("/api/v1/search?" + urllib.parse.urlencode({"query": "to:" + address}))
    return [m for m in result["messages"] if len(m["To"]) == 1 and m["To"][0]["Address"] == address]


def wait_notice(address):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        messages = owned_messages(address)
        if messages:
            assert len(messages) == 1, "exactly one owned notice"
            message = mail_request("/api/v1/message/" + urllib.parse.quote(messages[0]["ID"], safe=""))
            assert message["Subject"] == "Your passkey recovery configuration changed", "purpose-specific SMTP subject"
            assert message["To"][0]["Address"] == address, "owned verified recipient"
            text = message["Text"]
            assert "configured or replaced after a fresh passkey sign-in" in text, "configuration notice"
            assert "The code is never sent by email" in text, "no mailed recovery credential"
            assert not any(v in text for v in ["https://", "http://", "#token=", "code="]), "no recovery/sign-in URL or bearer value"
            return
        time.sleep(0.1)
    raise AssertionError("test infrastructure: owned SMTP notice timeout")


def wait_acknowledgement(database, notice):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        count = subprocess.check_output(
            psql(database) + ["-At", "-c", f"SELECT count(*) FROM auth_security_notifications WHERE id='{notice}'"],
            cwd=ROOT, stderr=subprocess.DEVNULL,
        ).strip()
        if count == b"0":
            return
        time.sleep(0.1)
    raise AssertionError("notification delivery must be acknowledged in the queue")


def server_environment(database, realm, port):
    environment = dict(os.environ)
    for line in (ROOT / ".env.example").read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line and "=" in line:
            key, value = line.split("=", 1)
            environment[key] = value
    connection = urllib.parse.urlsplit(os.environ.get("DATABASE_URL", environment["DATABASE_URL"]))
    assert connection.scheme in ("postgres", "postgresql"), "PostgreSQL test URL"
    assert connection.hostname in ("localhost", "127.0.0.1", "::1"), "loopback test database only"
    environment.update(
        DATABASE_URL=urllib.parse.urlunsplit(connection._replace(path="/" + database)),
        AUTH_REALM_ID=realm, AUTH_BIND=f"127.0.0.1:{port}", AUTH_PUBLIC_URL=f"http://127.0.0.1:{port}",
    )
    return environment


def wait_ready(child, port):
    for _ in range(100):
        assert child.poll() is None, "test infrastructure: owned server exited before readiness"
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz", timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.1)
    raise AssertionError("test infrastructure: owned server readiness timeout")


def main():
    namespace = uuid.uuid4().hex
    database = "easy_auth_recovery_notice_" + namespace
    address = "recovery-notice-" + namespace + "@example.test"
    realm, user, notice = (str(uuid.uuid4()) for _ in range(3))
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    sql(f'CREATE DATABASE "{database}"')
    child = None
    try:
        child = subprocess.Popen(
            [str(ROOT / "target/debug/easy-auth")], cwd=ROOT,
            env=server_environment(database, realm, port),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        wait_ready(child, port)
        # Fixed test SQL and internally generated UUID/recipient namespace only.
        # No authentication/session/proof is fabricated or returned by this fixture.
        statement = (
            f"INSERT INTO auth_users(realm_id,id,email) VALUES ('{realm}','{user}','{address}'); "
            "INSERT INTO auth_security_notifications(realm_id,id,user_id,recipient,kind) "
            f"VALUES ('{realm}','{notice}','{user}','{address}','passkey_recovery_changed');"
        )
        subprocess.run(
            psql(database) + ["-c", statement], cwd=ROOT, check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        wait_notice(address)
        wait_acknowledgement(database, notice)
        print("PASS: purpose-specific queued notice through the real SMTP worker")
    finally:
        if child is not None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        try:
            ids = [m["ID"] for m in owned_messages(address)]
            # Mailpit interprets an empty list as delete-all. Never submit one.
            if ids:
                mail_request("/api/v1/messages", ids)
            assert not owned_messages(address), "owned mail cleanup"
            print(f"PASS: removed {len(ids)} owned notice messages")
        finally:
            sql(f'DROP DATABASE "{database}"')
            print("PASS: owned notice database removed")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as error:
        # All assertion messages are fixed fixture diagnostics, never response data.
        raise SystemExit("FAIL: " + str(error)) from None
    except Exception as error:
        raise SystemExit("FAIL: recovery notice infrastructure (" + type(error).__name__ + "); transport details redacted") from None
