#!/usr/bin/env python3
"""Owned normal-binary OIDC startup checks; no provider exchange or seeded identity.

Build default and oidc-web binaries as documented. This script owns one disposable
DB and one protected synthetic-secret file. Never deploy test credentials.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import urllib.request
import uuid

import smoke_recovery_notice as support

ROOT = Path(__file__).resolve().parents[1]
SECRET_MARKER = b"owned-startup-secret-marker"
RESULTS = []
PHASE = "setup"


def result(name):
    RESULTS.append(name)
    print(json.dumps({"case": name, "status": "passed"}), flush=True)


def observe(database):
    query = """SELECT json_build_object(
      'revision',(SELECT revision::text FROM auth_oauth_connections),
      'enabled',(SELECT enabled FROM auth_oauth_connections),
      'connections',(SELECT count(*) FROM auth_oauth_connections),
      'policies',(SELECT count(*) FROM auth_oidc_identity_policies),
      'jit',(SELECT jit FROM auth_oidc_identity_policies),
      'users',(SELECT count(*) FROM auth_users),
      'sessions',(SELECT count(*) FROM auth_sessions),
      'pending',(SELECT count(*) FROM auth_oauth_transactions),
      'audits',(SELECT count(*) FROM auth_audit))"""
    output = subprocess.check_output(support.psql(database) + ["-At", "-c", query], cwd=ROOT, stderr=subprocess.DEVNULL)
    return json.loads(output)


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def environment(database, realm):
    values = support.server_environment(database, realm, port())
    values = {k: v for k, v in values.items() if not k.startswith("AUTH_OIDC_")}
    values.update(
        AUTH_PUBLIC_URL="https://app.example", AUTH_OIDC_ENABLED="true",
        AUTH_OIDC_CONNECTION_ID=str(uuid.uuid4()), AUTH_OIDC_LOCAL_CLIENT_ID=str(uuid.uuid4()),
        AUTH_OIDC_ISSUER="https://issuer.example/tenant", AUTH_OIDC_PROVIDER_CLIENT_ID="owned-startup-client",
        AUTH_OIDC_ALLOWED_ORIGINS="https://issuer.example", AUTH_OIDC_CLIENT_AUTH_METHOD="none",
        AUTH_OIDC_SIGNING_ALGORITHMS="RS256",
    )
    return values


def request(values, path):
    address = values["AUTH_BIND"].rsplit(":", 1)[1]
    with urllib.request.urlopen("http://127.0.0.1:" + address + path, timeout=2) as response:
        assert response.status == 200, "test infrastructure: normal binary HTTP response"
        return json.load(response)


def running(binary, values):
    child = subprocess.Popen([str(binary)], cwd=ROOT, env=values, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        support.wait_ready(child, int(values["AUTH_BIND"].rsplit(":", 1)[1]))
    except BaseException:
        stop(child)
        raise
    return child


def stop(child):
    if child.poll() is None:
        child.terminate()
    try:
        _, diagnostic = child.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate(timeout=5)
        raise AssertionError("test infrastructure: owned server did not stop") from None
    assert SECRET_MARKER not in diagnostic, "secret content must not enter diagnostics"


def rejected(binary, values, expected, name):
    global PHASE
    PHASE = name
    # Expected configuration refusals must have their exact finite reason. A DB,
    # bind, build or readiness failure cannot masquerade as that refusal.
    completed = subprocess.run([str(binary)], cwd=ROOT, env=values, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=15)
    assert completed.returncode != 0, "invalid configuration must not start a listener"
    assert expected in completed.stderr, "expected configuration refusal, not unrelated infrastructure failure"
    assert SECRET_MARKER not in completed.stdout + completed.stderr, "secret content must not enter diagnostics"
    result(name)


def configured_modes(values, database):
    global PHASE
    baseline = None
    for mode, binary in [("standalone", ROOT / "target/debug/easy-auth"),
                         ("embedded", ROOT / "target/debug/examples/embedded")]:
        PHASE = "configured-" + mode
        child = running(binary, values)
        try:
            spec = request(values, "/openapi.json")
            for path in ["/v1/oidc/sign-in/start", "/v1/oidc/sign-in/finish", "/oidc/callback", "/v1/account/provider-delete/finish"]:
                assert path in spec["paths"], "supported mode must expose the shared concrete routes"
            facts = observe(database)
            assert facts["connections"] == facts["policies"] == 1
            assert facts["jit"] == "deny" and facts["enabled"] is True
            for key in ["users", "sessions", "pending", "audits"]:
                assert facts[key] == 0, "startup must not fabricate authentication authority"
            if baseline is None:
                baseline = facts
            else:
                assert facts == baseline, "cross-mode restart preserves exact persisted definition/revision"
            result("configured-" + mode + "-routes-and-stable-revision")
        finally:
            stop(child)
    return baseline


def invalid_settings(values, unsupported):
    normal = ROOT / "target/debug/easy-auth"
    rejected(unsupported, values, b"requires the oidc-web server feature", "unsupported-build-refuses-activation")
    partial = dict(values)
    partial.pop("AUTH_OIDC_PROVIDER_CLIENT_ID")
    rejected(normal, partial, b"missing required OIDC setting", "partial-settings-refused")
    for key in ["AUTH_OIDC_TLS_ROOT_FILE", "AUTH_OIDC_ADDRESS_OVERRIDE", "AUTH_OIDC_CLIENT_SECRET"]:
        invalid = dict(values)
        invalid[key] = "private-config-marker"
        rejected(normal, invalid, b"unknown AUTH_OIDC setting", "unknown-" + key.lower().removeprefix("auth_oidc_"))
    invalid = dict(values, AUTH_PUBLIC_URL="http://localhost")
    rejected(normal, invalid, b"requires HTTPS", "development-cannot-downgrade-oidc-https")
    invalid = dict(values, AUTH_OIDC_CLIENT_AUTH_METHOD="client_secret_basic")
    rejected(normal, invalid, b"must agree explicitly", "missing-secret-cannot-fall-back-to-public")


def confidential_file(values, database, baseline, directory):
    global PHASE
    PHASE = "confidential-file-startup"
    path = Path(directory) / "client-secret"
    path.write_bytes(SECRET_MARKER + b"\n")
    path.chmod(0o600)
    confidential = dict(values, AUTH_OIDC_CLIENT_AUTH_METHOD="client_secret_basic", AUTH_OIDC_CLIENT_SECRET_FILE=str(path))
    child = running(ROOT / "target/debug/easy-auth", confidential)
    try:
        assert observe(database) == baseline, "credential loading must not rotate persisted identity authority"
        result("explicit-confidential-file-preserves-revision")
    finally:
        stop(child)
    path.chmod(0o644)
    rejected(ROOT / "target/debug/easy-auth", confidential, b"must not be accessible", "publicly-readable-secret-refused")


def storage_authority(values, database, baseline):
    changed = dict(values, AUTH_OIDC_JIT="allow")
    rejected(ROOT / "target/debug/easy-auth", changed, b"Unauthorized", "policy-mismatch-is-not-startup-reconfiguration")
    assert observe(database) == baseline, "mismatch must leave stored definition/revision unchanged"
    support.sql("UPDATE auth_oauth_connections SET enabled=false", database)
    rejected(ROOT / "target/debug/easy-auth", values, b"Unauthorized", "operator-disable-is-not-cleared-at-startup")
    disabled = observe(database)
    assert disabled["enabled"] is False and disabled["revision"] == baseline["revision"]
    assert disabled["users"] == disabled["sessions"] == 0


def main():
    unsupported = Path(os.environ["EASY_AUTH_OIDC_UNSUPPORTED_TEST_BINARY"]).resolve()
    assert unsupported.is_file(), "test infrastructure: freshly built default binary required"
    database = "easy_auth_oidc_startup_" + uuid.uuid4().hex
    created = False
    try:
        support.sql(f'CREATE DATABASE "{database}"')
        created = True
        values = environment(database, str(uuid.uuid4()))
        baseline = configured_modes(values, database)
        invalid_settings(values, unsupported)
        with tempfile.TemporaryDirectory(prefix="easy-auth-oidc-startup-") as directory:
            confidential_file(values, database, baseline, directory)
        storage_authority(values, database, baseline)
    finally:
        if created:
            support.sql(f'DROP DATABASE "{database}"')
    print(json.dumps({"passed": len(RESULTS), "fixture_database_removed": True,
                      "private_files_removed": True, "provider_exchange": False}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # No subprocess output, settings, DSN, file path or credential in diagnostics.
        print(json.dumps({"suite": "oidc-startup", "status": "failed", "category": type(error).__name__, "phase": PHASE}), flush=True)
        raise SystemExit(1) from None
