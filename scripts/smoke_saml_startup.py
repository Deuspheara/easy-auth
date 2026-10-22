#!/usr/bin/env python3
"""Ordinary startup gate checks using owned disposable PostgreSQL databases.

No IdP, assertions, cryptographic fixtures or activation override are involved.
Build the default binary and copy it to EASY_AUTH_SAML_UNSUPPORTED_TEST_BINARY,
then build the normal binary and embedded example with saml-web (optionally oidc-web).
"""
import json
import os
import subprocess
from pathlib import Path
import urllib.error
import urllib.request
import uuid

import smoke_oidc_startup as startup
import smoke_recovery_notice as support

ROOT = Path(__file__).resolve().parents[1]
PHASE = "setup"


def environment(database):
    values = support.server_environment(database, str(uuid.uuid4()), startup.port())
    values = {k: v for k, v in values.items() if not k.startswith(("AUTH_OIDC_", "AUTH_SAML_"))}
    values["AUTH_PUBLIC_URL"] = "https://app.example"
    return values


def enabled(values):
    return dict(values, AUTH_SAML_ENABLED="true", AUTH_SAML_CONNECTION_ID=str(uuid.uuid4()),
                AUTH_SAML_LOCAL_CLIENT_ID=str(uuid.uuid4()), AUTH_SAML_SP_ENTITY="urn:startup:sp",
                AUTH_SAML_IDP_ENTITY="urn:startup:idp", AUTH_SAML_SSO_URL="https://idp.example/sso")


def absent_routes(binary, values, mode):
    global PHASE
    PHASE = mode
    child = startup.running(binary, values)
    try:
        spec = startup.request(values, "/openapi.json")
        assert "/v1/session" in spec["paths"]
        assert not any("saml" in path for path in spec["paths"])
        port = values["AUTH_BIND"].rsplit(":", 1)[1]
        for path in ["/saml/metadata", "/saml/sign-in", "/saml/acs", "/v1/saml/sign-in/start"]:
            method = "POST" if path.endswith(("/acs", "/start")) else "GET"
            request = urllib.request.Request("http://127.0.0.1:" + port + path, method=method,
                                             headers={"Origin": "https://app.example"})
            try:
                urllib.request.urlopen(request, timeout=2).close()
                raise AssertionError("disabled SAML route unexpectedly mounted")
            except urllib.error.HTTPError as error:
                assert error.code == 404
        print(json.dumps({"case": mode, "status": "passed"}), flush=True)
    finally:
        startup.stop(child)


def main():
    global PHASE
    unsupported = Path(os.environ["EASY_AUTH_SAML_UNSUPPORTED_TEST_BINARY"]).resolve()
    assert unsupported.is_file()
    database = "easy_auth_saml_startup_" + uuid.uuid4().hex
    created = False
    try:
        support.sql(f'CREATE DATABASE "{database}"')
        created = True
        values = environment(database)
        for name, binary in [("default", unsupported), ("standalone", ROOT / "target/debug/easy-auth"),
                             ("embedded", ROOT / "target/debug/examples/embedded")]:
            for explicit in [False, True]:
                disabled = dict(values, AUTH_SAML_ENABLED="false") if explicit else values
                absent_routes(binary, disabled, name + ("-explicit-disabled" if explicit else "-unset"))
            PHASE = name + "-activation-refused"
            reason = b"requires the saml-web server feature" if name == "default" else b"AUTH-32 security approval gates"
            startup.rejected(binary, enabled(values), reason, PHASE)
            startup.rejected(binary, dict(values, AUTH_SAML_ENABLED="false", AUTH_SAML_JIT="allow"),
                             b"complete configuration", name + "-populated-disabled-refused")
            startup.rejected(binary, dict(values, AUTH_SAML_SECURITY_APPROVED="true"),
                             b"unknown AUTH_SAML setting", name + "-approval-override-refused")
        PHASE = "no-authority-mutations"
        output = subprocess.check_output(support.psql(database) + ["-At", "-c",
            "SELECT (SELECT count(*) FROM auth_saml_registrations)+(SELECT count(*) FROM auth_saml_certificates)+(SELECT count(*) FROM auth_saml_identity_policies)+(SELECT count(*) FROM auth_saml_requests)+(SELECT count(*) FROM auth_users)+(SELECT count(*) FROM auth_sessions)+(SELECT count(*) FROM auth_audit)"], cwd=ROOT, stderr=subprocess.DEVNULL)
        assert output.strip() == b"0"
        print(json.dumps({"case": PHASE, "status": "passed"}), flush=True)
    finally:
        if created:
            support.sql(f'DROP DATABASE "{database}" WITH (FORCE)')
    print(json.dumps({"suite": "saml-startup", "status": "passed", "database_removed": True,
                      "saml_activated": False}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"suite": "saml-startup", "status": "failed", "category": type(error).__name__,
                          "phase": PHASE}), flush=True)
        raise SystemExit(1) from None
