"""Owned enabled-provider startup scenarios; no signatures or XML fixtures."""
import json
from pathlib import Path
import subprocess
import uuid
import urllib.request
import urllib.parse

import smoke_oidc_startup as startup
import smoke_recovery_notice as support

ROOT = Path(__file__).resolve().parents[1]
PROVISION = ROOT / "target/debug/examples/saml-startup-provision"


def observe(database):
    query = """SELECT json_build_object(
      'revision',(SELECT revision::text FROM auth_saml_registrations),
      'enabled',(SELECT enabled FROM auth_saml_registrations),
      'jit',(SELECT jit FROM auth_saml_identity_policies),
      'pins',(SELECT count(*) FROM auth_saml_certificates),
      'users',(SELECT count(*) FROM auth_users),
      'sessions',(SELECT count(*) FROM auth_sessions),
      'pending',(SELECT count(*) FROM auth_saml_requests),
      'audits',(SELECT count(*) FROM auth_audit))"""
    return json.loads(subprocess.check_output(support.psql(database) + ["-At", "-c", query],
                                              cwd=ROOT, stderr=subprocess.DEVNULL))


def provision(values):
    result = subprocess.run([str(PROVISION)], cwd=ROOT, env=values, capture_output=True, timeout=30)
    assert result.returncode == 0, "owned public-API provisioning failed"



def start_and_cancel(values):
    port = values["AUTH_BIND"].rsplit(":", 1)[1]
    base = "http://127.0.0.1:" + port
    headers = {"Origin": values["AUTH_PUBLIC_URL"], "Content-Type": "application/json"}
    request = urllib.request.Request(base + "/v1/saml/sign-in/start", data=b"{}", headers=headers)
    with urllib.request.urlopen(request, timeout=3) as response:
        assert response.status == 200
        url = urllib.parse.urlsplit(json.load(response)["authorization_url"])
        assert (url.scheme, url.netloc, url.path) == ("https", "idp.example", "/sso")
        cookies = response.headers.get_all("Set-Cookie")
        assert cookies and all("Secure" in cookie and "HttpOnly" in cookie for cookie in cookies)
        headers["Cookie"] = "; ".join(cookie.split(";", 1)[0] for cookie in cookies)
    request = urllib.request.Request(base + "/v1/saml/sign-in/cancel", data=b"{}", headers=headers)
    with urllib.request.urlopen(request, timeout=3) as response:
        assert response.status == 204


def configured_modes(values, database):
    provision(values)
    baseline = observe(database)
    assert baseline["enabled"] is True and baseline["jit"] == "deny" and baseline["pins"] == 1
    assert all(baseline[key] == 0 for key in ["users", "sessions", "pending", "audits"])
    for mode, binary in [("standalone", ROOT / "target/debug/easy-auth"),
                         ("embedded", ROOT / "target/debug/examples/embedded")]:
        child = startup.running(binary, values)
        try:
            spec = startup.request(values, "/openapi.json")
            for path in ["/saml/metadata", "/saml/acs", "/saml/sign-in",
                         "/v1/saml/sign-in/start", "/v1/saml/account-delete/start"]:
                assert path in spec["paths"], "configured provider routes missing"
            assert observe(database) == baseline, "startup must preserve source/revision and authority"
            start_and_cancel(values)
            assert observe(database) == baseline, "canceled start must not issue local authority"
            startup.result("configured-saml-" + mode + "-routes-start-cancel-and-stable-revision")
        finally:
            startup.stop(child)
    return baseline


def rejected_policy(values, database):
    binary = ROOT / "target/debug/easy-auth"
    for key, value in [("AUTH_SAML_JIT", "allow"), ("AUTH_SAML_IDP_ENTITY", "urn:other:idp"),
                       ("AUTH_REALM_ID", str(uuid.uuid4())),
                       ("AUTH_SAML_CONNECTION_ID", str(uuid.uuid4()))]:
        before = observe(database)
        startup.rejected(binary, dict(values, **{key: value}), b"Unauthorized", "saml-mismatch-" + key)
        assert observe(database) == before, "startup must not repair/reconfigure another policy"
    for case, query in [
        ("expired-pin", "UPDATE auth_saml_certificates SET approved_until=approved_from+1"),
        ("missing-pin", "DELETE FROM auth_saml_certificates"),
        ("operator-disabled", "UPDATE auth_saml_registrations SET enabled=false"),
    ]:
        provision(values)
        support.sql(query, database)
        before = observe(database)
        startup.rejected(binary, values, b"Unauthorized", "saml-" + case + "-refused")
        assert observe(database) == before, "startup must not restore pins or operator enable"
