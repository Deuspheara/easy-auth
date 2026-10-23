"""Owned enabled-provider startup scenarios; no signatures or XML fixtures."""
import json
from pathlib import Path
import subprocess
import uuid
import urllib.error
import urllib.request

import saml_startup_contract as contract
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
      'trust',(SELECT json_agg(c ORDER BY slot) FROM auth_saml_certificates c),
      'users',(SELECT count(*) FROM auth_users),
      'sessions',(SELECT count(*) FROM auth_sessions),
      'pending',(SELECT count(*) FROM auth_saml_requests),
      'audits',(SELECT count(*) FROM auth_audit))"""
    return json.loads(subprocess.check_output(support.psql(database) + ["-At", "-c", query],
                                              cwd=ROOT, stderr=subprocess.DEVNULL))


def provision(values):
    result = subprocess.run([str(PROVISION)], cwd=ROOT, env=values, capture_output=True, timeout=30)
    assert result.returncode == 0, "owned public-API provisioning failed"



def start_and_cancel(values, database, baseline):
    port = values["AUTH_BIND"].rsplit(":", 1)[1]
    base = "http://127.0.0.1:" + port
    headers = {"Origin": values["AUTH_PUBLIC_URL"], "Content-Type": "application/json"}
    request = urllib.request.Request(base + "/v1/saml/sign-in/start", data=b"{}", headers=headers)
    with urllib.request.urlopen(request, timeout=3) as response:
        assert response.status == 200
        cookies = response.headers.get_all("Set-Cookie")
        contract.request_binding(json.load(response)["authorization_url"], cookies, values)
        headers["Cookie"] = "; ".join(cookie.split(";", 1)[0] for cookie in cookies)
    pending = dict(baseline, pending=1)
    assert observe(database) == pending, "start must persist only its correlated pending request"
    unbound = urllib.request.Request(base + "/v1/saml/sign-in/cancel", data=b"{}",
                                     headers={"Origin": values["AUTH_PUBLIC_URL"], "Content-Type": "application/json"})
    refused_cancel(unbound)
    assert observe(database) == pending, "missing private proof must leave the pending request intact"
    request = urllib.request.Request(base + "/v1/saml/sign-in/cancel", data=b"{}", headers=headers)
    with urllib.request.urlopen(request, timeout=3) as response:
        assert response.status == 204
    assert observe(database) == baseline, "bound cancellation must remove only the pending request"
    refused_cancel(request)
    assert observe(database) == baseline, "cancellation must be one-use without authority changes"


def refused_cancel(request):
    try:
        urllib.request.urlopen(request, timeout=3).close()
        raise AssertionError("unbound or spent cancellation unexpectedly accepted")
    except urllib.error.HTTPError as error:
        assert error.code == 401, "expected proof refusal, not an infrastructure failure"


def configured_modes(values, database):
    provision(values)
    baseline = observe(database)
    assert baseline["enabled"] is True and baseline["jit"] == "deny" and baseline["pins"] == 1
    assert all(baseline[key] == 0 for key in ["users", "sessions", "pending", "audits"])
    published = None
    for mode, binary in [("standalone", ROOT / "target/debug/easy-auth"),
                         ("embedded", ROOT / "target/debug/examples/embedded")]:
        child = startup.running(binary, values)
        try:
            spec = startup.request(values, "/openapi.json")
            for path in ["/saml/metadata", "/saml/acs", "/saml/sign-in",
                         "/v1/saml/sign-in/start", "/v1/saml/account-delete/start"]:
                assert path in spec["paths"], "configured provider routes missing"
            assert observe(database) == baseline, "startup must preserve source/revision and authority"
            base = "http://127.0.0.1:" + values["AUTH_BIND"].rsplit(":", 1)[1]
            metadata = contract.metadata(base, values)
            assert published is None or published == metadata, "both modes must publish the identical trusted profile"
            published = metadata
            startup.result("configured-saml-" + mode + "-exact-metadata")
            start_and_cancel(values, database, baseline)
            assert observe(database) == baseline, "canceled start must not issue local authority"
            startup.result("configured-saml-" + mode + "-request-binding-and-one-use-cancel")
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
