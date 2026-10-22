"""Ordinary CLI/startup and actual Compose resource inspection, without XML."""
import json
import os
from pathlib import Path
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from . import docker

ROOT = Path(__file__).resolve().parents[2]


def resources(details, *, proxy=False):
    host = details["HostConfig"]
    expected = {"NanoCpus": 2_000_000_000, "Memory": 1024**3,
                "MemorySwap": 1024**3, "PidsLimit": 128, "ReadonlyRootfs": True,
                "Init": True}
    if proxy:
        expected.update(NanoCpus=500_000_000, Memory=128 * 1024**2,
                        MemorySwap=128 * 1024**2, PidsLimit=64)
    if any(host.get(key) != value for key, value in expected.items()) \
            or host.get("CapDrop") != ["ALL"] \
            or "no-new-privileges:true" not in host.get("SecurityOpt", []) \
            or details["Config"].get("User") != "65532:65532":
        raise ValueError("actual auth resource policy differs from the reference")
    limit = 512 if proxy else 1024
    if host.get("Ulimits") != [dict(Name="nofile", Hard=limit, Soft=limit)] \
            or set(host.get("Tmpfs", {})) != {"/tmp"} \
            or set(host["Tmpfs"]["/tmp"].split(",")) != {
                "size=16m", "mode=1777", "noexec", "nosuid", "nodev"}:
        raise ValueError("actual filesystem/descriptor budget differs from the reference")
    return {**expected, "cap_drop": host["CapDrop"], "security_opt": host["SecurityOpt"],
            "tmpfs": host["Tmpfs"], "ulimits": host["Ulimits"],
            "scope": "Docker enforcement configuration; no load/CPU/RSS measurement"}


def request(port, path, method="GET"):
    req = urllib.request.Request(f"http://127.0.0.1:{port}" + path, method=method,
                                 headers={"Origin": "https://app.example"})
    try:
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, b""


def absent_routes(port):
    for _ in range(100):
        try:
            if request(port, "/readyz")[0] == 200:
                break
        except OSError:
            pass
        time.sleep(0.1)
    else:
        raise ValueError("release database readiness did not complete")
    status, body = request(port, "/openapi.json")
    if status != 200 or any("saml" in path for path in json.loads(body)["paths"]):
        raise ValueError("disabled release advertised SAML")
    for path, method in [("/saml/metadata", "GET"), ("/saml/sign-in", "GET"),
                         ("/saml/acs", "POST"), ("/v1/saml/sign-in/start", "POST")]:
        if request(port, path, method)[0] != 404:
            raise ValueError("disabled release mounted a SAML route")


def environment(database):
    import smoke_recovery_notice as support
    values = support.server_environment(database, str(uuid.uuid4()), "8080")
    connection = urllib.parse.urlsplit(values["DATABASE_URL"])
    # Existing support validates that the owned database is loopback-only.
    authority = "host.docker.internal:" + str(connection.port or 5432)
    if connection.username:
        authority = urllib.parse.quote(connection.username, safe="") + ":" + \
            urllib.parse.quote(connection.password or "", safe="") + "@" + authority
    values = {key: value for key, value in values.items()
              if key in {"DATABASE_URL", "AUTH_REALM_ID"}}
    values["DATABASE_URL"] = urllib.parse.urlunsplit(connection._replace(netloc=authority))
    return dict(values, AUTH_PUBLIC_URL="https://app.example", SMTP_HOST="smtp.example.invalid",
                SMTP_PORT="465", SMTP_USERNAME="owned-startup", SMTP_PASSWORD=uuid.uuid4().hex,
                SMTP_FROM="auth@app.example", AUTH_DEVELOPMENT="false")


def compose_check(image, proxy_image):
    import smoke_recovery_notice as support
    database = "easy_auth_release_" + uuid.uuid4().hex
    project = "easy-auth-release-" + uuid.uuid4().hex[:12]
    created = False
    with tempfile.TemporaryDirectory(prefix="easy-auth-release-") as directory:
        folder = Path(directory)
        private = folder / "runtime.env"
        override = folder / "override.json"
        override.write_text(json.dumps({"services": {"auth": {
            "ports": [{"target": 8080, "published": "0", "host_ip": "127.0.0.1"}],
            "extra_hosts": ["host.docker.internal:host-gateway"]}}}))
        env = dict(os.environ, EASY_AUTH_IMAGE=image, EASY_AUTH_PROXY_IMAGE=proxy_image,
                   AUTH_RUNTIME_ENV_FILE=str(private),
                   AUTH_TLS_CERT_FILE="/dev/null", AUTH_TLS_KEY_FILE="/dev/null")
        arguments = ["compose", "--project-name", project, "-f", str(ROOT / "deploy/saml/compose.yaml"),
                     "-f", str(override)]
        try:
            support.sql(f'CREATE DATABASE "{database}"')
            created = True
            private.write_text("".join(f"{k}={v}\n" for k, v in environment(database).items()))
            private.chmod(0o600)
            docker.run([*arguments, "create", "auth"], environment=env)
            identifier = docker.run([*arguments, "ps", "--all", "--quiet", "auth"], environment=env).strip()
            policy = resources(docker.inspect(identifier))
            docker.run([*arguments, "create", "proxy"], environment=env)
            proxy_id = docker.run([*arguments, "ps", "--all", "--quiet", "proxy"], environment=env).strip()
            proxy_policy = resources(docker.inspect(proxy_id), proxy=True)
            docker.run(["start", identifier])
            details = docker.inspect(identifier)
            port = details["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostPort"]
            absent_routes(port)
            import subprocess
            counts = subprocess.check_output(support.psql(database) + ["-At", "-c",
                "SELECT (SELECT count(*) FROM auth_users)+(SELECT count(*) FROM auth_sessions)"
                "+(SELECT count(*) FROM auth_saml_requests)+(SELECT count(*) FROM auth_audit)"],
                stderr=subprocess.DEVNULL)
            if counts.strip() != b"0":
                raise ValueError("disabled release unexpectedly created authority")
            return dict(resources=policy, proxy_resources=proxy_policy,
                        database_ready=True, saml_routes_absent=True,
                        authority_rows=0, database_removed=True, private_files_removed=True)
        finally:
            try:
                if private.exists():
                    docker.run([*arguments, "down", "--volumes", "--remove-orphans"], environment=env)
            finally:
                if created:
                    support.sql(f'DROP DATABASE "{database}" WITH (FORCE)')


def activation_refused(image):
    # Complete ordinary configuration must reach the source approval guard before DB I/O.
    values = dict(AUTH_PUBLIC_URL="https://app.example", AUTH_REALM_ID=str(uuid.uuid4()),
                  AUTH_SAML_ENABLED="true", AUTH_SAML_CONNECTION_ID=str(uuid.uuid4()),
                  AUTH_SAML_LOCAL_CLIENT_ID=str(uuid.uuid4()), AUTH_SAML_SP_ENTITY="urn:release:sp",
                  AUTH_SAML_IDP_ENTITY="urn:release:idp", AUTH_SAML_SSO_URL="https://idp.example/sso")
    import subprocess
    args = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL"]
    for key, value in values.items():
        args.extend(["-e", key + "=" + value])
    result = subprocess.run([*args, image], capture_output=True, timeout=30)
    if result.returncode == 0 or b"AUTH-32 security approval gates" not in result.stderr:
        raise ValueError("release activation guard did not reject complete configuration")
    return True
