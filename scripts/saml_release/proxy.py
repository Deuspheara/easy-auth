"""Validate the proxy with existing packaged public certificate/key fixtures."""
from pathlib import Path
import shutil
import tempfile

from . import docker

ROOT = Path(__file__).resolve().parents[2]


def check(image):
    fixtures = ROOT / "third-party/saml-rs/tests/fixtures/key"
    configuration = (ROOT / "deploy/saml/nginx.conf").read_text()
    if "location ^~ /saml/ { return 404; }" in configuration \
            or "location ^~ /v1/saml/ { return 404; }" in configuration:
        raise ValueError("proxy must forward configured SAML routes")
    with tempfile.TemporaryDirectory(prefix="easy-auth-proxy-") as directory:
        folder = Path(directory)
        # Linux bind mounts retain the host directory's ownership/mode. Only
        # these already-public package fixtures may be traversed by container UID65532.
        folder.chmod(0o755)
        # These exact public upstream files are already in the source inventory.
        # No certificate/key generation, signing, XML or TLS traffic occurs here.
        for original, name in [(fixtures / "sp_signing_cert.cer", "certificate.pem"),
                               (fixtures / "sp_privkey.pem", "private-key.pem")]:
            target = folder / name
            shutil.copyfile(original, target)
            target.chmod(0o644)
        docker.run(["run", "--rm", "--network", "none", "--read-only", "--user", "65532:65532",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                    "--tmpfs", "/tmp:size=16m,mode=1777,noexec,nosuid,nodev",
                    "--add-host", "auth:127.0.0.1", "--mount",
                    f"type=bind,src={folder},dst=/run/tls,readonly", "--mount",
                    f"type=bind,src={ROOT / 'deploy/saml/nginx.conf'},dst=/etc/nginx/nginx.conf,readonly",
                    "--entrypoint", "nginx", image, "-t"])
    return dict(image=image, configuration_valid=True, public_existing_fixtures=True,
                traffic_performed=False, saml_routes_forwarded=True)
