"""Inspect actual minimal release files without installing a shell in the image."""
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile

from . import docker

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(image, wanted):
    identifier = docker.run(["create", "--network", "none", "--entrypoint", "/unused", image]).strip()
    try:
        with tempfile.TemporaryDirectory(prefix="easy-auth-image-inventory-") as directory:
            archive_path = Path(directory) / "root.tar"
            docker.run(["export", "--output", str(archive_path), identifier])
            files, libraries, packages = {}, [], []
            with tarfile.open(archive_path) as archive:
                for member in archive.getmembers():
                    name = member.name.lstrip("./")
                    if not member.isfile():
                        continue
                    if name in wanted:
                        files[name] = archive.extractfile(member).read()
                    if name.startswith(("lib/", "usr/lib/")) and ".so" in Path(name).name:
                        data = archive.extractfile(member).read()
                        libraries.append(dict(path="/" + name, sha256=hashlib.sha256(data).hexdigest()))
                    if name.startswith("var/lib/dpkg/status.d/") and not name.endswith(".md5sums"):
                        text = archive.extractfile(member).read().decode()
                        for paragraph in text.split("\n\n"):
                            fields = dict(line.split(": ", 1) for line in paragraph.splitlines()
                                          if line.startswith(("Package: ", "Version: ", "Architecture: ")))
                            if "Package" in fields and "Version" in fields:
                                packages.append(fields)
            if set(files) != set(wanted) or not libraries or not packages:
                raise ValueError("minimal release inventory incomplete")
            return files, libraries, packages
    finally:
        docker.run(["rm", identifier])


def qualified(report):
    if report["exit_code"] or report["failed"] or report["ignored"] \
            or report["features"] != ["crypto-aws-lc"] \
            or report["source_inventory_sha256"] != digest(ROOT / "third-party/saml-rs-source.json") \
            or report["application_lock_sha256"] != digest(ROOT / "Cargo.lock") \
            or report["reproducer_sha256"] != digest(ROOT / "scripts/qualify_saml_c14n.py"):
        raise ValueError("release native qualification does not match current sources")
    for name, checksum in report["core_verification_source_sha256"].items():
        if digest(ROOT / name) != checksum:
            raise ValueError("release core source identity mismatch")


def identity(image):
    details = docker.inspect(image)
    configuration = details["Config"]
    if configuration["User"] != "65532:65532" \
            or configuration["Labels"].get("io.easy-auth.saml-activation") != "configuration-required":
        raise ValueError("release image identity/opt-in policy mismatch")
    return dict(image_id=details["Id"], repo_digests=details.get("RepoDigests", []),
                os=details["Os"], architecture=details["Architecture"],
                source_revision=configuration["Labels"].get("org.opencontainers.image.revision"))


def record(image):
    record = identity(image)
    binary = "usr/local/bin/easy-auth"
    build = "usr/share/doc/easy-auth/build.txt"
    qualification = "usr/share/doc/easy-auth/qualification.json"
    native_source = "usr/share/doc/easy-auth/native-source.json"
    native_hashes = "usr/share/doc/easy-auth/native-libraries.sha256"
    source_inputs = "usr/share/doc/easy-auth/source-inputs.json"
    files, libraries, packages = snapshot(record["image_id"],
        [binary, build, qualification, native_source, native_hashes, source_inputs, "usr/lib/os-release"])
    report = json.loads(files[qualification])
    qualified(report)
    inputs = json.loads(files[source_inputs])["source_files"]
    for item in inputs:
        path = ROOT / item["path"]
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT.resolve()) \
                or digest(path) != item["sha256"]:
            raise ValueError("release build-context input differs from the checkout")
    if not any("/libcrypto.so." in item["path"] for item in libraries):
        raise ValueError("release OpenSSL artifacts not identified")
    for line in files[native_hashes].decode().splitlines():
        checksum, path = line.split()
        if not any(Path(item["path"]).name == Path(path).name and item["sha256"] == checksum
                   for item in libraries):
            raise ValueError("native qualification and runtime OpenSSL artifacts differ")
    record.update(features=["saml-web", "oidc-web"], build_profile="release",
                  binary_sha256=hashlib.sha256(files[binary]).hexdigest(),
                  packaged_native_libraries=libraries, installed_packages=packages,
                  os_release=files["usr/lib/os-release"].decode(), build_toolchain=files[build].decode(),
                  native_qualification=report,
                  build_source_files=inputs,
                  aws_lc_source=json.loads(files[native_source]),
                  native_build_openssl_sha256=files[native_hashes].decode(),
                  source_inventory_sha256=digest(ROOT / "third-party/saml-rs-source.json"),
                  lock_sha256=digest(ROOT / "Cargo.lock"),
                  activation_configuration_sha256=digest(ROOT / "apps/auth-server/src/configuration/saml/settings.rs"),
                  scope="Actual opt-in release artifact/package inventory; libraries are packaged, not a claim each is loaded; no independent approval")
    return record


def proxy_record(image):
    record = identity(image)
    binary, config = "usr/sbin/nginx", "etc/nginx/nginx.conf"
    files, libraries, packages = snapshot(record["image_id"], [binary, config, "usr/lib/os-release"])
    if files[config] != (ROOT / "deploy/saml/nginx.conf").read_bytes():
        raise ValueError("proxy configuration does not match release source")
    record.update(installed_packages=packages, packaged_native_libraries=libraries,
                  nginx_sha256=hashlib.sha256(files[binary]).hexdigest(),
                  configuration_sha256=hashlib.sha256(files[config]).hexdigest(),
                  os_release=files["usr/lib/os-release"].decode())
    return record
