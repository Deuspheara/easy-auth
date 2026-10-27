"""A checksum-verified Go toolchain with isolated command/module/build state."""
import hashlib
import os
from pathlib import PurePosixPath
import platform
import subprocess
import tarfile
from urllib.request import urlopen

ARCHIVE_LIMIT = 100 * 1024 * 1024
EXTRACTED_LIMIT = 512 * 1024 * 1024
MEMBER_LIMIT = 30000


def validate_members(archive):
    members, names, total = archive.getmembers(), set(), 0
    if len(members) > MEMBER_LIMIT:
        raise ValueError("Go archive has too many entries")
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "go" \
                or "\\" in member.name or not (member.isfile() or member.isdir()) \
                or (len(path.parts) == 1 and not member.isdir()) or path in names:
            raise ValueError("unexpected Go archive entry")
        names.add(path)
        total += member.size
        if member.size < 0 or total > EXTRACTED_LIMIT:
            raise ValueError("Go archive exceeds extracted size bound")
    return members


def fetch_go(directory, pin):
    platform_name = platform.system() + "-" + platform.machine()
    if platform_name not in pin["archives"]:
        raise ValueError("unsupported backup tool build platform")
    entry = pin["archives"][platform_name]
    expected_name = {"Darwin-arm64": "darwin-arm64", "Linux-x86_64": "linux-amd64"}[platform_name]
    if entry["file"] != "go" + pin["version"] + "." + expected_name + ".tar.gz":
        raise ValueError("unreviewed Go archive name")
    archive_path, digest, size = directory / "go.tar.gz", hashlib.sha256(), 0
    with urlopen("https://go.dev/dl/" + entry["file"], timeout=60) as response, archive_path.open("xb") as output:
        if response.status != 200 or not response.url.startswith(("https://go.dev/", "https://dl.google.com/")):
            raise ValueError("unexpected Go download response")
        while block := response.read(1024 * 1024):
            size += len(block)
            if size > ARCHIVE_LIMIT:
                raise ValueError("Go archive exceeds download bound")
            digest.update(block)
            output.write(block)
    if digest.hexdigest() != entry["sha256"]:
        raise ValueError("Go archive checksum mismatch")
    with tarfile.open(archive_path) as archive:
        archive.extractall(directory, members=validate_members(archive), filter="data")
    return entry


class GoToolchain:
    def __init__(self, directory):
        self.directory = directory
        self.go = str(directory / "go/bin/go")
        (directory / "tmp").mkdir(mode=0o700)
        telemetry = directory / "telemetry"
        telemetry.mkdir(mode=0o700)
        (telemetry / "mode").write_text("off\n")
        self.environment = dict(os.environ, PATH=str(directory / "go/bin") + ":" + os.environ.get("PATH", ""),
            GOTOOLCHAIN="local", GOENV="off", GOWORK="off", CGO_ENABLED="0",
            GOOS={"Darwin": "darwin", "Linux": "linux"}[platform.system()],
            GOARCH={"arm64": "arm64", "x86_64": "amd64"}[platform.machine()],
            GOAMD64="v1", GOARM64="v8.0", GOEXPERIMENT="", GOFIPS140="off", GO111MODULE="on",
            GOCACHEPROG="", GOTMPDIR=str(directory / "tmp"), TEST_TELEMETRY_DIR=str(telemetry),
            GODEBUG="", GOINSECURE="", GOVCS="*:off",
            GOPATH=str(directory / "gopath"), GOMODCACHE=str(directory / "modules"),
            GOCACHE=str(directory / "cache"), GOBIN=str(directory / "bin"),
            GOPROXY="https://proxy.golang.org", GOSUMDB="sum.golang.org",
            GOPRIVATE="", GONOSUMDB="", GONOPROXY="")
        self.environment.pop("GOROOT", None)
        self.environment.pop("GOFLAGS", None)

    def check(self, name, arguments, *, cwd=None):
        path = self.directory / "logs" / (name + ".log")
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
            result = subprocess.run(arguments, cwd=cwd or self.directory, env=self.environment,
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, timeout=600)
        if result.returncode:
            raise ValueError("backup tool check failed: " + name)
        return path
