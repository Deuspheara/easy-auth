"""Build selected immutable operational fixtures into separate source/target trees."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tarfile

from .evidence import ci_source_identity, source_identity, write_receipt

ROOT = Path(__file__).resolve().parents[2]
PINS = {"schema37": ROOT / "tests/operational/upgrade-source.json",
        "schema38": ROOT / "tests/operational/upgrade-source-schema38.json",
        "schema39": ROOT / "tests/operational/upgrade-source-schema39.json"}
ARCHIVE_LIMIT = 256 * 1024 * 1024


def load_pin(profile="schema37"):
    expected = {"schema37": dict(schema_version=1, revision="0783ff48b6409d362fbcae527f46a483ca66fb55",
                                tree="ca9e75a6510e485094a110c74cfa05af74d552a1", migration_count=37),
                "schema38": dict(schema_version=1, revision="e6a061f9e6804eda323ce1af78b0369c73cdd021",
                                tree="5e615d2567c94ea930a962bd0a270266f07ed13c", migration_count=38),
                "schema39": dict(schema_version=1, revision="9209a2ae495b4fce4bfdfae33d7f65138e9e9119",
                                tree="a61024f985c198e2eac1d4abdfdc5068ccce1ef9", migration_count=39)}
    if profile not in expected:
        raise ValueError("unknown owned upgrade source profile")
    value = json.loads(PINS[profile].read_text())
    if value != expected[profile]:
        raise ValueError("unreviewed upgrade fixture source")
    return value


def git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=ROOT, stderr=subprocess.DEVNULL).decode().strip()


def source_export(directory, pin):
    if git("rev-parse", pin["revision"] + "^{tree}") != pin["tree"]:
        raise ValueError("upgrade fixture tree mismatch")
    subprocess.run(["git", "merge-base", "--is-ancestor", pin["revision"], "HEAD"], cwd=ROOT,
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    archive = directory / "source.tar"
    with archive.open("xb") as output:
        subprocess.run(["git", "archive", pin["revision"]], cwd=ROOT, stdout=output,
                       stderr=subprocess.DEVNULL, check=True)
    if archive.stat().st_size > ARCHIVE_LIMIT:
        raise ValueError("upgrade source archive exceeds bound")
    source = directory / "source"
    source.mkdir(mode=0o700)
    with tarfile.open(archive) as content:
        for member in content.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or "\\" in member.name \
                    or not (member.isfile() or member.isdir()):
                raise ValueError("unexpected upgrade source archive entry")
        content.extractall(source, filter="data")
    return source, hashlib.sha256(archive.read_bytes()).hexdigest()


def verify_inputs(source, pin):
    paths = ["Cargo.lock", "Cargo.toml", "rust-toolchain.toml", ".cargo/config.toml"]
    migrations = sorted((source / "crates/auth-postgres/migrations").glob("*.sql"))
    if len(migrations) != pin["migration_count"] \
            or [int(path.name.split("_", 1)[0]) for path in migrations] != list(range(1, pin["migration_count"] + 1)):
        raise ValueError("upgrade fixture migration prefix mismatch")
    paths += [str(path.relative_to(source)) for path in migrations]
    for name in paths:
        if (source / name).read_bytes() != (ROOT / name).read_bytes():
            raise ValueError("upgrade fixture dependency/toolchain/migration input differs")
    return {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in paths}


def source_files(source):
    records = {}
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError("upgrade fixture source acquired a link")
        if path.is_file():
            records[str(path.relative_to(source))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return records


def build_environment(directory):
    # Keep the established tool/cache locations; discard unrelated compiler,
    # native wrapper, credential and SQLx database overrides from other work.
    environment = {name: value for name, value in os.environ.items()
                   if name in ("PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME")}
    environment.update(CARGO_TARGET_DIR=str(directory / "target"), CARGO_INCREMENTAL="0",
        TMPDIR=str(directory / "tmp"),
        CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0", SQLX_OFFLINE="true",
        CARGO_PROFILE_DEV_BUILD_OVERRIDE_DEBUG="1", CARGO_PROFILE_TEST_BUILD_OVERRIDE_DEBUG="1",
        RUSTC_WRAPPER="", RUSTC_WORKSPACE_WRAPPER="", CARGO_BUILD_RUSTC_WRAPPER="",
        CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER="")
    return environment


def prepare(directory, profile="schema37"):
    if directory.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError("choose a new upgrade fixture directory outside source")
    source_identity_before, pin = ci_source_identity(ROOT), load_pin(profile)
    directory.mkdir(mode=0o700)
    source, archive_hash = source_export(directory, pin)
    inputs = verify_inputs(source, pin)
    exported = source_files(source)
    (directory / "tmp").mkdir(mode=0o700)
    environment = build_environment(directory)
    compiler = subprocess.check_output(["rustc", "-vV"], cwd=source, env=environment,
                                       stderr=subprocess.DEVNULL).decode().strip()
    if not compiler.startswith("rustc 1.95.0 "):
        raise ValueError("upgrade fixture compiler does not match the pinned toolchain")
    # CI fetches the same root lock's dependencies before this step; offline
    # compilation prevents an old fixture selecting new dependency versions.
    log = directory / "build.log"
    with os.fdopen(os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        built = subprocess.run(["cargo", "build", "--frozen", "-p", "easy-auth-server", "--bin", "easy-auth"],
            cwd=source, env=environment, stdout=output, stderr=subprocess.STDOUT, timeout=600)
    if built.returncode:
        raise ValueError("owned upgrade fixture build failed")
    if verify_inputs(source, pin) != inputs or source_files(source) != exported \
            or source_identity(ROOT) != source_identity_before:
        raise ValueError("upgrade fixture source changed during preparation")
    binary = directory / "target/debug/easy-auth"
    receipt = dict(pin=pin, source=source_identity_before, source_archive_sha256=archive_hash,
        preserved_inputs=inputs, binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        source_files_sha256=hashlib.sha256(json.dumps(exported, sort_keys=True).encode()).hexdigest(),
        compiler=compiler,
        build_log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(), production_acceptance=False)
    write_receipt(directory / "receipt.json", receipt)
    return receipt


def prepared_binary(directory, profile="schema37"):
    directory = Path(directory)
    value = directory.stat(follow_symlinks=False)
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.getuid() or value.st_mode & 0o077:
        raise ValueError("upgrade fixture directory must be owned and private")
    value = (directory / "receipt.json").stat(follow_symlinks=False)
    if not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid() or value.st_mode & 0o077:
        raise ValueError("upgrade fixture receipt must be an owned private regular file")
    receipt = json.loads((directory / "receipt.json").read_text())
    pin = load_pin(profile)
    if receipt["pin"] != pin or receipt["production_acceptance"] is not False \
            or len(receipt.get("preserved_inputs", {})) != pin["migration_count"] + 4 \
            or len(receipt.get("source_files_sha256", "")) != 64 \
            or not receipt.get("compiler", "").startswith("rustc 1.95.0 "):
        raise ValueError("upgrade fixture receipt identity mismatch")
    binary = directory / "target/debug/easy-auth"
    value = binary.stat(follow_symlinks=False)
    if not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid() or value.st_mode & 0o022 \
            or hashlib.sha256(binary.read_bytes()).hexdigest() != receipt["binary_sha256"]:
        raise ValueError("upgrade fixture binary changed")
    return binary, receipt
