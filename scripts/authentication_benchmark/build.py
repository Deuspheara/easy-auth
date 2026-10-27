"""Frozen optimized benchmark build and explicit build-tool symbol policy."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def build(directory):
    environment = dict(os.environ)
    if any(key.startswith(('CARGO_PROFILE_RELEASE_', 'CARGO_TARGET_')) for key in environment) \
            or any(environment.get(key) for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER')):
        raise ValueError('unrecorded optimization override')
    environment['CARGO_INCREMENTAL'] = '0'
    # Retain build-tool symbols to avoid the observed stripped Mach-O SQLx
    # procedural-macro load failure. Application release optimization is unchanged.
    environment['CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_DEBUG'] = '1'
    command = ['cargo', 'build', '--frozen', '--release', '-p', 'easy-auth-server',
               '--example', 'authentication_benchmark']
    with (directory / 'build.log').open('xb') as output:
        subprocess.run(command, cwd=ROOT, env=environment, stdout=output, stderr=output,
                       check=True, timeout=1800)
    return ROOT / 'target/release/examples/authentication_benchmark'

