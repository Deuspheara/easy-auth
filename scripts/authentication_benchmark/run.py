"""Frozen optimized build, fixture ownership, sequential repetitions and receipts."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import uuid

from operational_recovery.services import Services
from .build import build
from .measurement import launch
from .validation import validate

ROOT = Path(__file__).resolve().parents[2]


def git(*arguments):
    return subprocess.check_output(['git', *arguments], cwd=ROOT, text=True).strip()


def write_receipt(directory, receipt):
    (directory / 'results.json').write_text(json.dumps(receipt, indent=2) + '\n')


def run(output, repetitions):
    # Reject a dirty source before running any project code or creating fixtures.
    if git('status', '--porcelain'):
        raise ValueError('committed clean source required')
    output = output.absolute()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    receipt = {'source': git('rev-parse', 'HEAD'), 'platform': platform.system(),
               'machine': platform.machine(), 'logical_cpus': os.cpu_count(),
               'rustc': subprocess.check_output(['rustc', '-vV'], text=True),
               'build': {'frozen': True, 'profile': 'release', 'incremental': False,
                         'build_override_debug': 1},
               'repetitions': repetitions, 'results': [], 'cleanup_verified': False,
               'failure': None}
    services = None
    try:
        binary = build(output)
        receipt['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory(prefix='auth50-services-') as temporary:
            services = Services(temporary)
            services.owner = 'auth50-' + uuid.uuid4().hex
            services.names = {name: 'easy-auth-' + services.owner + '-' + name
                              for name in ('postgres', 'mail')}
            try:
                services.start()
                receipt['fixture_images'] = services.verify()
                for repetition in range(repetitions):
                    run_repetition(binary, services, receipt, repetition)
                    write_receipt(output, receipt)
            finally:
                services.close()
                receipt['cleanup_verified'] = True
        if git('rev-parse', 'HEAD') != receipt['source'] or git('status', '--porcelain'):
            raise ValueError('source changed during measurement')
        if hashlib.sha256(binary.read_bytes()).hexdigest() != receipt['binary_sha256']:
            raise ValueError('binary changed during measurement')
    except Exception:
        receipt['failure'] = 'owned benchmark qualification failed'
        raise
    finally:
        write_receipt(output, receipt)


def run_repetition(binary, services, receipt, repetition):
    database = 'auth50_' + uuid.uuid4().hex
    services.sql('fixture_admin', 'CREATE DATABASE "' + database + '"')
    environment = dict(os.environ)
    environment['PYTHONPATH'] = str(ROOT / 'scripts')
    environment['DATABASE_URL'] = ('postgresql://auth:' + services.admin_password
                                   + '@127.0.0.1:' + str(services.pg_port) + '/' + database)
    try:
        for profile in ('sessions', 'argon2'):
            result = launch(binary, profile, environment)
            validate(result)
            result['repetition'] = repetition
            receipt['results'].append(result)
    finally:
        # The actual child has exited, and pooled connections were closed by Rust.
        # Refuse to terminate unknown live sessions to force a cleanup to pass.
        active = services.sql('fixture_admin', "SELECT count(*) FROM pg_stat_activity WHERE datname='"
                              + database + "'")
        if active != '0':
            raise ValueError('owned database still has active backends')
        services.sql('fixture_admin', 'DROP DATABASE "' + database + '"')
        absent = services.sql('fixture_admin', "SELECT count(*) FROM pg_database WHERE datname='"
                              + database + "'")
        if absent != '0':
            raise ValueError('owned database cleanup not established')
