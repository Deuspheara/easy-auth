"""Exact executable build, actual owned HTTP workload and complete cleanup receipts."""
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time
import uuid

from operational_recovery.services import Services
from operational_recovery.processes import unused_port
from .build import build_server
from .http_daemon import Daemon
from .http_journey import Journey
from .http_logs import summarize
from .run import ROOT, git, write_receipt


def run(output, repetitions):
    if git('status', '--porcelain'):
        raise ValueError('committed clean source required')
    output = output.absolute()
    output.mkdir(mode=0o700, exist_ok=False)
    receipt = {'source': git('rev-parse', 'HEAD'), 'platform': platform.system(),
               'machine': platform.machine(), 'logical_cpus': os.cpu_count(),
               'rustc': subprocess.check_output(['rustc', '-vV'], text=True),
               'build': {'frozen': True, 'profile': 'release', 'incremental': False,
                         'build_override_debug': 1, 'features': 'default'},
               'transport': {'loopback': True, 'tls': False, 'fresh_connection_per_request': True},
               'repetitions': repetitions, 'results': [], 'cleanup_verified': False, 'failure': None}
    stage = 'build'
    try:
        binary = build_server(output)
        receipt['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory(prefix='auth50-http-services-') as temporary:
            services = Services(temporary)
            services.owner = 'auth50-http-' + uuid.uuid4().hex
            services.names = {name: 'easy-auth-' + services.owner + '-' + name for name in ('postgres', 'mail')}
            try:
                stage = 'fixture-start'
                services.start()
                receipt['fixture_images'] = services.verify()
                for index in range(repetitions):
                    stage = 'http-repetition-' + str(index)
                    result = {'repetition': index, 'reports': [], 'database_removed': False}
                    receipt['results'].append(result)
                    repetition(binary, services, result)
                    write_receipt(output, receipt)
            finally:
                services.close()
                receipt['cleanup_verified'] = True
        stage = 'source-and-binary-stability'
        if git('rev-parse', 'HEAD') != receipt['source'] or git('status', '--porcelain') \
                or hashlib.sha256(binary.read_bytes()).hexdigest() != receipt['binary_sha256']:
            raise ValueError('source/binary changed during measurement')
    except Exception:
        receipt['failure'] = stage
        raise
    finally:
        write_receipt(output, receipt)


def repetition(binary, services, result):
    database = 'auth50_' + uuid.uuid4().hex
    services.sql('fixture_admin', 'CREATE DATABASE "' + database + '"')
    daemon = None
    journey = None
    try:
        with tempfile.TemporaryDirectory(prefix='auth50-http-runtime-') as runtime:
            directory = Path(runtime)
            corpus = directory / 'corpus.txt'
            with os.fdopen(os.open(corpus, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as file:
                file.write('a compromised example password\n')
            environment = settings(services, database, corpus)
            log = directory / 'server.log'
            try:
                daemon = Daemon(binary, log, environment)
                result['phase'] = 'startup'
                daemon.ready()
                journey = Journey(environment['AUTH_PUBLIC_URL'], services, database)
                result['phase'] = 'account-setup'
                journey.setup()
                result['phase'] = 'session-load'
                journey.sessions(result['reports'])
                result['phase'] = 'password-load'
                journey.passwords(result['reports'])
                result['phase'] = 'budget-and-revocation-controls'
                result['controls'] = journey.controls()
                journey.remove_mail()
                result['owned_messages_removed'] = len(journey.messages)
            finally:
                if daemon is not None:
                    result['daemon'] = daemon.stop()
                if log.exists():
                    private = [environment['DATABASE_URL'].encode(), services.admin_password.encode()]
                    if journey is not None:
                        private += journey.private_values
                    if 'controls' in result:
                        result['observations'] = summarize(log.read_bytes(), private, result)
                    elif any(value in log.read_bytes() for value in private):
                        raise ValueError('daemon output contained a private fixture value')
    finally:
        drop_database(services, database)
        result['database_removed'] = True
    result['phase'] = 'complete'


def settings(services, database, corpus):
    origin = 'http://127.0.0.1:' + str(unused_port())
    return {'PATH': os.environ.get('PATH', ''), 'PYTHONPATH': str(ROOT / 'scripts'),
            'DATABASE_URL': 'postgresql://auth:' + services.admin_password + '@127.0.0.1:'
                            + str(services.pg_port) + '/' + database,
            'AUTH_DEVELOPMENT': 'true', 'AUTH_REALM_ID': str(uuid.uuid4()),
            'AUTH_PUBLIC_URL': origin, 'AUTH_BIND': origin.removeprefix('http://'),
            'AUTH_PASSWORD_BLOCKLIST_FILE': str(corpus), 'AUTH_DATABASE_MIGRATIONS': 'run',
            'SMTP_HOST': '127.0.0.1', 'SMTP_PORT': str(services.smtp_port), 'SMTP_FROM': 'auth@example.test'}


def drop_database(services, database):
    deadline = time.monotonic() + 10
    query = "SELECT count(*) FROM pg_stat_activity WHERE datname='" + database + "'"
    while services.sql('fixture_admin', query) != '0':
        if time.monotonic() >= deadline:
            raise ValueError('owned daemon database still has backends')
        time.sleep(0.05)
    services.sql('fixture_admin', 'DROP DATABASE "' + database + '"')
    if services.sql('fixture_admin', "SELECT count(*) FROM pg_database WHERE datname='" + database + "'") != '0':
        raise ValueError('owned HTTP database removal not established')
