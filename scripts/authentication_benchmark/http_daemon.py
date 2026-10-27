"""Exactly one server child per OS RSS observation; private pipe shutdown protocol."""
import json
import os
from pathlib import Path
import platform
import resource
import selectors
import signal
import subprocess
import sys
import time

from .http_wire import request, TransportFailure


class Daemon:
    def __init__(self, binary, log, environment):
        self.process = subprocess.Popen([sys.executable, '-m',
            'authentication_benchmark.http_daemon', str(binary), str(log)],
            env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True)

    def ready(self):
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=30) or self.process.stdout.readline() != b'ready\n':
                raise ValueError('owned daemon did not become ready')

    def stop(self):
        if self.process.stdin is not None:
            try:
                self.process.stdin.write(b'stop\n')
                self.process.stdin.flush()
            except BrokenPipeError:
                pass
            self.process.stdin.close()
            self.process.stdin = None
        try:
            output, diagnostic = self.process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            # This process group was created exclusively by this object.
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=5)
            raise ValueError('owned daemon did not stop') from None
        if self.process.returncode or diagnostic:
            raise ValueError('owned daemon observer failed')
        result = json.loads(output)
        if result['server_exit_code'] != 0 or result['process_peak_rss_bytes'] <= 0:
            raise ValueError('owned daemon shutdown/resource observation failed')
        return result


def observe(binary, log):
    if platform.system() not in ('Darwin', 'Linux'):
        raise ValueError('unsupported resource unit contract')
    started = time.monotonic()
    child = None
    readiness = []
    with os.fdopen(os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as output:
        try:
            child = subprocess.Popen([binary], stdin=subprocess.DEVNULL, stdout=output, stderr=output)
            deadline = time.monotonic() + 20
            while True:
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise ValueError('owned server startup failed')
                try:
                    status = request(os.environ['AUTH_PUBLIC_URL'], '/readyz')[0]
                    readiness.append(status)
                    if status == 200:
                        break
                except TransportFailure:
                    pass
                time.sleep(0.05)
            print('ready', flush=True)
            command = sys.stdin.buffer.readline(8)
            if command not in (b'stop\n', b''):
                raise ValueError('unknown owned daemon command')
        finally:
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {'server_exit_code': child.returncode,
            'readiness_statuses': readiness,
            'process_wall_seconds': time.monotonic() - started,
            'process_peak_rss_bytes': int(usage.ru_maxrss * (1 if platform.system() == 'Darwin' else 1024)),
            'process_user_seconds': usage.ru_utime, 'process_system_seconds': usage.ru_stime}


if __name__ == '__main__':
    try:
        print(json.dumps(observe(sys.argv[1], Path(sys.argv[2]))))
    except Exception:
        print('owned daemon observation failed', file=sys.stderr)
        raise SystemExit(1)
