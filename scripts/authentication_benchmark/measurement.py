"""One child lifetime per RSS observation; no polling or shared high-water mark."""
import json
import platform
import resource
import subprocess
import sys
import time


def measure(binary, profile):
    if platform.system() not in ('Darwin', 'Linux'):
        raise ValueError('unsupported RSS unit contract')
    started = time.monotonic()
    child = subprocess.run([binary, profile], capture_output=True, timeout=180)
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    if child.returncode or child.stderr:
        raise ValueError('benchmark child failed')
    report = json.loads(child.stdout)
    return {'profile': profile, 'process_wall_seconds': time.monotonic() - started,
            'process_peak_rss_bytes': int(usage.ru_maxrss * (1 if platform.system() == 'Darwin' else 1024)),
            'process_user_seconds': usage.ru_utime, 'process_system_seconds': usage.ru_stime,
            'measurement': report}


def launch(binary, profile, environment):
    # A fresh Python process launches exactly one child. Its RUSAGE_CHILDREN has
    # no preceding cargo/Docker or other profile's peak in it.
    command = [sys.executable, '-m', 'authentication_benchmark.measurement', str(binary), profile]
    child = subprocess.run(command, env=environment, capture_output=True, timeout=200)
    if child.returncode or child.stderr:
        raise ValueError('isolated measurement failed')
    return json.loads(child.stdout)


if __name__ == '__main__':
    try:
        print(json.dumps(measure(sys.argv[1], sys.argv[2])))
    except Exception:
        print('isolated benchmark process failed', file=sys.stderr)
        raise SystemExit(1)
