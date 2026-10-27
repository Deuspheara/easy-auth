"""Closed-loop socket workload with complete, separated status accounting."""
from concurrent.futures import ThreadPoolExecutor
import math
import threading
import time

from .http_wire import TransportFailure


def measure(name, concurrency, per_worker, operation):
    barrier = threading.Barrier(concurrency + 1)
    stopped = threading.Event()

    def worker(index):
        samples = []
        barrier.wait(timeout=10)
        for _ in range(per_worker):
            if stopped.is_set():
                break
            start = time.perf_counter()
            try:
                status, latency = operation(index)
                samples.append((str(status), latency))
            except TransportFailure:
                samples.append(('transport_error', (time.perf_counter() - start) * 1000))
                stopped.set()  # Retain partial attempts; never retry a lost completion.
            except Exception:
                stopped.set()
                raise
        return samples

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(worker, index) for index in range(concurrency)]
        started = time.perf_counter()
        barrier.wait(timeout=10)
        samples = [sample for future in futures for sample in future.result()]
        wall = time.perf_counter() - started
    outcomes = {}
    for status in sorted({sample[0] for sample in samples}):
        latencies = sorted(sample[1] for sample in samples if sample[0] == status)
        percentile = lambda rank: latencies[math.ceil(len(latencies) * rank / 100) - 1]
        outcomes[status] = {'count': len(latencies), 'per_second': len(latencies) / wall,
                            'latency_ms': {'p50': percentile(50), 'p95': percentile(95),
                                           'p99': percentile(99), 'max': latencies[-1],
                                           'samples': latencies}}
    return {'name': name, 'concurrency': concurrency, 'per_worker': per_worker,
            'expected_attempts': concurrency * per_worker, 'attempts': len(samples),
            'wall_seconds': wall, 'outcomes': outcomes}


def validate(report, allowed, *, require=None):
    expected = report['concurrency'] * report['per_worker']
    if report['expected_attempts'] != expected or report['attempts'] != expected:
        raise ValueError('incomplete socket workload')
    wall = report['wall_seconds']
    if not math.isfinite(wall) or wall <= 0 or not report['outcomes']:
        raise ValueError('invalid socket workload duration')
    outcomes = report['outcomes']
    if set(outcomes) - set(allowed) or 'transport_error' in outcomes:
        raise ValueError('unexpected HTTP/transport outcome')
    if require is not None and require not in outcomes:
        raise ValueError('required successful outcome missing')
    if sum(value['count'] for value in outcomes.values()) != expected:
        raise ValueError('missing socket completions')
    for value in outcomes.values():
        count = value['count']
        samples = value['latency_ms']['samples']
        if type(count) is not int or count <= 0 or len(samples) != count \
                or any(not math.isfinite(sample) or sample < 0 for sample in samples):
            raise ValueError('invalid socket latency samples')
        ordered = sorted(samples)
        for rank in (50, 95, 99):
            if value['latency_ms']['p' + str(rank)] != ordered[math.ceil(count * rank / 100) - 1]:
                raise ValueError('incorrect socket percentile')
        if value['latency_ms']['max'] != ordered[-1] \
                or not math.isclose(value['per_second'], count / wall, rel_tol=1e-9):
            raise ValueError('incorrect socket throughput/maximum')
