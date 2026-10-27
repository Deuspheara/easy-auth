"""Adversarial checks for benchmark evidence, not latency thresholds."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from authentication_benchmark.validation import validate


def result():
    reports = []
    for name in ('shared_session', 'independent_owners', 'unknown_session', 'foreign_realm'):
        for concurrency in (1, 2, 8):
            count = concurrency * 32
            allowed = 'success' if name in ('shared_session', 'independent_owners') else 'unauthorized'
            outcomes = {label: {'count': 0, 'per_second': 0, 'latency_ms': None}
                        for label in ('success', 'unauthorized', 'rate_limited')}
            outcomes[allowed] = {'count': count, 'per_second': count / 2,
                                 'latency_ms': {'samples': [1.0] * count, 'p50': 1.0,
                                                'p95': 1.0, 'p99': 1.0, 'max': 1.0}}
            reports.append({'name': name, 'concurrency': concurrency, 'per_worker': 32,
                            'attempts': count, 'wall_seconds': 2.0, 'outcomes': outcomes})
    return {'profile': 'sessions', 'process_peak_rss_bytes': 1000,
            'measurement': {'profile': 'sessions', 'reports': reports,
                            'foreign_realm_rejected': True, 'revocation_rejected': True,
                            'independent_owner_retained': True}}


class BenchmarkEvidenceTests(unittest.TestCase):
    def test_complete_observations_pass(self):
        validate(result())

    def test_missing_or_duplicate_workload_fails(self):
        for change in ('missing', 'duplicate'):
            value = result()
            reports = value['measurement']['reports']
            if change == 'missing':
                reports.pop()
            else:
                reports[-1] = copy.deepcopy(reports[0])
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate(value)

    def test_missing_samples_and_invalid_percentile_fail(self):
        for change in ('samples', 'percentile', 'maximum', 'throughput', 'nan'):
            value = result()
            outcome = value['measurement']['reports'][0]['outcomes']['success']
            if change == 'samples':
                outcome['latency_ms']['samples'].pop()
            elif change == 'percentile':
                outcome['latency_ms']['p99'] = 0
            elif change == 'maximum':
                outcome['latency_ms']['max'] = 0
            elif change == 'throughput':
                outcome['per_second'] = 1000
            else:
                outcome['latency_ms']['samples'][0] = float('nan')
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate(value)

    def test_wrong_realm_success_and_unproven_revocation_fail(self):
        value = result()
        outcomes = value['measurement']['reports'][-1]['outcomes']
        outcomes['success'], outcomes['unauthorized'] = outcomes['unauthorized'], outcomes['success']
        with self.assertRaises(ValueError):
            validate(value)
        value = result()
        value['measurement']['revocation_rejected'] = False
        with self.assertRaises(ValueError):
            validate(value)

    def test_invalid_duration_and_missing_process_peak_fail(self):
        for duration in (0, -1, float('inf'), float('nan')):
            value = result()
            value['measurement']['reports'][0]['wall_seconds'] = duration
            with self.subTest(duration=duration), self.assertRaises(ValueError):
                validate(value)
        value = result()
        value['process_peak_rss_bytes'] = 0
        with self.assertRaises(ValueError):
            validate(value)


if __name__ == '__main__':
    unittest.main()
