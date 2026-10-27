"""HTTP benchmark evidence rejects lost work, corrupted accounting and private logs."""
from collections import Counter
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import threading
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from authentication_benchmark.http_load import measure, validate
from authentication_benchmark.http_logs import summarize
from authentication_benchmark.http_wire import request, session_cookie, TransportFailure


def mixed():
    return measure('control', 2, 2, lambda worker: (204 if worker == 0 else 429, 1.0))


def logs():
    result = {'controls': {'issued_sessions_verified': 1},
              'daemon': {'readiness_statuses': [200]}, 'reports': [mixed()]}
    counts = Counter({'202': 8, '204': 19, '200': 19, '401': 1, '429': 3})
    lines = [f'INFO http_request_completed request_id={uuid.uuid4()} status={status} '
             'duration_micros=1 completion="response"'
             for status, count in counts.items() for _ in range(count)]
    lines += ['INFO fixture: auth_server_started', 'WARN fixture: development_http_and_smtp_enabled']
    return result, lines


class HttpEvidenceTests(unittest.TestCase):
    def test_refusals_are_separate_and_all_attempts_retained(self):
        result = mixed()
        validate(result, {'204', '429'}, require='204')
        self.assertEqual(result['outcomes']['204']['count'], 2)
        self.assertEqual(result['outcomes']['429']['count'], 2)

    def test_transport_loss_stops_without_retry_and_cannot_qualify(self):
        calls = []
        def lost(_):
            calls.append(1)
            raise TransportFailure()
        result = measure('lost', 1, 4, lost)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result['attempts'], 1)
        self.assertEqual(result['outcomes']['transport_error']['count'], 1)
        with self.assertRaises(ValueError):
            validate(result, {'204', '429'}, require='204')

    def test_corrupt_latency_outcome_and_completion_accounting_fail(self):
        for fault in ('missing', 'percentile', 'throughput', 'nonfinite', 'status'):
            result = copy.deepcopy(mixed())
            value = result['outcomes']['204']
            if fault == 'missing':
                value['latency_ms']['samples'].pop()
            elif fault == 'percentile':
                value['latency_ms']['p99'] = 0
            elif fault == 'throughput':
                value['per_second'] = 0
            elif fault == 'nonfinite':
                result['wall_seconds'] = float('nan')
            else:
                result['outcomes']['503'] = result['outcomes'].pop('204')
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                validate(result, {'204', '429'}, require='204')

    def test_actual_log_counts_ids_and_private_canaries_are_checked(self):
        result, lines = logs()
        report = summarize('\n'.join(lines).encode(), [b'private-canary'], result)
        self.assertEqual(report['events'], len(lines) - 2)
        self.assertEqual(report['unique_generated_request_ids'], len(lines) - 2)
        for changed in (lines[:-1], lines + [lines[0]],
                        [lines[0].replace('response', 'timed_out'), *lines[1:]],
                        [lines[0] + ' raw_token=unexpected', *lines[1:]],
                        [*lines, 'unexpected diagnostic'],
                        [*lines, lines[-1]],
                        [*lines, 'private-canary']):
            with self.assertRaises(ValueError):
                summarize('\n'.join(changed).encode(), [b'private-canary'], result)

    def test_missing_ambiguous_and_invalid_cookie_are_refused(self):
        valid = ('Set-Cookie', 'auth-session=' + 'A' * 43 + '; HttpOnly; Path=/')
        self.assertEqual(session_cookie([valid]), 'auth-session=' + 'A' * 43)
        for headers in ([], [valid, valid], [('Set-Cookie', 'auth-session=invalid')]):
            with self.assertRaises(ValueError):
                session_cookie(headers)


class ActualWireTests(unittest.TestCase):
    def test_real_socket_boundary_headers_and_response_are_checked(self):
        class Handler(BaseHTTPRequestHandler):
            policy = 'no-store'
            identifier = str(uuid.uuid4())
            def log_message(self, *arguments):
                pass
            def do_GET(self):
                self.send_response(200)
                self.send_header('Cache-Control', self.policy)
                self.send_header('x-request-id', self.identifier)
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'{}')
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        origin = 'http://127.0.0.1:' + str(server.server_port)
        try:
            self.assertEqual(request(origin, '/control')[:2], (200, {}))
            Handler.policy = 'public'
            with self.assertRaises(ValueError):
                request(origin, '/control')
            Handler.policy, Handler.identifier = 'no-store', 'client-controlled'
            with self.assertRaises(ValueError):
                request(origin, '/control')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())


if __name__ == '__main__':
    unittest.main()
