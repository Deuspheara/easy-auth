"""Cross-check actual daemon observations against all measured and setup requests."""
from collections import Counter
import hashlib
import re
import shlex
import uuid


def summarize(data, private_values, result):
    if any(value in data for value in private_values):
        raise ValueError('daemon output contained a private fixture value')
    text = re.sub(r'\x1b\[[0-9;]*m', '', data.decode())
    statuses = Counter()
    diagnostics = Counter()
    identifiers = set()
    for line in text.splitlines():
        if 'http_request_cancelled' in line:
            raise ValueError('unexpected socket cancellation observation')
        if 'http_request_completed' not in line:
            message = line.rsplit(': ', 1)[-1]
            if message not in ('auth_server_started', 'development_http_and_smtp_enabled'):
                raise ValueError('unexpected daemon diagnostic')
            diagnostics[message] += 1
            continue
        fields = {}
        for field in shlex.split(line.split('http_request_completed', 1)[1]):
            key, separator, value = field.partition('=')
            if not separator or key in fields:
                raise ValueError('ambiguous daemon observation field')
            fields[key] = value
        if set(fields) != {'status', 'duration_micros', 'request_id', 'completion'} \
                or not fields['status'].isdigit() or not fields['duration_micros'].isdigit() \
                or fields['completion'] != 'response':
            raise ValueError('incomplete daemon completion observation')
        value = fields['request_id']
        if uuid.UUID(value).version != 4 or str(uuid.UUID(value)) != value or value in identifiers:
            raise ValueError('ambiguous daemon request ID')
        identifiers.add(value)
        statuses[fields['status']] += 1
    expected = Counter({'202': 8, '204': 17, '200': 17 + result['controls']['issued_sessions_verified'],
                        '401': 1, '429': 1})
    expected.update(str(status) for status in result['daemon']['readiness_statuses'])
    for report in result['reports']:
        expected.update({status: value['count'] for status, value in report['outcomes'].items()})
    if diagnostics != {'auth_server_started': 1, 'development_http_and_smtp_enabled': 1}:
        raise ValueError('missing or duplicate owned startup diagnostic')
    if statuses != expected:
        raise ValueError('daemon and observed request accounting differ')
    return {'sha256': hashlib.sha256(data).hexdigest(), 'events': sum(statuses.values()),
            'status_counts': dict(statuses), 'unique_generated_request_ids': len(identifiers),
            'startup_diagnostics': dict(diagnostics),
            'private_value_scan': 'pass'}
