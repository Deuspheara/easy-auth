"""Cross-check actual daemon observations against all measured and setup requests."""
from collections import Counter
import hashlib
import re
import uuid


def summarize(data, private_values, result):
    if any(value in data for value in private_values):
        raise ValueError('daemon output contained a private fixture value')
    text = re.sub(r'\x1b\[[0-9;]*m', '', data.decode())
    statuses = Counter()
    identifiers = set()
    for line in text.splitlines():
        if 'http_request_cancelled' in line:
            raise ValueError('unexpected socket cancellation observation')
        if 'http_request_completed' not in line:
            continue
        status = re.search(r'\bstatus=(\d+)\b', line)
        duration = re.search(r'\bduration_micros=(\d+)\b', line)
        identifier = re.search(r'\brequest_id="?([0-9a-f-]{36})"?(?:\s|$)', line)
        completion = re.search(r'\bcompletion="?response"?(?:\s|$)', line)
        if not all((status, duration, identifier, completion)):
            raise ValueError('incomplete daemon completion observation')
        value = identifier[1]
        if uuid.UUID(value).version != 4 or value in identifiers:
            raise ValueError('ambiguous daemon request ID')
        identifiers.add(value)
        statuses[status[1]] += 1
    expected = Counter({'202': 8, '204': 17, '200': 17 + result['controls']['issued_sessions_verified'],
                        '401': 1, '429': 1})
    expected.update(str(status) for status in result['daemon']['readiness_statuses'])
    for report in result['reports']:
        expected.update({status: value['count'] for status, value in report['outcomes'].items()})
    if statuses != expected:
        raise ValueError('daemon and observed request accounting differ')
    return {'sha256': hashlib.sha256(data).hexdigest(), 'events': sum(statuses.values()),
            'status_counts': dict(statuses), 'unique_generated_request_ids': len(identifiers),
            'private_value_scan': 'pass'}
