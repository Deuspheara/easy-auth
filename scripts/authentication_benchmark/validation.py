"""Reject incomplete measurements and distinguish expected refusal from capacity."""
import math


def validate(result):
    profile = result['profile']
    measurement = result['measurement']
    if profile != measurement['profile'] or result['process_peak_rss_bytes'] <= 0:
        raise ValueError('invalid process observation')
    names = {'sessions': {'shared_session', 'independent_owners', 'unknown_session', 'foreign_realm'},
             'argon2': {'enroll', 'verify', 'wrong_password', 'unknown_account'}}[profile]
    reports = measurement['reports']
    expected = {(name, concurrency) for name in names for concurrency in (1, 2, 8)}
    if len(reports) != len(expected) or {(r['name'], r['concurrency']) for r in reports} != expected:
        raise ValueError('incomplete or duplicate workload')
    for report in reports:
        validate_report(profile, report)
    if profile == 'sessions' and not all(measurement[key] is True for key in (
            'foreign_realm_rejected', 'revocation_rejected', 'independent_owner_retained')):
        raise ValueError('session invariant not established')


def validate_report(profile, report):
    per_worker = 32 if profile == 'sessions' else 4
    expected = report['concurrency'] * per_worker
    if report['per_worker'] != per_worker or report['attempts'] != expected:
        raise ValueError('incorrect attempt count')
    if not math.isfinite(report['wall_seconds']) or report['wall_seconds'] <= 0:
        raise ValueError('invalid workload duration')
    outcomes = report['outcomes']
    if set(outcomes) != {'success', 'unauthorized', 'rate_limited'}:
        raise ValueError('unknown outcome')
    if sum(value['count'] for value in outcomes.values()) != expected:
        raise ValueError('missing completed attempts')
    if profile == 'argon2' and report['concurrency'] <= 2 and outcomes['rate_limited']['count']:
        raise ValueError('unexpected refusal below worker capacity')
    allowed = ('success' if report['name'] in ('shared_session', 'independent_owners', 'enroll', 'verify')
               else 'unauthorized')
    for name, value in outcomes.items():
        if name != allowed and not (profile == 'argon2' and name == 'rate_limited') and value['count']:
            raise ValueError('unexpected authentication outcome')
        count = value['count']
        if type(count) is not int or count < 0:
            raise ValueError('invalid completion count')
        latency = value['latency_ms']
        if count == 0:
            if latency is not None:
                raise ValueError('empty outcome has fabricated latency')
            continue
        samples = latency['samples']
        if len(samples) != count or any(not math.isfinite(s) or s < 0 for s in samples):
            raise ValueError('incomplete or invalid latency samples')
        ordered = sorted(samples)
        if latency['max'] != ordered[-1]:
            raise ValueError('incorrect maximum latency')
        for percentile in (50, 95, 99):
            if latency['p' + str(percentile)] != ordered[math.ceil(count * percentile / 100) - 1]:
                raise ValueError('incorrect percentile')
        if not math.isclose(value['per_second'], count / report['wall_seconds'], rel_tol=1e-9):
            raise ValueError('incorrect outcome throughput')
    if outcomes[allowed]['count'] == 0:
        raise ValueError('profile never exercised the required outcome')
