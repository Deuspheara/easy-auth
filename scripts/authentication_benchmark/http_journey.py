"""Genuine SMTP/HTTP ownership, enrollment, bounded loads and saved-bearer controls."""
import json
import threading
from urllib.request import Request

from operational_recovery.mailbox import sign_in, request as mail_request, remove_messages
from .http_load import measure, validate
from .http_wire import PASSWORD, request, session_cookie


class Journey:
    def __init__(self, origin, services, database):
        self.origin, self.services, self.database = origin, services, database
        self.owners, self.messages, self.private_values = [], [], [PASSWORD.encode()]
        self.issued = []
        self.issued_lock = threading.Lock()

    def setup(self):
        self.window = self.buckets()['window']
        for _ in range(8):
            (client, jar, user), message = sign_in(self.origin, self.services.mail_origin)
            self.messages.append(message)
            if mail_request(client, self.origin + '/v1/password/enroll', method='POST',
                            body={'password': PASSWORD}, origin=self.origin)[0] != 204:
                raise ValueError('owned HTTP enrollment failed')
            probe = Request(self.origin + '/v1/session')
            jar.add_cookie_header(probe)
            cookie = probe.get_header('Cookie')
            if not cookie or request(self.origin, '/v1/session', cookie=cookie)[1] != user:
                raise ValueError('enrollment replaced the actual owner incorrectly')
            self.owners.append({'user': user, 'cookie': cookie})
            self.private_values.append(cookie.partition('=')[2].encode())
            self.private_values.extend(user[field].encode() for field in ('id', 'realm_id', 'email'))

    def sessions(self, reports):
        for concurrency in (1, 2, 8):
            for name in ('shared_session', 'independent_owners', 'unknown_session'):
                def operation(index):
                    owner = self.owners[index if name == 'independent_owners' else 0]
                    cookie = None if name == 'unknown_session' else owner['cookie']
                    status, body, _, latency = request(self.origin, '/v1/session', cookie=cookie)
                    if name == 'unknown_session':
                        if status != 401 or body != {'code': 'authentication_required'}:
                            raise ValueError('anonymous HTTP session unexpectedly accepted')
                    elif status != 200 or body != owner['user']:
                        raise ValueError('actual HTTP session owner changed')
                    return status, latency
                report = measure(name, concurrency, 32, operation)
                reports.append(report)
                validate(report, {'401'} if name == 'unknown_session' else {'200'})

    def passwords(self, reports):
        def operation(index):
            owner = self.owners[index]
            status, body, headers, latency = request(self.origin, '/v1/password/login',
                body={'email': owner['user']['email'], 'password': PASSWORD})
            if status == 204:
                if body is not None:
                    raise ValueError('password response exposed data')
                with self.issued_lock:
                    cookie = session_cookie(headers)
                    self.issued.append((cookie, owner['user']))
                    self.private_values.append(cookie.partition('=')[2].encode())
            elif status != 429 or body != {'code': 'rate_limited'}:
                raise ValueError('unexpected password HTTP outcome')
            return status, latency
        report = measure('password_login', 8, 4, operation)
        reports.append(report)
        validate(report, {'204', '429'}, require='204')
        # Validation is outside the timed load/wall clock. Never publish cookies.
        for cookie, user in self.issued:
            if request(self.origin, '/v1/session', cookie=cookie)[:2] != (200, user):
                raise ValueError('issued HTTP credential does not prove its actual owner')

    def controls(self):
        before = self.buckets()
        expected = [('password_email', 5)] * 8 + [('password_source', 40)]
        actual = sorted((row['dimension'], row['attempts']) for row in before['buckets'])
        if before['window'] != self.window or any(row['window'] != self.window for row in before['buckets']) \
                or actual != expected:
            raise ValueError('workload did not prove the exact unchanged-window budgets')
        status, body, _, _ = request(self.origin, '/v1/password/login',
            body={'email': 'budget-probe@example.test', 'password': PASSWORD})
        if status != 429 or body != {'code': 'rate_limited'} or self.buckets() != before:
            raise ValueError('source refusal changed persisted budgets')
        saved = self.owners[0]['cookie']
        if request(self.origin, '/v1/logout', cookie=saved, body={})[0] != 204 \
                or request(self.origin, '/v1/session', cookie=saved)[0] != 401 \
                or request(self.origin, '/v1/session', cookie=self.owners[1]['cookie'])[0] != 200:
            raise ValueError('saved-cookie revocation/other-owner control failed')
        return {'same_window_source_budget': True, 'refusal_rolled_back_budget': True,
                'issued_sessions_verified': len(self.issued), 'saved_cookie_revoked': True,
                'independent_owner_retained': True}

    def buckets(self):
        sql = """SELECT json_build_object('window',floor(extract(epoch FROM statement_timestamp())/600)::bigint,
          'buckets',coalesce((SELECT json_agg(x ORDER BY x.dimension,x.attempts,x.window) FROM
          (SELECT dimension,attempts,window_id AS window FROM auth_rate_buckets
           WHERE dimension IN ('password_email','password_source')) x),'[]'::json))::text"""
        return json.loads(self.services.sql(self.database, sql))

    def remove_mail(self):
        if self.messages:
            remove_messages(self.services.mail_origin, self.messages)
