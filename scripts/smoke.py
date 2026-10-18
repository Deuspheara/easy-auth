#!/usr/bin/env python3
"""Local SMTP/API smoke. Requires a running easy-auth and the isolated Mailpit.
Never prints authentication secrets or raw email contents.
"""
import http.cookiejar
import json
import re
import time
import sys
import urllib.error
import urllib.request

base = 'http://127.0.0.1:58417'
jar = http.cookiejar.CookieJar()
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
def request(path, data=None):
    headers = {'Origin': base}
    if data is not None:
        headers['Content-Type'] = 'application/json'
        data = json.dumps(data).encode()
    return client.open(urllib.request.Request(base+path, data=data, headers=headers), timeout=15)

email = f'smoke-{time.time_ns()}@example.test'
assert request('/readyz').status == 200
assert request('/v1/email/start', {'email': email}).status == 202
messages = json.load(urllib.request.urlopen('http://127.0.0.1:8025/api/v1/messages', timeout=5))['messages']
message_id = next(m['ID'] for m in messages if any(a['Address'] == email for a in m['To']))
message = json.load(urllib.request.urlopen('http://127.0.0.1:8025/api/v1/message/'+message_id, timeout=5))
token = re.search(r'#token=([A-Za-z0-9_-]{43})', message['Text']).group(1)
assert request('/v1/email/finish', {'token': token}).status == 204
user = json.load(request('/v1/session'))
assert user['email'] == email and 'token' not in user
if '--embedded' in sys.argv:
    assert json.load(request('/private')) == user
try:
    request('/v1/email/finish', {'token': token})
    raise AssertionError('proof replay accepted')
except urllib.error.HTTPError as error:
    assert error.code == 401
assert request('/v1/logout', {}).status == 204
try:
    request('/v1/session')
    raise AssertionError('revoked session accepted')
except urllib.error.HTTPError as error:
    assert error.code == 401
print('PASS: readiness, actual SMTP delivery, browser binding, verified identity, session, replay rejection and logout')
