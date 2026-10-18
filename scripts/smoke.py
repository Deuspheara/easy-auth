#!/usr/bin/env python3
"""Local SMTP/API smoke. Requires a running easy-auth and the isolated Mailpit.
Never prints authentication secrets or raw email contents.
"""
import http.cookiejar
import json
import os
import re
import time
import sys
import urllib.error
import urllib.request

base = os.environ.get('AUTH_SMOKE_URL', 'http://127.0.0.1:58417')
from urllib.parse import urlsplit
assert urlsplit(base).hostname == '127.0.0.1', 'smoke only supports loopback development'
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
if '--password' in sys.argv or '--recovery' in sys.argv or '--lifecycle' in sys.argv:
    # Synthetic per-run password; never print or persist it outside the test account.
    import secrets
    password = secrets.token_urlsafe(32)
    assert request('/v1/password/enroll', {'password': password}).status == 204
    assert json.load(request('/v1/session')) == user
    assert request('/v1/logout', {}).status == 204
    for address in [email, 'missing-'+str(time.time_ns())+'@example.test']:
        try:
            request('/v1/password/login', {'email': address, 'password': 'incorrect synthetic password'})
            raise AssertionError('invalid password accepted')
        except urllib.error.HTTPError as error:
            assert error.code == 401
            assert json.load(error) == {'code':'authentication_required'}
    assert request('/v1/password/login', {'email': email, 'password': password}).status == 204
    assert json.load(request('/v1/session')) == user
    print('PASS: password enrollment, generic rejection, password login and shared session identity')
if '--recovery' in sys.argv:
    old_cookie = '; '.join(c.name+'='+c.value for c in jar)
    assert request('/v1/password/reset/start', {'email': email}).status == 202
    messages = json.load(urllib.request.urlopen('http://127.0.0.1:8025/api/v1/messages', timeout=5))['messages']
    reset_id = next(m['ID'] for m in messages if m['Subject'] == 'Password reset request' and any(a['Address'] == email for a in m['To']))
    reset_message = json.load(urllib.request.urlopen('http://127.0.0.1:8025/api/v1/message/'+reset_id, timeout=5))
    reset_token = re.search(r'#token=([A-Za-z0-9_-]{43})', reset_message['Text']).group(1)
    new_password = secrets.token_urlsafe(32)
    assert request('/v1/password/reset/finish', {'token': reset_token, 'password': new_password}).status == 204
    try:
        urllib.request.urlopen(urllib.request.Request(base+'/v1/session', headers={'Cookie':old_cookie}), timeout=5)
        raise AssertionError('pre-reset session accepted')
    except urllib.error.HTTPError as error:
        assert error.code == 401
    try:
        request('/v1/password/login', {'email': email, 'password': password})
        raise AssertionError('old password accepted')
    except urllib.error.HTTPError as error:
        assert error.code == 401
    assert request('/v1/password/login', {'email': email, 'password': new_password}).status == 204
    assert json.load(request('/v1/session')) == user
    deadline = time.monotonic()+20
    notice_id = None
    while time.monotonic() < deadline:
        messages = json.load(urllib.request.urlopen('http://127.0.0.1:8025/api/v1/messages', timeout=5))['messages']
        notice_id = next((m['ID'] for m in messages if m['Subject'] == 'Your password was reset' and any(a['Address'] == email for a in m['To'])), None)
        if notice_id: break
        time.sleep(0.1)
    assert notice_id, 'notification worker did not deliver'
    notice = json.load(urllib.request.urlopen('http://127.0.0.1:8025/api/v1/message/'+notice_id, timeout=5))
    assert password not in notice['Text'] and new_password not in notice['Text'] and reset_token not in notice['Text']
    print('PASS: purpose-bound recovery, old password/session rejection, new login and non-secret SMTP notification')
if '--sessions' in sys.argv:
    # Keep scenarios within the real per-account admission budget; never relax or clear counters.
    primary_state = (email, user, jar, client)
    email = f'sessions-{time.time_ns()}@example.test'
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    def email_sign_in():
        assert request('/v1/email/start', {'email':email}).status == 202
        messages = json.load(urllib.request.urlopen('http://127.0.0.1:8025/api/v1/messages', timeout=5))['messages']
        message_id = next(m['ID'] for m in messages if m['Subject'] == 'Your sign-in link' and any(a['Address'] == email for a in m['To']))
        message = json.load(urllib.request.urlopen('http://127.0.0.1:8025/api/v1/message/'+message_id, timeout=5))
        proof = re.search(r'#token=([A-Za-z0-9_-]{43})', message['Text']).group(1)
        assert request('/v1/email/finish', {'token':proof}).status == 204
        return json.load(request('/v1/session'))
    def reject_cookie(value):
        try:
            urllib.request.urlopen(urllib.request.Request(base+'/v1/session', headers={'Cookie':value}), timeout=5)
            raise AssertionError('revoked session cookie accepted')
        except urllib.error.HTTPError as error:
            assert error.code == 401
    user = email_sign_in()
    first_cookie = '; '.join(c.name+'='+c.value for c in jar)
    original = json.load(request('/v1/sessions'))
    first_id = next(item['id'] for item in original['sessions'] if item['current'])
    assert email_sign_in() == user
    inventory = json.load(request('/v1/sessions'))
    assert inventory['next'] is None and len(inventory['sessions']) == 2
    assert sum(item['current'] for item in inventory['sessions']) == 1
    for item in inventory['sessions']:
        assert set(item) == {'id','current','created_at_ms','last_seen_at_ms','expires_at_ms','idle_expires_at_ms','authenticated_at_ms'}
    assert request('/v1/sessions/revoke', {'id':first_id}).status == 204
    reject_cookie(first_cookie)
    second_cookie = '; '.join(c.name+'='+c.value for c in jar)
    assert request('/v1/sessions/revoke-all', {}).status == 204
    reject_cookie(second_cookie)
    assert not list(jar), 'revocation must clear authentication/action cookies'
    assert email_sign_in() == user
    assert len(json.load(request('/v1/sessions'))['sessions']) == 1
    if '--embedded' in sys.argv: assert json.load(request('/private')) == user
    assert request('/v1/logout', {}).status == 204
    email, user, jar, client = primary_state
    assert json.load(request('/v1/session')) == user
    print('PASS: public session inventory, individual/all revocation, old-cookie rejection and new login after revocation')
if '--lifecycle' in sys.argv:
    def mail_with(subject, address):
        messages = json.load(urllib.request.urlopen('http://127.0.0.1:8025/api/v1/messages', timeout=5))['messages']
        found = next((m['ID'] for m in messages if m['Subject'] == subject and any(a['Address'] == address for a in m['To'])), None)
        return json.load(urllib.request.urlopen('http://127.0.0.1:8025/api/v1/message/'+found, timeout=5)) if found else None
    def wait_notice(subject, address):
        deadline = time.monotonic()+20
        while time.monotonic() < deadline:
            notice = mail_with(subject, address)
            if notice: return notice
            time.sleep(0.1)
        raise AssertionError('notification worker did not deliver')
    previous_email = email
    previous_cookie = '; '.join(c.name+'='+c.value for c in jar)
    new_email = 'changed-'+str(time.time_ns())+'@example.test'
    assert request('/v1/account/email/start', {'email':new_email}).status == 202
    old_proof = re.search(r'#token=([A-Za-z0-9_-]{43})', mail_with('Confirm email change', email)['Text']).group(1)
    new_proof = re.search(r'#token=([A-Za-z0-9_-]{43})', mail_with('Confirm email change', new_email)['Text']).group(1)
    assert request('/v1/account/email/confirm', {'token':old_proof}).status == 202
    assert request('/v1/account/email/confirm', {'token':new_proof}).status == 204
    try:
        urllib.request.urlopen(urllib.request.Request(base+'/v1/session', headers={'Cookie':previous_cookie}), timeout=5)
        raise AssertionError('pre-change session accepted')
    except urllib.error.HTTPError as error:
        assert error.code == 401
    change_notice = wait_notice('Your sign-in email changed', previous_email)
    assert old_proof not in change_notice['Text'] and new_proof not in change_notice['Text']
    if '--recovery' in sys.argv: password = new_password
    assert request('/v1/password/login', {'email':new_email,'password':password}).status == 204
    changed = json.load(request('/v1/session'))
    assert changed['id'] == user['id'] and changed['email'] == new_email
    if '--embedded' in sys.argv: assert json.load(request('/private')) == changed
    email = new_email
    assert request('/v1/account/delete/start', {'confirmation':'delete my account'}).status == 202
    deletion = re.search(r'#token=([A-Za-z0-9_-]{43})', mail_with('Confirm account deletion', email)['Text']).group(1)
    assert request('/v1/account/delete/finish', {'token':deletion,'confirmation':'delete my account'}).status == 204
    try:
        request('/v1/password/login', {'email':email,'password':password})
        raise AssertionError('deleted account authenticated')
    except urllib.error.HTTPError as error:
        assert error.code == 401
    deleted_notice = wait_notice('Your authentication account was deleted', email)
    assert deletion not in deleted_notice['Text'] and password not in deleted_notice['Text']
    print('PASS: both-address email change, stable identity, old-session rejection, confirmed account deletion and safe notices')
assert request('/v1/logout', {}).status == 204
try:
    request('/v1/session')
    raise AssertionError('revoked session accepted')
except urllib.error.HTTPError as error:
    assert error.code == 401
print('PASS: readiness, actual SMTP delivery, browser binding, verified identity, session, replay rejection and logout')
