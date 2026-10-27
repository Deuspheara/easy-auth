"""Actual bounded fresh-connection HTTP; private response/cookie data stays in RAM."""
from http.client import HTTPConnection, HTTPException
from http.cookies import SimpleCookie
import json
import re
import time
from urllib.parse import urlsplit
import uuid

PASSWORD = 'synthetic owned HTTP benchmark phrase'
MAX_RESPONSE = 8192


class TransportFailure(Exception):
    pass


def request(origin, path, *, cookie=None, body=None):
    parsed = urlsplit(origin)
    if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or not parsed.port \
            or parsed.path or parsed.query or parsed.fragment \
            or parsed.username is not None or parsed.password is not None:
        raise ValueError('owned literal-loopback origin required')
    data = None if body is None else json.dumps(body).encode()
    headers = {}
    if cookie:
        headers['Cookie'] = cookie
    if data is not None:
        headers.update({'Content-Type': 'application/json', 'Origin': origin})
    connection = HTTPConnection('127.0.0.1', parsed.port, timeout=5)
    start = time.perf_counter()
    try:
        connection.request('GET' if data is None else 'POST', path, data, headers)
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE + 1)
        elapsed = (time.perf_counter() - start) * 1000
        if len(raw) > MAX_RESPONSE:
            raise ValueError('oversized HTTP response')
        if response.getheader('cache-control') != 'no-store':
            raise ValueError('missing HTTP boundary policy')
        request_id = response.getheader('x-request-id')
        identifier = uuid.UUID(request_id)
        if identifier.version != 4 or str(identifier) != request_id:
            raise ValueError('noncanonical server request ID')
        result = (response.status, json.loads(raw) if raw else None, response.getheaders(), elapsed)
        return result
    except (OSError, EOFError, HTTPException) as error:
        raise TransportFailure('owned HTTP transport failed') from error
    finally:
        connection.close()


def session_cookie(headers):
    values = []
    for name, value in headers:
        if name.lower() != 'set-cookie':
            continue
        cookies = SimpleCookie()
        cookies.load(value)
        if 'auth-session' in cookies and cookies['auth-session'].value:
            token = cookies['auth-session'].value
            if not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
                raise ValueError('invalid owned session cookie')
            values.append('auth-session=' + token)
    if len(values) != 1:
        raise ValueError('missing or ambiguous owned session cookie')
    return values[0]
