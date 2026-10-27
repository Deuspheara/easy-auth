"""Ordinary HTTP/cookie/SMTP flow; credentials stay in memory and out of receipts."""
from http.cookiejar import CookieJar
import json
import re
import time
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener
import uuid

MAX_RESPONSE_BYTES = 1024 * 1024


def request(opener, url, *, method="GET", body=None, origin=None, expect_json=True):
    data = None if body is None else json.dumps(body).encode()
    headers = {} if body is None else {"Content-Type": "application/json"}
    if origin:
        headers["Origin"] = origin
    try:
        with opener.open(Request(url, data=data, method=method, headers=headers), timeout=5) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError("owned HTTP response exceeds bound")
            return response.status, json.loads(raw) if raw and expect_json else None
    except HTTPError as error:
        error.close()
        return error.code, None


def sign_in(origin, mail_origin):
    recipient = "auth49-" + uuid.uuid4().hex + "@example.test"
    jar = CookieJar()
    client = build_opener(ProxyHandler({}), HTTPCookieProcessor(jar))
    status, _ = request(client, origin + "/v1/email/start", method="POST",
                        body={"email": recipient}, origin=origin)
    if status != 202:
        raise ValueError("runtime email request failed")
    mail = build_opener(ProxyHandler({}))
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        status, found = request(mail, mail_origin + "/api/v1/search?" + urlencode({"query": "to:" + recipient}))
        if status != 200:
            raise ValueError("owned mailbox lookup failed")
        for item in found["messages"]:
            status, message = request(mail, mail_origin + "/api/v1/message/" + item["ID"])
            if status != 200 or len(message["To"]) != 1 or message["To"][0]["Address"] != recipient:
                raise ValueError("owned mailbox recipient mismatch")
            if message["Subject"] != "Your sign-in link":
                continue
            for value in re.findall(r"https?://[^\s]+", message["Text"]):
                link = urlsplit(value)
                if link.scheme + "://" + link.netloc == origin and link.path == "/" \
                        and not link.query and re.fullmatch(r"token=[A-Za-z0-9_-]{43}", link.fragment):
                    return finish(client, jar, origin, recipient, link.fragment[6:]), item["ID"]
        time.sleep(0.1)
    raise ValueError("owned sign-in mail deadline")


def finish(client, jar, origin, recipient, token):
    status, _ = request(client, origin + "/v1/email/finish", method="POST",
                        body={"token": token}, origin=origin)
    if status != 204:
        raise ValueError("runtime mailbox completion failed")
    status, user = request(client, origin + "/v1/session")
    if status != 200 or user["email"] != recipient or user["authentication_policy"] != "mailbox":
        raise ValueError("runtime actual user not confirmed")
    return client, jar, user


def isolation_and_logout(first, second_origin, first_origin):
    client, jar, _ = first
    cross = Request(second_origin + "/v1/session")
    jar.add_cookie_header(cross)
    try:
        build_opener(ProxyHandler({})).open(cross, timeout=5).close()
        raise ValueError("foreign-realm session unexpectedly accepted")
    except HTTPError as error:
        status = error.code
        error.close()
        if status != 401:
            raise ValueError("foreign-realm session refusal missing")
    if request(client, first_origin + "/v1/session")[0] != 200:
        raise ValueError("foreign-realm refusal damaged original session")
    if request(client, first_origin + "/v1/logout", method="POST", origin=first_origin)[0] != 204 \
            or request(client, first_origin + "/v1/session")[0] != 401:
        raise ValueError("runtime logout did not revoke the session")


def remove_messages(mail_origin, ids):
    client = build_opener(ProxyHandler({}))
    if not ids or len(set(ids)) != len(ids):
        raise ValueError("exact owned message identifiers required")
    if request(client, mail_origin + "/api/v1/messages", method="DELETE", body={"IDs": ids},
               expect_json=False)[0] != 200:
        raise ValueError("owned role messages not removed")
    status, remaining = request(client, mail_origin + "/api/v1/messages")
    if status != 200 or remaining["messages"]:
        raise ValueError("owned role mailbox is not empty")
