"""Continuously check an actual owned session while a peer replica is replaced."""
from copy import copy
from http.cookiejar import CookieJar
import json
import threading
import time
from urllib.parse import urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, build_opener

MAX_RESPONSE_BYTES = 1024 * 1024


class RefuseRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


class SessionProbe:
    def __init__(self, signed, origin):
        target = urlsplit(origin)
        if target.scheme != "http" or target.hostname != "127.0.0.1" or target.path or target.query or target.fragment:
            raise ValueError("upgrade availability probe requires its owned loopback origin")
        jar = CookieJar()
        for cookie in signed[1]:
            jar.set_cookie(copy(cookie))
        self.client = build_opener(ProxyHandler({}), HTTPCookieProcessor(jar), RefuseRedirect())
        self.url, self.expected = origin + "/v1/session", signed[2]
        self.stop, self.ready, self.lock = threading.Event(), threading.Event(), threading.Lock()
        self.count, self.failed = 0, False
        self.thread = threading.Thread(target=self._run)

    def __enter__(self):
        self.thread.start()
        if not self.ready.wait(5) or self.failed:
            self._close()
            raise ValueError("owned replica probe has no positive session control")
        return self

    def __exit__(self, kind, value, traceback):
        self._close()
        if self.failed:
            raise ValueError("owned replica availability probe failed")

    def _close(self):
        self.stop.set()
        self.thread.join(timeout=3)
        if self.thread.is_alive():
            raise ValueError("owned replica probe did not stop")

    def _run(self):
        try:
            while not self.stop.is_set():
                with self.client.open(self.url, timeout=2) as response:
                    raw = response.read(MAX_RESPONSE_BYTES + 1)
                    if response.status != 200 or len(raw) > MAX_RESPONSE_BYTES:
                        raise ValueError("invalid owned probe response")
                    user = json.loads(raw)
                if user["id"] != self.expected["id"] or user["realm_id"] != self.expected["realm_id"]:
                    raise ValueError("owned probe identity changed")
                with self.lock:
                    self.count += 1
                self.ready.set()
                self.stop.wait(0.01)
        except (OSError, ValueError, KeyError, TypeError):
            self.failed = True
            self.ready.set()

    def require_more(self):
        with self.lock:
            before = self.count
        deadline = time.monotonic() + 5
        while not self.failed:
            with self.lock:
                if self.count > before:
                    return self.count
            if time.monotonic() >= deadline:
                break
            self.stop.wait(0.005)
        raise ValueError("owned replica probe lost request progress")
