"""Real loopback probe controls: request progress and changed-owner refusal."""
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest

from operational_recovery.upgrade_probe import SessionProbe


class ProbeHandler(BaseHTTPRequestHandler):
    def log_message(self, *arguments):
        pass

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(self.server.reply).encode())


class UpgradeProbeTests(unittest.TestCase):
    def setUp(self):
        self.expected = dict(id="owned-fixture", realm_id="owned-realm")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
        self.server.reply = dict(self.expected)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.origin = "http://127.0.0.1:" + str(self.server.server_port)
        self.signed = (None, CookieJar(), self.expected)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_real_requests_progress_and_the_owned_thread_stops(self):
        with SessionProbe(self.signed, self.origin) as probe:
            self.assertGreaterEqual(probe.require_more(), 2)
        self.assertFalse(probe.thread.is_alive())

    def test_changed_owner_cannot_be_counted_as_availability(self):
        self.server.reply = dict(id="other-fixture", realm_id="owned-realm")
        probe = SessionProbe(self.signed, self.origin)
        with self.assertRaises(ValueError):
            with probe:
                self.fail("changed owner unexpectedly accepted")
        self.assertFalse(probe.thread.is_alive())
        self.assertEqual(probe.count, 0)


if __name__ == "__main__":
    unittest.main()
