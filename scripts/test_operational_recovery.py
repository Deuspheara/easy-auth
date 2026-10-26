"""Actual HTTP format bounds and private, non-overwriting operational receipts."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.request import ProxyHandler, build_opener

from operational_recovery import mailbox
from operational_recovery.evidence import write_receipt


class OwnedHandler(BaseHTTPRequestHandler):
    def log_message(self, *arguments):
        pass

    def do_GET(self):
        body = {"/valid": b'{"status":"accepted"}', "/invalid": b"not json",
                "/large": b"x" * (mailbox.MAX_RESPONSE_BYTES + 1)}[self.path]
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def do_DELETE(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Messages deleted")


class HttpContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), OwnedHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.start()
        cls.origin = "http://127.0.0.1:" + str(cls.server.server_port)
        cls.client = build_opener(ProxyHandler({}))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_json_contract_remains_strict_after_plain_text_deletion(self):
        self.assertEqual(mailbox.request(self.client, self.origin, method="DELETE", expect_json=False), (200, None))
        self.assertEqual(mailbox.request(self.client, self.origin + "/valid"), (200, {"status": "accepted"}))
        with self.assertRaises(json.JSONDecodeError):
            mailbox.request(self.client, self.origin + "/invalid")

    def test_response_size_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "response exceeds bound"):
            mailbox.request(self.client, self.origin + "/large")

    def test_empty_or_duplicate_deletion_cannot_become_delete_all(self):
        for identifiers in ([], ["owned", "owned"]):
            with self.assertRaisesRegex(ValueError, "exact owned message identifiers"):
                mailbox.remove_messages("http://invalid.example.test", identifiers)


class ReceiptTests(unittest.TestCase):
    def test_receipt_is_private_and_existing_bytes_survive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            write_receipt(path, {"status": "passed"})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            before = path.read_bytes()
            with self.assertRaises(FileExistsError):
                write_receipt(path, {"status": "replaced"})
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
