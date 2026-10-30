"""Live box and "Jetzt scannen" button. Run: python -m unittest discover tests"""

import json
import os
import re
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
FAKE_ADB = Path(__file__).resolve().parent / "fake_adb.py"
sys.path.insert(0, str(ROOT))

from famcheck.__main__ import scan_device  # noqa: E402
from famcheck.live import LIVE  # noqa: E402
from famcheck.web import make_handler  # noqa: E402


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class LiveTest(unittest.TestCase):
    def setUp(self):
        FAKE_ADB.chmod(0o755)
        self.tmp = tempfile.TemporaryDirectory()
        self.cases = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"FAMCHECK_ADB": str(FAKE_ADB)})
        self.env.start()
        self.calls = []
        self.servers = []

    def tearDown(self):
        for s in self.servers:
            s.shutdown()
            s.server_close()
        self.env.stop()
        self.tmp.cleanup()

    def fake_scan(self, serial, label, cases_root):
        self.calls.append((serial, label, cases_root))
        LIVE.begin(serial, label)
        LIVE.line("Lese Paketlisten ...")
        LIVE.end()

    def start(self, scan="fake"):
        server = ThreadingHTTPServer(("127.0.0.1", 0), None)
        server.RequestHandlerClass = make_handler(self.cases, server.server_address[1],
                                                  self.fake_scan if scan == "fake" else scan)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.servers.append(server)
        self.base = f"http://127.0.0.1:{server.server_address[1]}"
        self.jar = urllib.request.HTTPCookieProcessor()
        urllib.request.build_opener(self.jar).open(server.RequestHandlerClass.login_url)

    def get(self, path):
        return urllib.request.build_opener(self.jar).open(self.base + path).read().decode()

    def post_scan(self, serial="SAUBER01", token=None):
        token = token or re.search(r"name='token' value='([^']+)'", self.get("/")).group(1)
        req = urllib.request.Request(self.base + "/scan", data=urllib.parse.urlencode(
            {"token": token, "serial": serial, "back": "https://evil.example/"}).encode())
        try:
            r = urllib.request.build_opener(self.jar, NoRedirect).open(req)
            return r.status, r.headers.get("Location")
        except urllib.error.HTTPError as e:  # NoRedirect turns the 303 into an "error" too
            return e.code, e.headers.get("Location") or e.read().decode()

    def wait_idle(self):
        for _ in range(100):
            if not LIVE.scan_lock.locked():
                return
            time.sleep(0.05)
        self.fail("scan did not finish")

    def test_button_starts_a_scan(self):
        self.start()
        page = self.get("/")
        self.assertIn("Jetzt scannen: Pixel_7", page)       # fake adb reports two connected phones
        self.assertIn("Jetzt scannen: SM_A525F", page)
        status, location = self.post_scan()
        self.assertEqual((status, location), (303, "/device/SAUBER01"))  # never to the address from the form
        self.wait_idle()
        self.assertEqual(self.calls, [("SAUBER01", "Pixel_7", self.cases)])
        live = json.loads(self.get("/api/live"))
        self.assertEqual((live["running"], live["label"], live["lines"]), (False, "Pixel_7", ["Lese Paketlisten ..."]))

    def test_one_scan_at_a_time_and_only_connected_phones(self):
        self.start()
        with LIVE.scan_lock:
            status, text = self.post_scan()
        self.assertEqual(status, 409)
        self.assertIn("läuft schon ein Scan", text)
        status, text = self.post_scan("NICHT_DA")
        self.assertEqual(status, 409)
        self.assertIn("nicht (mehr) angeschlossen", text)
        self.assertEqual(self.post_scan(token="falsch")[0], 403)
        self.assertEqual(self.calls, [])

    def test_locked_phone_is_reported_in_the_live_box(self):
        self.start()
        with mock.patch.dict(os.environ, {"FAKE_ADB_LOCKED": "1"}):
            self.assertEqual(self.post_scan()[0], 303)
            self.wait_idle()
        live = json.loads(self.get("/api/live"))
        self.assertEqual(live["error"], "Handy gesperrt")
        self.assertEqual(self.calls, [])

    def test_without_scan_function_no_button(self):
        self.start(scan=None)
        self.assertNotIn("Jetzt scannen", self.get("/"))

    def test_live_endpoint_needs_login(self):
        self.start()
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self.base + "/api/live")
        self.assertEqual(ctx.exception.code, 401)

    def test_real_scan_fills_the_live_box(self):
        with mock.patch("builtins.print"):
            scan_device("SAUBER01", "Handy", self.cases)
        live = LIVE.snapshot()
        self.assertFalse(live["running"])
        self.assertIsNone(live["error"])
        self.assertIn("Lese Paketlisten ...", live["lines"])
        self.assertEqual(live["lines"][-1], "Ergebnis: NIEDRIG 1")


if __name__ == "__main__":
    unittest.main()
