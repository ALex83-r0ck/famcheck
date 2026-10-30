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


class LiveBase(unittest.TestCase):
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



class LiveTest(LiveBase):
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


class PhoneTest(LiveBase):
    """"Am Handy öffnen": the dashboard only opens a screen on the phone; the change is a tap there."""

    FLASH = "App außerhalb eines Stores installiert: com.example.flashlight"

    def setUp(self):
        super().setUp()
        self.state = self.cases / "phone.json"
        os.environ["FAKE_ADB_STATE"] = str(self.state)
        with mock.patch("builtins.print"), mock.patch.dict(os.environ, {"FAKE_ADB_NEWAPP": "1"}):
            scan_device("SAUBER01", "Handy", self.cases)
            scan_device("INFIZIERT01", "Papa", self.cases)
        self.start()

    def phone(self, serial, key, what):
        page = self.get(f"/device/{serial}")
        token = re.search(r"name='token' value='([^']+)'", page).group(1)
        req = urllib.request.Request(self.base + "/phone", data=urllib.parse.urlencode(
            {"token": token, "serial": serial, "key": key, "what": what}).encode())
        try:
            return urllib.request.build_opener(self.jar, NoRedirect).open(req).status
        except urllib.error.HTTPError as e:
            return e.code

    def phone_state(self):
        return json.loads(self.state.read_text(encoding="utf-8")) if self.state.exists() else {}

    def test_buttons_only_where_it_is_safe(self):
        page = self.get("/device/SAUBER01")
        self.assertIn("Deinstallieren am Handy bestätigen", page)
        self.assertIn("Am Handy öffnen", page)
        papa = self.get("/device/INFIZIERT01")
        stalker = papa[papa.index("Bedienungshilfe aktiv: com.systemservice"):]
        stalker = stalker[:stalker.index("</details>")]
        self.assertNotIn("Am Handy öffnen", stalker)  # stalkerware: never

    def test_uninstall_opens_androids_own_dialog(self):
        self.assertEqual(self.phone("SAUBER01", self.FLASH, "uninstall"), 303)
        state = self.phone_state()
        self.assertEqual(state["opened"],
                         ["SAUBER01: am start -a android.intent.action.DELETE -d package:com.example.flashlight"])
        self.assertEqual(state.get("writes", []), [])  # nothing was changed by FamCheck itself
        log = (self.cases / "phone_actions.jsonl").read_text(encoding="utf-8")
        self.assertIn('"what": "uninstall"', log)

    def test_open_settings_screen(self):
        self.assertEqual(self.phone("SAUBER01", "USB-Debugging ist an", "open"), 303)
        self.assertEqual(self.phone_state()["opened"],
                         ["SAUBER01: am start -a android.settings.APPLICATION_DEVELOPMENT_SETTINGS"])

    def test_refused_for_stalkerware_and_unknown(self):
        self.assertEqual(self.phone("INFIZIERT01", "Bedienungshilfe aktiv: com.systemservice", "open"), 400)
        self.assertEqual(self.phone("SAUBER01", "USB-Debugging ist an", "uninstall"), 400)
        self.assertEqual(self.phone("SAUBER01", "gibt es nicht", "open"), 400)
        self.assertNotIn("opened", self.phone_state())


if __name__ == "__main__":
    unittest.main()
