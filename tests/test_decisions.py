"""Triage of findings (Stufe A). Run: python -m unittest discover tests"""

import json
import os
import re
import subprocess
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

ROOT = Path(__file__).resolve().parent.parent
FAKE_ADB = Path(__file__).resolve().parent / "fake_adb.py"
sys.path.insert(0, str(ROOT))

from famcheck import decisions  # noqa: E402
from famcheck.web import make_handler  # noqa: E402

USB = "USB-Debugging ist an"


def finding(title="X", severity="MITTEL", detail="Zugriff auf: Kamera. 45 MB"):
    return {"title": title, "severity": severity, "detail": detail, "action": "", "package": None}


class EvaluateTest(unittest.TestCase):
    def decide(self, f, status, at="2026-10-24T10:00:00+00:00"):
        return {"status": status, "note": "", "at": at, "severity": f["severity"],
                "fingerprint": decisions.fingerprint(f)}

    def test_states(self):
        f = finding()
        self.assertEqual(decisions.evaluate(f, None, "2026-10-25"), "none")
        self.assertEqual(decisions.evaluate(f, self.decide(f, "ok"), "2026-10-25"), "suppressed")
        self.assertEqual(decisions.evaluate(f, self.decide(f, "watch"), "2026-10-25"), "watch")

    def test_numbers_do_not_reopen_but_new_content_does(self):
        d = self.decide(finding(), "ok")
        self.assertEqual(decisions.evaluate(finding(detail="Zugriff auf: Kamera. 300 MB"), d, "x"), "suppressed")
        self.assertEqual(decisions.evaluate(finding(detail="Zugriff auf: Kamera, Mikrofon. 45 MB"), d, "x"), "changed")

    def test_worse_severity_reopens(self):
        d = self.decide(finding(severity="MITTEL"), "ok")
        self.assertEqual(decisions.evaluate(finding(severity="HOCH"), d, "x"), "changed")
        self.assertEqual(decisions.evaluate(finding(severity="NIEDRIG"), d, "x"), "suppressed")  # better stays ok

    def test_done_holds_until_next_scan(self):
        f = finding()
        d = self.decide(f, "done", at="2026-10-24T10:00:00+00:00")
        self.assertEqual(decisions.evaluate(f, d, "2026-10-24T09:00:00+00:00"), "suppressed")  # same/older scan
        self.assertEqual(decisions.evaluate(f, d, "2026-10-25T09:00:00+00:00"), "reopened")


class DashboardTriageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FAKE_ADB.chmod(0o755)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cases = Path(cls.tmp.name)
        cls.scan()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), None)
        cls.port = cls.server.server_address[1]
        cls.server.RequestHandlerClass = make_handler(cls.cases, cls.port)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.jar = urllib.request.HTTPCookieProcessor()
        urllib.request.build_opener(cls.jar).open(cls.server.RequestHandlerClass.login_url)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    @classmethod
    def scan(cls):
        subprocess.run([sys.executable, "-m", "famcheck", "scan", "--serial", "SAUBER01", "--cases", str(cls.cases)],
                       cwd=ROOT, env={**os.environ, "FAMCHECK_ADB": str(FAKE_ADB)}, check=True, capture_output=True)

    def get(self, path):
        return urllib.request.build_opener(self.jar).open(self.base + path).read().decode()

    def post(self, fields, headers=None):
        req = urllib.request.Request(self.base + "/decide", data=urllib.parse.urlencode(fields).encode(),
                                     headers=headers or {})
        opener = urllib.request.build_opener(self.jar, NoRedirect)
        try:
            return opener.open(req).status
        except urllib.error.HTTPError as e:
            return e.code

    def token(self):
        return re.search(r"name='token' value='([^']+)'", self.get("/device/SAUBER01")).group(1)

    def test_1_rejects_forged_requests(self):
        good = {"token": self.token(), "serial": "SAUBER01", "key": USB, "status": "ok"}
        self.assertEqual(self.post({**good, "token": "falsch"}), 403)
        self.assertEqual(self.post(good, {"Origin": "https://evil.example"}), 403)
        self.assertEqual(self.post(good, {"Host": "evil.example"}), 403)
        self.assertEqual(self.post({**good, "key": "<gibt es nicht>"}), 400)
        self.assertEqual(self.post({**good, "status": "delete"}), 400)
        self.assertFalse((self.cases / "decisions.json").exists())

    def test_2_ok_hides_finding_from_traffic_light(self):
        self.assertIn("Kleinigkeiten", self.get("/"))
        status = self.post({"token": self.token(), "serial": "SAUBER01", "key": USB, "status": "ok",
                            "note": "Brauche ich für FamCheck"}, {"Origin": self.base})
        self.assertEqual(status, 303)
        overview = self.get("/")
        self.assertIn("Alles in Ordnung", overview)
        self.assertIn("1 eingeordnet", overview)
        device = self.get("/device/SAUBER01")
        self.assertIn("Eingeordnet (1)", device)
        self.assertIn("Brauche ich für FamCheck", device)
        log = (self.cases / "decisions_log.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(json.loads(log[-1])["status"], "ok")

    def test_3_done_reopens_after_next_scan(self):
        self.post({"token": self.token(), "serial": "SAUBER01", "key": USB, "status": "done"})
        self.assertIn("Alles in Ordnung", self.get("/"))
        time.sleep(1.1)  # the next scan must start in a later second than the decision
        self.scan()
        device = self.get("/device/SAUBER01")
        self.assertIn("als erledigt markiert, ist aber noch da", device)
        self.assertIn("1 wieder offen", self.get("/"))

    def test_4_reset_removes_decision(self):
        self.post({"token": self.token(), "serial": "SAUBER01", "key": USB, "status": "reset"})
        self.assertNotIn(USB, json.loads((self.cases / "decisions.json").read_text(encoding="utf-8")).get("SAUBER01", {}))
        lines = (self.cases / "decisions_log.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual([json.loads(x)["status"] for x in lines], ["ok", "done", "reset"])  # full trail kept


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


if __name__ == "__main__":
    unittest.main()
