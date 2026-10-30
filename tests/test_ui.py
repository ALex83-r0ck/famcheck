"""Readable app table, local time, device names. Run: python -m unittest discover tests"""

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from datetime import timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAKE_ADB = Path(__file__).resolve().parent / "fake_adb.py"
sys.path.insert(0, str(ROOT))

from famcheck.report import apps_html, install_info, source_label  # noqa: E402
from famcheck.style import local_time  # noqa: E402
from famcheck.web import make_handler  # noqa: E402

SCAN = "2026-10-30T11:20:47+00:00"


def app(installer="com.android.vending", first="2026-10-30 10:42:01", granted=(), icon=True):
    return {"installer": installer, "first_install": first, "granted": list(granted), "requested": [],
            "has_launcher_icon": icon}


class AppTableTest(unittest.TestCase):
    def test_sources_in_plain_language(self):
        self.assertEqual(source_label("com.android.vending"), ("Google Play", False))
        self.assertEqual(source_label("com.sec.android.app.samsungapps"), ("Galaxy Store", False))
        self.assertEqual(source_label(None), ("unbekannt (APK-Datei oder USB)", True))
        self.assertEqual(source_label("com.facebook.system"), ("Facebook-Installer (vom Hersteller)", True))
        self.assertEqual(source_label("com.evil.store"), ("com.evil.store", True))

    def test_install_dates(self):
        self.assertEqual(install_info("2008-12-31 16:00:00", SCAN), ("ab Werk", False))
        self.assertEqual(install_info("2026-10-30 10:42:01", SCAN), ("30.10.2026 10:42", True))
        self.assertEqual(install_info("2026-10-16 08:00:00", SCAN), ("16.10.2026 08:00", True))  # 14 days
        self.assertEqual(install_info("2026-10-15 08:00:00", SCAN), ("15.10.2026 08:00", False))
        self.assertEqual(install_info(None, SCAN), ("–", False))

    def test_table(self):
        data = {"apps": {
            "pdf.reader.pdfviewer.pdfeditor": app(first="2024-11-24 08:41:07"),
            "com.qr.qrcode.barcode.scanner": app(granted=["android.permission.CAMERA"]),
            "com.sec.android.app.clockpackage": app("com.sec.android.app.samsungapps", "2008-12-31 16:00:00"),
            "com.hidden<x>": app(None, "2026-09-01 10:00:00", icon=False),
        }}
        html = apps_html(data, SCAN)
        order = re.findall(r"data-name='([^']+)'", html)
        self.assertEqual(order, ["com.qr.qrcode.barcode.scanner", "com.hidden&lt;x&gt;",
                                 "pdf.reader.pdfviewer.pdfeditor", "com.sec.android.app.clockpackage"])  # newest first
        self.assertIn("https://play.google.com/store/apps/details?id=pdf.reader.pdfviewer.pdfeditor", html)
        self.assertIn("https://galaxystore.samsung.com/detail/com.sec.android.app.clockpackage", html)
        self.assertIn("ab Werk", html)
        self.assertIn("title='Kamera'>1 heikel</span>", html)
        self.assertNotIn("<x>", html)  # package names come from the phone and stay escaped
        qr = re.search(r"<tr[^>]*data-name='com.qr[^>]*>", html).group(0)
        self.assertIn("data-new", qr)
        self.assertIn("data-sensitive", qr)
        hidden = re.search(r"<tr[^>]*data-name='com.hidden[^>]*>", html).group(0)
        self.assertIn("data-foreign", hidden)
        self.assertIn("data-noicon", hidden)
        self.assertNotIn("data-app-filter", html)  # the stored report has no script, so no dead buttons
        self.assertIn("data-app-filter='new' aria-pressed='false'>Neu 1</button>", apps_html(data, SCAN, True))

    def test_local_time(self):
        cet = timezone(timedelta(hours=1))
        self.assertEqual(local_time("2026-10-30T11:20:47+00:00", cet), "30.10.2026 12:20")
        self.assertEqual(local_time("kaputt"), "kaputt")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class RenameTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FAKE_ADB.chmod(0o755)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cases = Path(cls.tmp.name)
        subprocess.run([sys.executable, "-m", "famcheck", "scan", "--serial", "SAUBER01", "--label", "moto_g06",
                        "--cases", str(cls.cases)],
                       cwd=ROOT, env={**os.environ, "FAMCHECK_ADB": str(FAKE_ADB)}, check=True, capture_output=True)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), None)
        cls.server.RequestHandlerClass = make_handler(cls.cases, cls.server.server_address[1])
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.jar = urllib.request.HTTPCookieProcessor()
        urllib.request.build_opener(cls.jar).open(cls.server.RequestHandlerClass.login_url)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def get(self, path):
        return urllib.request.build_opener(self.jar).open(self.base + path).read().decode()

    def rename(self, name, token=None, serial="SAUBER01"):
        token = token or re.search(r"name='token' value='([^']+)'", self.get("/device/SAUBER01")).group(1)
        req = urllib.request.Request(self.base + "/rename", data=urllib.parse.urlencode(
            {"token": token, "serial": serial, "name": name}).encode())
        try:
            return urllib.request.build_opener(self.jar, NoRedirect).open(req).status
        except urllib.error.HTTPError as e:
            return e.code

    def test_rename_and_reset(self):
        self.assertEqual(self.rename("Handy <b>Alex</b>"), 303)
        overview = self.get("/")
        self.assertIn("Handy &lt;b&gt;Alex&lt;/b&gt;", overview)
        self.assertNotIn("<b>Alex</b>", overview)
        self.assertIn("Handy &lt;b&gt;Alex&lt;/b&gt;", self.get("/verlauf"))
        scan = next(d for d in self.cases.iterdir() if d.is_dir())
        self.assertEqual(json.loads((scan / "findings.json").read_text(encoding="utf-8"))["meta"]["label"],
                         "moto_g06")  # the scan itself stays as it was
        self.assertEqual(self.rename("   "), 303)
        self.assertIn(">moto_g06</a>", self.get("/"))

    def test_rename_is_protected(self):
        self.assertEqual(self.rename("x", token="falsch"), 403)
        self.assertEqual(self.rename("x", serial="UNBEKANNT"), 400)
        self.assertEqual(self.rename("A" * 500), 303)
        names = json.loads((self.cases / "devices.json").read_text(encoding="utf-8"))
        self.assertEqual(len(names["SAUBER01"]), 40)
        self.rename("")

    def test_plain_form_keeps_its_origin(self):
        # Referrer-Policy no-referrer made browsers send "Origin: null" on plain forms, so renaming failed;
        # same-origin fixes that, while a null or foreign Origin is still refused
        page = urllib.request.build_opener(self.jar).open(self.base + "/")
        self.assertEqual(page.headers["Referrer-Policy"], "same-origin")
        token = re.search(r"name='token' value='([^']+)'", self.get("/device/SAUBER01")).group(1)
        for origin in ("null", "https://evil.example"):
            req = urllib.request.Request(self.base + "/rename", headers={"Origin": origin}, data=urllib.parse.urlencode(
                {"token": token, "serial": "SAUBER01", "name": "x"}).encode())
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.build_opener(self.jar, NoRedirect).open(req)
            self.assertEqual(ctx.exception.code, 403, origin)


class CompareTest(unittest.TestCase):
    """Any two scans of a device, chosen in the dashboard instead of 'famcheck diff' with long folder names."""

    @classmethod
    def setUpClass(cls):
        FAKE_ADB.chmod(0o755)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cases = Path(cls.tmp.name)
        env = {**os.environ, "FAMCHECK_ADB": str(FAKE_ADB)}
        for extra in ({}, {"FAKE_ADB_NEWAPP": "1"}, {}):  # app appears, then disappears again
            subprocess.run([sys.executable, "-m", "famcheck", "scan", "--serial", "SAUBER01", "--cases",
                            str(cls.cases)], cwd=ROOT, env={**env, **extra}, check=True, capture_output=True)
        cls.scans = sorted(d.name for d in cls.cases.iterdir() if d.is_dir())
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), None)
        cls.server.RequestHandlerClass = make_handler(cls.cases, cls.server.server_address[1])
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.jar = urllib.request.HTTPCookieProcessor()
        urllib.request.build_opener(cls.jar).open(cls.server.RequestHandlerClass.login_url)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def get(self, path):
        try:
            return 200, urllib.request.build_opener(self.jar).open(self.base + path).read().decode()
        except urllib.error.HTTPError as e:
            return e.code, ""

    def test_device_page_offers_comparison(self):
        _, page = self.get("/device/SAUBER01")
        self.assertIn("action='/vergleich/SAUBER01'", page)
        self.assertIn(f"/vergleich/SAUBER01?a={self.scans[1]}&amp;b={self.scans[2]}", page)  # per row
        self.assertIn("com.example.flashlight</span><span class='muted'>entfernt, zuletzt gesehen beim Scan am", page)

    def test_compare_any_two(self):
        first, middle, last = self.scans
        _, page = self.get(f"/vergleich/SAUBER01?a={first}&b={middle}")
        self.assertIn("com.example.flashlight</span><span class='muted'><span class='chip s-mid'>fremde Quelle</span> "
                      "installiert am 01.09.2026 10:00 über APK-Datei", page)
        self.assertIn("App außerhalb eines Stores installiert: com.example.flashlight</span>"
                      "<span class='muted'>neu</span>", page)
        _, reverse = self.get(f"/vergleich/SAUBER01?a={middle}&b={first}")  # order of the choice does not matter
        self.assertIn("installiert am 01.09.2026", reverse)
        _, same = self.get(f"/vergleich/SAUBER01?a={first}&b={last}")
        self.assertIn("Keine Änderungen an Apps, Rechten und Konten.", same)
        self.assertIn("Dieselben Befunde in beiden Scans.", same)

    def test_only_scans_of_this_device(self):
        self.assertEqual(self.get(f"/vergleich/SAUBER01?a=../../etc&b={self.scans[0]}")[0], 404)
        self.assertEqual(self.get(f"/vergleich/UNBEKANNT?a={self.scans[0]}&b={self.scans[1]}")[0], 404)


if __name__ == "__main__":
    unittest.main()
