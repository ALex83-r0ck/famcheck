"""End-to-end test with a fake adb. Run: python -m unittest discover tests"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAKE_ADB = Path(__file__).resolve().parent / "fake_adb.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
V1_SHA256 = "d1a0a4652f39618ab0d3f844b2f10b48d003d22a1b68cee1c62cf307533521d4"
V2_CERT_SHA1 = "8604d19f51ab170a6781666b2c8ec51237b5a788"
sys.path.insert(0, str(ROOT))

from famcheck.web import make_handler  # noqa: E402


TEST_ENV = {}


def run_famcheck(*args, **env):
    env = {**os.environ, "FAMCHECK_ADB": str(FAKE_ADB), **TEST_ENV, **env}
    return subprocess.run([sys.executable, "-m", "famcheck", *args], cwd=ROOT, env=env,
                          capture_output=True, text=True, check=True).stdout


class SmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FAKE_ADB.chmod(0o755)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cases = Path(cls.tmp.name) / "cases"
        # Real indicator DB plus two test entries for the fixture APKs
        db = json.loads((ROOT / "famcheck" / "data" / "iocs.json").read_text(encoding="utf-8"))
        db["sha256"][V1_SHA256] = "TestBanker"
        db["cert_sha1"][V2_CERT_SHA1] = "TestSpy (Stalkerware)"
        test_db = Path(cls.tmp.name) / "iocs.json"
        test_db.write_text(json.dumps(db), encoding="utf-8")
        TEST_ENV["FAMCHECK_IOCS"] = str(test_db)
        run_famcheck("scan", "--all", "--cases", str(cls.cases))
        # Second scan of the clean phone, now with a new sideloaded app
        run_famcheck("scan", "--serial", "SAUBER01", "--label", "<script>x</script>",
                     "--cases", str(cls.cases), FAKE_ADB_NEWAPP="1")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def findings(self, serial):
        case = sorted(self.cases.glob(f"*_{serial}"))[-1]
        return json.loads((case / "findings.json").read_text(encoding="utf-8"))["findings"]

    def test_detects_stalkerware(self):
        titles = [f["title"] for f in self.findings("INFIZIERT01")]
        self.assertIn("Bekannte Spyware: TheTruthSpy (Stalkerware)", titles)
        self.assertTrue(any(t.startswith("Bedienungshilfe aktiv: com.systemservice") for t in titles))
        self.assertTrue(any(t.startswith("Versteckte App") for t in titles))

    def test_stufe1_checks(self):
        by_title = {f["title"]: f["severity"] for f in self.findings("INFIZIERT01")}
        self.assertEqual(by_title["Gerät wird fremdverwaltet: com.systemservice"], "HOCH")
        self.assertEqual(by_title["Keine Displaysperre"], "HOCH")
        self.assertEqual(by_title["Fremde Standard-SMS-App: com.systemservice"], "HOCH")
        self.assertEqual(by_title["Hoher Upload durch App aus fremder Quelle: com.systemservice"], "HOCH")
        self.assertEqual(by_title["Läuft dauerhaft im Hintergrund: com.systemservice"], "MITTEL")
        self.assertEqual(by_title["Sonderrechte für App aus fremder Quelle: com.systemservice"], "MITTEL")
        self.assertEqual(by_title["Darf weitere Apps installieren: com.systemservice"], "MITTEL")
        self.assertEqual(by_title["2 Google-Konten auf dem Gerät"], "NIEDRIG")

    def test_stufe2_checks(self):
        by_title = {f["title"]: f["severity"] for f in self.findings("INFIZIERT01")}
        self.assertEqual(by_title["Signatur bekannter Spyware: TestSpy (Stalkerware)"], "KRITISCH")  # renamed
        self.assertEqual(by_title["Bekannte Schad-APK: TestBanker"], "KRITISCH")
        self.assertEqual(by_title["Inoffizieller Messenger-Mod: YoWhatsApp"], "HOCH")
        self.assertEqual(by_title["Aktives VPN einer App aus fremder Quelle: com.systemservice"], "HOCH")
        self.assertEqual(by_title["Privates DNS: dns.spy-example.net"], "MITTEL")
        self.assertEqual(by_title["Play Protect möglicherweise ausgeschaltet"], "MITTEL")
        self.assertEqual(by_title["Per USB installierte Apps werden nicht geprüft"], "NIEDRIG")

    def test_apks_are_fingerprinted_but_never_stored(self):
        case = sorted(self.cases.glob("*_INFIZIERT01"))[0]
        self.assertEqual(list(case.rglob("*.apk")), [])
        manifest = (case / "manifest.csv").read_text(encoding="utf-8")
        self.assertIn("pull /data/app/", manifest)
        self.assertIn(V1_SHA256, manifest)
        data = json.loads((case / "data.json").read_text(encoding="utf-8"))
        self.assertEqual(data["apps"]["com.example.flashlight"]["apk"]["cert_sha1"], V2_CERT_SHA1)
        # store apps are not pulled, the phone computes their hash itself
        self.assertNotIn("pull /data/app/~~Xy12==/com.whatsapp", manifest)
        wa = data["apps"]["com.whatsapp"]["apk"]
        self.assertTrue(wa["on_device"])
        self.assertEqual(wa["files"][0]["sha256"], hashlib.sha256(b"com.whatsapp").hexdigest())
        report = (case / "report.html").read_text(encoding="utf-8")
        self.assertIn("https://www.virustotal.com/gui/file/" + wa["files"][0]["sha256"], report)
        self.assertIn("rel='noopener noreferrer'", report)

    def test_store_app_with_known_bad_hash(self):
        # droppers (fake PDF readers, QR scanners) come from the Play Store; their hash must be checked too
        with tempfile.TemporaryDirectory() as tmp:
            db = json.loads((ROOT / "famcheck" / "data" / "iocs.json").read_text(encoding="utf-8"))
            db["sha256"][hashlib.sha256(b"com.whatsapp").hexdigest()] = "TestDropper"
            (Path(tmp) / "iocs.json").write_text(json.dumps(db), encoding="utf-8")
            run_famcheck("scan", "--serial", "SAUBER01", "--cases", str(Path(tmp) / "cases"),
                         FAMCHECK_IOCS=str(Path(tmp) / "iocs.json"))
            case = next((Path(tmp) / "cases").iterdir())
            findings = json.loads((case / "findings.json").read_text(encoding="utf-8"))["findings"]
            hit = next(f for f in findings if f["title"] == "Bekannte Schad-APK: TestDropper")
            self.assertEqual((hit["severity"], hit["package"]), ("KRITISCH", "com.whatsapp"))

    def test_uploads_parsed(self):
        case = sorted(self.cases.glob("*_SAUBER01"))[0]
        data = json.loads((case / "data.json").read_text(encoding="utf-8"))
        wa = next(u for u in data["uploads"] if "com.whatsapp" in u["packages"])
        self.assertEqual(wa["tx"], 45 * 1024 * 1024)       # tagged subset not counted
        self.assertEqual(wa["tx_bg"], 5 * 1024 * 1024)
        self.assertAlmostEqual(data["uploads_days"], 10, delta=0.2)
        self.assertEqual(data["accounts"], {"com.google": 1, "com.whatsapp": 1})  # history block ignored

    def test_account_names_never_stored(self):
        for case in self.cases.iterdir():
            for f in (case / "raw").iterdir():
                self.assertNotIn(b"@gmail.com", f.read_bytes(), f)
                self.assertNotIn(b"+491701234567", f.read_bytes(), f)
            self.assertNotIn("@gmail.com", (case / "data.json").read_text(encoding="utf-8"))

    def test_no_false_positives_on_clean_phone(self):
        first = sorted(self.cases.glob("*_SAUBER01"))[0]
        findings = json.loads((first / "findings.json").read_text(encoding="utf-8"))["findings"]
        self.assertEqual([f["severity"] for f in findings], ["NIEDRIG"])  # only USB debugging

    def test_manifest_hashes_match(self):
        import csv, hashlib
        case = sorted(self.cases.glob("*_INFIZIERT01"))[0]
        with open(case / "manifest.csv", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if not row["datei"].startswith("raw/"):  # pulled APKs are hashed, not stored
                    continue
                actual = hashlib.sha256((case / row["datei"]).read_bytes()).hexdigest()
                self.assertEqual(actual, row["sha256"])

    def test_diff_shows_new_app(self):
        old, new = sorted(self.cases.glob("*_SAUBER01"))
        out = run_famcheck("diff", str(old), str(new))
        self.assertIn("+ com.example.flashlight", out)
        self.assertIn("Neue Konten auf dem Gerät: 1", out)

    def test_dashboard(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), None)
        port = server.server_address[1]
        server.RequestHandlerClass = make_handler(self.cases, port)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())
        try:
            base = f"http://127.0.0.1:{port}"
            opener.open(server.RequestHandlerClass.login_url)
            overview = opener.open(base + "/").read().decode()
            self.assertIn("INFIZIERT01", overview)
            self.assertNotIn("<script>x", overview)          # label is escaped
            self.assertIn("&lt;script&gt;x", overview)

            history = opener.open(base + "/verlauf").read().decode()
            self.assertEqual(history.count("class='mark'"), 3)  # 2 scans SAUBER01 + 1 INFIZIERT01
            self.assertIn("+1 App", history)

            device = opener.open(base + "/device/SAUBER01").read().decode()
            self.assertIn("com.example.flashlight", device)  # change since previous scan

            case = sorted(self.cases.glob("*_INFIZIERT01"))[0]
            stored = (case / "report.html").read_bytes()
            resp = opener.open(base + "/report/" + case.name)
            self.assertEqual(resp.headers["Cache-Control"], "no-store")
            report = resp.read().decode()
            self.assertIn("Scan-Bericht", report)
            self.assertIn("/device/INFIZIERT01", report)              # link back to the dashboard
            self.assertEqual((case / "report.html").read_bytes(), stored)  # stored file untouched (hash logged)

            for bad in ("/report/../../etc/passwd", "/report/%2e%2e%2fetc", "/device/nope"):
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    opener.open(base + bad)
                self.assertEqual(ctx.exception.code, 404)

            req = urllib.request.Request(base + "/", headers={"Host": "evil.example:80"})
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                opener.open(req)
            self.assertEqual(ctx.exception.code, 403)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
