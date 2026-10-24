"""End-to-end test with a fake adb. Run: python -m unittest discover tests"""

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
sys.path.insert(0, str(ROOT))

from famcheck.web import make_handler  # noqa: E402


def run_famcheck(*args, **env):
    env = {**os.environ, "FAMCHECK_ADB": str(FAKE_ADB), **env}
    return subprocess.run([sys.executable, "-m", "famcheck", *args], cwd=ROOT, env=env,
                          capture_output=True, text=True, check=True).stdout


class SmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FAKE_ADB.chmod(0o755)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cases = Path(cls.tmp.name)
        run_famcheck("scan", "--all", "--cases", str(cls.cases))
        # Second scan of the clean phone, now with a new sideloaded app
        run_famcheck("scan", "--serial", "SAUBER01", "--label", "<script>x</script>",
                     "--cases", str(cls.cases), FAKE_ADB_NEWAPP="1")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def findings(self, serial):
        case = sorted(self.cases.glob(f"*_{serial}"))[-1]
        return json.loads((case / "findings.json").read_text())["findings"]

    def test_detects_stalkerware(self):
        titles = [f["title"] for f in self.findings("INFIZIERT01")]
        self.assertIn("Bekannte Stalkerware: TheTruthSpy", titles)
        self.assertTrue(any(t.startswith("Bedienungshilfe aktiv: com.systemservice") for t in titles))
        self.assertTrue(any(t.startswith("Versteckte App") for t in titles))

    def test_no_false_positives_on_clean_phone(self):
        first = sorted(self.cases.glob("*_SAUBER01"))[0]
        findings = json.loads((first / "findings.json").read_text())["findings"]
        self.assertEqual([f["severity"] for f in findings], ["NIEDRIG"])  # only USB debugging

    def test_manifest_hashes_match(self):
        import csv, hashlib
        case = sorted(self.cases.glob("*_INFIZIERT01"))[0]
        with open(case / "manifest.csv", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                actual = hashlib.sha256((case / row["datei"]).read_bytes()).hexdigest()
                self.assertEqual(actual, row["sha256"])

    def test_diff_shows_new_app(self):
        old, new = sorted(self.cases.glob("*_SAUBER01"))
        out = run_famcheck("diff", str(old), str(new))
        self.assertIn("+ com.example.flashlight", out)

    def test_dashboard(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), None)
        port = server.server_address[1]
        server.RequestHandlerClass = make_handler(self.cases, port)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{port}"
            overview = urllib.request.urlopen(base + "/").read().decode()
            self.assertIn("INFIZIERT01", overview)
            self.assertNotIn("<script>x", overview)          # label is escaped
            self.assertIn("&lt;script&gt;x", overview)

            history = urllib.request.urlopen(base + "/verlauf").read().decode()
            self.assertEqual(history.count("class='mark'"), 3)  # 2 scans SAUBER01 + 1 INFIZIERT01
            self.assertIn("+1 App", history)

            device = urllib.request.urlopen(base + "/device/SAUBER01").read().decode()
            self.assertIn("com.example.flashlight", device)  # change since previous scan

            for bad in ("/report/../../etc/passwd", "/report/%2e%2e%2fetc", "/device/nope"):
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(base + bad)
                self.assertEqual(ctx.exception.code, 404)

            req = urllib.request.Request(base + "/", headers={"Host": "evil.example:80"})
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req)
            self.assertEqual(ctx.exception.code, 403)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
