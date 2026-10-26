"""MalwareBazaar check against a local fake server. Run: python -m unittest discover tests"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parent.parent
FAKE_ADB = Path(__file__).resolve().parent / "fake_adb.py"
V1_SHA256 = "d1a0a4652f39618ab0d3f844b2f10b48d003d22a1b68cee1c62cf307533521d4"


class FakeBazaar(BaseHTTPRequestHandler):
    requests: list = []

    def do_POST(self):
        body = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
        FakeBazaar.requests.append({"key": self.headers.get("Auth-Key"), "body": body})
        if body["hash"][0] == V1_SHA256:
            answer = {"query_status": "ok", "data": [{"signature": "Triada", "tags": ["apk", "spy"]}]}
        else:
            answer = {"query_status": "hash_not_found"}
        data = json.dumps(answer).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class MalwareBazaarTest(unittest.TestCase):
    def run_scan(self, cases, **env):
        env = {**os.environ, "FAMCHECK_ADB": str(FAKE_ADB), **env}
        return subprocess.run([sys.executable, "-m", "famcheck", "scan", "--serial", "INFIZIERT01",
                               "--malwarebazaar", "--cases", str(cases)],
                              cwd=ROOT, env=env, capture_output=True, text=True)

    def test_only_hashes_are_sent_and_hits_become_findings(self):
        FAKE_ADB.chmod(0o755)
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeBazaar)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                proc = self.run_scan(Path(tmp), FAMCHECK_ABUSECH_KEY="test-key",
                                     FAMCHECK_MB_URL=f"http://127.0.0.1:{server.server_address[1]}/")
                self.assertEqual(proc.returncode, 0, proc.stderr)
                case = next(Path(tmp).iterdir())
                findings = json.loads((case / "findings.json").read_text(encoding="utf-8"))["findings"]
                caselog = (case / "caselog.txt").read_text(encoding="utf-8")
        finally:
            server.shutdown()
            server.server_close()

        self.assertIn("MalwareBazaar kennt diese APK: Triada", [f["title"] for f in findings])
        self.assertEqual(len(FakeBazaar.requests), 2)  # two APKs from unknown sources
        for r in FakeBazaar.requests:
            self.assertEqual(r["key"], "test-key")
            self.assertEqual(set(r["body"]), {"query", "hash"})  # nothing else leaves the PC
        self.assertIn(f"MalwareBazaar-Abfrage (nur Hash) für com.systemservice: {V1_SHA256}", caselog)

    def test_refuses_without_key(self):
        env = {k: v for k, v in os.environ.items() if k != "FAMCHECK_ABUSECH_KEY"}
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run([sys.executable, "-m", "famcheck", "scan", "--serial", "INFIZIERT01",
                                   "--malwarebazaar", "--cases", tmp],
                                  cwd=ROOT, env={**env, "FAMCHECK_ADB": str(FAKE_ADB)},
                                  capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("auth.abuse.ch", proc.stderr)
            self.assertEqual(list(Path(tmp).iterdir()), [])  # nothing scanned


if __name__ == "__main__":
    unittest.main()
