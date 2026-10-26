"""Attacks against FamCheck itself. Run: python -m unittest discover tests"""

import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
FAKE_ADB = Path(__file__).resolve().parent / "fake_adb.py"
sys.path.insert(0, str(ROOT))

from famcheck import apk, fix  # noqa: E402
from famcheck.__main__ import scan_device  # noqa: E402
from famcheck.adb import RecordingAdb, safe_serial  # noqa: E402
from famcheck.web import make_handler  # noqa: E402


class SecurityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {"FAMCHECK_ADB": str(FAKE_ADB),
                                                "FAKE_ADB_STATE": str(self.root / "phone.json")})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_malicious_serial_stays_inside_cases(self):
        """A manipulated phone reports a serial like '../../x' (was: files written outside cases/)."""
        cases = self.root / "cases"
        with mock.patch("builtins.print"):
            case = scan_device("../../../ENTKOMMEN", "Test", cases)
        self.assertTrue(case.resolve().is_relative_to(cases.resolve()), case)
        self.assertEqual([p.name for p in self.root.iterdir() if "ENTKOMMEN" in p.name], [])
        name = safe_serial("a*b?[c]/..\\d:5555")
        self.assertEqual(name, "a_b__c__.._d_5555")  # one harmless name: no separators, no wildcards
        self.assertFalse(set(name) & set("/\\*?[]:"))
        self.assertEqual(safe_serial("..."), "unbekannt")

    def test_dashboard_cannot_be_framed(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), None)
        port = server.server_address[1]
        server.RequestHandlerClass = make_handler(self.root, port)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            headers = urllib.request.urlopen(f"http://127.0.0.1:{port}/").headers
            self.assertEqual(headers["X-Frame-Options"], "DENY")
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])

            # negative Content-Length used to hang the request
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(f"POST /decide HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: -1\r\n\r\n".encode())
            self.assertIn(b" 400 ", s.recv(100))
            s.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_huge_apk_is_not_copied(self):
        adb = RecordingAdb("INFIZIERT01", self.root / "case")
        with mock.patch.dict(os.environ, {"FAKE_ADB_HUGE": "1"}):
            result = adb.pull_fingerprints("/data/app/x/com.systemservice-1/base.apk")
        self.assertIn("nicht kopiert", result["error"])
        manifest = (self.root / "case" / "manifest.csv").read_text(encoding="utf-8")
        self.assertNotIn("pull /data/app", manifest)

    def test_zip_bomb_signature_file_is_refused(self):
        path = self.root / "bomb.apk"
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("META-INF/CERT.RSA", b"\0" * (5 * 1024 * 1024))  # tiny compressed, 5 MB unpacked
        result = apk.fingerprints(path)
        self.assertIsNone(result["cert_sha1"])
        self.assertIn("unplausibel", result["error"])

    def test_tampered_undo_log_is_refused(self):
        fix_dir = self.root / "cases" / "x_fix_INFIZIERT01"
        fix_dir.mkdir(parents=True)
        (fix_dir / "fixlog.json").write_text(json.dumps({"serial": "INFIZIERT01", "actions": [
            {"label": "manipuliert", "status": "ausgeführt", "warning": "",
             "undo": ["pm uninstall com.whatsapp"]},
            {"label": "echt", "status": "ausgeführt", "warning": "",
             "undo": ["settings put global adb_wifi_enabled 1"]}]}), encoding="utf-8")
        out = io.StringIO()
        fix.run_undo(fix_dir, self.root / "cases", input_fn=lambda _: "j", print_fn=lambda *a: print(*a, file=out))
        writes = json.loads((self.root / "phone.json").read_text(encoding="utf-8"))["writes"]
        self.assertEqual(writes, ["INFIZIERT01: settings put global adb_wifi_enabled 1"])
        self.assertIn("ABGELEHNT", out.getvalue())


if __name__ == "__main__":
    unittest.main()
