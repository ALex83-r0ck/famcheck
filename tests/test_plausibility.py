"""A scan that could not read the device must never look like "Alles in Ordnung".
Run: python -m unittest discover tests"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAKE_ADB = Path(__file__).resolve().parent / "fake_adb.py"
sys.path.insert(0, str(ROOT))

from famcheck.analyze import coverage_findings  # noqa: E402
from famcheck.style import worst  # noqa: E402


class PlausibilityTest(unittest.TestCase):
    def scan(self, serial="SAUBER01", **env):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        out = subprocess.run([sys.executable, "-m", "famcheck", "scan", "--serial", serial, "--cases", tmp.name],
                             cwd=ROOT, capture_output=True, text=True, check=True,
                             env={**os.environ, "FAMCHECK_ADB": str(FAKE_ADB), **env}).stdout
        case = next(Path(tmp.name).iterdir())
        return json.loads((case / "findings.json").read_text(encoding="utf-8"))["findings"], out

    def test_unreadable_device_is_not_all_clear(self):
        findings, out = self.scan(FAKE_ADB_BROKEN="1")
        titles = {f["title"]: f["severity"] for f in findings}
        self.assertEqual(titles["Scan unvollständig: Paketliste fehlt oder ist zu kurz"], "HOCH")
        self.assertEqual(titles["Scan unvollständig: Geräteeigenschaften nicht lesbar"], "HOCH")
        self.assertEqual(titles["Scan unvollständig: Einstellungen nicht lesbar"], "HOCH")
        self.assertNotEqual(worst(findings), "ok")          # dashboard: never "Alles in Ordnung"
        self.assertIn("! Nicht alles prüfbar", out)         # terminal says so too

    def test_single_missing_part_is_named(self):
        findings, _ = self.scan(FAKE_ADB_NO_NETSTATS="1")
        gaps = [f["title"] for f in findings if "nicht möglich" in f["title"] or "unvollständig" in f["title"]]
        self.assertEqual(gaps, ["Teilprüfung nicht möglich: Uploads pro App"])

    def test_clean_device_has_no_gaps(self):
        findings, out = self.scan()
        self.assertFalse([f for f in findings if "unvollständig" in f["title"] or "nicht möglich" in f["title"]])
        self.assertNotIn("Nicht alles prüfbar", out)

    def test_timeouts_and_old_scans(self):
        base = {"props": {}, "settings": {"adb_enabled": "1"}}
        cov = {"props": True, "packages": 300, "apps": 5, "apps_with_permissions": 5, "launcher": True,
               "netstats": True, "accounts": True, "device_policy": True, "lock_settings": True,
               "timeouts": ["dumpsys netstats detail"]}
        titles = [f["title"] for f in coverage_findings({**base, "coverage": cov})]
        self.assertEqual(titles, ["Scan unvollständig: Zeitüberschreitung"])
        self.assertEqual(coverage_findings(base), [])       # scans from before this check: no false alarms


if __name__ == "__main__":
    unittest.main()
