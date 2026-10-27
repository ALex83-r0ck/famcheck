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
from famcheck.report import compute_diff  # noqa: E402
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

    def test_app_data_error_is_not_an_app_without_rights(self):
        # real device: "dumpsys package" answered with 39 bytes of error for 64 of 120 apps; the scan
        # showed nothing, the next comparison then listed every right of those apps as "new"
        findings, out = self.scan("INFIZIERT01", FAKE_ADB_DUMP_FAIL="com.whatsapp,com.systemservice")
        titles = {f["title"]: f for f in findings}
        gap = titles["Scan unvollständig: Daten von 2 von 3 Apps nicht lesbar"]
        self.assertEqual(gap["severity"], "HOCH")
        self.assertIn("Failure calling service package", gap["detail"])
        self.assertNotIn("Scan unvollständig: App-Rechte nicht lesbar", titles)  # no double report
        self.assertIn("! Nicht alles prüfbar", out)

    def test_single_unreadable_app_is_medium(self):
        data = {"props": {}, "settings": {"adb_enabled": "1"},
                "apps": {f"app{i}": {"dump_ok": True, "granted": [], "requested": []} for i in range(9)}}
        data["apps"]["app0"] = {"dump_ok": False, "dump_error": "Error: x", "granted": [], "requested": []}
        data["coverage"] = {"props": True, "packages": 300, "apps": 9, "apps_with_permissions": 8, "launcher": True,
                            "netstats": True, "accounts": True, "device_policy": True, "lock_settings": True,
                            "timeouts": []}
        (f,) = coverage_findings(data)
        self.assertEqual((f["severity"], f["title"]),
                         ("MITTEL", "Scan unvollständig: Daten von 1 von 9 Apps nicht lesbar"))

    def test_retry_recovers_a_flaky_answer(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        findings, _ = self.scan(FAKE_ADB_DUMP_FLAKY=str(Path(tmp.name) / "failed-once"))
        self.assertFalse([f for f in findings if "unvollständig" in f["title"]])

    def test_diff_skips_unreadable_apps_and_harmless_rights(self):
        readable = {"installer": "com.android.vending", "version": "1.0", "requested": ["x"],
                    "granted": ["android.permission.INTERNET"]}
        broken_old_scan = {"installer": "com.android.vending", "version": None, "requested": [], "granted": []}
        later = {**readable, "granted": ["android.permission.CAMERA", "android.permission.INTERNET",
                                         "android.permission.WAKE_LOCK"]}
        old = {"apps": {"a": readable, "b": broken_old_scan, "c": readable}}
        new = {"apps": {"a": later, "b": later, "c": {**readable, "granted": readable["granted"] + ["android.permission.VIBRATE"]}}}
        d = compute_diff(old, new)
        self.assertEqual(d["new_permissions"], {"a": ["Kamera"]})  # b not comparable, c only harmless
        self.assertEqual(d["not_comparable"], 1)


if __name__ == "__main__":
    unittest.main()
