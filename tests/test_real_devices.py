"""Lessons from scans of real devices (moto g06, Android 13). Run: python -m unittest discover tests"""

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

from famcheck.style import uploads_html  # noqa: E402

LEGACY = "Installation aus unbekannten Quellen erlaubt (global)"


class ScanHelper(unittest.TestCase):
    def scan(self, **env):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        subprocess.run([sys.executable, "-m", "famcheck", "scan", "--serial", "SAUBER01", "--cases", tmp.name],
                       cwd=ROOT, capture_output=True, check=True,
                       env={**os.environ, "FAMCHECK_ADB": str(FAKE_ADB), **env})
        case = next(Path(tmp.name).iterdir())
        load = lambda name: json.loads((case / name).read_text(encoding="utf-8"))  # noqa: E731
        return load("findings.json")["findings"], load("data.json")


class RealDeviceLessons(ScanHelper):
    def test_legacy_unknown_sources_only_before_android_8(self):
        """Android 8+ always reports install_non_market_apps=1; per-app check covers it there."""
        modern, _ = self.scan()
        self.assertNotIn(LEGACY, [f["title"] for f in modern])
        old, _ = self.scan(FAKE_ADB_SDK="25")
        self.assertIn(LEGACY, [f["title"] for f in old])

    def test_upload_total_is_not_an_app(self):
        _, data = self.scan()
        self.assertNotIn(-1, [u["uid"] for u in data["uploads"]])   # the sum over all apps
        html = uploads_html(data)
        self.assertIn("System (Kernel)", html)
        self.assertNotIn("uid 0", html)

    def test_older_scans_are_shown_cleaned_up(self):
        old_data = {"apps": {}, "uploads_days": 7, "uploads": [
            {"uid": -1, "packages": ["uid -1"], "tx": 673 * 2**20, "tx_bg": 0},
            {"uid": 0, "packages": ["uid 0"], "tx": 12 * 2**20, "tx_bg": 12 * 2**20}]}
        html = uploads_html(old_data)
        self.assertNotIn("uid -1", html)
        self.assertNotIn("673", html)
        self.assertIn("System (Kernel)", html)


class DropperTest(ScanHelper):
    """Neighbour's Galaxy A05s: two QR scanners from the Play Store, installed the same day. Store apps
    that ask to install more apps are how banking trojans like Anatsa get onto phones."""

    TITLE = "Neue App will weitere Apps installieren: com.qr.scanner.free"

    def by_title(self, **env):
        findings, _ = self.scan(**env)
        return {f["title"]: f for f in findings}

    def test_new_store_app_asking_to_install_apps(self):
        f = self.by_title(FAKE_ADB_DROPPER="new")[self.TITLE]
        self.assertEqual(f["severity"], "MITTEL")
        self.assertIn("Heute installiert (Quelle: Google Play)", f["detail"])
        self.assertIn("Anatsa", f["detail"])

    def test_already_allowed_is_high_and_not_reported_twice(self):
        titles = self.by_title(FAKE_ADB_DROPPER="granted")
        self.assertEqual(titles[self.TITLE]["severity"], "HOCH")
        self.assertIn("und hat es bereits bekommen", titles[self.TITLE]["detail"])
        self.assertNotIn("Darf weitere Apps installieren: com.qr.scanner.free", titles)

    def test_old_app_is_not_reported(self):
        self.assertNotIn(self.TITLE, self.by_title(FAKE_ADB_DROPPER="old"))

    def test_browsers_and_file_managers_may_ask(self):
        from datetime import date
        from famcheck.analyze import analyze
        _, data = self.scan(FAKE_ADB_DROPPER="new")
        data["apps"]["com.android.chrome"] = data["apps"].pop("com.qr.scanner.free")
        self.assertFalse([f for f in analyze(data, date.today()) if f["title"].startswith("Neue App will")])

    def test_dashboard_offers_steps_and_remove(self):
        from famcheck import fix, guides
        f = self.by_title(FAKE_ADB_DROPPER="new")[self.TITLE]
        self.assertTrue(fix.removable(f, [f]))
        self.assertIn("Deinstallieren", guides.steps_html(f, {"ro.product.manufacturer": "samsung"}, [f]))


if __name__ == "__main__":
    unittest.main()
