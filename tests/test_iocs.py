"""Freshness warning of the indicator database. Run: python -m unittest discover tests"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from famcheck import iocs, web  # noqa: E402

NOW = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)


class FreshnessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "iocs.json"
        self.env = mock.patch.dict(os.environ, {"FAMCHECK_IOCS": str(self.path)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def write(self, generated):
        meta = {"generated": generated} if generated else {}
        self.path.write_text(json.dumps({"packages": {}, "meta": meta}), encoding="utf-8")

    def test_fresh_list_gives_no_warning(self):
        self.write((NOW - timedelta(days=30)).isoformat())
        self.assertIsNone(iocs.freshness_warning(NOW))

    def test_old_list_warns_with_age(self):
        self.write((NOW - timedelta(days=41)).isoformat())
        self.assertIn("41 Tage alt", iocs.freshness_warning(NOW))

    def test_missing_or_undated_list_warns(self):
        self.assertIn("Keine Indikatorliste", iocs.freshness_warning(NOW))
        self.write(None)
        self.assertIn("unbekannt", iocs.freshness_warning(NOW))

    def test_dashboard_shows_banner_only_when_old(self):
        self.write((datetime.now(timezone.utc) - timedelta(days=90)).isoformat())
        self.assertIn("class='banner'", web.render_overview({}))
        self.write(datetime.now(timezone.utc).isoformat())
        self.assertNotIn("class='banner'", web.render_overview({}))


if __name__ == "__main__":
    unittest.main()
