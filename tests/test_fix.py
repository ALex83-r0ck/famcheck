"""Stufe B: fixing findings on the phone. Run: python -m unittest discover tests"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAKE_ADB = Path(__file__).resolve().parent / "fake_adb.py"


class FixTest(unittest.TestCase):
    def setUp(self):
        FAKE_ADB.chmod(0o755)
        self.tmp = tempfile.TemporaryDirectory()
        self.cases = Path(self.tmp.name) / "cases"
        self.state = Path(self.tmp.name) / "phone.json"
        self.env = {k: v for k, v in os.environ.items() if k != "FAMCHECK_IOCS"}
        self.env.update({"FAMCHECK_ADB": str(FAKE_ADB), "FAKE_ADB_STATE": str(self.state)})
        self.famcheck("scan", "--serial", "INFIZIERT01")

    def tearDown(self):
        self.tmp.cleanup()

    def famcheck(self, *args, stdin="", **env):
        return subprocess.run([sys.executable, "-m", "famcheck", *args, "--cases", str(self.cases)], cwd=ROOT,
                              env={**self.env, **env}, input=stdin, capture_output=True, text=True, check=True).stdout

    def writes(self):
        return json.loads(self.state.read_text(encoding="utf-8")).get("writes", []) if self.state.exists() else []

    def fixlog(self):
        return json.loads(next(self.cases.glob("*_fix_*")).joinpath("fixlog.json").read_text(encoding="utf-8"))

    def test_scan_writes_nothing_to_the_phone(self):
        self.assertEqual(self.writes(), [])

    def test_dry_run_changes_nothing(self):
        out = self.famcheck("fix", "--serial", "INFIZIERT01", "--dry-run", stdin="alle\n")
        self.assertIn("adb shell settings put global adb_wifi_enabled 0", out)
        self.assertEqual(self.writes(), [])

    def test_declined_changes_nothing(self):
        self.famcheck("fix", "--serial", "INFIZIERT01", stdin="alle\n" + "n\n" * 20)
        self.assertEqual(self.writes(), [])
        self.assertTrue(all(a["status"] == "übersprungen" for a in self.fixlog()["actions"]))

    def test_locked_phone_is_refused(self):
        out = self.famcheck("fix", "--serial", "INFIZIERT01", stdin="alle\n" + "j\n" * 20, FAKE_ADB_LOCKED="1")
        self.assertIn("entsperren", out)
        self.assertEqual(self.writes(), [])

    def test_fix_and_undo(self):
        out = self.famcheck("fix", "--serial", "INFIZIERT01", stdin="alle\n" + "j\n" * 20)
        writes = [w.split(": ", 1)[1] for w in self.writes()]

        # stalkerware app is left alone, with the safety note
        self.assertIn("Bewusst nicht angeboten", out)
        self.assertIn("Bekannte Spyware: TheTruthSpy (Stalkerware)", out)
        self.assertFalse([w for w in writes if "com.systemservice" in w], writes)
        # no uninstall, ever
        self.assertFalse([w for w in writes if "uninstall" in w])
        # manual guidance for what ADB should not change
        self.assertIn("Keine Displaysperre", out)
        self.assertIn("FamCheck setzt bewusst keine PIN", out)

        self.assertIn("settings put global adb_wifi_enabled 0", writes)
        self.assertIn("settings put global private_dns_mode opportunistic", writes)
        self.assertIn("pm revoke com.example.flashlight android.permission.CAMERA", writes)
        self.assertEqual(writes[-1], "settings put global adb_enabled 0")  # cuts the connection, so last

        # fixed findings are marked as done in the dashboard decisions
        done = json.loads((self.cases / "decisions.json").read_text(encoding="utf-8"))["INFIZIERT01"]
        self.assertEqual(done["Kabelloses Debugging ist an"]["status"], "done")
        fix_dir = next(self.cases.glob("*_fix_*"))
        self.assertTrue((fix_dir / "manifest.csv").exists())

        # undo restores the previous values, in reverse order; USB debugging cannot be undone remotely
        before = len(writes)
        out = self.famcheck("fix", "--undo", str(fix_dir), stdin="j\n" * 20)
        undo = [w.split(": ", 1)[1] for w in self.writes()][before:]
        self.assertIn("settings put global adb_wifi_enabled 1", undo)
        self.assertIn("settings put global private_dns_mode hostname", undo)
        self.assertIn("pm grant com.example.flashlight android.permission.CAMERA", undo)
        self.assertIn("Nicht automatisch umkehrbar", out)
        self.assertTrue((next(self.cases.glob("*_undo_*")) / "undolog.json").exists())

    def test_dashboard_hint(self):
        sys.path.insert(0, str(ROOT))
        from famcheck import fix
        scan = next(d for d in self.cases.iterdir() if (d / "findings.json").exists())
        findings = json.loads((scan / "findings.json").read_text(encoding="utf-8"))["findings"]
        kind = {f["title"]: fix.fix_kind(f, findings) for f in findings}
        self.assertEqual(kind["Kabelloses Debugging ist an"], "auto")
        self.assertEqual(kind["Bedienungshilfe aktiv: com.systemservice"], "blocked")
        self.assertEqual(kind["Keine Displaysperre"], "manual")

    def test_already_fixed_is_not_offered_again(self):
        self.famcheck("fix", "--serial", "INFIZIERT01", stdin="1\nj\n")  # fix only the first action
        first = self.fixlog()["actions"][0]["label"]
        out = self.famcheck("fix", "--serial", "INFIZIERT01", "--dry-run", stdin="\n")
        self.assertNotIn(first, out)


class RemoveTest(FixTest):
    """famcheck remove: deinstalls one app, asks first, refuses stalkerware, logs everything."""

    def remove(self, pkg, stdin="", **env):
        return self.famcheck("remove", "--serial", "INFIZIERT01", pkg, stdin=stdin, **env)

    def test_asks_first(self):
        out = self.remove("com.example.flashlight", stdin="n\n")
        self.assertIn("Heikle Rechte: Kamera, Kontakte", out)
        self.assertIn("Abgebrochen, nichts geändert.", out)
        self.assertEqual(self.writes(), [])

    def test_removes_and_marks_done(self):
        out = self.remove("com.example.flashlight", stdin="j\n")
        self.assertIn("Erledigt.", out)
        self.assertEqual(self.writes(), ["INFIZIERT01: pm uninstall com.example.flashlight"])
        log = json.loads(next(self.cases.glob("*_remove_*")).joinpath("removelog.json").read_text(encoding="utf-8"))
        self.assertEqual((log["package"], log["status"]), ("com.example.flashlight", "ausgeführt"))
        done = json.loads((self.cases / "decisions.json").read_text(encoding="utf-8"))["INFIZIERT01"]
        self.assertEqual(done["App außerhalb eines Stores installiert: com.example.flashlight"]["status"], "done")

    def test_refuses_stalkerware_unknown_and_system_apps(self):
        self.assertIn("Bewusst nicht", self.remove("com.systemservice", stdin="j\n"))
        self.assertIn("keine vom Nutzer installierte App", self.remove("com.android.system.part01", stdin="j\n"))
        self.assertIn("keine vom Nutzer installierte App", self.remove("x;rm -rf /", stdin="j\n"))
        self.assertEqual(self.writes(), [])

    def test_device_admin_explains_what_to_do(self):
        out = self.remove("com.example.flashlight", stdin="j\n", FAKE_ADB_ADMIN="1")
        self.assertIn("als Geräteadministrator eingetragen", out)
        self.assertFalse((self.cases / "decisions.json").exists())


if __name__ == "__main__":
    unittest.main()
