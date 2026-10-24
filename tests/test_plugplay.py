"""Tests for watch mode, adb setup and device parsing. Run: python -m unittest discover tests"""

import io
import os
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
FAKE_ADB = Path(__file__).resolve().parent / "fake_adb.py"
sys.path.insert(0, str(ROOT))

from famcheck import adb, watch  # noqa: E402


class DeviceParsingTest(unittest.TestCase):
    def setUp(self):
        FAKE_ADB.chmod(0o755)
        self.env = mock.patch.dict(os.environ, {"FAMCHECK_ADB": str(FAKE_ADB)})
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_daemon_messages_are_not_devices(self):
        serials = [d["serial"] for d in adb.list_devices()]
        self.assertEqual(serials, ["SAUBER01", "INFIZIERT01"])

    def test_lock_state_from_keyguard(self):
        self.assertIs(adb.is_locked("SAUBER01"), False)


class SetupTest(unittest.TestCase):
    def _zip(self, tmp, entries):
        path = Path(tmp) / "pt.zip"
        with zipfile.ZipFile(path, "w") as zf:
            for name in entries:
                zf.writestr(name, "#!/bin/sh\necho fake\n")
        return str(path)

    def test_installs_and_is_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            tools = Path(tmp) / "home" / "platform-tools"
            exe = "adb.exe" if sys.platform == "win32" else "adb"
            with mock.patch.object(adb, "tools_dir", return_value=tools), \
                 mock.patch.dict(os.environ, {"FAMCHECK_ADB": ""}):
                adb.install_platform_tools(self._zip(tmp, [f"platform-tools/{exe}"]))
                self.assertEqual(adb.adb_binary(), str(tools / exe))

    def test_finds_platform_tools_in_and_next_to_project(self):
        exe = "adb.exe" if sys.platform == "win32" else "adb"
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "famcheck"
            sibling = Path(tmp) / "platform-tools" / exe
            inside = project / "platform-tools" / exe
            for f in (sibling, inside):
                f.parent.mkdir(parents=True)
                f.write_text("")
            with mock.patch.object(adb, "PROJECT_DIR", project), \
                 mock.patch.object(adb, "tools_dir", return_value=Path(tmp) / "none"), \
                 mock.patch.dict(os.environ, {"FAMCHECK_ADB": ""}):
                self.assertEqual(adb.adb_binary(), str(inside))
                inside.unlink()
                self.assertEqual(adb.adb_binary(), str(sibling))

    def test_rejects_zip_slip(self):
        with tempfile.TemporaryDirectory() as tmp:
            tools = Path(tmp) / "home" / "platform-tools"
            with mock.patch.object(adb, "tools_dir", return_value=tools):
                with self.assertRaises(adb.AdbError):
                    adb.install_platform_tools(self._zip(tmp, ["../../evil.txt"]))
            self.assertFalse((Path(tmp) / "evil.txt").exists())


class WatchTest(unittest.TestCase):
    """Drives the watch loop through: unauthorized -> locked -> unlocked -> unplugged -> replugged."""

    def test_scans_only_after_unlock_and_again_after_replug(self):
        timeline = [
            ([{"serial": "S1", "state": "unauthorized", "model": "Pixel"}], None),
            ([{"serial": "S1", "state": "device", "model": "Pixel"}], True),
            ([{"serial": "S1", "state": "device", "model": "Pixel"}], True),
            ([{"serial": "S1", "state": "device", "model": "Pixel"}], False),
            ([{"serial": "S1", "state": "device", "model": "Pixel"}], False),
            ([], None),
            ([{"serial": "S1", "state": "device", "model": "Pixel"}], False),
        ]
        step = {"i": 0}

        def fake_list():
            return timeline[step["i"]][0]

        def fake_locked(_serial):
            return timeline[step["i"]][1]

        def fake_sleep(_s):
            step["i"] += 1
            if step["i"] >= len(timeline):
                raise KeyboardInterrupt

        scans = []
        out = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(watch, "list_devices", fake_list), \
             mock.patch.object(watch, "is_locked", fake_locked), \
             mock.patch.object(watch.time, "sleep", fake_sleep), \
             redirect_stdout(out):
            watch.watch(Path(tmp), None, lambda serial, label, root: scans.append((step["i"], serial)))

        self.assertEqual(scans, [(3, "S1"), (6, "S1")])  # not while unauthorized/locked, again after replug
        text = out.getvalue()
        self.assertEqual(text.count("USB-Debugging zulassen"), 1)  # hints are not repeated
        self.assertEqual(text.count("gesperrt"), 1)
        self.assertIn("abgezogen", text)


if __name__ == "__main__":
    unittest.main()
