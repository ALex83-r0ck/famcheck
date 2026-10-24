"""Read-only ADB access. Every command output is stored with its SHA-256 hash."""

import csv
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PLATFORM_TOOLS_URL = "https://dl.google.com/android/repository/platform-tools-latest-{os}.zip"


class AdbError(RuntimeError):
    pass


def tools_dir() -> Path:
    """Where 'famcheck setup' puts the platform-tools."""
    base = os.environ.get("LOCALAPPDATA") if sys.platform == "win32" else None
    return (Path(base) / "famcheck" if base else Path.home() / ".famcheck") / "platform-tools"


def adb_binary() -> str:
    bundled = tools_dir() / ("adb.exe" if sys.platform == "win32" else "adb")
    path = os.environ.get("FAMCHECK_ADB") or (str(bundled) if bundled.exists() else shutil.which("adb"))
    if not path:
        raise AdbError("adb nicht gefunden. Einmalig ausführen: python -m famcheck setup")
    return path


def install_platform_tools(zip_source: str | None = None) -> Path:
    """Downloads Google's platform-tools and unpacks them into tools_dir()."""
    os_name = {"win32": "windows", "darwin": "darwin"}.get(sys.platform, "linux")
    target = tools_dir().parent
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        zip_path = Path(tmp) / "platform-tools.zip"
        if zip_source and Path(zip_source).exists():
            shutil.copy(zip_source, zip_path)
        else:
            url = zip_source or PLATFORM_TOOLS_URL.format(os=os_name)
            print(f"Lade {url} ...")
            with urllib.request.urlopen(url, timeout=300) as resp:
                zip_path.write_bytes(resp.read())
        with zipfile.ZipFile(zip_path) as zf:
            for member in zf.namelist():  # refuse entries that would escape the target folder
                if not (target / member).resolve().is_relative_to(target.resolve()):
                    raise AdbError(f"Unsicherer Pfad im Zip: {member}")
            if tools_dir().exists():
                shutil.rmtree(tools_dir())
            zf.extractall(target)
    adb = tools_dir() / ("adb.exe" if sys.platform == "win32" else "adb")
    if not adb.exists():
        raise AdbError("Download enthielt kein adb.")
    if sys.platform != "win32":
        adb.chmod(0o755)
    return adb


def list_devices() -> list[dict]:
    """Returns connected devices as [{'serial':..., 'state':..., 'model':...}]."""
    out = subprocess.run(
        [adb_binary(), "devices", "-l"], capture_output=True, text=True, timeout=30
    ).stdout
    devices = []
    for line in out.splitlines():
        parts = line.split()
        # skip header and daemon messages like "* daemon not running; starting now"
        if len(parts) < 2 or line.startswith(("*", "List of devices")):
            continue
        model = next((p.split(":", 1)[1] for p in parts if p.startswith("model:")), "")
        devices.append({"serial": parts[0], "state": parts[1], "model": model})
    return devices


def is_locked(serial: str) -> bool | None:
    """True if the lock screen is showing or the screen is off. None if it cannot be determined."""
    def sh(cmd):
        try:
            return subprocess.run([adb_binary(), "-s", serial, "shell", cmd],
                                  capture_output=True, text=True, timeout=20).stdout
        except subprocess.TimeoutExpired:
            return ""

    power = sh("dumpsys power")
    if re.search(r"mWakefulness=(Asleep|Dozing)", power):
        return True
    window = sh("dumpsys window policy") + sh("dumpsys window")
    m = re.search(r"KeyguardServiceDelegate[\s\S]{0,400}?showing=(true|false)", window)
    if m:
        return m.group(1) == "true"
    m = re.search(r"(?:mShowingLockscreen|mDreamingLockscreen|isStatusBarKeyguard|mKeyguardShowing)=(true|false)", window)
    if m:
        return m.group(1) == "true"
    m = re.search(r"mScreenState=(ON_LOCKED|ON_UNLOCKED|OFF_\w+)", sh("dumpsys nfc"))
    if m:
        return m.group(1) != "ON_UNLOCKED"
    return None


class RecordingAdb:
    """Runs shell commands on one device and records each output in the case folder."""

    def __init__(self, serial: str, case_dir: Path):
        self.serial = serial
        self.raw_dir = case_dir / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = case_dir / "manifest.csv"
        self._counter = 0
        with open(self.manifest_path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["nr", "zeit_utc", "befehl", "exit_code", "datei", "sha256"])

    def shell(self, command: str, timeout: int = 120) -> str:
        self._counter += 1
        try:
            proc = subprocess.run(
                [adb_binary(), "-s", self.serial, "shell", command],
                capture_output=True, timeout=timeout,
            )
            output, rc = proc.stdout + proc.stderr, proc.returncode
        except subprocess.TimeoutExpired:
            output, rc = b"<TIMEOUT>", -1

        slug = re.sub(r"[^A-Za-z0-9]+", "_", command)[:60].strip("_")
        filename = f"{self._counter:03d}_{slug}.txt"
        (self.raw_dir / filename).write_bytes(output)
        with open(self.manifest_path, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                self._counter,
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                command, rc, f"raw/{filename}",
                hashlib.sha256(output).hexdigest(),
            ])
        return output.decode("utf-8", errors="replace")
