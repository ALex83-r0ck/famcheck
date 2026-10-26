"""Read-only ADB access. Every command output is stored with its SHA-256 hash."""

import csv
import hashlib
import os
import re
import shlex
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


PROJECT_DIR = Path(__file__).resolve().parent.parent


def adb_binary() -> str:
    """FAMCHECK_ADB, then platform-tools in/next to the project folder, then 'setup' location, then PATH."""
    if os.environ.get("FAMCHECK_ADB"):
        return os.environ["FAMCHECK_ADB"]
    exe = "adb.exe" if sys.platform == "win32" else "adb"
    for candidate in (PROJECT_DIR / "platform-tools" / exe,
                      PROJECT_DIR.parent / "platform-tools" / exe,
                      tools_dir() / exe):
        if candidate.is_file():
            return str(candidate)
    path = shutil.which("adb")
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


def safe_serial(serial: str) -> str:
    """Device serial as a safe file-name part. The serial comes from the device itself, so a manipulated
    phone could send '../../' or wildcard characters; only letters, digits, '.', '_' and '-' survive."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", serial).lstrip(".")
    return cleaned[:64] or "unbekannt"


def adb_command() -> list[str]:
    """The adb call as argument list. A FAMCHECK_ADB ending in .py (the test double) runs with this Python,
    because Windows cannot start .py files directly."""
    path = adb_binary()
    return [sys.executable, path] if path.endswith(".py") else [path]


def list_devices() -> list[dict]:
    """Returns connected devices as [{'serial':..., 'state':..., 'model':...}]."""
    out = subprocess.run(
        [*adb_command(), "devices", "-l"], capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=30
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
            return subprocess.run([*adb_command(), "-s", serial, "shell", cmd], capture_output=True,
                                  text=True, encoding="utf-8", errors="replace", timeout=20).stdout
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
        self.timeouts: list[str] = []  # commands that did not answer in time (plausibility check)
        with open(self.manifest_path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["nr", "zeit_utc", "befehl", "exit_code", "datei", "sha256", "hinweis"])

    def shell(self, command: str, timeout: int = 120, redact=None) -> str:
        """redact: optional function bytes -> bytes applied BEFORE storing and hashing (e.g. remove e-mails)."""
        self._counter += 1
        try:
            proc = subprocess.run(
                [*adb_command(), "-s", self.serial, "shell", command],
                capture_output=True, timeout=timeout,
            )
            output, rc = proc.stdout + proc.stderr, proc.returncode
        except subprocess.TimeoutExpired:
            output, rc = b"<TIMEOUT>", -1
            self.timeouts.append(command)

        note = ""
        if redact:
            output, note = redact(output), "geschwärzt"
        slug = re.sub(r"[^A-Za-z0-9]+", "_", command)[:60].strip("_")
        filename = f"{self._counter:03d}_{slug}.txt"
        (self.raw_dir / filename).write_bytes(output)
        with open(self.manifest_path, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                self._counter,
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                command, rc, f"raw/{filename}",
                hashlib.sha256(output).hexdigest(), note,
            ])
        # Old adb shell (Android < 7) and Windows tools send \r\n; parsers expect \n. Raw file stays byte-exact.
        return output.decode("utf-8", errors="replace").replace("\r\n", "\n")

    def pull_fingerprints(self, remote: str, max_bytes: int = 300 * 1024 * 1024) -> dict:
        """Pulls one APK into a temp folder, fingerprints it (hash + signing cert) and deletes it again.

        The APK itself is never kept: it may be malware, and antivirus software on the PC may react to it.
        The manifest records the pull with the file's SHA-256.
        """
        from .apk import fingerprints

        size = self.shell(f"stat -c %s {shlex.quote(remote)}").strip()
        if size.isdigit() and int(size) > max_bytes:  # never copy what is too big (disk filling device)
            return {"path": remote, "error": f"zu groß ({int(size) // 1048576} MB), nicht kopiert"}
        self._counter += 1
        result: dict = {"path": remote}
        rc, digest = -1, ""
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / "app.apk"
            try:
                proc = subprocess.run([*adb_command(), "-s", self.serial, "pull", remote, str(local)],
                                      capture_output=True, timeout=600)
                rc = proc.returncode
                if rc != 0 or not local.exists():
                    result["error"] = "Kopieren fehlgeschlagen: " + proc.stderr.decode("utf-8", "replace").strip()[:200]
                elif local.stat().st_size > max_bytes:
                    result["error"] = f"zu groß ({local.stat().st_size // 1048576} MB), übersprungen"
                else:
                    result["size"] = local.stat().st_size
                    result.update(fingerprints(local))
                    digest = result["sha256"]
            except subprocess.TimeoutExpired:
                result["error"] = "Zeitüberschreitung beim Kopieren"
            except OSError as e:  # e.g. antivirus removed the file right after the pull
                result["error"] = f"Datei nicht lesbar (Virenschutz?): {e}"
        with open(self.manifest_path, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                self._counter, datetime.now(timezone.utc).isoformat(timespec="seconds"),
                f"pull {remote}", rc, "(APK nicht gespeichert)", digest,
                result.get("error", "nur Hash und Zertifikat ausgewertet"),
            ])
        return result
