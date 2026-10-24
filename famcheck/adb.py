"""Read-only ADB access. Every command output is stored with its SHA-256 hash."""

import csv
import hashlib
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


class AdbError(RuntimeError):
    pass


def adb_binary() -> str:
    path = os.environ.get("FAMCHECK_ADB") or shutil.which("adb")
    if not path:
        raise AdbError(
            "adb nicht gefunden. Installiere die Android Platform-Tools "
            "und sorge dafür, dass 'adb' im PATH liegt (oder setze FAMCHECK_ADB)."
        )
    return path


def list_devices() -> list[dict]:
    """Returns connected devices as [{'serial':..., 'state':..., 'model':...}]."""
    out = subprocess.run(
        [adb_binary(), "devices", "-l"], capture_output=True, text=True, timeout=30
    ).stdout
    devices = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        model = next((p.split(":", 1)[1] for p in parts if p.startswith("model:")), "")
        devices.append({"serial": parts[0], "state": parts[1], "model": model})
    return devices


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
