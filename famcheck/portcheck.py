"""When the dashboard port is taken: find out whether an older FamCheck holds it and offer to stop it.

Only a process that answers like the FamCheck dashboard AND is a Python process is offered for stopping,
and only after a [j/N] question in the terminal. Anything else keeps the old message with the manual steps.
"""

import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

FAMCHECK_MARK = "FamCheck – Anmeldung nötig"  # title of the page every FamCheck dashboard shows without login


def famcheck_on_port(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3) as r:
            body = r.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:  # without the login cookie FamCheck answers 401
        body = e.read(4096).decode("utf-8", "replace")
    except Exception:
        return False
    return FAMCHECK_MARK in body


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=10).stdout
    except Exception:
        return ""


def listening_pid(port: int) -> int | None:
    if sys.platform == "win32":
        # "  TCP    127.0.0.1:8765    0.0.0.0:0    LISTENING    36036"; the state is translated
        # ("ABHÖREN" on German Windows), so it is recognised by the empty remote address instead
        for line in _run(["netstat", "-ano", "-p", "TCP"]).splitlines():
            parts = line.split()
            if len(parts) == 5 and parts[1].endswith(f":{port}") and parts[2] in ("0.0.0.0:0", "[::]:0") \
                    and parts[4].isdigit():
                return int(parts[4])
        return None
    out = _run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"]).split()
    if out and out[0].isdigit():
        return int(out[0])
    m = re.search(r"pid=(\d+)", _run(["ss", "-ltnpH", f"sport = :{port}"]))
    return int(m.group(1)) if m else None


def is_python(pid: int) -> bool:
    if sys.platform == "win32":
        name = _run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"]).split(",")[0].strip('"').lower()
        return name.startswith("python")
    try:
        with open(f"/proc/{pid}/comm", encoding="utf-8") as f:
            return f.read().strip().startswith("python")
    except OSError:
        return "python" in _run(["ps", "-p", str(pid), "-o", "comm="]).lower()


def stop(pid: int) -> None:
    if sys.platform == "win32":
        _run(["taskkill", "/PID", str(pid), "/F"])
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass


def offer_to_stop(port: int, ask, print_fn=print, wait: float = 10.0) -> bool:
    """True if an old FamCheck was stopped and the port is free again."""
    if not famcheck_on_port(port):
        print_fn(f"Port {port} ist von einem anderen Programm belegt (kein FamCheck), das bleibt unangetastet.")
        return False
    pid = listening_pid(port)
    if not pid or pid == os.getpid() or not is_python(pid):
        return False
    answer = ask(f"Auf Port {port} läuft noch ein älteres FamCheck-Dashboard (Prozess {pid}). Läuft dort gerade "
                 f"ein Scan, wird er abgebrochen. Beenden und hier neu starten? [j/N] ")
    if answer.strip().lower() not in ("j", "ja", "y", "yes"):
        return False
    stop(pid)
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if listening_pid(port) is None:
            print_fn(f"Altes FamCheck (Prozess {pid}) beendet.")
            return True
        time.sleep(0.2)
    print_fn(f"Prozess {pid} hat sich nicht beendet.")
    return False
