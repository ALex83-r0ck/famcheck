"""What the scan in this process is doing right now, for the live box in the dashboard.

Only scans that run in the same process as the dashboard show up here: 'watch' (dashboard and scans together)
and the "Jetzt scannen" button. A scan started in a second terminal is not visible live; its result still
appears in the dashboard when it is finished. The box only shows text, nothing in it can be typed or run.
"""

import threading
from datetime import datetime, timezone

MAX_LINES = 200


class Live:
    def __init__(self):
        self._lock = threading.Lock()
        # Held for the whole scan. Two scans at once would compete for adb and the phone.
        self.scan_lock = threading.Lock()
        self._state = {"id": 0, "running": False, "serial": None, "label": None, "lines": [],
                       "started": None, "finished": None, "error": None}

    def begin(self, serial: str, label: str) -> None:
        with self._lock:
            self._state = {"id": self._state["id"] + 1, "running": True, "serial": serial, "label": label,
                           "lines": [], "started": _now(), "finished": None, "error": None}

    def line(self, text: str) -> None:
        with self._lock:
            lines = self._state["lines"]
            lines.append(text)
            del lines[:-MAX_LINES]

    def end(self, error: str | None = None) -> None:
        with self._lock:
            self._state.update(running=False, finished=_now(), error=error)

    def snapshot(self) -> dict:
        with self._lock:
            return {**self._state, "lines": list(self._state["lines"])}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


LIVE = Live()
