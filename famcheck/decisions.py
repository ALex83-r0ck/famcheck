"""Triage of findings: the user marks a finding as known/okay, fixed, or to keep watching.

Decisions live next to the scans (cases/decisions.json, never in the repo). Every change is also
appended to cases/decisions_log.jsonl, so it stays traceable who accepted what and when.
Nothing here touches the phone.
"""

import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

STATUSES = {"ok": "Bekannt, in Ordnung", "done": "Erledigt", "watch": "Beobachten"}
SEVERITY_RANK = {"KRITISCH": 0, "HOCH": 1, "MITTEL": 2, "NIEDRIG": 3, "INFO": 4}
MAX_NOTE = 500

_lock = threading.Lock()


def finding_key(finding: dict) -> str:
    """Stable identity of a finding across scans (the title names the problem and the app)."""
    return finding["title"]


def fingerprint(finding: dict) -> str:
    """Changes when the substance of a finding changes, e.g. new permissions in the detail text.
    Digits are ignored so that changing amounts (MB uploaded, months since patch) don't count."""
    text = re.sub(r"\d+", "#", finding["detail"])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _paths(cases_root: Path) -> tuple[Path, Path]:
    return cases_root / "decisions.json", cases_root / "decisions_log.jsonl"


def load(cases_root: Path) -> dict:
    """{serial: {finding_key: decision}}"""
    path, _ = _paths(cases_root)
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def record(cases_root: Path, serial: str, finding: dict, status: str, note: str = "") -> dict | None:
    """Stores a decision ('reset' removes it). Returns the stored decision or None."""
    if status not in STATUSES and status != "reset":
        raise ValueError(f"unbekannter Status: {status}")
    note = note.strip()[:MAX_NOTE]
    key = finding_key(finding)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    decision = None if status == "reset" else {
        "status": status, "note": note, "at": now,
        "severity": finding["severity"], "fingerprint": fingerprint(finding),
    }
    path, log_path = _paths(cases_root)
    with _lock:
        data = load(cases_root)
        if decision:
            data.setdefault(serial, {})[key] = decision
        else:
            data.get(serial, {}).pop(key, None)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)  # atomic: a crash never leaves a half-written file
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"at": now, "serial": serial, "finding": key, "severity": finding["severity"],
                                "status": status, "note": note}, ensure_ascii=False) + "\n")
    return decision


def evaluate(finding: dict, decision: dict | None, scan_started: str) -> str:
    """How a decision applies to this finding in this scan.

    'none'       no decision
    'suppressed' accepted or fixed, does not count
    'watch'      still counts, marked for observation
    'changed'    finding got worse or different since the decision, counts again
    'reopened'   marked as fixed, but a later scan still finds it, counts again
    """
    if not decision:
        return "none"
    worse = SEVERITY_RANK[finding["severity"]] < SEVERITY_RANK.get(decision["severity"], 4)
    if worse or fingerprint(finding) != decision["fingerprint"]:
        return "changed"
    if decision["status"] == "watch":
        return "watch"
    if decision["status"] == "done" and scan_started > decision["at"]:
        return "reopened"
    return "suppressed"


def annotate(findings: list[dict], device_decisions: dict, scan_started: str) -> list[dict]:
    """Copies of the findings with 'decision' and 'decision_state' added."""
    out = []
    for f in findings:
        d = device_decisions.get(finding_key(f))
        out.append({**f, "decision": d, "decision_state": evaluate(f, d, scan_started)})
    return out


def counting(findings: list[dict]) -> list[dict]:
    """The annotated findings that still count for the traffic light."""
    return [f for f in findings if f.get("decision_state") != "suppressed"]
