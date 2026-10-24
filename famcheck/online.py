"""Optional online check of APK hashes against MalwareBazaar (abuse.ch).

Only SHA-256 hashes leave the PC, never the APK or anything else about the device.
Needs a free Auth-Key from https://auth.abuse.ch/ in the environment variable FAMCHECK_ABUSECH_KEY.
"""

import json
import os
import urllib.parse
import urllib.request

API_URL = "https://mb-api.abuse.ch/api/v1/"


def api_key() -> str | None:
    return os.environ.get("FAMCHECK_ABUSECH_KEY") or None


def lookup(sha256: str, key: str) -> dict:
    """{'status': 'found'|'not_found'|'error', 'signature': ..., 'tags': [...], 'detail': ...}"""
    url = os.environ.get("FAMCHECK_MB_URL", API_URL)
    body = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
    req = urllib.request.Request(url, data=body, headers={"Auth-Key": key, "User-Agent": "FamCheck"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            answer = json.loads(resp.read())
    except Exception as e:
        return {"status": "error", "detail": str(e)[:200]}
    status = answer.get("query_status")
    if status == "ok" and answer.get("data"):
        entry = answer["data"][0]
        return {"status": "found", "signature": entry.get("signature") or "unbekannt",
                "tags": entry.get("tags") or []}
    if status in ("hash_not_found", "no_results"):
        return {"status": "not_found"}
    return {"status": "error", "detail": str(status)}


def check_apps(data: dict, key: str, log) -> None:
    """Adds a 'malwarebazaar' result to every fingerprinted APK file in data['apps']."""
    for pkg, app in data["apps"].items():
        for f in (app.get("apk") or {}).get("files", []):
            if f.get("sha256"):
                log(f"MalwareBazaar-Abfrage (nur Hash) für {pkg}: {f['sha256']}")
                f["malwarebazaar"] = lookup(f["sha256"], key)
