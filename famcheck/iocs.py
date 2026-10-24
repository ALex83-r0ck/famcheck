"""Indicator database: package names, signing certificates and APK hashes of known spy-/stalkerware.

Built from the Echap stalkerware list and all MVT indicator collections, stored as one JSON file
so that scanning works offline and does not need pyyaml.
"""

import hashlib
import json
import os
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
DEFAULT_PATH = DATA_DIR / "iocs.json"

ECHAP_URL = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
MVT_INDEX_URL = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"

# STIX pattern keys -> our tables
STIX_KEYS = {"app:id": "packages", "app:cert.sha1": "cert_sha1",
             "app:cert.sha256": "cert_sha256", "file:hashes.sha256": "sha256"}
TABLES = ("packages", "cert_sha1", "cert_sha256", "sha256")


def ioc_path() -> Path:
    return Path(os.environ.get("FAMCHECK_IOCS") or DEFAULT_PATH)


def load() -> dict:
    """Returns {'packages': {name: family}, 'cert_sha1': {...}, 'cert_sha256': {...}, 'sha256': {...}, 'meta': {...}}.
    Empty tables if no database exists."""
    path = ioc_path()
    if not path.exists():
        return {t: {} for t in TABLES} | {"meta": {}}
    db = json.loads(path.read_text(encoding="utf-8"))
    for t in TABLES:
        db.setdefault(t, {})
    return db


def file_sha256() -> str:
    path = ioc_path()
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "keine-ioc-liste"


def _norm(table: str, value: str) -> str:
    value = value.strip()
    return value if table == "packages" else value.replace(":", "").lower()


def add_echap(db: dict, entries: list[dict]) -> int:
    n = 0
    for e in entries or []:
        name = e.get("name", "Stalkerware")
        for pkg in e.get("packages") or []:
            db["packages"].setdefault(_norm("packages", pkg), f"{name} (Stalkerware)")
            n += 1
        for cert in e.get("certificates") or []:
            db["cert_sha1"].setdefault(_norm("cert_sha1", cert), f"{name} (Stalkerware)")
            n += 1
    return n


def add_stix(db: dict, collection: str, bundle: dict) -> int:
    """Adds all Android-relevant indicators of one STIX2 bundle.

    The family name comes from the 'malware' object an indicator points to; otherwise the collection name.
    """
    objects = bundle.get("objects", [])
    malware = {o["id"]: o.get("name") for o in objects if o.get("type") == "malware"}
    family = {}
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "indicates":
            if o.get("target_ref") in malware:
                family[o.get("source_ref")] = malware[o["target_ref"]]
    n = 0
    for o in objects:
        if o.get("type") != "indicator":
            continue
        name = family.get(o["id"]) or collection
        for key, value in re.findall(r"\[([\w:.\-]+)\s*=\s*'([^']+)'\]", o.get("pattern", "")):
            table = STIX_KEYS.get(key)
            if table:
                db[table].setdefault(_norm(table, value), name)
                n += 1
    return n


def _fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as resp:
        return resp.read()


def update(log=print) -> Path:
    """Downloads Echap + all MVT collections and writes the database. Needs pyyaml."""
    try:
        import yaml
    except ModuleNotFoundError:
        raise SystemExit("Paket 'pyyaml' fehlt. Installieren mit: pip install -r requirements.txt")

    db = {t: {} for t in TABLES}
    sources = []

    def record(name, url, content, count):
        sources.append({"name": name, "url": url, "sha256": hashlib.sha256(content).hexdigest(), "indicators": count})
        log(f"  {count:5d}  {name}")

    content = _fetch(ECHAP_URL)
    record("Echap Stalkerware Indicators", ECHAP_URL, content, add_echap(db, yaml.safe_load(content)))

    index = _fetch(MVT_INDEX_URL)
    for entry in yaml.safe_load(index).get("indicators", []):
        gh = entry.get("github")
        if entry.get("type") != "github" or not gh:
            continue
        url = f"https://raw.githubusercontent.com/{gh['owner']}/{gh['repo']}/{gh['branch']}/{gh['path']}"
        try:
            content = _fetch(url)
            count = add_stix(db, entry["name"].replace(" Indicators of Compromise", ""), json.loads(content))
        except Exception as e:  # one broken collection must not stop the update
            log(f"  ! {entry.get('name')}: {e}")
            continue
        if count:
            record(entry["name"], url, content, count)

    db["meta"] = {"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "sources": sources}
    path = ioc_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(db, indent=0, sort_keys=True, ensure_ascii=False), encoding="utf-8")
    log("  " + ", ".join(f"{len(db[t])} {t}" for t in TABLES))
    return path
