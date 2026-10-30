"""Collects security-relevant state from the device. Only reads, never changes anything."""

import re
import shlex
import time

from .adb import RecordingAdb
from .analyze import TRUSTED_STORES, app_readable

# App-ops that matter for malware; read per app via "appops get".
WATCHED_APPOPS = ["SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "MANAGE_EXTERNAL_STORAGE"]

PROPS = [
    "ro.product.manufacturer", "ro.product.model", "ro.build.version.release",
    "ro.build.version.sdk", "ro.build.version.security_patch", "ro.build.fingerprint",
    "ro.boot.verifiedbootstate", "ro.boot.flash.locked", "ro.debuggable", "ro.serialno",
]

SETTINGS = [
    ("global", "adb_enabled"),
    ("global", "adb_wifi_enabled"),
    ("global", "development_settings_enabled"),
    ("global", "http_proxy"),
    ("global", "package_verifier_enable"),
    ("secure", "install_non_market_apps"),
    ("secure", "enabled_accessibility_services"),
    ("secure", "enabled_notification_listeners"),
    ("secure", "always_on_vpn_app"),
    ("secure", "sms_default_application"),
    ("global", "private_dns_mode"),
    ("global", "private_dns_specifier"),
    ("global", "package_verifier_user_consent"),
    ("global", "verifier_verify_adb_installs"),
]


def _components(value: str) -> list[str]:
    """'pkg/.Cls:pkg2/.Cls2' -> ['pkg', 'pkg2']"""
    if not value or value.strip() in ("null", ""):
        return []
    return sorted({c.split("/")[0] for c in value.strip().split(":") if "/" in c})


def _parse_package_list(out: str) -> dict[str, dict]:
    # package:com.foo installer=com.android.vending uid:10234
    pkgs = {}
    for line in out.splitlines():
        m = re.match(r"package:(\S+)(?:\s+installer=(\S+))?(?:\s+uid:(\d+))?", line.strip())
        if m:
            installer = m.group(2)
            pkgs[m.group(1)] = {"installer": None if installer in (None, "null") else installer,
                                "uid": int(m.group(3)) if m.group(3) else None}
    return pkgs


def _parse_dumpsys_package(out: str) -> dict:
    info = {"granted": [], "requested": [], "version": None,
            "first_install": None, "last_update": None}
    section = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("requested permissions:"):
            section = "requested"
            continue
        if s.startswith(("install permissions:", "runtime permissions:")):
            section = "granted"
            continue
        if section == "requested":
            m = re.match(r"^[a-z]\w*(?:\.\w+)+", s)
            if m:
                info["requested"].append(m.group(0))
                continue
        if section == "granted" and "granted=true" in s:
            info["granted"].append(s.split(":")[0])
            continue
        if s and not s.startswith(("android.", "com.")) and ":" in s:
            section = None
        for key, field in (("versionName=", "version"), ("firstInstallTime=", "first_install"),
                           ("lastUpdateTime=", "last_update")):
            if s.startswith(key) and info[field] is None:
                info[field] = s.split("=", 1)[1]
    info["granted"] = sorted(set(info["granted"]))
    info["requested"] = sorted(set(info["requested"]))
    return info


def _read_package(adb: RecordingAdb, pkg: str) -> dict:
    """dumpsys package for one app. A real answer always names the package; anything else is an error
    message (seen on a real device: 39 bytes instead of 20-40 KB). Try once more, then mark it unreadable
    instead of passing it off as "app without permissions"."""
    for attempt in range(2):
        out = adb.shell(f"dumpsys package {pkg}")
        if f"Package [{pkg}]" in out:
            return {**_parse_dumpsys_package(out), "dump_ok": True}
        if attempt == 0:
            time.sleep(1)
    return {**_parse_dumpsys_package(""), "dump_ok": False, "dump_error": out.strip()[:200]}


def _parse_device_admins(out: str) -> list[str]:
    admins = set(re.findall(r"ComponentInfo\{([^/}]+)/", out))
    in_section = False
    for line in out.splitlines():
        if "Enabled Device Admins" in line:
            in_section = True
            continue
        if in_section:
            m = re.match(r"^\s+([\w.]+)/[\w.$]+:?\s*$", line)
            if m:
                admins.add(m.group(1))
            elif line.strip() and not line.startswith(" " * 4):
                in_section = False
    return sorted(admins)


def _parse_owners(out: str) -> tuple[str | None, list[str]]:
    """Device owner package and profile owner packages (work profiles) from 'dumpsys device_policy'."""
    device_owner, profile_owners = None, []
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if re.match(r"\s*(Device Owner|Profile Owner)", line):
            for nxt in lines[i:i + 6]:
                m = re.search(r"ComponentInfo\{([^/}]+)/", nxt) or re.search(r"package=([\w.]+)", nxt)
                if m:
                    if "Device Owner" in line:
                        device_owner = m.group(1)
                    else:
                        profile_owners.append(m.group(1))
                    break
    return device_owner, sorted(set(profile_owners))


def _redact_accounts(raw: bytes) -> bytes:
    """Keeps account types, removes account names (e-mail addresses) before anything is stored."""
    return re.sub(rb"name=[^,}\n]*", b"name=<entfernt>", raw)


def _parse_accounts(out: str) -> dict[str, int]:
    """'Account {name=..., type=com.google}' -> {'com.google': n}. Only the first block (current accounts)."""
    counts: dict[str, int] = {}
    block = out.split("\n\n")[0] if "Accounts:" in out else out
    for account_type in re.findall(r"Account \{name=[^,}]*, type=([\w.]+)\}", block):
        counts[account_type] = counts.get(account_type, 0) + 1
    return counts


def _parse_lock_credential(out: str) -> str | None:
    """'CredentialType: PIN' from 'dumpsys lock_settings' (Android 11+). None if unknown."""
    m = re.search(r"CredentialType:\s*(\w+)", out)
    return m.group(1).upper() if m else None


def _parse_battery_exempt(out: str) -> list[str]:
    """User-added entries ('user,com.foo,10123') from 'dumpsys deviceidle whitelist'."""
    return sorted({m.group(1) for m in re.finditer(r"^user,([\w.]+),", out, re.M)})


def _parse_appops(out: str) -> list[str]:
    allowed = set()
    for line in out.splitlines():
        m = re.match(r"\s*(?:Uid mode: )?([A-Z_]+): (allow|foreground)", line)
        if m and m.group(1) in WATCHED_APPOPS:
            allowed.add(m.group(1))
    return sorted(allowed)


def _parse_netstats(out: str, now: float) -> tuple[dict[int, dict], float | None]:
    """Uploaded bytes per uid from 'dumpsys netstats detail'.

    Returns ({uid: {'tx': total, 'tx_bg': background}}, covered_days). Only tag=0x0 lines count,
    tagged lines are subsets of them. set=DEFAULT means the app was in the background.
    """
    per_uid: dict[int, dict] = {}
    current = None
    oldest = None
    for line in out.splitlines():
        if "ident=" in line or re.search(r"\buid=-?\d+\s+set=", line):
            m = re.search(r"\buid=(-?\d+)\s+set=(\w+)\s+tag=(0x[0-9a-fA-F]+)", line)
            current = (int(m.group(1)), m.group(2)) if m and int(m.group(3), 16) == 0 else None
            continue
        if current is None:
            continue
        m = re.search(r"\bst=(\d+)\b.*?\btb=(\d+)", line)
        if m:
            start, tx = int(m.group(1)), int(m.group(2))
            oldest = start if oldest is None else min(oldest, start)
            entry = per_uid.setdefault(current[0], {"tx": 0, "tx_bg": 0})
            entry["tx"] += tx
            if current[1] == "DEFAULT":
                entry["tx_bg"] += tx
    days = round((now - oldest) / 86400, 1) if oldest else None
    return per_uid, days


def _parse_vpn_owner_uids(out: str) -> list[int]:
    """Owner uids of active VPN networks from 'dumpsys connectivity'."""
    uids = set()
    for line in out.splitlines():
        if re.search(r"Transports: ?[A-Z_|]*VPN", line) or "ni{VPN" in line:
            m = re.search(r"Owner ?Uid: ?(\d+)", line, re.I)
            if m:
                uids.add(int(m.group(1)))
    return sorted(uids)


def _apk_paths(out: str) -> list[str]:
    return [line.split(":", 1)[1].strip() for line in out.splitlines() if line.startswith("package:")]


def _hash_on_device(adb: RecordingAdb, pkg: str) -> list[dict]:
    """SHA-256 of an app's files, computed by the phone itself: nothing is copied to the PC.
    Store apps are not pulled, but droppers (e.g. fake PDF readers and QR scanners) come from stores."""
    out = adb.shell(f'for f in $(pm path {shlex.quote(pkg)} | cut -d: -f2); do sha256sum "$f"; done')
    return [{"path": m.group(2), "sha256": m.group(1)}
            for m in re.finditer(r"^([0-9a-f]{64})\s+(/\S+)$", out, re.M)]


def collect(adb: RecordingAdb, log, check_apks: bool = True) -> dict:
    data = {"props": {}, "settings": {}}

    log("Lese Geräteeigenschaften ...")
    for prop in PROPS:
        data["props"][prop] = adb.shell(f"getprop {prop}").strip()

    log("Lese Einstellungen ...")
    for ns, key in SETTINGS:
        data["settings"][key] = adb.shell(f"settings get {ns} {key}").strip()

    data["accessibility"] = _components(data["settings"]["enabled_accessibility_services"])
    data["notification_listeners"] = _components(data["settings"]["enabled_notification_listeners"])

    log("Prüfe auf Root ...")
    data["su_present"] = bool(adb.shell("command -v su || which su").strip())

    log("Lese Geräteverwaltung ...")
    policy = adb.shell("dumpsys device_policy")
    coverage = {"device_policy": "Device Policy" in policy}
    data["device_admins"] = _parse_device_admins(policy)
    data["device_owner"], data["profile_owners"] = _parse_owners(policy)

    log("Lese Displaysperre, Konten, Akku-Ausnahmen ...")
    data["lock_credential"] = _parse_lock_credential(adb.shell("dumpsys lock_settings"))
    accounts_out = adb.shell("dumpsys account", redact=_redact_accounts)
    data["accounts"] = _parse_accounts(accounts_out)
    coverage["accounts"] = "Accounts:" in accounts_out or "Account {" in accounts_out
    data["battery_exempt"] = _parse_battery_exempt(adb.shell("dumpsys deviceidle whitelist"))
    sms = data["settings"].get("sms_default_application", "")
    data["sms_default"] = sms if sms and sms != "null" else None

    log("Lese Paketlisten ...")
    # "-U" (uid) needs Android 8+; fall back to the plain list on older devices
    all_packages = (_parse_package_list(adb.shell("pm list packages -U"))
                    or _parse_package_list(adb.shell("pm list packages")))
    data["all_packages"] = sorted(all_packages)
    third_party = _parse_package_list(adb.shell("pm list packages -3 -i -U"))

    launcher_out = adb.shell(
        "cmd package query-activities --brief -a android.intent.action.MAIN "
        "-c android.intent.category.LAUNCHER"
    )
    launcher = set(re.findall(r"^\s*([\w.]+)/", launcher_out, re.M))
    data["launcher_query_ok"] = bool(launcher)

    uid_names: dict[int, list[str]] = {}
    for pkg, meta in all_packages.items():
        if meta["uid"] is not None:
            uid_names.setdefault(meta["uid"], []).append(pkg)

    log(f"Analysiere {len(third_party)} installierte Apps ...")
    for pkg, meta in third_party.items():
        meta.update(_read_package(adb, pkg))
        meta["has_launcher_icon"] = pkg in launcher if launcher else None
        meta["appops"] = _parse_appops(adb.shell(f"appops get {pkg}"))
    data["apps"] = third_party

    if check_apks:
        unknown_source = [p for p, m in third_party.items() if m["installer"] not in TRUSTED_STORES]
        if unknown_source:
            log(f"Prüfe {len(unknown_source)} App-Datei(en) aus fremder Quelle (Hash + Signatur) ...")
        for pkg in unknown_source:
            files = [adb.pull_fingerprints(path) for path in _apk_paths(adb.shell(f"pm path {pkg}"))]
            base = next((f for f in files if f["path"].endswith("/base.apk")), files[0] if files else {})
            third_party[pkg]["apk"] = {"files": files, "cert_sha1": base.get("cert_sha1"),
                                       "cert_sha256": base.get("cert_sha256")}

        store_apps = [p for p in third_party if p not in unknown_source]
        if store_apps:
            log(f"Berechne Fingerabdrücke von {len(store_apps)} Store-App(s) auf dem Handy ...")
        for pkg in store_apps:
            if files := _hash_on_device(adb, pkg):
                third_party[pkg]["apk"] = {"files": files, "cert_sha1": None, "cert_sha256": None, "on_device": True}
        hashed_store_apps = sum(1 for p in store_apps if "apk" in third_party[p])

    log("Lese aktive VPN-Verbindungen ...")
    vpn_uids = _parse_vpn_owner_uids(adb.shell("dumpsys connectivity"))
    data["active_vpn"] = sorted({p for uid in vpn_uids for p in uid_names.get(uid, [f"uid {uid}"])})

    log("Lese Datenverbrauch (Uploads) ...")
    per_uid, days = _parse_netstats(adb.shell("dumpsys netstats detail", timeout=180), time.time())
    data["uploads"] = sorted(
        ({"uid": uid, "packages": sorted(uid_names.get(uid, [f"uid {uid}"])), **v}
         for uid, v in per_uid.items() if v["tx"] > 0 and uid != -1),  # -1 = sum over all apps
        key=lambda e: e["tx"], reverse=True)
    data["uploads_days"] = days

    # What could actually be read. analyze() turns gaps into findings, so a scan that read nothing
    # never looks like "Alles in Ordnung".
    data["coverage"] = {
        **coverage,
        "props": bool(data["props"].get("ro.product.model") or data["props"].get("ro.build.version.release")),
        "packages": len(all_packages),
        "apps": len(third_party),
        "apps_with_permissions": sum(1 for m in third_party.values() if m["requested"] or m["granted"]),
        "apps_unreadable": sorted(p for p, m in third_party.items() if not app_readable(m)),
        "launcher": data["launcher_query_ok"],
        "netstats": bool(per_uid),
        "lock_settings": data["lock_credential"] is not None,
        "timeouts": list(adb.timeouts),
    }
    if check_apks:
        data["coverage"].update(store_apps=len(store_apps), store_apps_hashed=hashed_store_apps)
    return data
