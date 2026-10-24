"""Collects security-relevant state from the device. Only reads, never changes anything."""

import re

from .adb import RecordingAdb

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
            pkgs[m.group(1)] = {"installer": None if installer in (None, "null") else installer}
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


def collect(adb: RecordingAdb, log) -> dict:
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

    log("Lese Geräteadministratoren ...")
    data["device_admins"] = _parse_device_admins(adb.shell("dumpsys device_policy"))

    log("Lese Paketlisten ...")
    data["all_packages"] = sorted(_parse_package_list(adb.shell("pm list packages")))
    third_party = _parse_package_list(adb.shell("pm list packages -3 -i -U"))

    launcher_out = adb.shell(
        "cmd package query-activities --brief -a android.intent.action.MAIN "
        "-c android.intent.category.LAUNCHER"
    )
    launcher = set(re.findall(r"^\s*([\w.]+)/", launcher_out, re.M))
    data["launcher_query_ok"] = bool(launcher)

    log(f"Analysiere {len(third_party)} installierte Apps ...")
    for pkg, meta in third_party.items():
        meta.update(_parse_dumpsys_package(adb.shell(f"dumpsys package {pkg}")))
        meta["has_launcher_icon"] = pkg in launcher if launcher else None
    data["apps"] = third_party
    return data
