"""Turns collected device data into findings. Heuristics, not proof: every finding needs a human look."""

from datetime import date
from pathlib import Path

import yaml

IOC_PATH = Path(__file__).parent / "data" / "ioc.yaml"

TRUSTED_STORES = {
    "com.android.vending": "Google Play",
    "com.sec.android.app.samsungapps": "Galaxy Store",
    "com.huawei.appmarket": "Huawei AppGallery",
    "com.xiaomi.market": "Xiaomi GetApps",
    "com.heytap.market": "Oppo/OnePlus Store",
    "com.oppo.market": "Oppo Store",
    "com.amazon.venezia": "Amazon Appstore",
}

# Permissions that let an app see or record private data.
SENSITIVE = {
    "android.permission.CAMERA": "Kamera",
    "android.permission.RECORD_AUDIO": "Mikrofon",
    "android.permission.ACCESS_FINE_LOCATION": "Genauer Standort",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Standort im Hintergrund",
    "android.permission.READ_SMS": "SMS lesen",
    "android.permission.RECEIVE_SMS": "SMS empfangen",
    "android.permission.READ_CALL_LOG": "Anrufliste",
    "android.permission.READ_CONTACTS": "Kontakte",
    "android.permission.READ_EXTERNAL_STORAGE": "Speicher/Fotos",
    "android.permission.READ_MEDIA_IMAGES": "Fotos",
    "android.permission.READ_MEDIA_VIDEO": "Videos",
    "android.permission.PROCESS_OUTGOING_CALLS": "Ausgehende Anrufe",
}

ORDER = {"KRITISCH": 0, "HOCH": 1, "MITTEL": 2, "NIEDRIG": 3, "INFO": 4}


def load_ioc() -> dict[str, str]:
    """package name -> spyware family name"""
    if not IOC_PATH.exists():
        return {}
    entries = yaml.safe_load(IOC_PATH.read_text(encoding="utf-8")) or []
    return {pkg: e["name"] for e in entries for pkg in e.get("packages") or []}


def _finding(sev, title, detail, action, pkg=None):
    return {"severity": sev, "title": title, "detail": detail, "action": action, "package": pkg}


def analyze(data: dict, today: date | None = None) -> list[dict]:
    today = today or date.today()
    findings = []
    props, settings, apps = data["props"], data["settings"], data["apps"]
    ioc = load_ioc()

    # --- Known stalkerware ---------------------------------------------------
    for pkg in data["all_packages"]:
        if pkg in ioc:
            findings.append(_finding(
                "KRITISCH", f"Bekannte Stalkerware: {ioc[pkg]}",
                f"Das Paket {pkg} steht auf der Stalkerware-Indikatorliste (Echap).",
                "NICHT sofort löschen: Wer sie installiert hat, merkt das evtl. "
                "Erst Ergebnis sichern, Sicherheit der Person klären, dann Hilfe holen "
                "(z. B. Hilfetelefon 116 016 bei häuslicher Gewalt).", pkg))

    # --- Device integrity ----------------------------------------------------
    if props.get("ro.boot.verifiedbootstate") in ("orange", "yellow", "red"):
        findings.append(_finding(
            "HOCH", "Bootloader entsperrt / Verified Boot verletzt",
            f"verifiedbootstate = {props['ro.boot.verifiedbootstate']}. "
            "Damit lässt sich das System selbst manipulieren.",
            "Wenn das niemand bewusst gemacht hat: ernstes Warnsignal."))
    if data.get("su_present"):
        findings.append(_finding(
            "HOCH", "Gerät ist gerootet (su gefunden)",
            "Mit Root kann sich Spyware tief im System verstecken.",
            "Klären, wer das Gerät gerootet hat."))

    patch = props.get("ro.build.version.security_patch", "")
    try:
        age_days = (today - date.fromisoformat(patch)).days
        if age_days > 365:
            findings.append(_finding(
                "MITTEL", "Sicherheitsupdates veraltet",
                f"Letzter Sicherheitspatch: {patch} ({age_days // 30} Monate alt).",
                "Updates installieren. Bekommt das Gerät keine mehr, Ersatz einplanen."))
        elif age_days > 120:
            findings.append(_finding(
                "NIEDRIG", "Sicherheitspatch nicht aktuell",
                f"Letzter Sicherheitspatch: {patch}.", "Nach Systemupdates suchen."))
    except ValueError:
        pass

    # --- Settings ------------------------------------------------------------
    if settings.get("adb_wifi_enabled") == "1":
        findings.append(_finding(
            "MITTEL", "Kabelloses Debugging ist an",
            "Das Gerät ist im WLAN per ADB erreichbar.",
            "Entwickleroptionen → Kabelloses Debugging ausschalten."))
    if settings.get("adb_enabled") == "1":
        findings.append(_finding(
            "NIEDRIG", "USB-Debugging ist an",
            "Wer das entsperrte Handy kurz in der Hand hat, kann per Kabel Apps installieren.",
            "Nach dem Scan: Entwickleroptionen → USB-Debugging aus."))
    proxy = settings.get("http_proxy", "")
    if proxy and proxy not in ("null", ":0"):
        findings.append(_finding(
            "HOCH", "Globaler HTTP-Proxy gesetzt",
            f"http_proxy = {proxy}. Datenverkehr kann darüber mitgelesen werden.",
            "Klären, wer den Proxy gesetzt hat."))
    vpn = settings.get("always_on_vpn_app", "")
    if vpn and vpn != "null":
        findings.append(_finding(
            "INFO", "Always-on-VPN aktiv", f"VPN-App: {vpn}",
            "Prüfen, ob diese VPN-App bewusst genutzt wird.", vpn))
    if settings.get("install_non_market_apps") == "1":
        findings.append(_finding(
            "NIEDRIG", "Installation aus unbekannten Quellen erlaubt (global)",
            "Ältere Android-Einstellung.", "Ausschalten, wenn nicht benötigt."))

    # --- Powerful roles held by third-party apps ------------------------------
    for pkg in data["accessibility"]:
        if pkg in apps:
            findings.append(_finding(
                "HOCH", f"Bedienungshilfe aktiv: {pkg}",
                "Bedienungshilfen können alles auf dem Bildschirm lesen und Eingaben "
                "mitschneiden. Das ist der Lieblingstrick von Stalkerware.",
                "Ist das eine bewusst genutzte App (Passwortmanager, Screenreader)? "
                "Wenn nicht: Einstellungen → Bedienungshilfen → deaktivieren.", pkg))
    for pkg in data["notification_listeners"]:
        if pkg in apps:
            findings.append(_finding(
                "MITTEL", f"Liest alle Benachrichtigungen: {pkg}",
                "Kann Inhalte von WhatsApp, SMS, 2FA-Codes mitlesen.",
                "Prüfen, ob gewollt (Smartwatch-App ist normal).", pkg))
    for pkg in data["device_admins"]:
        if pkg in apps:
            findings.append(_finding(
                "MITTEL", f"Geräteadministrator: {pkg}",
                "Geräteadmins lassen sich nicht einfach deinstallieren.",
                "Prüfen, ob gewollt (Firmen-MDM, „Mein Gerät finden“ ist normal).", pkg))

    # --- Individual apps -----------------------------------------------------
    for pkg, app in apps.items():
        sensitive = [SENSITIVE[p] for p in app["granted"] if p in SENSITIVE]
        store = TRUSTED_STORES.get(app["installer"] or "")
        hidden = app.get("has_launcher_icon") is False

        if hidden and sensitive:
            findings.append(_finding(
                "HOCH", f"Versteckte App mit Zugriff auf Privates: {pkg}",
                f"Kein App-Symbol, hat aber Zugriff auf: {', '.join(sensitive)}. "
                f"Quelle: {store or app['installer'] or 'unbekannt/manuell'}.",
                "Herausfinden, was das ist. Kennt niemand die App: verdächtig.", pkg))
        elif not store and sensitive:
            findings.append(_finding(
                "MITTEL", f"App außerhalb eines Stores installiert: {pkg}",
                f"Installer: {app['installer'] or 'unbekannt (APK/ADB)'}. "
                f"Zugriff auf: {', '.join(sensitive)}.",
                "Prüfen, ob jemand diese APK bewusst installiert hat.", pkg))
        elif not store:
            findings.append(_finding(
                "INFO", f"App außerhalb eines Stores installiert: {pkg}",
                f"Installer: {app['installer'] or 'unbekannt (APK/ADB)'}.",
                "Kurz prüfen, ob bekannt.", pkg))

    findings.sort(key=lambda f: (ORDER[f["severity"]], f["title"]))
    return findings
