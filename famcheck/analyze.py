"""Turns collected device data into findings. Heuristics, not proof: every finding needs a human look."""

from datetime import date
from pathlib import Path


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

APPOP_LABELS = {
    "SYSTEM_ALERT_WINDOW": "über anderen Apps einblenden",
    "REQUEST_INSTALL_PACKAGES": "weitere Apps installieren",
    "MANAGE_EXTERNAL_STORAGE": "Zugriff auf alle Dateien inkl. Fotos",
}

MB = 1024 * 1024
UPLOAD_ALERT_BG = 50 * MB      # background upload by a non-store app
UPLOAD_ALERT_TOTAL = 200 * MB  # total upload by a non-store app


def _mb(n: int) -> str:
    return f"{n / MB:,.0f} MB".replace(",", ".")

ORDER = {"KRITISCH": 0, "HOCH": 1, "MITTEL": 2, "NIEDRIG": 3, "INFO": 4}


def load_ioc() -> dict[str, str]:
    """package name -> spyware family name"""
    if not IOC_PATH.exists():
        return {}
    try:
        import yaml
    except ModuleNotFoundError:
        raise SystemExit("Paket 'pyyaml' fehlt. Installieren mit: pip install -r requirements.txt")
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

    # --- Device control, lock, accounts --------------------------------------
    owner = data.get("device_owner")
    if owner:
        findings.append(_finding(
            "HOCH", f"Gerät wird fremdverwaltet: {owner}",
            "Ein Device Owner (Firmen-/MDM-Verwaltung) hat fast volle Kontrolle: Apps installieren, "
            "Einstellungen sperren, Daten auslesen.",
            "Ist das ein Firmenhandy? Wenn nicht: dringend klären, wer das eingerichtet hat.", owner))
    for po in data.get("profile_owners", []):
        findings.append(_finding(
            "MITTEL", f"Arbeitsprofil vorhanden: {po}",
            "Ein Arbeitsprofil wird von einer fremden Stelle verwaltet.",
            "Normal bei Firmen-Apps. Sonst prüfen, wer es eingerichtet hat.", po))

    if data.get("lock_credential") in ("NONE", "SWIPE"):
        findings.append(_finding(
            "HOCH", "Keine Displaysperre",
            "Ohne PIN/Muster/Passwort kann jeder mit dem Handy in der Hand in Minuten Stalkerware installieren.",
            "Einstellungen → Sicherheit → Displaysperre: PIN oder Passwort einrichten."))

    accounts = data.get("accounts") or {}
    google = accounts.get("com.google", 0)
    if google > 1:
        findings.append(_finding(
            "NIEDRIG", f"{google} Google-Konten auf dem Gerät",
            "Jedes Google-Konto kann eigene Fotosicherung und Synchronisierung haben. "
            "Ein fremdes Konto bekäme so alle Fotos.",
            "Mit der Person durchgehen: Einstellungen → Konten. Sind alle bekannt? "
            "Bei Google Fotos prüfen, in welches Konto gesichert wird."))

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

    sms = data.get("sms_default")
    if sms and sms in apps:
        store = TRUSTED_STORES.get(apps[sms]["installer"] or "")
        findings.append(_finding(
            "NIEDRIG" if store else "HOCH", f"Fremde Standard-SMS-App: {sms}",
            "Die Standard-SMS-App bekommt alle SMS, auch Bestätigungscodes fürs Online-Banking.",
            "Bewusst gewählt (z. B. Signal)? Sonst Standard-SMS-App zurückstellen.", sms))

    uploads_by_pkg = {p: u for u in data.get("uploads", []) for p in u["packages"]}
    days = data.get("uploads_days")
    period = f"in den letzten ~{days:.0f} Tagen" if days else "im erfassten Zeitraum"

    # --- Individual apps -----------------------------------------------------
    for pkg, app in apps.items():
        sensitive = [SENSITIVE[p] for p in app["granted"] if p in SENSITIVE]
        if "MANAGE_EXTERNAL_STORAGE" in app.get("appops", []):
            sensitive.append("Alle Dateien inkl. Fotos")
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

        ops = app.get("appops", [])
        if "REQUEST_INSTALL_PACKAGES" in ops:
            findings.append(_finding(
                "NIEDRIG" if store else "MITTEL", f"Darf weitere Apps installieren: {pkg}",
                "Über diese App lassen sich APKs an Google Play vorbei installieren.",
                "Einstellungen → Apps → Spezieller App-Zugriff → Unbekannte Apps installieren: ausschalten.", pkg))
        if not store and ("SYSTEM_ALERT_WINDOW" in ops or "MANAGE_EXTERNAL_STORAGE" in ops):
            labels = [APPOP_LABELS[o] for o in ("SYSTEM_ALERT_WINDOW", "MANAGE_EXTERNAL_STORAGE") if o in ops]
            findings.append(_finding(
                "MITTEL", f"Sonderrechte für App aus fremder Quelle: {pkg}",
                f"Darf: {', '.join(labels)}. Einblenden über anderen Apps nutzen Banking-Trojaner "
                "für gefälschte Login-Masken.",
                "Prüfen, ob die App das wirklich braucht, sonst Recht entziehen.", pkg))
        if not store and pkg in data.get("battery_exempt", []):
            findings.append(_finding(
                "MITTEL", f"Läuft dauerhaft im Hintergrund: {pkg}",
                "Vom Akkusparen ausgenommen, Android beendet sie nie. Spyware fordert das gezielt an.",
                "Prüfen, ob gewollt. Sonst Einstellungen → Akku → Optimierung wieder einschalten.", pkg))

        up = uploads_by_pkg.get(pkg)
        if up and not store and (up["tx_bg"] >= UPLOAD_ALERT_BG or up["tx"] >= UPLOAD_ALERT_TOTAL):
            findings.append(_finding(
                "HOCH", f"Hoher Upload durch App aus fremder Quelle: {pkg}",
                f"Hat {period} {_mb(up['tx'])} hochgeladen, davon {_mb(up['tx_bg'])} im Hintergrund.",
                "Genau so sieht heimliches Hochladen von Fotos aus. Klären, was die App ist.", pkg))

    findings.sort(key=lambda f: (ORDER[f["severity"]], f["title"]))
    return findings
