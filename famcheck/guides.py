"""Step-by-step instructions for the phone, with the menu path of the phone's maker.

Menu names differ between makers and Android versions. Every guide therefore also names a search term:
the search field at the top of the settings finds the page even where the path is different.
Nothing here touches the phone; it only produces text for report and dashboard.
"""

from html import escape

SAMSUNG = "samsung"
DEFAULT = "default"

# Every step list may use {app} (package name of the finding). Search terms are what the settings search finds.
GUIDES = {
    "accessibility": {
        "search": "Installierte Apps",
        SAMSUNG: ["Einstellungen → Eingabehilfe → Installierte Apps", "{app} antippen → ausschalten"],
        DEFAULT: ["Einstellungen → Bedienungshilfen", "Unter „Heruntergeladene Apps“ {app} antippen → ausschalten"],
    },
    "notifications": {
        "search": "Benachrichtigungszugriff",
        SAMSUNG: ["Einstellungen → Apps → ⋮ (oben rechts) → Spezieller Zugriff",
                  "Benachrichtigungen lesen, beantworten und steuern", "{app} ausschalten"],
        DEFAULT: ["Einstellungen → Apps → Spezieller App-Zugriff → Benachrichtigungszugriff", "{app} ausschalten"],
    },
    "device_admin": {
        "search": "Geräteadministrator",
        SAMSUNG: ["Einstellungen → Sicherheit und Datenschutz → Weitere Sicherheitseinstellungen",
                  "Geräteadministrator-Apps → {app} ausschalten",
                  "Erst danach lässt sich die App normal deinstallieren"],
        DEFAULT: ["Einstellungen → Sicherheit & Datenschutz → Weitere Sicherheitseinstellungen",
                  "Apps zur Geräteverwaltung → {app} deaktivieren",
                  "Erst danach lässt sich die App normal deinstallieren"],
    },
    "install_apps": {
        "search": "Unbekannte Apps installieren",
        SAMSUNG: ["Einstellungen → Apps → ⋮ (oben rechts) → Spezieller Zugriff → Unbekannte Apps installieren",
                  "{app} → „Zulassen“ ausschalten"],
        DEFAULT: ["Einstellungen → Apps → Spezieller App-Zugriff → Unbekannte Apps installieren",
                  "{app} → „Dieser Quelle vertrauen“ ausschalten"],
    },
    "special_access": {
        "search": "Über anderen Apps",
        SAMSUNG: ["Einstellungen → Apps → ⋮ (oben rechts) → Spezieller Zugriff",
                  "„Über anderen Apps anzeigen“ → {app} ausschalten",
                  "„Zugriff auf alle Dateien“ → {app} ausschalten"],
        DEFAULT: ["Einstellungen → Apps → Spezieller App-Zugriff",
                  "„Über anderen Apps einblenden“ → {app} ausschalten",
                  "„Zugriff auf alle Dateien“ → {app} ausschalten"],
    },
    "battery": {
        "search": "Akkunutzung",
        SAMSUNG: ["Einstellungen → Apps → {app} → Akku", "„Optimiert“ wählen"],
        DEFAULT: ["Einstellungen → Apps → {app} → Akkunutzung der App", "„Optimiert“ wählen"],
    },
    "app_info": {
        "search": "Apps",
        SAMSUNG: ["Einstellungen → Apps → {app}", "Unter „Berechtigungen“ prüfen, was die App darf",
                  "Wenn niemand die App kennt: „Deinstallieren“"],
        DEFAULT: ["Einstellungen → Apps → Alle Apps anzeigen → {app}",
                  "Unter „Berechtigungen“ prüfen, was die App darf",
                  "Wenn niemand die App kennt: „Deinstallieren“"],
    },
    "usb_debugging": {
        "search": "USB-Debugging",
        SAMSUNG: ["Einstellungen → Entwickleroptionen (ganz unten)", "USB-Debugging ausschalten"],
        DEFAULT: ["Einstellungen → System → Entwickleroptionen", "USB-Debugging ausschalten"],
    },
    "wifi_debugging": {
        "search": "Debugging über WLAN",
        SAMSUNG: ["Einstellungen → Entwickleroptionen (ganz unten)", "„Debugging über WLAN“ ausschalten"],
        DEFAULT: ["Einstellungen → System → Entwickleroptionen", "„Kabelloses Debugging“ ausschalten"],
    },
    "verify_adb": {
        "search": "Apps über USB überprüfen",
        SAMSUNG: ["Einstellungen → Entwickleroptionen (ganz unten)", "„Apps über USB überprüfen“ einschalten"],
        DEFAULT: ["Einstellungen → System → Entwickleroptionen", "„Apps über USB überprüfen“ einschalten"],
    },
    "screen_lock": {
        "search": "Sperrbildschirmtyp",
        SAMSUNG: ["Einstellungen → Sperrbildschirm und AOD → Sperrbildschirmtyp", "PIN oder Passwort wählen"],
        DEFAULT: ["Einstellungen → Sicherheit & Datenschutz → Displaysperre", "PIN oder Passwort wählen"],
    },
    "updates": {
        "search": "Software-Update",
        SAMSUNG: ["Einstellungen → Software-Update → Herunterladen und installieren"],
        DEFAULT: ["Einstellungen → System → Softwareupdates",
                  "Zusätzlich: Einstellungen → Sicherheit & Datenschutz → System & Updates → Google Play-Systemupdate"],
    },
    "play_protect": {
        "search": None,  # lives in the Play Store, not in the settings
        SAMSUNG: ["Play Store öffnen → Profilbild (oben rechts) → Play Protect",
                  "Zahnrad (oben rechts) → „Apps mit Play Protect scannen“ einschalten"],
        DEFAULT: ["Play Store öffnen → Profilbild (oben rechts) → Play Protect",
                  "Zahnrad (oben rechts) → „Apps mit Play Protect scannen“ einschalten"],
    },
    "private_dns": {
        "search": "Privates DNS",
        SAMSUNG: ["Einstellungen → Verbindungen → Weitere Verbindungseinstellungen → Privates DNS",
                  "Wenn niemand den Server kennt: „Automatisch“ oder „Aus“ wählen"],
        DEFAULT: ["Einstellungen → Netzwerk & Internet → Privates DNS",
                  "Wenn niemand den Server kennt: „Automatisch“ oder „Aus“ wählen"],
    },
    "sms_app": {
        "search": "Standard-Apps",
        SAMSUNG: ["Einstellungen → Apps → Standard-Apps auswählen → SMS-App", "„Nachrichten“ wählen"],
        DEFAULT: ["Einstellungen → Apps → Standard-Apps → SMS-App", "„Messages“ wählen"],
    },
    "accounts": {
        "search": "Konten",
        SAMSUNG: ["Einstellungen → Konten und Sicherung → Konten verwalten",
                  "Jedes Konto gemeinsam durchgehen: Ist es bekannt? Fremdes Konto antippen → „Konto entfernen“"],
        DEFAULT: ["Einstellungen → Passwörter & Konten (bei manchen: „Konten“)",
                  "Jedes Konto gemeinsam durchgehen: Ist es bekannt? Fremdes Konto antippen → „Konto entfernen“"],
    },
    "vpn": {
        "search": "VPN",
        SAMSUNG: ["Einstellungen → Verbindungen → Weitere Verbindungseinstellungen → VPN",
                  "Unbekanntes VPN antippen → trennen bzw. löschen"],
        DEFAULT: ["Einstellungen → Netzwerk & Internet → VPN", "Unbekanntes VPN antippen → trennen bzw. vergessen"],
    },
}

# Title prefix (as written by analyze.py) -> guide
TOPICS = [
    ("Bedienungshilfe aktiv:", "accessibility"),
    ("Liest alle Benachrichtigungen:", "notifications"),
    ("Geräteadministrator:", "device_admin"),
    ("Darf weitere Apps installieren:", "install_apps"),
    ("Sonderrechte für App aus fremder Quelle:", "special_access"),
    ("Läuft dauerhaft im Hintergrund:", "battery"),
    ("Versteckte App mit Zugriff auf Privates:", "app_info"),
    ("App außerhalb eines Stores installiert:", "app_info"),
    ("Hoher Upload durch App aus fremder Quelle:", "app_info"),
    ("USB-Debugging ist an", "usb_debugging"),
    ("Kabelloses Debugging ist an", "wifi_debugging"),
    ("Per USB installierte Apps werden nicht geprüft", "verify_adb"),
    ("Keine Displaysperre", "screen_lock"),
    ("Sicherheitsupdates veraltet", "updates"),
    ("Sicherheitspatch nicht aktuell", "updates"),
    ("Play Protect möglicherweise ausgeschaltet", "play_protect"),
    ("Privates DNS:", "private_dns"),
    ("Fremde Standard-SMS-App:", "sms_app"),
    ("Aktives VPN einer App aus fremder Quelle:", "vpn"),
]

CLEANUP = {
    SAMSUNG: ["Kabel abziehen",
              "Einstellungen → Entwickleroptionen → „USB-Debugging-Autorisierungen widerrufen“ "
              "(wichtig, wenn das Handy nicht dir gehört)",
              "Dort „USB-Debugging“ ausschalten",
              "Ganz oben in den Entwickleroptionen den Schalter ausschalten (Entwicklermodus aus)",
              "Falls für den Scan ausgeschaltet: Einstellungen → Sicherheit und Datenschutz → "
              "Automatische Sperre wieder einschalten"],
    DEFAULT: ["Kabel abziehen",
              "Einstellungen → System → Entwickleroptionen → „USB-Debugging-Autorisierungen aufheben“ "
              "(wichtig, wenn das Handy nicht dir gehört)",
              "Dort „USB-Debugging“ ausschalten",
              "Ganz oben in den Entwickleroptionen den Schalter ausschalten (Entwicklermodus aus)"],
}


def vendor(props: dict) -> tuple[str, str]:
    """(guide key, label shown above the steps)."""
    maker = (props.get("ro.product.manufacturer") or "").strip()
    if maker.lower() == SAMSUNG:
        return SAMSUNG, "Samsung"
    if maker.lower() in ("google", "motorola", "nokia", "hmd global", "fairphone", "nothing", ""):
        return DEFAULT, maker.capitalize() or "Android"
    return DEFAULT, f"Android allgemein, bei {maker} können Menünamen abweichen"


def topic(finding: dict) -> str | None:
    if finding["title"].endswith("Google-Konten auf dem Gerät"):
        return "accounts"
    return next((t for prefix, t in TOPICS if finding["title"].startswith(prefix)), None)


def steps_html(finding: dict, props: dict, findings: list[dict]) -> str:
    """Numbered steps for this finding on this phone, or '' if there is no guide.

    Apps with a KRITISCH finding get none on purpose: whoever installed stalkerware may notice its
    removal; the finding's own text says to secure evidence and the person's safety first."""
    key = topic(finding)
    if not key or finding["severity"] == "KRITISCH":
        return ""
    pkg = finding.get("package")
    if pkg and any(f["severity"] == "KRITISCH" and f.get("package") == pkg for f in findings):
        return ""
    guide = GUIDES[key]
    vkey, label = vendor(props)
    app = f"<span class='mono'>{escape(pkg)}</span>" if pkg else "die App"
    items = "".join(f"<li>{escape(step).replace('{app}', app)}</li>" for step in guide[vkey])
    search = (f"<div class='muted small'>Nicht gefunden? Oben in den Einstellungen nach "
              f"„{escape(guide['search'])}“ suchen.</div>") if guide["search"] else ""
    return f"<div class='steps'><b>So geht’s ({escape(label)}):</b><ol>{items}</ol>{search}</div>"


def cleanup_html(props: dict) -> str:
    vkey, label = vendor(props)
    items = "".join(f"<li>{escape(step)}</li>" for step in CLEANUP[vkey])
    return (f"<details class='cleanup'><summary>Nach dem Scan: Handy aufräumen ({escape(label)})</summary>"
            f"<ol>{items}</ol></details>")
