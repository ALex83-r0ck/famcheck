"""Stufe B: fix findings on the phone, deliberately, from the terminal only.

Rules this module keeps:
- Only reversible changes (settings, permissions, app-ops, disabling an app). No uninstall, no data deletion.
- Before each change the current state is read from the phone and stored, so 'fix --undo' restores it.
- Nothing is offered for an app that has a critical finding (known spy-/stalkerware): removing it
  can alert whoever installed it. The user gets a safety note instead.
- Every command (read and write) is recorded in its own case folder with hashes, plus fixlog.json.
"""

import json
import re
import shlex
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import decisions
import glob

from .adb import RecordingAdb, is_locked, new_case_dir, safe_serial
from .analyze import SENSITIVE
from .collect import _parse_dumpsys_package
from .style import local_time

SAFETY_NOTE = ("Für diese App bietet FamCheck bewusst keine Änderung an: Sie steht auf einer Spyware-Liste. "
               "Wer sie installiert hat, merkt das Entfernen. Erst die Sicherheit der betroffenen Person klären "
               "(Hilfetelefon 116 016), am besten mit einer Beratungsstelle das Vorgehen planen.")


@dataclass
class Action:
    finding: str             # title of the finding this action fixes
    label: str               # what happens, in plain words
    commands: list[str]
    undo: list[str]
    warning: str = ""
    last: bool = False       # must run after everything else (turns off USB debugging)


@dataclass
class Plan:
    actions: list[Action] = field(default_factory=list)
    manual: list[tuple[str, str]] = field(default_factory=list)   # (finding title, instructions)
    blocked: list[str] = field(default_factory=list)              # finding titles left alone for safety


def _q(value: str) -> str:
    return shlex.quote(value)


def _setting(adb: RecordingAdb, ns: str, key: str) -> str:
    return adb.shell(f"settings get {ns} {key}").strip()


def _set_setting(adb, finding, label, ns, key, new) -> Action | None:
    old = _setting(adb, ns, key)
    if old == new:
        return None  # already fixed since the scan
    undo = f"settings delete {ns} {key}" if old in ("", "null") else f"settings put {ns} {key} {_q(old)}"
    return Action(finding, label, [f"settings put {ns} {key} {_q(new)}"], [undo])


def _without_package(value: str, pkg: str) -> list[str]:
    return [c for c in value.split(":") if c and c != "null" and not c.startswith(pkg + "/")]


def _appop_actions(adb, finding, pkg, ops, label) -> Action | None:
    commands, undo = [], []
    for op in ops:
        m = re.search(rf"{op}: (\w+)", adb.shell(f"appops get {_q(pkg)} {op}"))
        old = m.group(1) if m else "default"
        if old in ("deny", "ignore"):
            continue
        commands.append(f"appops set {_q(pkg)} {op} deny")
        undo.append(f"appops set {_q(pkg)} {op} {old}")
    return Action(finding, label, commands, undo) if commands else None


# Findings FamCheck cannot or should not change via ADB: (title prefix, instructions)
MANUAL = [
    ("Gerät wird fremdverwaltet", "Lässt sich per ADB nicht entfernen. Ist es kein Firmenhandy: Daten sichern und "
     "das Gerät auf Werkseinstellungen zurücksetzen, danach neu einrichten. Vorher klären, wer es eingerichtet hat."),
    ("Arbeitsprofil vorhanden", "Einstellungen → Konten → Arbeitsprofil entfernen, falls es nicht gebraucht wird."),
    ("Geräteadministrator", "Einstellungen → Sicherheit → Geräteadministratoren (bei Samsung: Biometrische Daten und "
     "Sicherheit → Weitere Sicherheitseinstellungen): Haken entfernen, danach lässt sich die App normal entfernen."),
    ("Keine Displaysperre", "Die Person richtet selbst eine PIN oder ein Passwort ein: Einstellungen → Sicherheit → "
     "Displaysperre. FamCheck setzt bewusst keine PIN für jemand anderen."),
    ("Fremde Standard-SMS-App", "Einstellungen → Apps → Standard-Apps → SMS-App: die vorinstallierte Nachrichten-App wählen."),
    ("Inoffizieller Messenger-Mod", "Erst die Chats sichern (Mod-eigene Sicherung), dann den Mod deinstallieren und "
     "WhatsApp aus dem Play Store installieren. FamCheck deinstalliert nichts, damit keine Chats verloren gehen."),
    ("Sicherheitsupdates veraltet", "Einstellungen → System → Software-Update. Kommen keine Updates mehr, "
     "Ersatz einplanen und bis dahin keine Apps aus fremden Quellen installieren."),
    ("Sicherheitspatch nicht aktuell", "Einstellungen → System → Software-Update."),
    ("Play Protect möglicherweise ausgeschaltet", "Play Store → Profilbild → Play Protect → Zahnrad: "
     "„Apps mit Play Protect scannen“ einschalten."),
    ("Bootloader entsperrt", "Nur per Werksreset und erneutem Sperren des Bootloaders behebbar. "
     "Vorher klären, wer das gemacht hat."),
    ("Gerät ist gerootet", "Root lässt sich nicht per FamCheck entfernen. Klären, wer gerootet hat, ggf. Werksreset."),
    ("Google-Konten auf dem Gerät", "Mit der Person durchgehen: Einstellungen → Konten. Unbekannte Konten entfernen, "
     "in Google Fotos prüfen, in welches Konto gesichert wird."),
]


# Titles (prefixes) that 'fix' can change automatically; used by the dashboard for a hint, without a device.
AUTO_PREFIXES = (
    "Kabelloses Debugging ist an", "Globaler HTTP-Proxy gesetzt", "Per USB installierte Apps werden nicht geprüft",
    "Installation aus unbekannten Quellen erlaubt", "USB-Debugging ist an", "Privates DNS:",
    "Bedienungshilfe aktiv:", "Liest alle Benachrichtigungen:", "Darf weitere Apps installieren:",
    "Sonderrechte für App aus fremder Quelle:", "Läuft dauerhaft im Hintergrund:",
    "Versteckte App mit Zugriff auf Privates:", "App außerhalb eines Stores installiert:",
    "Hoher Upload durch App aus fremder Quelle:", "Aktives VPN einer App aus fremder Quelle:",
)


def fix_kind(finding: dict, findings: list[dict]) -> str | None:
    """'auto', 'manual', 'blocked' or None, judged from the scan alone (for the dashboard)."""
    pkg = finding.get("package")
    critical = {f["package"] for f in findings if f["severity"] == "KRITISCH" and f.get("package")}
    if finding["severity"] == "KRITISCH" or (pkg and pkg in critical):
        return "blocked"
    if finding["severity"] == "INFO":
        return None
    if finding["title"].startswith(AUTO_PREFIXES):
        return "auto"
    if any(prefix in finding["title"] for prefix, _ in MANUAL) or finding["title"].endswith(
            "nicht aus einem App-Store installiert"):
        return "manual"
    return None


def build_plan(adb: RecordingAdb, findings: list[dict], data: dict) -> Plan:
    plan = Plan()
    critical_pkgs = {f["package"] for f in findings if f["severity"] == "KRITISCH" and f.get("package")}

    for f in findings:
        title, pkg = f["title"], f.get("package")
        if f["severity"] == "KRITISCH" or (pkg and pkg in critical_pkgs):
            plan.blocked.append(title)
            continue
        if f["severity"] == "INFO":
            continue
        action = _action_for(adb, f, data)
        if isinstance(action, Action):
            plan.actions.append(action)
            continue
        if action == "already":
            continue
        manual = next((text for prefix, text in MANUAL if prefix in title), None)
        if title.endswith("nicht aus einem App-Store installiert"):
            manual = "Die App über den Play Store neu installieren (vorher Chats sichern)."
        if manual:
            plan.manual.append((title, manual))

    plan.actions.sort(key=lambda a: a.last)
    return plan


def _action_for(adb: RecordingAdb, f: dict, data: dict):
    """An Action, 'already' if the problem is gone since the scan, or None if there is no automatic fix."""
    title, pkg = f["title"], f.get("package")

    simple_settings = {
        "Kabelloses Debugging ist an": ("Kabelloses Debugging ausschalten", "global", "adb_wifi_enabled", "0"),
        "Globaler HTTP-Proxy gesetzt": ("Proxy entfernen", "global", "http_proxy", ":0"),
        "Per USB installierte Apps werden nicht geprüft": ("Prüfung von USB-Installationen einschalten",
                                                           "global", "verifier_verify_adb_installs", "1"),
        "Installation aus unbekannten Quellen erlaubt (global)": ("Unbekannte Quellen sperren",
                                                                  "secure", "install_non_market_apps", "0"),
    }
    if title in simple_settings:
        label, ns, key, new = simple_settings[title]
        return _set_setting(adb, title, label, ns, key, new) or "already"

    if title == "USB-Debugging ist an":
        a = _set_setting(adb, title, "USB-Debugging ausschalten", "global", "adb_enabled", "0")
        if a:
            a.last, a.undo = True, []
            a.warning = ("Danach bricht die Verbindung ab. Rückgängig nur am Handy selbst "
                         "(Entwickleroptionen → USB-Debugging).")
        return a or "already"

    if title.startswith("Privates DNS:"):
        return _set_setting(adb, title, "Privates DNS auf „Automatisch“ zurückstellen",
                            "global", "private_dns_mode", "opportunistic") or "already"

    if not pkg:
        return None

    if title.startswith("Bedienungshilfe aktiv:"):
        old = _setting(adb, "secure", "enabled_accessibility_services")
        if not any(c.startswith(pkg + "/") for c in old.split(":")):
            return "already"
        keep = _without_package(old, pkg)
        cmd = (f"settings put secure enabled_accessibility_services {_q(':'.join(keep))}" if keep
               else "settings delete secure enabled_accessibility_services")
        return Action(title, f"Bedienungshilfe von {pkg} ausschalten", [cmd],
                      [f"settings put secure enabled_accessibility_services {_q(old)}"])

    if title.startswith("Liest alle Benachrichtigungen:"):
        old = _setting(adb, "secure", "enabled_notification_listeners")
        comps = [c for c in old.split(":") if c.startswith(pkg + "/")]
        if not comps:
            return "already"
        return Action(title, f"Benachrichtigungszugriff von {pkg} entziehen",
                      [f"cmd notification disallow_listener {_q(c)}" for c in comps],
                      [f"cmd notification allow_listener {_q(c)}" for c in comps])

    if title.startswith("Darf weitere Apps installieren:"):
        return _appop_actions(adb, title, pkg, ["REQUEST_INSTALL_PACKAGES"],
                              f"{pkg} das Installieren weiterer Apps verbieten") or "already"

    if title.startswith("Sonderrechte für App aus fremder Quelle:"):
        return _appop_actions(adb, title, pkg, ["SYSTEM_ALERT_WINDOW", "MANAGE_EXTERNAL_STORAGE"],
                              f"{pkg} das Einblenden und den Zugriff auf alle Dateien entziehen") or "already"

    if title.startswith("Läuft dauerhaft im Hintergrund:"):
        return Action(title, f"Akku-Ausnahme für {pkg} aufheben",
                      [f"cmd deviceidle whitelist -{pkg}"], [f"cmd deviceidle whitelist +{pkg}"])

    if title.startswith(("Versteckte App mit Zugriff auf Privates:", "App außerhalb eines Stores installiert:")):
        live = _parse_dumpsys_package(adb.shell(f"dumpsys package {_q(pkg)}"))["granted"]
        granted = [p for p in live if p in SENSITIVE]
        if not granted:
            return "already" if pkg in data["apps"] else None
        return Action(title, f"{pkg} die Rechte entziehen: " + ", ".join(SENSITIVE[p] for p in granted),
                      [f"pm revoke {_q(pkg)} {p}" for p in granted],
                      [f"pm grant {_q(pkg)} {p}" for p in granted],
                      warning="Die App fragt beim nächsten Öffnen evtl. erneut nach den Rechten.")

    if title.startswith(("Hoher Upload durch App aus fremder Quelle:", "Aktives VPN einer App aus fremder Quelle:")):
        return Action(title, f"App {pkg} deaktivieren (bleibt installiert, Daten bleiben erhalten)",
                      [f"pm disable-user --user 0 {_q(pkg)}"], [f"pm enable --user 0 {_q(pkg)}"])

    return None


# Undo commands come from fixlog.json on disk; only these kinds (the ones fix writes) are executed.
UNDO_ALLOWED = re.compile(
    r"^(settings (put|delete) (global|secure) [\w.]+( \S+)?"
    r"|appops set \S+ [A-Z_]+ \w+"
    r"|pm (grant \S+ [\w.]+|enable --user 0 \S+)"
    r"|cmd deviceidle whitelist \+[\w.]+"
    r"|cmd notification allow_listener \S+)$")


def _ask(prompt: str, input_fn) -> bool:
    return input_fn(prompt).strip().lower() in ("j", "ja", "y", "yes")


def _choose(n: int, input_fn) -> list[int]:
    answer = input_fn("Welche Nummern beheben? (z. B. 1,3 oder 'alle', Enter = abbrechen) ").strip().lower()
    if answer in ("alle", "all"):
        return list(range(1, n + 1))
    picked = sorted({int(x) for x in re.findall(r"\d+", answer) if 1 <= int(x) <= n})
    return picked


def run_fix(serial: str, scan_dir: Path, cases_root: Path, dry_run: bool = False,
            input_fn=input, print_fn=print) -> Path | None:
    findings = json.loads((scan_dir / "findings.json").read_text(encoding="utf-8"))
    meta, findings = findings["meta"], findings["findings"]
    data = json.loads((scan_dir / "data.json").read_text(encoding="utf-8"))
    label = meta["label"]

    if is_locked(serial):
        print_fn(f"{label}: Bitte das Handy entsperren (Fingerabdruck/PIN) und den Befehl erneut starten.")
        return None

    started = datetime.now(timezone.utc)
    safe_label = re.sub(r"[^\w-]+", "_", label)
    fix_dir = new_case_dir(cases_root, f"{started.astimezone():%Y%m%d-%H%M%S}_fix_{safe_label}_{safe_serial(serial)}")
    adb = RecordingAdb(serial, fix_dir)
    print_fn(f"\nFamCheck fix für {label} ({serial}), Grundlage: Scan vom {local_time(meta['started'])}")
    print_fn("Lese den aktuellen Zustand des Handys ...")
    plan = build_plan(adb, findings, data)

    if plan.blocked:
        print_fn("\n⚠ Bewusst nicht angeboten (Sicherheit geht vor):")
        for t in plan.blocked:
            print_fn(f"   - {t}")
        print_fn(f"   {SAFETY_NOTE}")
    if plan.manual:
        print_fn("\nVon Hand zu erledigen:")
        for t, text in plan.manual:
            print_fn(f"   - {t}\n     {text}")
    if not plan.actions:
        print_fn("\nNichts, was FamCheck automatisch beheben kann.")
        _write_log(fix_dir, serial, meta, scan_dir, [], dry_run)
        return fix_dir

    print_fn("\nAutomatisch behebbar (alles umkehrbar mit 'fix --undo', außer wo vermerkt):")
    for i, a in enumerate(plan.actions, 1):
        print_fn(f"  {i}. {a.label}\n     wegen: {a.finding}" + (f"\n     ! {a.warning}" if a.warning else ""))
    picked = _choose(len(plan.actions), input_fn)
    if not picked:
        print_fn("Abgebrochen, nichts geändert.")
        _write_log(fix_dir, serial, meta, scan_dir, [], dry_run)
        return fix_dir

    results = []
    for i in picked:
        a = plan.actions[i - 1]
        print_fn(f"\n[{i}] {a.label}")
        for c in a.commands:
            print_fn(f"     adb shell {c}")
        if dry_run:
            results.append({**asdict(a), "status": "dry-run"})
            continue
        if not _ask("     Ausführen? [j/N] ", input_fn):
            results.append({**asdict(a), "status": "übersprungen"})
            print_fn("     übersprungen")
            continue
        outputs, ok = [], True
        for c in a.commands:
            out = adb.shell(c).strip()
            outputs.append(out)
            if re.search(r"(?i)exception|error|unknown|not allowed|denied|fail", out):
                ok = False
        status = "ausgeführt" if ok else "fehlgeschlagen"
        results.append({**asdict(a), "status": status, "outputs": outputs})
        print_fn(f"     {'erledigt' if ok else 'FEHLER: ' + ' | '.join(o for o in outputs if o)[:200]}")
        if ok:
            finding = next(f for f in findings if f["title"] == a.finding)
            decisions.record(cases_root, serial, finding, "done", f"per famcheck fix: {a.label}")

    _write_log(fix_dir, serial, meta, scan_dir, results, dry_run)
    if not dry_run and any(r["status"] == "ausgeführt" for r in results):
        print_fn("\nBehobene Befunde sind im Dashboard als „Erledigt“ eingeordnet. Der nächste Scan zeigt, ob es "
                 f"geklappt hat. Rückgängig: python -m famcheck fix --undo \"{fix_dir}\"")
    return fix_dir


def _write_log(fix_dir, serial, meta, scan_dir, results, dry_run):
    log = {"serial": serial, "label": meta["label"], "based_on_scan": scan_dir.name, "dry_run": dry_run,
           "at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "actions": results}
    (fix_dir / "fixlog.json").write_text(json.dumps(log, indent=2, ensure_ascii=False), encoding="utf-8")


def run_undo(fix_dir: Path, cases_root: Path, input_fn=input, print_fn=print) -> Path | None:
    log = json.loads((fix_dir / "fixlog.json").read_text(encoding="utf-8"))
    serial = log["serial"]
    todo = [r for r in log["actions"] if r["status"] == "ausgeführt"]
    if not todo:
        print_fn("In diesem Durchlauf wurde nichts geändert, es gibt nichts rückgängig zu machen.")
        return None
    if is_locked(serial):
        print_fn("Bitte das Handy entsperren und den Befehl erneut starten.")
        return None
    started = datetime.now(timezone.utc)
    undo_dir = new_case_dir(cases_root, f"{started.astimezone():%Y%m%d-%H%M%S}_undo_{safe_serial(serial)}")
    adb = RecordingAdb(serial, undo_dir)
    results = []
    for r in reversed(todo):  # undo in reverse order
        print_fn(f"\nRückgängig: {r['label']}")
        if not r["undo"]:
            print_fn(f"     Nicht automatisch umkehrbar. {r.get('warning', '')}")
            results.append({**r, "undo_status": "nicht möglich"})
            continue
        bad = [c for c in r["undo"] if not UNDO_ALLOWED.match(c)]
        if bad:
            print_fn(f"     ABGELEHNT, unerwarteter Befehl in fixlog.json (manipuliert?): {bad[0]}")
            results.append({**r, "undo_status": "abgelehnt"})
            continue
        for c in r["undo"]:
            print_fn(f"     adb shell {c}")
        if not _ask("     Ausführen? [j/N] ", input_fn):
            results.append({**r, "undo_status": "übersprungen"})
            continue
        outputs = [adb.shell(c).strip() for c in r["undo"]]
        results.append({**r, "undo_status": "ausgeführt", "undo_outputs": outputs})
        print_fn("     erledigt")
    (undo_dir / "undolog.json").write_text(json.dumps(
        {"serial": serial, "undoes": fix_dir.name, "at": started.isoformat(timespec="seconds"), "actions": results},
        indent=2, ensure_ascii=False), encoding="utf-8")
    print_fn("\nHinweis: Die Einordnung „Erledigt“ im Dashboard bleibt bestehen und wird beim nächsten Scan "
             "automatisch wieder geöffnet, falls der Befund noch da ist.")
    return undo_dir


# Findings about one app where deinstalling is a sensible way out (offered as a command in the dashboard)
REMOVABLE = ("App außerhalb eines Stores installiert:", "Versteckte App mit Zugriff auf Privates:",
             "Hoher Upload durch App aus fremder Quelle:", "Neue App will weitere Apps installieren:")
PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")


def removable(finding: dict, findings: list[dict]) -> bool:
    return (bool(finding.get("package")) and finding["title"].startswith(REMOVABLE)
            and fix_kind(finding, findings) != "blocked")


def run_remove(serial: str, pkg: str, scan_dir: Path, cases_root: Path,
               input_fn=input, print_fn=print) -> Path | None:
    """Deinstalls one app after asking. Not undoable, so: only apps the scan saw as installed by the user,
    never one with a KRITISCH finding (whoever installed stalkerware notices), always logged."""
    content = json.loads((scan_dir / "findings.json").read_text(encoding="utf-8"))
    meta, findings = content["meta"], content["findings"]
    apps = json.loads((scan_dir / "data.json").read_text(encoding="utf-8"))["apps"]
    if not PACKAGE_RE.match(pkg) or pkg not in apps:
        print_fn(f"{pkg} ist im letzten Scan keine vom Nutzer installierte App. "
                 "System-Apps entfernt FamCheck nicht.")
        return None
    if any(f["severity"] == "KRITISCH" and f.get("package") == pkg for f in findings):
        print_fn(f"Bewusst nicht: {SAFETY_NOTE}")
        return None
    if is_locked(serial):
        print_fn(f"{meta['label']}: Bitte das Handy entsperren (Fingerabdruck/PIN) und den Befehl erneut starten.")
        return None

    app = apps[pkg]
    rights = sorted({SENSITIVE[p] for p in app["granted"] if p in SENSITIVE})
    print_fn(f"\nFamCheck remove für {meta['label']} ({serial}), Grundlage: Scan vom {local_time(meta['started'])}")
    print_fn(f"  App:          {pkg}")
    print_fn(f"  Installiert:  {app.get('first_install') or '?'} über {app['installer'] or 'unbekannt (APK/USB)'}")
    print_fn(f"  Heikle Rechte: {', '.join(rights) or 'keine'}")
    for f in findings:
        if f.get("package") == pkg:
            print_fn(f"  Befund:       {f['title']}")
    print_fn("Deinstallieren löscht die App mit ihren Daten. Rückgängig nur durch Neuinstallation.")
    if not _ask("App wirklich deinstallieren? [j/N] ", input_fn):
        print_fn("Abgebrochen, nichts geändert.")
        return None

    started = datetime.now(timezone.utc)
    remove_dir = new_case_dir(cases_root, f"{started.astimezone():%Y%m%d-%H%M%S}_remove_{safe_serial(serial)}")
    out = RecordingAdb(serial, remove_dir).shell(f"pm uninstall {_q(pkg)}").strip()
    ok = out.startswith("Success")
    if ok:
        print_fn("Erledigt. Der nächste Scan zeigt, ob sie wirklich weg ist.")
        for f in findings:
            if f.get("package") == pkg:
                decisions.record(cases_root, serial, f, "done", "per famcheck remove deinstalliert")
    elif "DEVICE_POLICY" in out:
        print_fn("Nicht möglich: Die App ist als Geräteadministrator eingetragen und schützt sich so vor dem "
                 "Löschen. Erst am Handy die Geräteadministrator-Rechte entziehen (Anleitung im Dashboard beim "
                 "Befund „Geräteadministrator“), dann diesen Befehl wiederholen.")
    else:
        print_fn(f"FEHLER: {out[:200] or 'keine Antwort'}")
    log = {"serial": serial, "label": meta["label"], "based_on_scan": scan_dir.name, "package": pkg,
           "at": started.isoformat(timespec="seconds"), "status": "ausgeführt" if ok else "fehlgeschlagen",
           "output": out}
    (remove_dir / "removelog.json").write_text(json.dumps(log, indent=2, ensure_ascii=False), encoding="utf-8")
    return remove_dir


def latest_scan(cases_root: Path, serial: str) -> Path | None:
    scans = [d for d in cases_root.glob(f"*_{glob.escape(safe_serial(serial))}") if (d / "findings.json").is_file()]
    return max(scans, key=lambda d: (json.loads((d / "findings.json").read_text(encoding="utf-8"))["meta"]["started"],
                                     d.name), default=None)  # same second: the later -2 folder wins
