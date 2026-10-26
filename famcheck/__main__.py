"""FamCheck: read-only stalkerware / security check for Android devices via ADB."""

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .adb import AdbError, RecordingAdb, install_platform_tools, list_devices, tools_dir
from . import iocs, online
from .analyze import ORDER, analyze
from .collect import collect
from .report import diff_scans, write_html


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else "keine-ioc-liste"


def scan_device(serial: str, label: str, cases_root: Path, check_apks: bool = True,
                malwarebazaar: bool = False) -> Path:
    started = datetime.now(timezone.utc)
    safe_label = re.sub(r"[^\w-]+", "_", label)
    case_dir = cases_root / f"{started:%Y%m%d-%H%M%S}_{safe_label}_{serial}"
    case_dir.mkdir(parents=True)
    log_file = open(case_dir / "caselog.txt", "a", encoding="utf-8")

    def log(msg):
        line = f"{datetime.now(timezone.utc).isoformat(timespec='seconds')}  {msg}"
        print(f"  {msg}")
        log_file.write(line + "\n")

    meta = {"label": label, "serial": serial, "started": started.isoformat(timespec="seconds"),
            "tool_version": __version__, "ioc_sha256": iocs.file_sha256(),
            "ioc_generated": iocs.load()["meta"].get("generated")}
    log(f"Scan gestartet: {label} ({serial}), FamCheck {__version__}")

    data = collect(RecordingAdb(serial, case_dir), log, check_apks=check_apks)
    if malwarebazaar:
        online.check_apps(data, online.api_key(), log)
    findings = analyze(data)

    (case_dir / "data.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), "utf-8")
    (case_dir / "findings.json").write_text(
        json.dumps({"meta": meta, "findings": findings}, indent=2, ensure_ascii=False), "utf-8")
    report = write_html(case_dir, meta, data, findings)

    for name in ("data.json", "findings.json", "report.html", "manifest.csv"):
        log(f"SHA-256 {name}: {_sha256(case_dir / name)}")
    log("Scan beendet.")
    log_file.close()

    counts = {s: sum(f["severity"] == s for f in findings) for s in ORDER}
    summary = ", ".join(f"{s} {n}" for s, n in counts.items() if n)
    print(f"  Ergebnis: {summary or 'keine Befunde'}")
    print(f"  Bericht: {report}")
    return case_dir


def _check_prerequisites(args):
    warning = iocs.freshness_warning()
    if warning:
        print(f"! {warning}")
    if args.malwarebazaar and not online.api_key():
        sys.exit("Für --malwarebazaar wird ein kostenloser Schlüssel von https://auth.abuse.ch/ gebraucht.\n"
                 "Setzen mit:  $env:FAMCHECK_ABUSECH_KEY = \"<schlüssel>\"   (PowerShell)")


def cmd_scan(args):
    devices = [d for d in list_devices() if d["state"] == "device"]
    unauthorized = [d for d in list_devices() if d["state"] == "unauthorized"]
    for d in unauthorized:
        print(f"! {d['serial']}: nicht autorisiert. Auf dem Handy 'USB-Debugging zulassen' bestätigen.")
    if args.serial:
        devices = [d for d in devices if d["serial"] == args.serial]
    if not devices:
        sys.exit("Kein autorisiertes Gerät gefunden (adb devices).")
    if len(devices) > 1 and not args.all and not args.serial:
        print("Mehrere Geräte verbunden. Nutze --serial oder --all:")
        for d in devices:
            print(f"  {d['serial']}  {d['model']}")
        sys.exit(1)
    _check_prerequisites(args)

    for d in devices:
        label = args.label if args.label and len(devices) == 1 else (d["model"] or d["serial"])
        print(f"\n== {label} ({d['serial']}) ==")
        scan_device(d["serial"], label, Path(args.cases), not args.no_apk_check, args.malwarebazaar)


def cmd_update_ioc(_args):
    print("Lade Indikatorlisten (Echap + MVT) ...")
    path = iocs.update()
    print(f"Gespeichert: {path}\nSHA-256: {iocs.file_sha256()}")


def cmd_diff(args):
    print(diff_scans(Path(args.old), Path(args.new)))


def cmd_setup(args):
    if not args.yes:
        print("Lädt die Android Platform-Tools (adb) von Google herunter.\n"
              "Mit dem Download akzeptierst du die Android SDK-Lizenzbedingungen:\n"
              "https://developer.android.com/studio/terms")
        if input("Fortfahren? [j/N] ").strip().lower() not in ("j", "ja", "y", "yes"):
            sys.exit("Abgebrochen.")
    adb = install_platform_tools(args.zip)
    print(f"adb installiert: {adb}")
    if not iocs.ioc_path().exists():
        cmd_update_ioc(args)


def cmd_watch(args):
    from functools import partial
    from .watch import watch
    _check_prerequisites(args)
    scan = partial(scan_device, check_apks=not args.no_apk_check, malwarebazaar=args.malwarebazaar)
    watch(Path(args.cases), None if args.no_dashboard else args.port, scan)


def cmd_fix(args):
    from . import fix
    cases = Path(args.cases)
    if args.undo:
        fix.run_undo(Path(args.undo), cases)
        return
    devices = [d for d in list_devices() if d["state"] == "device"]
    if args.serial:
        devices = [d for d in devices if d["serial"] == args.serial]
    if len(devices) != 1:
        sys.exit("Genau ein angeschlossenes, freigegebenes Handy nötig (oder --serial angeben)."
                 if devices else "Kein freigegebenes Handy gefunden. Anstecken, entsperren, USB-Debugging zulassen.")
    serial = devices[0]["serial"]
    scan_dir = fix.latest_scan(cases, serial)
    if not scan_dir:
        sys.exit(f"Für {serial} gibt es noch keinen Scan. Erst: python -m famcheck scan")
    started = json.loads((scan_dir / "findings.json").read_text(encoding="utf-8"))["meta"]["started"]
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(started)).days
    if age >= 1:
        print(f"! Der letzte Scan ist {age} Tag(e) alt. Empfehlung: erst neu scannen, damit die Liste aktuell ist.")
    fix.run_fix(serial, scan_dir, cases, dry_run=args.dry_run)


def cmd_serve(args):
    from .web import serve
    serve(Path(args.cases), args.port)


def _scan_options(p):
    p.add_argument("--no-apk-check", action="store_true",
                   help="App-Dateien aus fremder Quelle nicht vom Handy holen und prüfen (schneller)")
    p.add_argument("--malwarebazaar", action="store_true",
                   help="Hashes dieser App-Dateien zusätzlich online bei MalwareBazaar prüfen "
                        "(nur der Hash wird gesendet; braucht FAMCHECK_ABUSECH_KEY)")


def main():
    parser = argparse.ArgumentParser(prog="famcheck", description=__doc__)
    sub = parser.add_subparsers(required=True)

    p = sub.add_parser("scan", help="Verbundene Geräte scannen (nur lesend)")
    p.add_argument("--serial", help="Nur dieses Gerät")
    p.add_argument("--all", action="store_true", help="Alle verbundenen Geräte nacheinander")
    p.add_argument("--label", help="Name für den Bericht, z. B. 'Handy Papa'")
    p.add_argument("--cases", default="cases", help="Ordner für Scan-Ergebnisse")
    _scan_options(p)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("update-ioc", help="Indikatorlisten (Echap + MVT) aktualisieren")
    p.set_defaults(func=cmd_update_ioc)

    p = sub.add_parser("diff", help="Zwei Scans desselben Geräts vergleichen")
    p.add_argument("old")
    p.add_argument("new")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("setup", help=f"adb automatisch installieren (nach {tools_dir()})")
    p.add_argument("--yes", action="store_true", help="Nicht nachfragen")
    p.add_argument("--zip", help=argparse.SUPPRESS)  # local zip/URL, for tests
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("watch", help="Plug & Play: auf Handys warten und automatisch scannen")
    p.add_argument("--cases", default="cases", help="Ordner für Scan-Ergebnisse")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-dashboard", action="store_true", help="Kein Dashboard/Browser starten")
    _scan_options(p)
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("fix", help="Befunde am Handy beheben (mit Rückfrage, umkehrbar)")
    p.add_argument("--serial", help="Nur dieses Gerät")
    p.add_argument("--cases", default="cases", help="Ordner mit Scan-Ergebnissen")
    p.add_argument("--dry-run", action="store_true", help="Nur zeigen, was passieren würde")
    p.add_argument("--undo", metavar="FIX_ORDNER", help="Einen früheren fix-Durchlauf rückgängig machen")
    p.set_defaults(func=cmd_fix)

    p = sub.add_parser("serve", help="Monitoring-Dashboard auf localhost starten")
    p.add_argument("--cases", default="cases", help="Ordner mit Scan-Ergebnissen")
    p.add_argument("--port", type=int, default=8765)
    p.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):  # redirected output on Windows must not crash on "→" or "⚠"
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    try:
        args.func(args)
    except AdbError as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
