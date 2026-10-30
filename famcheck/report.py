"""Writes the HTML report and compares two scans."""

import json
from datetime import date
from html import escape
from pathlib import Path
from urllib.parse import quote

from .analyze import SENSITIVE, TRUSTED_STORES, app_readable
from .guides import steps_html
from .style import CSS, HEADLINE, ICON, SEV_KEY, SEV_LABEL, chips, local_time, uploads_html, worst


VT_URL = "https://www.virustotal.com/gui/file/"
PLAY_URL = "https://play.google.com/store/apps/details?id="
GALAXY_URL = "https://galaxystore.samsung.com/detail/"
NEW_DAYS = 14  # apps installed this shortly before the scan are highlighted
OTHER_INSTALLERS = {  # not a store, but say what it is instead of a package name
    None: "unbekannt (APK-Datei oder USB)",
    "com.android.shell": "per USB-Kabel (ADB)",
    "com.android.packageinstaller": "APK-Datei",
    "com.google.android.packageinstaller": "APK-Datei",
    "com.facebook.system": "Facebook-Installer (vom Hersteller)",
}


def source_label(installer: str | None) -> tuple[str, bool]:
    """(plain-language source, from a foreign source?) – foreign means the same as in analyze."""
    if installer in TRUSTED_STORES:
        return TRUSTED_STORES[installer], False
    return OTHER_INSTALLERS.get(installer, installer or ""), True


def install_info(first_install: str | None, scan_started: str) -> tuple[str, bool]:
    """(text for the table, installed shortly before the scan?). Android stamps apps that came with
    the phone with a date around 2009 (start of Android), which only confuses."""
    if not first_install:
        return "–", False
    try:
        day = date.fromisoformat(first_install[:10])
    except ValueError:
        return first_install, False
    if day.year < 2010:
        return "ab Werk", False
    age = (date.fromisoformat(scan_started[:10]) - day).days
    return f"{day:%d.%m.%Y}{first_install[10:16]}", -1 <= age <= NEW_DAYS


def store_link(pkg: str, installer: str | None) -> str:
    url = (GALAXY_URL if installer == "com.sec.android.app.samsungapps" else PLAY_URL) + quote(pkg)
    name = "Galaxy Store" if installer == "com.sec.android.app.samsungapps" else "Play Store"
    return (f"<a class='applinks' href='{escape(url)}' target='_blank' rel='noopener noreferrer' "
            f"title='Name, Entwickler und Bewertungen im {name} ansehen'>{name}</a>")


def apps_html(data: dict, scan_started: str, interactive: bool = False) -> str:
    """App table, newest first. interactive: filter buttons (dashboard only, they need app.js)."""
    rows, counts = [], {"all": 0, "new": 0, "foreign": 0, "noicon": 0, "sensitive": 0}

    def check_link(a):
        files = (a.get("apk") or {}).get("files", [])
        f = next((f for f in files if f["path"].endswith("/base.apk") and f.get("sha256")),
                 next((f for f in files if f.get("sha256")), None))
        if not f:
            return "–"
        return (f"<a href='{VT_URL}{escape(f['sha256'])}' target='_blank' rel='noopener noreferrer' "
                f"title='SHA-256 {escape(f['sha256'])}'>VirusTotal</a>")

    def newest_first(item):
        a = item[1]
        stamp = a.get("first_install") or ""
        return ("" if stamp[:4] < "2010" else stamp, item[0])

    for pkg, a in sorted(sorted(data["apps"].items()), key=newest_first, reverse=True):
        source, foreign = source_label(a["installer"])
        installed, new = install_info(a.get("first_install"), scan_started)
        sensitive = sorted({SENSITIVE[p] for p in a["granted"] if p in SENSITIVE})
        noicon = a.get("has_launcher_icon") is False
        flags = {"new": new, "foreign": foreign, "noicon": noicon, "sensitive": bool(sensitive)}
        counts["all"] += 1
        for k, v in flags.items():
            counts[k] += v
        attrs = " ".join(f"data-{k}" for k, v in flags.items() if v)
        icon = {True: "ja", False: "<b>nein</b>"}.get(a.get("has_launcher_icon"), "?")
        rights = str(len(a["granted"])) + (
            f" <span class='chip s-mid' title='{escape(', '.join(sensitive))}'>{len(sensitive)} heikel</span>"
            if sensitive else "")
        new_chip = " <span class='chip s-high'>neu</span>" if new else ""
        foreign_chip = "<span class='chip s-mid'>fremde Quelle</span> " if foreign else ""
        rows.append(
            f"<tr{' class=app-new' if new else ''} data-app data-name='{escape(pkg)}' "
            f"data-installed='{escape(newest_first((pkg, a))[0])}' {attrs}>"
            f"<td><span class='mono'>{escape(pkg)}</span>{new_chip}{store_link(pkg, a['installer'])}</td>"
            f"<td>{foreign_chip}{escape(source)}</td>"
            f"<td>{icon}</td><td class='num'>{escape(installed)}</td><td class='num'>{rights}</td>"
            f"<td>{check_link(a)}</td></tr>")

    bar = ""
    if interactive:
        names = {"all": "Alle", "new": "Neu", "foreign": "Fremde Quelle", "noicon": "Ohne App-Symbol",
                 "sensitive": "Mit heiklen Rechten"}
        buttons = "".join(f"<button type='button' data-app-filter='{k}' aria-pressed='{str(k == 'all').lower()}'>"
                          f"{n} {counts[k]}</button>" for k, n in names.items() if k == "all" or counts[k])
        bar = (f"<div class='apps-bar js-only' role='group' aria-label='Apps filtern'>{buttons}"
               "<select id='app-sort' aria-label='Sortierung'><option value='installed'>Neueste zuerst</option>"
               "<option value='name'>Nach Name</option></select></div>")
    return (f"<div class='panel'><h2>Installierte Apps ({len(data['apps'])})</h2>"
            f"<p class='muted small' style='margin:0 0 8px'>Neueste zuerst. <b>Neu</b> = in den {NEW_DAYS} Tagen vor "
            f"dem Scan installiert. „Play Store“ zeigt Name, Entwickler und Bewertungen der App.</p>{bar}"
            "<div class='scroll'><table data-apps><tr><th>App</th><th>Installiert über</th><th>App-Symbol</th>"
            f"<th>Installiert am</th><th>Rechte</th><th>Prüfen</th></tr>{''.join(rows)}</table></div>"
            "<p class='muted small' style='margin:10px 0 0'>„VirusTotal“ öffnet die Prüfung der App-Datei. Dabei wird "
            "nur ihr Fingerabdruck (SHA-256) übertragen, keine Datei und keine persönlichen Daten. Viele rote "
            "Treffer = Schadsoftware; „nicht gefunden“ ist kein Freispruch.</p></div>")


def render_html(meta: dict, data: dict, findings: list[dict], back: str | None = None) -> str:
    """The scan report: everything this one scan found, without any later triage."""
    p = data["props"]
    w = worst(findings)
    rows = "".join(
        f"<div class='finding'><span class='chip s-{SEV_KEY.get(f['severity'], 'ok')}'>"
        f"{SEV_LABEL.get(SEV_KEY.get(f['severity']), 'Info')}</span>"
        f"<b>{escape(f['title'])}</b><span class='a'>{escape(f['detail'])}<br>→ {escape(f['action'])}</span>"
        f"{steps_html(f, p, findings)}</div>"
        for f in findings) or "<p class='muted' style='margin:0'>Keine Auffälligkeiten gefunden.</p>"

    # the stored report.html is a plain file without scripts; inside the dashboard app.js adds the filters
    script = "<script src='/static/app.js' defer></script>" if back else ""
    nav = f"<p style='margin:0 0 8px'><a href='{escape(back)}'>← Zum Gerät im Dashboard</a></p>" if back else ""
    model = f"{p.get('ro.product.manufacturer', '')} {p.get('ro.product.model', '')}".strip()
    return f"""<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FamCheck-Bericht – {escape(meta['label'])}</title><style>{CSS}</style>{script}</head><body><main>
<div class="panel">{nav}
<h2 style="font-size:1.3rem;margin:0">Scan-Bericht: {escape(meta['label'])}</h2>
<div class="muted small">{escape(model)} · Android {escape(p.get('ro.build.version.release', '?'))} ·
Patch <span class="num">{escape(p.get('ro.build.version.security_patch', '?'))}</span> ·
<span class="mono">{escape(meta['serial'])}</span></div>
<div class="muted small">Scan {escape(local_time(meta['started']))} · FamCheck {escape(meta['tool_version'])} ·
Indikatorliste SHA-256 <span class="mono">{escape(meta['ioc_sha256'][:16])}…</span></div>
<div class="state s-{w}" style="margin-top:12px"><span class="big d-{w}">{ICON[w]}</span>{HEADLINE[w]}</div>
<div style="margin-top:8px">{chips(findings)}</div>
<p class="muted small" style="margin:10px 0 0">So, wie dieser Scan es gefunden hat, ohne spätere Einordnung.
Heuristiken: „Kein Befund“ heißt nicht „garantiert sauber“, ein Befund heißt nicht automatisch „Spyware“.</p>
</div>
<div class="panel"><h2>Befunde ({len(findings)})</h2>{rows}</div>
{uploads_html(data)}
{apps_html(data, meta['started'], interactive=bool(back))}
</main></body></html>"""


def write_html(case_dir: Path, meta: dict, data: dict, findings: list[dict]) -> Path:
    out = case_dir / "report.html"
    out.write_text(render_html(meta, data, findings), encoding="utf-8")
    return out


ROLE_LABELS = {"accessibility": "Bedienungshilfen", "notification_listeners": "Benachrichtigungszugriff",
               "device_admins": "Geräteadministratoren", "battery_exempt": "Akku-Ausnahmen"}


def compute_diff(old: dict, new: dict) -> dict:
    """Structured changes between two data.json contents of the same device.

    Keys missing in the older scan (added in a later FamCheck version) are not reported as changes.
    """
    def total_accounts(d):
        return sum((d.get("accounts") or {}).values())

    owner_new = new.get("device_owner")
    both = sorted(set(old["apps"]) & set(new["apps"]))
    # an app whose data could not be read in one of the scans would show all its rights as "new"
    comparable = [p for p in both if app_readable(old["apps"][p]) and app_readable(new["apps"][p])]
    return {
        "added": {p: new["apps"][p]["installer"] for p in sorted(set(new["apps"]) - set(old["apps"]))},
        "removed": sorted(set(old["apps"]) - set(new["apps"])),
        # Only rights that let an app see or record private data; app updates add harmless ones all the time.
        "new_permissions": {
            pkg: gained for pkg in comparable
            if (gained := sorted(SENSITIVE[p] for p in set(new["apps"][pkg]["granted"]) - set(old["apps"][pkg]["granted"])
                                 if p in SENSITIVE))
        },
        "not_comparable": len(both) - len(comparable),
        "new_roles": {
            key: items for key in ROLE_LABELS
            if key in old and key in new and (items := sorted(set(new[key]) - set(old[key])))
        },
        "accounts_added": (max(0, total_accounts(new) - total_accounts(old)) if "accounts" in old else 0),
        "new_device_owner": owner_new if "device_owner" in old and owner_new != old.get("device_owner") else None,
    }


def diff_scans(old_dir: Path, new_dir: Path) -> str:
    old = json.loads((old_dir / "data.json").read_text(encoding="utf-8"))
    new = json.loads((new_dir / "data.json").read_text(encoding="utf-8"))
    d = compute_diff(old, new)
    lines = [f"Vergleich {old_dir.name}  →  {new_dir.name}", ""]
    lines += ["Neu installiert:"] + [f"  + {p}  (über {i or '?'})" for p, i in d["added"].items()]
    lines += ["Entfernt:"] + [f"  - {p}" for p in d["removed"]]
    for pkg, gained in d["new_permissions"].items():
        lines.append(f"Neue Rechte für {pkg}: {', '.join(gained)}")
    for key, items in d["new_roles"].items():
        lines.append(f"Neu bei {ROLE_LABELS[key]}: {', '.join(items)}")
    if d["accounts_added"]:
        lines.append(f"Neue Konten auf dem Gerät: {d['accounts_added']}")
    if d["new_device_owner"]:
        lines.append(f"Neue Geräteverwaltung: {d['new_device_owner']}")
    if d["not_comparable"]:
        lines.append(f"Nicht vergleichbar (Daten in einem Scan unlesbar): {d['not_comparable']} Apps")
    return "\n".join(lines)
