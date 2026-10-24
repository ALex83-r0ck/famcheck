"""Writes the HTML report and compares two scans."""

import json
from html import escape
from pathlib import Path

COLORS = {"KRITISCH": "#b00020", "HOCH": "#d9480f", "MITTEL": "#e0a800",
          "NIEDRIG": "#4a7bd0", "INFO": "#888"}


def write_html(case_dir: Path, meta: dict, data: dict, findings: list[dict]) -> Path:
    p = data["props"]
    rows = "".join(
        f"<tr><td><span class='sev' style='background:{COLORS[f['severity']]}'>"
        f"{f['severity']}</span></td><td><b>{escape(f['title'])}</b><br>"
        f"{escape(f['detail'])}<br><i>→ {escape(f['action'])}</i></td></tr>"
        for f in findings
    ) or "<tr><td colspan=2>Keine Auffälligkeiten gefunden.</td></tr>"

    app_rows = "".join(
        f"<tr><td>{escape(pkg)}</td><td>{escape(a['installer'] or '–')}</td>"
        f"<td>{'ja' if a.get('has_launcher_icon') else ('nein' if a.get('has_launcher_icon') is False else '?')}</td>"
        f"<td>{escape(a.get('first_install') or '')}</td>"
        f"<td>{len(a['granted'])}</td></tr>"
        for pkg, a in sorted(data["apps"].items())
    )

    html = f"""<!doctype html><html lang="de"><head><meta charset="utf-8">
<title>FamCheck – {escape(meta['label'])}</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1000px;margin:2em auto;padding:0 1em;color:#222}}
table{{border-collapse:collapse;width:100%;margin-bottom:2em}}
td,th{{border-bottom:1px solid #ddd;padding:.5em;text-align:left;vertical-align:top}}
.sev{{color:#fff;padding:2px 6px;border-radius:4px;font-size:.8em;white-space:nowrap}}
small{{color:#666}}
</style></head><body>
<h1>FamCheck: {escape(meta['label'])}</h1>
<p>{escape(p.get('ro.product.manufacturer',''))} {escape(p.get('ro.product.model',''))} ·
Android {escape(p.get('ro.build.version.release',''))} ·
Patch {escape(p.get('ro.build.version.security_patch',''))} ·
Seriennr. {escape(meta['serial'])}<br>
<small>Scan: {escape(meta['started'])} · Werkzeug-Version {escape(meta['tool_version'])} ·
IOC-Liste SHA-256 {escape(meta['ioc_sha256'][:16])}…</small></p>
<p><small>Hinweis: Das sind Heuristiken. „Kein Befund“ heißt nicht „garantiert sauber“,
ein Befund heißt nicht automatisch „Spyware“.</small></p>
<h2>Befunde ({len(findings)})</h2><table>{rows}</table>
<h2>Installierte Apps ({len(data['apps'])})</h2>
<table><tr><th>Paket</th><th>Installiert über</th><th>App-Symbol</th><th>Erstinstallation</th><th>Rechte</th></tr>
{app_rows}</table>
</body></html>"""
    out = case_dir / "report.html"
    out.write_text(html, encoding="utf-8")
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
    return {
        "added": {p: new["apps"][p]["installer"] for p in sorted(set(new["apps"]) - set(old["apps"]))},
        "removed": sorted(set(old["apps"]) - set(new["apps"])),
        "new_permissions": {
            pkg: gained for pkg in sorted(set(old["apps"]) & set(new["apps"]))
            if (gained := sorted(set(new["apps"][pkg]["granted"]) - set(old["apps"][pkg]["granted"])))
        },
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
    return "\n".join(lines)
