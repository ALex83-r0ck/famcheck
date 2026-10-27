"""Writes the HTML report and compares two scans."""

import json
from html import escape
from pathlib import Path

from .analyze import SENSITIVE, app_readable
from .style import CSS, HEADLINE, ICON, SEV_KEY, SEV_LABEL, chips, uploads_html, worst


def render_html(meta: dict, data: dict, findings: list[dict], back: str | None = None) -> str:
    """The scan report: everything this one scan found, without any later triage."""
    p = data["props"]
    w = worst(findings)
    rows = "".join(
        f"<div class='finding'><span class='chip s-{SEV_KEY.get(f['severity'], 'ok')}'>"
        f"{SEV_LABEL.get(SEV_KEY.get(f['severity']), 'Info')}</span>"
        f"<b>{escape(f['title'])}</b><span class='a'>{escape(f['detail'])}<br>→ {escape(f['action'])}</span></div>"
        for f in findings) or "<p class='muted' style='margin:0'>Keine Auffälligkeiten gefunden.</p>"

    def icon(a):
        return {True: "ja", False: "nein"}.get(a.get("has_launcher_icon"), "?")

    app_rows = "".join(
        f"<tr><td class='mono'>{escape(pkg)}</td><td class='mono'>{escape(a['installer'] or '–')}</td>"
        f"<td>{icon(a)}</td><td class='num'>{escape(a.get('first_install') or '')}</td>"
        f"<td class='num'>{len(a['granted'])}</td></tr>"
        for pkg, a in sorted(data["apps"].items()))
    nav = f"<p style='margin:0 0 8px'><a href='{escape(back)}'>← Zum Gerät im Dashboard</a></p>" if back else ""
    model = f"{p.get('ro.product.manufacturer', '')} {p.get('ro.product.model', '')}".strip()
    return f"""<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FamCheck-Bericht – {escape(meta['label'])}</title><style>{CSS}</style></head><body><main>
<div class="panel">{nav}
<h2 style="font-size:1.3rem;margin:0">Scan-Bericht: {escape(meta['label'])}</h2>
<div class="muted small">{escape(model)} · Android {escape(p.get('ro.build.version.release', '?'))} ·
Patch <span class="num">{escape(p.get('ro.build.version.security_patch', '?'))}</span> ·
<span class="mono">{escape(meta['serial'])}</span></div>
<div class="muted small">Scan {escape(meta['started'][:16].replace('T', ' '))} UTC · FamCheck {escape(meta['tool_version'])} ·
Indikatorliste SHA-256 <span class="mono">{escape(meta['ioc_sha256'][:16])}…</span></div>
<div class="state s-{w}" style="margin-top:12px"><span class="big d-{w}">{ICON[w]}</span>{HEADLINE[w]}</div>
<div style="margin-top:8px">{chips(findings)}</div>
<p class="muted small" style="margin:10px 0 0">So, wie dieser Scan es gefunden hat, ohne spätere Einordnung.
Heuristiken: „Kein Befund“ heißt nicht „garantiert sauber“, ein Befund heißt nicht automatisch „Spyware“.</p>
</div>
<div class="panel"><h2>Befunde ({len(findings)})</h2>{rows}</div>
{uploads_html(data)}
<div class="panel"><h2>Installierte Apps ({len(data['apps'])})</h2><div class="scroll"><table>
<tr><th>Paket</th><th>Installiert über</th><th>App-Symbol</th><th>Erstinstallation</th><th>Rechte</th></tr>
{app_rows}</table></div></div>
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
