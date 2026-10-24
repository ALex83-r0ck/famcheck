"""Local monitoring dashboard over the scan results in the cases folder.

Binds to 127.0.0.1 only: the data shows which apps family members use.
Everything coming from a device (package names etc.) is HTML-escaped, since a
malicious app controls its own package name.
"""

import json
from datetime import date, datetime, timedelta, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from .report import ROLE_LABELS, compute_diff

SEV_KEY = {"KRITISCH": "crit", "HOCH": "high", "MITTEL": "mid", "NIEDRIG": "low"}
SEV_LABEL = {"crit": "Kritisch", "high": "Hoch", "mid": "Mittel", "low": "Niedrig", "ok": "OK"}
HEADLINE = {"crit": "Sofort ansehen", "high": "Dringend ansehen", "mid": "Etwas prüfen",
            "low": "Kleinigkeiten", "ok": "Alles in Ordnung"}
ICON = {"crit": "!", "high": "!", "mid": "?", "low": "i", "ok": "✓"}
STALE_DAYS = 45  # a device not scanned for this long gets a hint

_TOKENS_DARK = """--bg:#12171c;--surface:#1b2229;--sunken:#151b21;--fg:#e4e9ee;--muted:#93a1ad;--line:#2c353e;
--accent:#6fb7cf;--crit:#f0857c;--high:#f29a5c;--mid:#e3b84f;--low:#86a9e0;--ok:#6cc488;
--crit-soft:#3a1f1d;--high-soft:#3a2617;--mid-soft:#352b13;--low-soft:#1d2a3d;--ok-soft:#1a3122;color-scheme:dark"""

CSS = """
:root{--bg:#eef1f4;--surface:#fff;--sunken:#f5f7f9;--fg:#18212b;--muted:#5d6b78;--line:#d9dfe5;
--accent:#1d6b85;--crit:#b3261e;--high:#c4520f;--mid:#a87400;--low:#3f6fb5;--ok:#2f7d45;
--crit-soft:#fbe7e5;--high-soft:#fcebdf;--mid-soft:#fbf1d9;--low-soft:#e5edf8;--ok-soft:#e3f2e7;
--mono:ui-monospace,"Cascadia Mono",Consolas,monospace}
@media (prefers-color-scheme:dark){:root{""" + _TOKENS_DARK + """}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 48px;display:grid;gap:20px}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
a:focus-visible{outline:3px solid var(--accent);outline-offset:2px;border-radius:4px}
h1{font-size:1.5rem;margin:0} h2{font-size:1.1rem;margin:0 0 10px}
.muted{color:var(--muted)} .small{font-size:.85rem} .mono{font-family:var(--mono);font-size:.85em}
.num{font-variant-numeric:tabular-nums}
.top{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:12px}
.nav{display:flex;gap:6px}
.nav a{padding:6px 14px;border-radius:8px;border:1px solid var(--line);background:var(--surface);color:var(--fg)}
.nav a[aria-current=page]{background:var(--accent);border-color:var(--accent);color:var(--surface)}
.nav a:hover{text-decoration:none}
.summary{display:flex;flex-wrap:wrap;gap:6px}
.chip{display:inline-flex;align-items:center;font-size:.75rem;font-weight:600;border-radius:999px;padding:1px 8px;white-space:nowrap}
.s-crit{color:var(--crit);background:var(--crit-soft)} .s-high{color:var(--high);background:var(--high-soft)}
.s-mid{color:var(--mid);background:var(--mid-soft)} .s-low{color:var(--low);background:var(--low-soft)}
.s-ok{color:var(--ok);background:var(--ok-soft)}
.dot{width:12px;height:12px;border-radius:50%;display:inline-block;flex:none}
.d-crit{background:var(--crit)} .d-high{background:var(--high)} .d-mid{background:var(--mid)}
.d-low{background:var(--low)} .d-ok{background:var(--ok)}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:18px;min-width:0}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:14px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:16px;display:grid;gap:10px;align-content:start}
.card h3{margin:0;font-size:1.05rem}
.state{display:flex;align-items:center;gap:10px;border-radius:10px;padding:10px 12px;font-weight:600}
.state .big{width:30px;height:30px;border-radius:50%;display:grid;place-items:center;color:var(--surface);flex:none}
.meta{font-size:.82rem;color:var(--muted);display:grid;gap:2px}
.chg{font-size:.85rem;border-top:1px dashed var(--line);padding-top:8px}
.stale{color:var(--mid);font-weight:600}
.finding{display:grid;grid-template-columns:auto 1fr;gap:4px 10px;padding:10px 0;border-top:1px solid var(--line)}
.finding:first-child{border-top:0}
.finding .a{grid-column:2;font-size:.85rem;color:var(--muted)}
.change{display:flex;gap:8px;align-items:baseline;font-size:.9rem;padding:3px 0;flex-wrap:wrap}
.op{font-family:var(--mono);font-weight:700;width:1em}
.op-add,.op-role{color:var(--high)} .op-perm{color:var(--mid)} .op-rm{color:var(--muted)}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse}
td,th{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:middle}
th{font-size:.74rem;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);font-weight:600}
.tl-inner{min-width:680px}
.tl-row{display:grid;grid-template-columns:170px 1fr;align-items:center;border-bottom:1px solid var(--line);min-height:64px}
.tl-row .lbl small{display:block;color:var(--muted);font-size:.78rem}
.track{position:relative;height:64px;margin:0 12px}
.track::before{content:"";position:absolute;left:0;right:0;top:50%;border-top:1px dashed var(--line)}
.mark{position:absolute;top:50%;transform:translate(-50%,-50%);line-height:0}
.mark .dot{width:14px;height:14px;box-shadow:0 0 0 3px var(--surface)}
.mark .tip{position:absolute;top:18px;left:50%;transform:translateX(-50%);font-size:.7rem;line-height:1.2;white-space:nowrap;color:var(--high);font-weight:600}
.axis{display:grid;grid-template-columns:170px 1fr;font-size:.74rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.ticks{position:relative;height:22px;margin:0 12px}
.ticks span{position:absolute;transform:translateX(-50%)}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:.8rem;color:var(--muted);margin-top:14px}
.legend span{display:flex;align-items:center;gap:6px}
"""


def load_cases(cases_root: Path) -> dict[str, list[dict]]:
    """serial -> scans (oldest first). Each scan: {dir, meta, findings, data, diff (to previous or None)}."""
    devices: dict[str, list[dict]] = {}
    if not cases_root.is_dir():
        return devices
    for case_dir in cases_root.iterdir():
        f, d = case_dir / "findings.json", case_dir / "data.json"
        if not (f.is_file() and d.is_file()):
            continue
        content = json.loads(f.read_text(encoding="utf-8"))
        devices.setdefault(content["meta"]["serial"], []).append(
            {"dir": case_dir, "meta": content["meta"], "findings": content["findings"],
             "data": json.loads(d.read_text(encoding="utf-8"))})
    for scans in devices.values():
        scans.sort(key=lambda s: s["meta"]["started"])
        for prev, cur in zip([None] + scans, scans):
            cur["diff"] = compute_diff(prev["data"], cur["data"]) if prev else None
    return devices


def _started(scan: dict) -> datetime:
    return datetime.fromisoformat(scan["meta"]["started"])


def _ago(dt: datetime, now: datetime) -> str:
    days = (now.date() - dt.date()).days
    if days <= 0:
        return "heute"
    if days == 1:
        return "gestern"
    if days < 14:
        return f"vor {days} Tagen"
    if days < 60:
        return f"vor {days // 7} Wochen"
    return f"vor {days // 30} Monaten"


def _worst(findings: list[dict]) -> str:
    keys = [SEV_KEY[f["severity"]] for f in findings if f["severity"] in SEV_KEY]
    return min(keys, key=list(HEADLINE).index) if keys else "ok"


def _chips(findings: list[dict]) -> str:
    out = []
    for sev, key in SEV_KEY.items():
        n = sum(f["severity"] == sev for f in findings)
        if n:
            out.append(f"<span class='chip s-{key}'>{SEV_LABEL[key]} {n}</span>")
    return " ".join(out) or "<span class='chip s-ok'>Keine Befunde</span>"


def _change_count(diff: dict | None) -> tuple[int, int, int]:
    """(new apps, new rights/roles/accounts/owner, removed apps)"""
    if not diff:
        return 0, 0, 0
    other = (sum(map(len, diff["new_roles"].values())) + len(diff["new_permissions"])
             + diff.get("accounts_added", 0) + bool(diff.get("new_device_owner")))
    return len(diff["added"]), other, len(diff["removed"])


def _change_line(diff: dict | None) -> str:
    if diff is None:
        return "<span class='muted'>Erster Scan, noch kein Vergleich</span>"
    added, perms, removed = _change_count(diff)
    parts = []
    if added:
        parts.append(f"<b>{added} neue App{'s' if added > 1 else ''}</b>")
    if perms:
        parts.append(f"<b>{perms} neue Rechte/Konten/Rollen</b>")
    if removed and not parts:
        parts.append(f"{removed} App{'s' if removed > 1 else ''} entfernt")
    if not parts:
        return "<span class='muted'>Keine Änderungen seit letztem Scan</span>"
    return ", ".join(parts) + " seit letztem Scan"


def _sorted_devices(devices: dict[str, list[dict]]) -> list[tuple[str, list[dict]]]:
    order = list(HEADLINE)
    return sorted(devices.items(), key=lambda kv: (order.index(_worst(kv[1][-1]["findings"])),
                                                   kv[1][-1]["meta"]["label"].lower()))


def _page(title: str, active: str, body: str, devices: dict) -> str:
    counts: dict[str, int] = {}
    for scans in devices.values():
        w = _worst(scans[-1]["findings"])
        counts[w] = counts.get(w, 0) + 1
    summary = "".join(f"<span class='chip s-{k}'>{counts[k]} × {HEADLINE[k]}</span>"
                      for k in HEADLINE if counts.get(k))
    nav = "".join(f"<a href='{href}'{' aria-current=page' if key == active else ''}>{label}</a>"
                  for key, href, label in (("overview", "/", "Übersicht"), ("history", "/verlauf", "Verlauf")))
    return (f"<!doctype html><html lang='de'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<meta http-equiv='refresh' content='60'><title>{escape(title)}</title>"
            f"<style>{CSS}</style></head><body><main>"
            f"<div class='top'><h1>FamCheck</h1><nav class='nav'>{nav}</nav></div>"
            f"<div class='summary'>{summary}</div>{body}</main></body></html>")


def render_overview(devices: dict[str, list[dict]], now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    if not devices:
        return _page("FamCheck", "overview", "<div class='panel'>Noch keine Scans. Starte "
                     "<code>python -m famcheck watch</code> und stecke ein Handy an.</div>", devices)
    cards = []
    for serial, scans in _sorted_devices(devices):
        last = scans[-1]
        props = last["data"]["props"]
        w = _worst(last["findings"])
        model = f"{props.get('ro.product.manufacturer', '')} {props.get('ro.product.model', '')}".strip()
        stale = ((now - _started(last)).days >= STALE_DAYS and
                 f"<span class='stale'>Lange nicht gescannt</span>") or ""
        cards.append(
            f"<article class='card'>"
            f"<div><h3><a href='/device/{escape(serial)}'>{escape(last['meta']['label'])}</a></h3>"
            f"<div class='muted small'>{escape(model)}</div></div>"
            f"<div class='state s-{w}'><span class='big d-{w}'>{ICON[w]}</span>{HEADLINE[w]}</div>"
            f"<div>{_chips(last['findings'])}</div>"
            f"<div class='meta'><span>Letzter Scan: {_ago(_started(last), now)} {stale}</span>"
            f"<span>Sicherheitspatch: <span class='num'>{escape(props.get('ro.build.version.security_patch', '?'))}</span></span></div>"
            f"<div class='chg'>{_change_line(last['diff'])}</div></article>")
    return _page("FamCheck", "overview", f"<div class='cards'>{''.join(cards)}</div>", devices)


def render_history(devices: dict[str, list[dict]], now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    if not devices:
        return _page("FamCheck – Verlauf", "history", "<div class='panel'>Noch keine Scans.</div>", devices)
    first = min(_started(s) for scans in devices.values() for s in scans)
    start = min(first - timedelta(days=3), now - timedelta(days=30))
    end = now + timedelta(days=3)
    span = (end - start).total_seconds()

    def pos(dt: datetime) -> str:
        return f"{(dt - start).total_seconds() / span * 100:.2f}"

    ticks, month = [], date(start.year, start.month, 1)
    month_names = "Jan Feb Mär Apr Mai Jun Jul Aug Sep Okt Nov Dez".split()
    while True:
        month = date(month.year + month.month // 12, month.month % 12 + 1, 1)
        dt = datetime(month.year, month.month, 1, tzinfo=timezone.utc)
        if dt > end:
            break
        ticks.append(f"<span style='left:{pos(dt)}%'>{month_names[month.month - 1]}</span>")

    rows = []
    for serial, scans in _sorted_devices(devices):
        marks = []
        for s in scans:
            w = _worst(s["findings"])
            added, perms, _ = _change_count(s["diff"])
            tip = " ".join(x for x in (f"+{added} App{'s' if added > 1 else ''}" if added else "",
                                       f"+{perms} Rechte/Konten" if perms else "") if x)
            title = f"{s['meta']['started'][:10]}: {HEADLINE[w]}"
            marks.append(f"<a class='mark' style='left:{pos(_started(s))}%' href='/report/{escape(s['dir'].name)}' "
                         f"title='{escape(title)}' aria-label='{escape(title)}'><span class='dot d-{w}'></span>"
                         + (f"<span class='tip'>{escape(tip)}</span>" if tip else "") + "</a>")
        w = _worst(scans[-1]["findings"])
        rows.append(f"<div class='tl-row'><div class='lbl'><a href='/device/{escape(serial)}'>"
                    f"{escape(scans[-1]['meta']['label'])}</a><small>{HEADLINE[w]}</small></div>"
                    f"<div class='track'>{''.join(marks)}</div></div>")
    legend = "".join(f"<span><i class='dot d-{k}'></i>{SEV_LABEL[k]}</span>" for k in HEADLINE)
    body = (f"<div class='panel'><div class='scroll'><div class='tl-inner'>"
            f"<div class='axis'><span></span><div class='ticks'>{''.join(ticks)}</div></div>{''.join(rows)}"
            f"</div></div><div class='legend'>{legend}<span>Jeder Punkt ist ein Scan (Klick öffnet den Bericht), "
            f"Farbe = schwerster Befund</span></div></div>")
    return _page("FamCheck – Verlauf", "history", body, devices)


def _diff_html(diff: dict) -> str:
    rows = [f"<div class='change'><span class='op op-add'>+</span><span class='mono'>{escape(p)}</span>"
            f"<span class='muted'>neu installiert über {escape(i or 'unbekannt (APK/ADB)')}</span></div>"
            for p, i in diff["added"].items()]
    rows += [f"<div class='change'><span class='op op-perm'>!</span><span class='mono'>{escape(p)}</span>"
             f"<span class='muted'>neue Rechte: {escape(', '.join(g))}</span></div>"
             for p, g in diff["new_permissions"].items()]
    rows += [f"<div class='change'><span class='op op-role'>!</span><span class='mono'>{escape(', '.join(v))}</span>"
             f"<span class='muted'>neu bei {ROLE_LABELS[k]}</span></div>" for k, v in diff["new_roles"].items()]
    if diff.get("accounts_added"):
        rows.append(f"<div class='change'><span class='op op-role'>!</span><b>{diff['accounts_added']} neue(s) Konto/Konten</b>"
                    f"<span class='muted'>auf dem Gerät angemeldet</span></div>")
    if diff.get("new_device_owner"):
        rows.append(f"<div class='change'><span class='op op-role'>!</span><span class='mono'>{escape(diff['new_device_owner'])}</span>"
                    f"<span class='muted'>verwaltet jetzt das Gerät</span></div>")
    rows += [f"<div class='change'><span class='op op-rm'>−</span><span class='mono'>{escape(p)}</span>"
             f"<span class='muted'>entfernt</span></div>" for p in diff["removed"]]
    return "".join(rows) or "<p class='muted' style='margin:0'>Keine Änderungen seit dem vorherigen Scan.</p>"


def _uploads_html(data: dict, top: int = 8) -> str:
    uploads = data.get("uploads")
    if not uploads:
        return ""
    third_party = data["apps"]
    days = data.get("uploads_days")
    installed_chip = " <span class='chip s-low'>installiert</span>"
    rows = "".join(
        f"<tr><td class='mono'>{escape(', '.join(u['packages']))}"
        f"{installed_chip if any(p in third_party for p in u['packages']) else ''}</td>"
        f"<td class='num'>{u['tx'] / 1048576:,.1f} MB</td><td class='num'>{u['tx_bg'] / 1048576:,.1f} MB</td></tr>"
        for u in uploads[:top])
    period = f"letzte ~{days:.0f} Tage" if days else "erfasster Zeitraum"
    return (f"<div class='panel'><h2>Größte Uploads ({period})</h2>"
            f"<p class='muted small' style='margin:0 0 8px'>Wie viele Daten jede App ins Internet geschickt hat. "
            f"„Hintergrund“ heißt: ohne dass die App offen war.</p>"
            f"<div class='scroll'><table><tr><th>App</th><th>Gesamt</th><th>Davon Hintergrund</th></tr>"
            f"{rows}</table></div></div>")


def render_device(serial: str, scans: list[dict], devices: dict, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    last = scans[-1]
    props = last["data"]["props"]
    w = _worst(last["findings"])
    findings = "".join(
        f"<div class='finding'><span class='chip s-{SEV_KEY.get(f['severity'], 'ok')}'>"
        f"{SEV_LABEL.get(SEV_KEY.get(f['severity']), 'Info')}</span>"
        f"<b>{escape(f['title'])}</b><span class='a'>{escape(f['detail'])}<br>→ {escape(f['action'])}</span></div>"
        for f in last["findings"]) or "<p class='muted' style='margin:0'>Keine Befunde.</p>"
    history = "".join(
        f"<tr><td class='num'>{escape(s['meta']['started'][:16].replace('T', ' '))} UTC</td>"
        f"<td>{_chips(s['findings'])}</td><td class='small'>{_change_line(s['diff'])}</td>"
        f"<td><a href='/report/{escape(s['dir'].name)}'>Bericht</a></td></tr>"
        for s in reversed(scans))
    diff = (_diff_html(last["diff"]) if last["diff"] is not None
            else "<p class='muted' style='margin:0'>Erst ein Scan vorhanden, noch kein Vergleich möglich.</p>")
    body = (f"<div class='panel'><p style='margin:0 0 8px'><a href='/'>← Übersicht</a></p>"
            f"<h2 style='font-size:1.3rem;margin:0'>{escape(last['meta']['label'])}</h2>"
            f"<div class='muted small'>{escape(props.get('ro.product.manufacturer', ''))} "
            f"{escape(props.get('ro.product.model', ''))} · Android {escape(props.get('ro.build.version.release', '?'))} · "
            f"Patch <span class='num'>{escape(props.get('ro.build.version.security_patch', '?'))}</span> · "
            f"<span class='mono'>{escape(serial)}</span> · Letzter Scan {_ago(_started(last), now)}</div>"
            f"<div class='state s-{w}' style='margin-top:12px'><span class='big d-{w}'>{ICON[w]}</span>{HEADLINE[w]}</div></div>"
            f"<div class='panel'><h2>Seit letztem Scan</h2>{diff}</div>"
            f"<div class='panel'><h2>Befunde</h2>{findings}</div>"
            f"{_uploads_html(last['data'])}"
            f"<div class='panel'><h2>Alle Scans</h2><div class='scroll'><table><tr><th>Zeit</th><th>Befunde</th>"
            f"<th>Änderungen</th><th></th></tr>{history}</table></div></div>")
    return _page(f"FamCheck – {last['meta']['label']}", "", body, devices)


def make_handler(cases_root: Path, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: str, ctype="text/html; charset=utf-8"):
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            # Blocks DNS-rebinding: a foreign website must not read the dashboard.
            if self.headers.get("Host") not in allowed_hosts:
                return self._send(403, "Forbidden", "text/plain")
            devices = load_cases(cases_root)
            path = unquote(self.path.split("?")[0])

            if path == "/":
                return self._send(200, render_overview(devices))
            if path == "/verlauf":
                return self._send(200, render_history(devices))
            if path.startswith("/device/"):
                serial = path[len("/device/"):]
                if serial in devices:
                    return self._send(200, render_device(serial, devices[serial], devices))
            if path.startswith("/report/"):
                name = path[len("/report/"):]
                known = {s["dir"].name: s["dir"] for scans in devices.values() for s in scans}
                if name in known:  # only exact case-folder names, no path traversal
                    return self._send(200, (known[name] / "report.html").read_text(encoding="utf-8"))
            self._send(404, "Nicht gefunden", "text/plain")

        def log_message(self, *args):
            pass

    return Handler


def start_background(cases_root: Path, port: int) -> ThreadingHTTPServer:
    """Starts the dashboard in a daemon thread (used by 'watch')."""
    import threading
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(cases_root, port))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def serve(cases_root: Path, port: int):
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(cases_root, port))
    print(f"FamCheck-Dashboard: http://127.0.0.1:{port}  (Strg+C zum Beenden)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
