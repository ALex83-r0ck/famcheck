"""Local monitoring dashboard over the scan results in the cases folder.

Binds to 127.0.0.1 only: the data shows which apps family members use.
Everything coming from a device (package names etc.) is HTML-escaped, since a
malicious app controls its own package name.
"""

import json
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from .analyze import ORDER
from .report import COLORS, ROLE_LABELS, compute_diff

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1d1f23;--muted:#667;--line:#e2e4e8;--accent:#2b59c3}
@media (prefers-color-scheme:dark){:root{--bg:#15171a;--card:#1f2226;--text:#e6e8eb;--muted:#9aa0a8;--line:#30343a;--accent:#7aa2ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
h1{font-size:1.5em;margin:0 0 4px} h2{font-size:1.15em;margin:28px 0 10px}
.muted{color:var(--muted);font-size:.9em}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px;margin-top:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.card h3{margin:0 0 2px;font-size:1.1em}
.sev{color:#fff;padding:1px 7px;border-radius:4px;font-size:.78em;white-space:nowrap;display:inline-block;margin:2px 4px 2px 0}
.ok{color:#2e7d32;font-weight:600}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
td,th{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:.85em;color:var(--muted);font-weight:600}
.change{border-left:4px solid #d9480f}
.scroll{overflow-x:auto}
"""


def load_cases(cases_root: Path) -> dict[str, list[dict]]:
    """serial -> scans (oldest first). Each scan: {dir, meta, findings}."""
    devices: dict[str, list[dict]] = {}
    if not cases_root.is_dir():
        return devices
    for case_dir in cases_root.iterdir():
        f = case_dir / "findings.json"
        if not (f.is_file() and (case_dir / "data.json").is_file()):
            continue
        content = json.loads(f.read_text(encoding="utf-8"))
        devices.setdefault(content["meta"]["serial"], []).append(
            {"dir": case_dir, "meta": content["meta"], "findings": content["findings"]})
    for scans in devices.values():
        scans.sort(key=lambda s: s["meta"]["started"])
    return devices


def _time(iso: str) -> str:
    return iso.replace("T", " ").replace("+00:00", " UTC")


def _badges(findings: list[dict]) -> str:
    counts = {s: sum(f["severity"] == s for f in findings) for s in ORDER}
    shown = [f"<span class='sev' style='background:{COLORS[s]}'>{s} {n}</span>"
             for s, n in counts.items() if n and s != "INFO"]
    return "".join(shown) or "<span class='ok'>keine Befunde</span>"


def _page(title: str, body: str) -> str:
    return (f"<!doctype html><html lang='de'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<meta http-equiv='refresh' content='60'><title>{escape(title)}</title>"
            f"<style>{CSS}</style></head><body><main>{body}</main></body></html>")


def _diff_html(case_old: Path, case_new: Path) -> str:
    old = json.loads((case_old / "data.json").read_text(encoding="utf-8"))
    new = json.loads((case_new / "data.json").read_text(encoding="utf-8"))
    d = compute_diff(old, new)
    rows = [f"<tr class='change'><td>Neu installiert</td><td>{escape(p)}</td>"
            f"<td>über {escape(i or 'unbekannt (APK/ADB)')}</td></tr>" for p, i in d["added"].items()]
    rows += [f"<tr><td>Entfernt</td><td>{escape(p)}</td><td></td></tr>" for p in d["removed"]]
    rows += [f"<tr class='change'><td>Neue Rechte</td><td>{escape(p)}</td>"
             f"<td>{escape(', '.join(g))}</td></tr>" for p, g in d["new_permissions"].items()]
    rows += [f"<tr class='change'><td>Neu bei {ROLE_LABELS[k]}</td><td>{escape(', '.join(v))}</td><td></td></tr>"
             for k, v in d["new_roles"].items()]
    if not rows:
        return "<p class='muted'>Keine Änderungen seit dem vorherigen Scan.</p>"
    return ("<div class='scroll'><table><tr><th>Art</th><th>Paket</th><th>Details</th></tr>"
            + "".join(rows) + "</table></div>")


def render_overview(devices: dict[str, list[dict]]) -> str:
    if not devices:
        return _page("FamCheck", "<h1>FamCheck</h1><p>Noch keine Scans. Starte mit "
                     "<code>python -m famcheck scan</code>.</p>")
    cards = []
    for serial, scans in sorted(devices.items(), key=lambda kv: kv[1][-1]["meta"]["label"].lower()):
        last = scans[-1]
        changes = ""
        if len(scans) > 1:
            d = compute_diff(*(json.loads((s["dir"] / "data.json").read_text(encoding="utf-8"))
                               for s in scans[-2:]))
            n = len(d["added"]) + len(d["new_permissions"]) + sum(map(len, d["new_roles"].values()))
            changes = f"<br><b>{n} Änderung(en)</b> seit vorherigem Scan" if n else ""
        cards.append(
            f"<div class='card'><h3><a href='/device/{escape(serial)}'>{escape(last['meta']['label'])}</a></h3>"
            f"<div class='muted'>{escape(serial)} · {len(scans)} Scan(s)<br>"
            f"Letzter Scan: {escape(_time(last['meta']['started']))}</div>"
            f"<div style='margin-top:8px'>{_badges(last['findings'])}{changes}</div></div>")
    return _page("FamCheck", "<h1>FamCheck</h1><div class='muted'>Übersicht aller gescannten Geräte "
                 "(aktualisiert sich jede Minute)</div><div class='grid'>" + "".join(cards) + "</div>")


def render_device(serial: str, scans: list[dict]) -> str:
    last = scans[-1]
    findings = "".join(
        f"<tr><td><span class='sev' style='background:{COLORS[f['severity']]}'>{f['severity']}</span></td>"
        f"<td><b>{escape(f['title'])}</b><br>{escape(f['detail'])}<br>"
        f"<span class='muted'>→ {escape(f['action'])}</span></td></tr>"
        for f in last["findings"]) or "<tr><td colspan=2>Keine Befunde.</td></tr>"
    history = "".join(
        f"<tr><td>{escape(_time(s['meta']['started']))}</td><td>{_badges(s['findings'])}</td>"
        f"<td><a href='/report/{escape(s['dir'].name)}'>Bericht</a></td></tr>"
        for s in reversed(scans))
    diff = (_diff_html(scans[-2]["dir"], last["dir"]) if len(scans) > 1
            else "<p class='muted'>Erst ein Scan vorhanden, noch kein Vergleich möglich.</p>")
    body = (f"<p><a href='/'>← Übersicht</a></p><h1>{escape(last['meta']['label'])}</h1>"
            f"<div class='muted'>{escape(serial)}</div>"
            f"<h2>Änderungen seit vorherigem Scan</h2>{diff}"
            f"<h2>Befunde letzter Scan</h2><div class='scroll'><table>{findings}</table></div>"
            f"<h2>Verlauf</h2><div class='scroll'><table><tr><th>Zeit</th><th>Befunde</th>"
            f"<th></th></tr>{history}</table></div>")
    return _page(f"FamCheck – {last['meta']['label']}", body)


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
            if path.startswith("/device/"):
                serial = path[len("/device/"):]
                if serial in devices:
                    return self._send(200, render_device(serial, devices[serial]))
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
