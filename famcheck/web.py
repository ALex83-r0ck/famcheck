"""Local monitoring dashboard over the scan results in the cases folder.

Binds to 127.0.0.1 only: the data shows which apps family members use.
Everything coming from a device (package names etc.) is HTML-escaped, since a
malicious app controls its own package name.
"""

import hashlib
import hmac
import json
import secrets
import socket
import sys
import webbrowser
from datetime import date, datetime, timedelta, timezone
from html import escape
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote

from . import decisions, fix, iocs
from .report import ROLE_LABELS, compute_diff, render_html
from .style import CSS, HEADLINE, ICON, SEV_KEY, SEV_LABEL
from .style import chips as _chips
from .style import uploads_html as _uploads_html
from .style import worst as _worst

STALE_DAYS = 45  # a device not scanned for this long gets a hint



def load_cases(cases_root: Path) -> dict[str, list[dict]]:
    """serial -> scans (oldest first).

    Each scan: {dir, meta, findings (raw), triaged (with decision state), counting (what the traffic light
    uses), data, diff (to previous or None)}.
    """
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
    all_decisions = decisions.load(cases_root)
    for serial, scans in devices.items():
        scans.sort(key=lambda s: s["meta"]["started"])
        for prev, cur in zip([None] + scans, scans):
            cur["diff"] = compute_diff(prev["data"], cur["data"]) if prev else None
            cur["triaged"] = decisions.annotate(cur["findings"], all_decisions.get(serial, {}), cur["meta"]["started"])
            cur["counting"] = decisions.counting(cur["triaged"])
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
    return sorted(devices.items(), key=lambda kv: (order.index(_worst(kv[1][-1]["counting"])),
                                                   kv[1][-1]["meta"]["label"].lower()))


def _page(title: str, active: str, body: str, devices: dict) -> str:
    counts: dict[str, int] = {}
    for scans in devices.values():
        w = _worst(scans[-1]["counting"])
        counts[w] = counts.get(w, 0) + 1
    summary = "".join(f"<span class='chip s-{k}'>{counts[k]} × {HEADLINE[k]}</span>"
                      for k in HEADLINE if counts.get(k))
    nav = "".join(f"<a href='{href}'{' aria-current=page' if key == active else ''}>{label}</a>"
                  for key, href, label in (("overview", "/", "Übersicht"), ("history", "/verlauf", "Verlauf")))
    return (f"<!doctype html><html lang='de'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{escape(title)}</title><style>{CSS}</style>"
            f"<script src='/static/app.js' defer></script></head><body><main>"
            f"<div class='top'><h1>FamCheck</h1><nav class='nav'>{nav}</nav></div>"
            f"{_banner()}<div class='summary'>{summary}</div>{body}</main></body></html>")


def _banner() -> str:
    warning = iocs.freshness_warning()
    return f"<div class='banner' role='status'><b>Hinweis:</b> {escape(warning)}</div>" if warning else ""


def render_overview(devices: dict[str, list[dict]], now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    if not devices:
        return _page("FamCheck", "overview", "<div class='panel'>Noch keine Scans. Starte "
                     "<code>python -m famcheck watch</code> und stecke ein Handy an.</div>", devices)
    cards = []
    for serial, scans in _sorted_devices(devices):
        last = scans[-1]
        props = last["data"]["props"]
        w = _worst(last["counting"])
        model = f"{props.get('ro.product.manufacturer', '')} {props.get('ro.product.model', '')}".strip()
        stale = ((now - _started(last)).days >= STALE_DAYS and
                 f"<span class='stale'>Lange nicht gescannt</span>") or ""
        cards.append(
            f"<article class='card'>"
            f"<div><h3><a href='/device/{escape(serial)}'>{escape(last['meta']['label'])}</a></h3>"
            f"<div class='muted small'>{escape(model)}</div></div>"
            f"<div class='state s-{w}'><span class='big d-{w}'>{ICON[w]}</span>{HEADLINE[w]}</div>"
            f"<div>{_chips(last['counting'])}</div>{_triage_line(last['triaged'])}"
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
             f"<span class='muted'>neue heikle Rechte: {escape(', '.join(g))}</span></div>"
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
    if diff.get("not_comparable"):
        rows.append(f"<div class='change'><span class='op'>?</span><b>{diff['not_comparable']} Apps nicht vergleichbar</b>"
                    f"<span class='muted'>ihre Daten waren in einem der beiden Scans nicht lesbar</span></div>")
    return "".join(rows) or "<p class='muted' style='margin:0'>Keine Änderungen seit dem vorherigen Scan.</p>"


def _triage_line(triaged: list[dict]) -> str:
    states = [f["decision_state"] for f in triaged]
    parts = []
    if states.count("suppressed"):
        parts.append(f"{states.count('suppressed')} eingeordnet")
    reopened = states.count("changed") + states.count("reopened")
    if reopened:
        parts.append(f"<span class='stale'>{reopened} wieder offen</span>")
    return f"<div class='muted small'>{' · '.join(parts)}</div>" if parts else ""


def _anchor(f: dict) -> str:
    return "f-" + hashlib.sha1(decisions.finding_key(f).encode("utf-8")).hexdigest()[:10]


def _decision_html(f: dict) -> str:
    d, state = f.get("decision"), f.get("decision_state")
    if not d:
        return ""
    when = d["at"][:10]
    note = f": „{escape(d['note'])}“" if d.get("note") else ""
    label = decisions.STATUSES[d["status"]]
    if state == "changed":
        return (f"<div class='decision warn'>Hat sich seit deiner Einordnung „{label}“ am {when} verändert "
                f"und zählt wieder{note}</div>")
    if state == "reopened":
        return f"<div class='decision warn'>Am {when} als erledigt markiert, ist aber noch da{note}</div>"
    if state == "watch":
        return f"<div class='decision'>Wird beobachtet seit {when}{note}</div>"
    if d["status"] == "done":
        return f"<div class='decision'>Am {when} als erledigt markiert, wird beim nächsten Scan kontrolliert{note}</div>"
    return f"<div class='decision'>{label} (eingeordnet am {when}){note}</div>"


STATE_TAGS = {"suppressed": ("", None), "watch": ("Beobachten", ""), "changed": ("wieder offen", "warn"),
              "reopened": ("wieder offen", "warn")}


def _finding_html(serial: str, f: dict, token: str, all_findings: list[dict], rank: int) -> str:
    key = SEV_KEY.get(f["severity"], "ok")
    sev = SEV_KEY.get(f["severity"], "info")  # for the filter, INFO stays its own group
    label = SEV_LABEL.get(SEV_KEY.get(f["severity"]), "Info")
    d = f.get("decision") or {}
    buttons = "".join(f"<button name='status' value='{v}'>{escape(t)}</button>" for v, t in decisions.STATUSES.items())
    if d:
        buttons += "<button name='status' value='reset'>Zurücksetzen</button>"
    form = (f"<form class='triage' method='post' action='/decide'>"
            f"<input type='hidden' name='token' value='{escape(token)}'>"
            f"<input type='hidden' name='serial' value='{escape(serial)}'>"
            f"<input type='hidden' name='key' value='{escape(decisions.finding_key(f))}'>"
            f"<input type='text' name='note' maxlength='{decisions.MAX_NOTE}' placeholder='Notiz (optional)' "
            f"aria-label='Notiz' value='{escape(d.get('note', ''))}'>{buttons}</form>") if token else ""
    if d and f.get("decision_state") == "suppressed":
        tag_text, tag_cls = decisions.STATUSES[d["status"]], ""
    else:
        tag_text, tag_cls = STATE_TAGS.get(f.get("decision_state"), ("", None))
    tag = f"<span class='tag {tag_cls}'>{tag_text}</span>" if tag_text else ""
    search = f"{f['title']} {f['detail']} {f.get('package') or ''}".lower()
    return (f"<details class='fx' id='{_anchor(f)}' data-sev='{sev}' data-rank='{rank}' "
            f"data-title='{escape(f['title'].lower())}' data-pkg='{escape(f.get('package') or '')}' "
            f"data-search='{escape(search)}'>"
            f"<summary><span class='chip s-{key}'>{label}</span><b>{escape(f['title'])}</b>{tag}</summary>"
            f"<div class='fbody'><span class='a'>{escape(f['detail'])}<br>→ {escape(f['action'])}</span>"
            f"{_fix_hint(serial, f, all_findings)}{_decision_html(f)}{form}</div></details>")


def _toolbar(findings: list[dict]) -> str:
    counts = {k: 0 for k in ("crit", "high", "mid", "low", "info")}
    for f in findings:
        counts[SEV_KEY.get(f["severity"], "info")] += 1
    names = {"crit": "Kritisch", "high": "Hoch", "mid": "Mittel", "low": "Niedrig", "info": "Info"}
    chips = "".join(f"<button type='button' class='chip s-{k if k != 'info' else 'ok'}' data-sev-toggle='{k}' "
                    f"aria-pressed='true'>{names[k]} {n}</button>" for k, n in counts.items() if n)
    return ("<div class='toolbar js-only' role='group' aria-label='Befunde filtern und sortieren'>"
            f"<div class='sevs'>{chips}</div>"
            "<input id='f-search' type='search' placeholder='Suchen: App oder Befund' aria-label='Befunde durchsuchen'>"
            "<select id='f-sort' aria-label='Sortierung'><option value='rank'>Nach Schwere</option>"
            "<option value='title'>Nach Titel</option><option value='pkg'>Nach App</option></select>"
            "<button type='button' class='btn' data-expand='open'>Alle auf</button>"
            "<button type='button' class='btn' data-expand='close'>Alle zu</button>"
            "<span id='f-count' class='muted small' aria-live='polite'></span></div>")


def _fix_hint(serial: str, f: dict, all_findings: list[dict]) -> str:
    kind = fix.fix_kind(f, all_findings)
    if kind == "auto":
        return (f"<div class='decision'>Behebbar im Terminal, mit Rückfrage und umkehrbar: "
                f"<code>python -m famcheck fix --serial {escape(serial)}</code></div>")
    if kind == "blocked" and f.get("package"):
        return ("<div class='decision'>Bewusst keine automatische Änderung: App mit kritischem Befund. "
                "Erst die Sicherheit der betroffenen Person klären.</div>")
    return ""


def render_device(serial: str, scans: list[dict], devices: dict, now: datetime | None = None,
                  token: str = "") -> str:
    now = now or datetime.now(timezone.utc)
    last = scans[-1]
    props = last["data"]["props"]
    w = _worst(last["counting"])
    active = [f for f in last["triaged"] if f["decision_state"] != "suppressed"]
    hidden = [f for f in last["triaged"] if f["decision_state"] == "suppressed"]
    rank = {id(f): i for i, f in enumerate(last["triaged"])}
    findings = (_toolbar(last["triaged"]) + "<div data-findings>"
                + ("".join(_finding_html(serial, f, token, last["findings"], rank[id(f)]) for f in active)
                   or "<p class='muted' style='margin:0'>Keine offenen Befunde.</p>") + "</div>")
    if hidden:
        findings += (f"<details class='triaged'><summary>Eingeordnet ({len(hidden)}), zählen nicht zur Ampel</summary>"
                     "<div data-findings>"
                     + "".join(_finding_html(serial, f, token, last["findings"], rank[id(f)]) for f in hidden)
                     + "</div></details>")
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
            f"<div class='panel'><h2>Befunde</h2><p class='muted small' style='margin:0 0 6px'>Einordnen ändert nichts "
            f"am Handy, nur wie FamCheck den Befund zählt. „Bekannt“ gilt, bis sich der Befund verändert, "
            f"„Erledigt“ bis zum nächsten Scan. Klick auf einen Befund zeigt Details.</p>{findings}</div>"
            f"{_uploads_html(last['data'])}"
            f"<div class='panel'><h2>Alle Scans</h2><p class='muted small' style='margin:0 0 6px'>Ohne Einordnung, "
            f"so wie gescannt.</p><div class='scroll'><table><tr><th>Zeit</th><th>Befunde</th>"
            f"<th>Änderungen</th><th></th></tr>{history}</table></div></div>")
    return _page(f"FamCheck – {last['meta']['label']}", "", body, devices)


COOKIE = "famcheck_session"
APP_JS = Path(__file__).parent / "static" / "app.js"


def data_version(cases_root: Path) -> str:
    """Changes whenever a scan finishes or a decision is stored; the page polls it for live updates."""
    h = hashlib.sha256()
    if cases_root.is_dir():
        for d in sorted(cases_root.iterdir()):
            f = d / "findings.json"
            if f.is_file():
                h.update(f"{d.name}:{f.stat().st_mtime_ns}\n".encode())
        dec = cases_root / "decisions.json"
        if dec.is_file():
            h.update(f"decisions:{dec.stat().st_mtime_ns}".encode())
    return h.hexdigest()[:16]

LOCKED_PAGE = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>FamCheck – Anmeldung nötig</title>
<style>%CSS%</style></head><body><main><div class="panel"><h2>Anmeldung nötig</h2>
<p>Das Dashboard zeigt private Daten und öffnet sich nur über den Link, den <code>famcheck serve</code> oder
<code>famcheck watch</code> beim Start im Terminal anzeigt und im Browser öffnet.</p>
<p class="muted small">Nach jedem Neustart des Dashboards gilt ein neuer Link.</p></div></main></body></html>"""


def make_handler(cases_root: Path, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}
    # Secret per dashboard start; forms must send it back. A foreign website cannot know it (CSRF protection).
    token = secrets.token_urlsafe(32)
    # Second secret per start: opens the dashboard at all. Only the person who started it (terminal/browser)
    # gets the login link, so other accounts or programs on the same PC cannot read the family's data.
    access_key = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: str, ctype="text/html; charset=utf-8"):
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")  # always the current state, never a stale page
            # frame-ancestors/X-Frame-Options: no foreign page may embed the dashboard (clickjacking)
            # scripts only as files from this server (no inline code), requests only back to this server
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; "
                             "script-src 'self'; connect-src 'self'; "
                             "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(data)

        def _logged_in(self) -> bool:
            jar = SimpleCookie()
            try:
                jar.load(self.headers.get("Cookie", ""))
            except Exception:
                return False
            return COOKIE in jar and hmac.compare_digest(jar[COOKIE].value, access_key)

        def do_GET(self):
            # Blocks DNS-rebinding: a foreign website must not read the dashboard.
            if self.headers.get("Host") not in allowed_hosts:
                return self._send(403, "Forbidden", "text/plain")
            path = unquote(self.path.split("?")[0])

            if path == "/login":
                key = parse_qs(self.path.partition("?")[2]).get("key", [""])[0]
                if not hmac.compare_digest(key, access_key):
                    return self._send(403, LOCKED_PAGE.replace("%CSS%", CSS))
                self.send_response(303)  # key leaves the address bar right away
                self.send_header("Set-Cookie", f"{COOKIE}={access_key}; HttpOnly; SameSite=Strict; Path=/")
                self.send_header("Location", "/")
                self.send_header("Content-Length", "0")
                self.send_header("Referrer-Policy", "no-referrer")
                self.end_headers()
                return
            if not self._logged_in():
                return self._send(401, LOCKED_PAGE.replace("%CSS%", CSS))

            if path == "/static/app.js":
                return self._send(200, APP_JS.read_text(encoding="utf-8"), "text/javascript; charset=utf-8")
            if path == "/api/version":
                return self._send(200, json.dumps({"version": data_version(cases_root)}), "application/json")

            devices = load_cases(cases_root)

            if path == "/":
                return self._send(200, render_overview(devices))
            if path == "/verlauf":
                return self._send(200, render_history(devices))
            if path.startswith("/device/"):
                serial = path[len("/device/"):]
                if serial in devices:
                    return self._send(200, render_device(serial, devices[serial], devices, token=token))
            if path.startswith("/report/"):
                name = path[len("/report/"):]
                known = {s["dir"].name: s["dir"] for scans in devices.values() for s in scans}
                if name in known:  # only exact case-folder names, no path traversal
                    scan = next(sc for scans in devices.values() for sc in scans if sc["dir"].name == name)
                    # rendered fresh from the JSON files; the stored report.html stays untouched (its hash is logged)
                    return self._send(200, render_html(scan["meta"], scan["data"], scan["findings"],
                                                       back=f"/device/{quote(scan['meta']['serial'])}"))
            self._send(404, "Nicht gefunden", "text/plain")

        def do_POST(self):
            if self.headers.get("Host") not in allowed_hosts:
                return self._send(403, "Forbidden", "text/plain")
            origin = self.headers.get("Origin")
            if origin and origin not in allowed_origins:
                return self._send(403, "Fremde Herkunft", "text/plain")
            if not self._logged_in():
                return self._send(401, LOCKED_PAGE.replace("%CSS%", CSS))
            if unquote(self.path.split("?")[0]) != "/decide":
                return self._send(404, "Nicht gefunden", "text/plain")
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if length < 0:
                return self._send(400, "Ungültige Anfrage", "text/plain")
            if length > 8192:
                return self._send(413, "Zu groß", "text/plain")
            form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode("utf-8", "replace")).items()}
            if not hmac.compare_digest(form.get("token", ""), token):
                return self._send(403, "Ungültiges Formular. Seite neu laden und nochmal versuchen.", "text/plain")

            devices = load_cases(cases_root)
            serial, key, status = form.get("serial", ""), form.get("key", ""), form.get("status", "")
            if serial not in devices:
                return self._send(400, "Unbekanntes Gerät", "text/plain")
            finding = next((f for f in devices[serial][-1]["findings"] if decisions.finding_key(f) == key), None)
            if finding is None or (status not in decisions.STATUSES and status != "reset"):
                return self._send(400, "Unbekannter Befund oder Status", "text/plain")
            decisions.record(cases_root, serial, finding, status, form.get("note", ""))

            self.send_response(303)  # back to the finding, so a reload does not resend the form
            self.send_header("Location", f"/device/{quote(serial)}#{_anchor(finding)}")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    Handler.login_url = f"http://127.0.0.1:{port}/login?key={access_key}"
    return Handler


PORT_BUSY = ("Port {port} ist schon belegt. Meist läuft noch ein älteres FamCheck-Fenster.\n"
             "Prüfen:   netstat -ano | findstr :{port}\n"
             "Beenden:  Stop-Process -Id <Nummer ganz rechts>\n"
             "Oder einen anderen Port nehmen: --port 8800")


class DashboardServer(ThreadingHTTPServer):
    """Takes the port exclusively. Python's default SO_REUSEADDR lets a second process share an already
    used port on Windows; it would then get the connections, including the login link with its key."""

    allow_reuse_address = sys.platform != "win32"

    def server_bind(self):
        if sys.platform == "win32" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def create_server(cases_root: Path, port: int) -> DashboardServer:
    try:
        return DashboardServer(("127.0.0.1", port), make_handler(cases_root, port))
    except OSError as e:
        raise SystemExit(PORT_BUSY.format(port=port)) from e


def start_background(cases_root: Path, port: int) -> ThreadingHTTPServer:
    """Starts the dashboard in a daemon thread (used by 'watch'). The login link is
    server.RequestHandlerClass.login_url."""
    import threading
    server = create_server(cases_root, port)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def serve(cases_root: Path, port: int, open_browser: bool = True):
    server = create_server(cases_root, port)
    url = server.RequestHandlerClass.login_url
    print(f"FamCheck-Dashboard: {url}\n(Link gilt bis zum Beenden, Strg+C zum Beenden)")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
