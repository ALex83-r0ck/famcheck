"""Local monitoring dashboard over the scan results in the cases folder.

Binds to 127.0.0.1 only: the data shows which apps family members use.
Everything coming from a device (package names etc.) is HTML-escaped, since a
malicious app controls its own package name.
"""

import hashlib
import hmac
import json
import os
import re
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

from . import decisions, fix, guides, iocs
from .live import LIVE
from .report import ROLE_LABELS, compute_diff, install_info, render_html, source_label
from .style import CSS, HEADLINE, ICON, SEV_KEY, SEV_LABEL, local_time, tiles
from .style import chips as _chips
from .style import uploads_html as _uploads_html
from .style import worst as _worst

STALE_DAYS = 45  # a device not scanned for this long gets a hint
MAX_NAME = 40


def _names_path(cases_root: Path) -> Path:
    return cases_root / "devices.json"


def load_names(cases_root: Path) -> dict[str, str]:
    """Names the user gave the devices in the dashboard (serial -> name). Scans keep their original label."""
    path = _names_path(cases_root)
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def save_name(cases_root: Path, serial: str, name: str) -> None:
    """Empty name = back to the label from the scan."""
    name = "".join(c for c in name if c.isprintable()).strip()[:MAX_NAME]
    names = load_names(cases_root)
    if name:
        names[serial] = name
    else:
        names.pop(serial, None)
    tmp = _names_path(cases_root).with_suffix(".tmp")
    tmp.write_text(json.dumps(names, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, _names_path(cases_root))


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
    names = load_names(cases_root)
    for serial, scans in devices.items():
        scans.sort(key=lambda s: s["meta"]["started"])
        for s in scans:  # one name per device, even if scans were labelled differently
            s["name"] = names.get(serial) or scans[-1]["meta"]["label"]
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
                                                   kv[1][-1]["name"].lower()))


def _page(title: str, active: str, body: str, devices: dict, summary: bool = True) -> str:
    counts: dict[str, int] = {}
    for scans in devices.values():
        w = _worst(scans[-1]["counting"])
        counts[w] = counts.get(w, 0) + 1
    chips_row = "<div class='summary'>" + "".join(f"<span class='chip s-{k}'>{counts[k]} × {HEADLINE[k]}</span>"
                                                  for k in HEADLINE if counts.get(k)) + "</div>"
    nav = "".join(f"<a href='{href}'{' aria-current=page' if key == active else ''}>{label}</a>"
                  for key, href, label in (("overview", "/", "Übersicht"), ("history", "/verlauf", "Verlauf")))
    return (f"<!doctype html><html lang='de'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{escape(title)}</title><style>{CSS}</style>"
            f"<script src='/static/app.js' defer></script></head><body><main>"
            f"<div class='top'><h1>FamCheck</h1><nav class='nav'>{nav}</nav></div>"
            f"{_banner()}<section id='live' class='panel live' hidden aria-live='polite'></section>"
            f"{chips_row if summary else ''}{body}</main></body></html>")


def _banner() -> str:
    warning = iocs.freshness_warning()
    return f"<div class='banner' role='status'><b>Hinweis:</b> {escape(warning)}</div>" if warning else ""


SEV_ORDER = {"KRITISCH": 0, "HOCH": 1, "MITTEL": 2, "NIEDRIG": 3, "INFO": 4}
ATTENTION = ("crit", "high", "mid")  # these need a look; "low" and "ok" do not
FEED_SCANS = 5   # how many recent scans per device feed "Was ist neu"
FEED_ITEMS = 8

def _start_steps(extra: str = "") -> str:
    return ("<div class='panel'><h2>Neues Handy prüfen</h2><div class='steps3'>"
            "<div><b>1</b><code>FamCheck.bat</code> starten</div>"
            "<div><b>2</b>Handy per USB anstecken und entsperren</div>"
            "<div><b>3</b>Am Handy „USB-Debugging zulassen“ tippen, der Scan startet von selbst</div></div>"
            f"{extra}</div>")


def _hero(devices: dict, ordered: list, now: datetime) -> str:
    need = [(serial, scans) for serial, scans in ordered if _worst(scans[-1]["counting"]) in ATTENTION]
    n = len(devices)
    if need:
        if n == 1:
            title = "Das Handy braucht deine Aufmerksamkeit"
        else:
            title = (f"{len(need)} von {n} Handys braucht deine Aufmerksamkeit" if len(need) == 1
                     else f"{len(need)} von {n} Handys brauchen deine Aufmerksamkeit")
        serial, scans = need[0]
        top = sorted(scans[-1]["counting"], key=lambda f: SEV_ORDER.get(f["severity"], 4))[0]
        text = f"„{escape(scans[-1]['name'])}“: {escape(top['title'])}."
        if len(need) < n:
            text += " Die anderen Geräte sind unauffällig."
    else:
        title = "Alles im grünen Bereich" if n > 1 else "Das Handy ist unauffällig"
        text = f"{n} Handy{'s' if n > 1 else ''} ohne offene Befunde, die Aufmerksamkeit brauchen."
    newest = max(_started(scans[-1]) for scans in devices.values())
    text += f" Letzter Scan {_ago(newest, now)}."
    every = [f for scans in devices.values() for f in scans[-1]["counting"]]
    return (f"<div class='panel hero'><h2>{title}</h2><p>{text}</p>{tiles(every)}</div>")


def _device_card(serial: str, scans: list[dict], now: datetime) -> str:
    last = scans[-1]
    props = last["data"]["props"]
    w = _worst(last["counting"])
    model = " ".join(x for x in (props.get("ro.product.manufacturer", "").capitalize(), props.get("ro.product.model", ""))
                     if x)
    android = props.get("ro.build.version.release")
    if android:
        model += f" · Android {android}"
    open_findings = sorted((f for f in last["counting"] if f["severity"] != "INFO"),
                           key=lambda f: SEV_ORDER.get(f["severity"], 4))
    todo = "".join(f"<li><span class='chip s-{SEV_KEY[f['severity']]}'>{SEV_LABEL[SEV_KEY[f['severity']]]}</span>"
                   f"<span>{escape(f['title'])}</span></li>" for f in open_findings[:2])
    if len(open_findings) > 2:
        todo += f"<li class='muted'>+ {len(open_findings) - 2} weitere</li>"
    stale = (f" · <span class='stale'>neu scannen</span>" if (now - _started(last)).days >= STALE_DAYS else "")
    url = f"/device/{escape(serial)}"
    return (f"<article class='dev' style='--sv:var(--{w})'>"
            f"<div><h3><a href='{url}'>{escape(last['name'])}</a></h3><div class='muted small'>{escape(model)}</div></div>"
            f"<div class='state s-{w}'><span class='big d-{w}'>{ICON[w]}</span>{HEADLINE[w]}</div>"
            + (f"<ul class='todo'>{todo}</ul>" if todo else "") +
            f"{_triage_line(last['triaged'])}"
            f"<div class='meta'><span>Letzter Scan: {_ago(_started(last), now)}, "
            f"{escape(local_time(last['meta']['started'])[-5:])}{stale}</span>"
            f"<span>Sicherheitspatch: <span class='num'>{escape(props.get('ro.build.version.security_patch', '?'))}</span></span>"
            f"<span>{_change_line(last['diff'])}</span></div>"
            f"<a class='btn-p' href='{url}'>Ansehen</a></article>")


def _short_time(iso: str, now: datetime) -> str:
    """'heute 13:55', 'gestern 09:10' or '28.10. 18:28', in local time."""
    dt = datetime.fromisoformat(iso).astimezone()
    days = (now.astimezone().date() - dt.date()).days
    day = {0: "heute", 1: "gestern"}.get(days, f"{dt:%d.%m.}")
    return f"{day} {dt:%H:%M}"


def _feed(ordered: list, now: datetime) -> str:
    """Recent changes over all devices, newest first."""
    events = []
    for serial, scans in ordered:
        name = escape(scans[-1]["name"])
        for prev, cur in list(zip([None] + scans, scans))[-FEED_SCANS:]:
            when = cur["meta"]["started"]
            if prev is None:
                events.append((when, f"<b>{name}:</b> erster Scan"))
                continue
            items = []
            for pkg, installer in cur["diff"]["added"].items():
                _, foreign = source_label(installer)
                warn = " <span class='chip s-mid'>fremde Quelle</span>" if foreign else ""
                items.append(f"<b>{name}:</b> neue App <span class='mono'>{escape(pkg)}</span>{warn}")
            items += [f"<b>{name}:</b> App entfernt <span class='mono'>{escape(pkg)}</span>"
                      for pkg in cur["diff"]["removed"]]
            before = {f["title"] for f in prev["findings"]}
            items += [f"<b>{name}:</b> neuer Befund „{escape(f['title'])}“" for f in cur["findings"]
                      if f["title"] not in before and f["severity"] != "INFO"]
            if items:
                events += [(when, i) for i in items]
            elif cur is scans[-1]:  # only the latest quiet scan, a row of them says nothing
                events.append((when, f"<b>{name}:</b> Scan ohne Änderungen"))
    events.sort(key=lambda e: e[0], reverse=True)
    rows = "".join(f"<div><time>{escape(_short_time(when, now))}</time><span>{text}</span></div>"
                   for when, text in events[:FEED_ITEMS])
    return f"<div class='panel'><h2>Was ist neu</h2><div class='feed'>{rows}</div></div>"


def _reminders(ordered: list, now: datetime) -> str:
    items = []
    for serial, scans in ordered:
        last = scans[-1]
        days = (now - _started(last)).days
        if days >= STALE_DAYS:
            items.append(f"<span class='stale'>{escape(last['name'])} seit {days} Tagen nicht gescannt</span>")
        reopened = sum(f["decision_state"] in ("changed", "reopened") for f in last["triaged"])
        if reopened:
            items.append(f"<a href='/device/{escape(serial)}'>{escape(last['name'])}: {reopened} eingeordnete(r) "
                         f"Befund(e) wieder offen</a>")
    body = "".join(f"<div>{i}</div>" for i in items) or "<div class='muted'>Keine. Alles aktuell.</div>"
    return f"<div class='panel'><h2>Erinnerungen</h2><div class='feed'>{body}</div></div>"


def _scan_button(serial: str, label: str, token: str, back: str) -> str:
    return (f"<form class='scan-now' method='post' action='/scan'>"
            f"<input type='hidden' name='token' value='{escape(token)}'>"
            f"<input type='hidden' name='serial' value='{escape(serial)}'>"
            f"<input type='hidden' name='back' value='{escape(back)}'>"
            f"<button>{escape(label)}</button></form>")


def _connected_html(devices: dict, connected: list[dict] | None, token: str) -> str:
    """Phones plugged in right now, with a scan button. None: scanning from the dashboard is not available."""
    if connected is None or not token:
        return ""
    if not connected:
        return "<p class='muted small' style='margin:12px 0 0'>Gerade ist kein Handy angeschlossen.</p>"
    names = load_names_cached(devices)
    rows = []
    for d in connected:
        name = names.get(d["serial"]) or d["model"] or d["serial"]
        if d["state"] == "device":
            rows.append(_scan_button(d["serial"], f"Jetzt scannen: {name}", token, "/"))
        elif d["state"] == "unauthorized":
            rows.append(f"<p class='small' style='margin:0'><b>{escape(name)}:</b> am Handy entsperren und "
                        f"„USB-Debugging zulassen“ tippen.</p>")
        else:
            rows.append(f"<p class='small' style='margin:0'><b>{escape(name)}:</b> Status {escape(d['state'])}, "
                        f"Kabel bzw. USB-Modus prüfen.</p>")
    return f"<div class='connected'><b class='small'>Angeschlossen:</b>{''.join(rows)}</div>"


def load_names_cached(devices: dict) -> dict:
    """serial -> display name, from what load_cases already put on the scans."""
    return {serial: scans[-1]["name"] for serial, scans in devices.items()}


def render_overview(devices: dict[str, list[dict]], now: datetime | None = None, token: str = "",
                    connected: list[dict] | None = None) -> str:
    """Start page: how is the family doing, what changed, what to do next."""
    now = now or datetime.now(timezone.utc)
    steps = _start_steps(_connected_html(devices, connected, token))
    if not devices:
        body = ("<div class='panel hero'><h2>Noch kein Handy geprüft</h2><p>So geht der erste Scan, "
                "danach erscheinen hier alle Geräte der Familie.</p></div>" + steps)
        return _page("FamCheck", "overview", body, devices, summary=False)
    ordered = _sorted_devices(devices)
    cards = "".join(_device_card(serial, scans, now) for serial, scans in ordered)
    body = (f"{_hero(devices, ordered, now)}<div class='two'><div class='dev-list'>{cards}</div>"
            f"<div class='side'>{_feed(ordered, now)}{_reminders(ordered, now)}{steps}</div></div>")
    return _page("FamCheck", "overview", body, devices, summary=False)


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
            title = f"{local_time(s['meta']['started'])}: {HEADLINE[w]}"
            marks.append(f"<a class='mark' style='left:{pos(_started(s))}%' href='/report/{escape(s['dir'].name)}' "
                         f"title='{escape(title)}' aria-label='{escape(title)}'><span class='dot d-{w}'></span>"
                         + (f"<span class='tip'>{escape(tip)}</span>" if tip else "") + "</a>")
        w = _worst(scans[-1]["findings"])
        rows.append(f"<div class='tl-row'><div class='lbl'><a href='/device/{escape(serial)}'>"
                    f"{escape(scans[-1]['name'])}</a><small>{HEADLINE[w]}</small></div>"
                    f"<div class='track'>{''.join(marks)}</div></div>")
    legend = "".join(f"<span><i class='dot d-{k}'></i>{SEV_LABEL[k]}</span>" for k in HEADLINE)
    body = (f"<div class='panel'><div class='scroll'><div class='tl-inner'>"
            f"<div class='axis'><span></span><div class='ticks'>{''.join(ticks)}</div></div>{''.join(rows)}"
            f"</div></div><div class='legend'>{legend}<span>Jeder Punkt ist ein Scan (Klick öffnet den Bericht), "
            f"Farbe = schwerster Befund</span></div></div>")
    return _page("FamCheck – Verlauf", "history", body, devices)


def _diff_html(diff: dict, old: dict | None = None, new: dict | None = None) -> str:
    """old/new: the two scans, for install dates of new apps and when removed apps were last seen."""
    rows = []
    for p, i in diff["added"].items():
        source, foreign = source_label(i)
        warn = "<span class='chip s-mid'>fremde Quelle</span> " if foreign else ""
        when = ""
        if new:
            day, _ = install_info(new["data"]["apps"][p].get("first_install"), new["meta"]["started"])
            when = f" am {day}" if day not in ("–", "ab Werk") else ""
        rows.append(f"<div class='change'><span class='op op-add'>+</span><span class='mono'>{escape(p)}</span>"
                    f"<span class='muted'>{warn}installiert{escape(when)} über {escape(source)}</span></div>")
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
    seen = f", zuletzt gesehen beim Scan am {local_time(old['meta']['started'])}" if old else ""
    rows += [f"<div class='change'><span class='op op-rm'>−</span><span class='mono'>{escape(p)}</span>"
             f"<span class='muted'>entfernt{escape(seen)}</span></div>" for p in diff["removed"]]
    if diff.get("not_comparable"):
        rows.append(f"<div class='change'><span class='op'>?</span><b>{diff['not_comparable']} Apps nicht vergleichbar</b>"
                    f"<span class='muted'>ihre Daten waren in einem der beiden Scans nicht lesbar</span></div>")
    return "".join(rows) or "<p class='muted' style='margin:0'>Keine Änderungen an Apps, Rechten und Konten.</p>"


def _findings_diff_html(old: dict, new: dict) -> str:
    """Findings that appeared or disappeared between two scans (by title, as the triage does)."""
    before = {f["title"]: f for f in old["findings"]}
    after = {f["title"]: f for f in new["findings"]}

    def row(op, cls, f, text):
        key = SEV_KEY.get(f["severity"], "ok")
        label = SEV_LABEL.get(SEV_KEY.get(f["severity"]), "Info")
        return (f"<div class='change'><span class='op {cls}'>{op}</span><span class='chip s-{key}'>{label}</span>"
                f"<span>{escape(f['title'])}</span><span class='muted'>{text}</span></div>")

    rows = [row("+", "op-add", f, "neu") for t, f in after.items() if t not in before]
    rows += [row("−", "op-rm", f, "nicht mehr gefunden") for t, f in before.items() if t not in after]
    return "".join(rows) or "<p class='muted' style='margin:0'>Dieselben Befunde in beiden Scans.</p>"


def _scan_options(scans: list[dict], selected: str) -> str:
    return "".join(f"<option value='{escape(s['dir'].name)}'{' selected' if s['dir'].name == selected else ''}>"
                   f"{escape(local_time(s['meta']['started']))}</option>" for s in reversed(scans))


def _compare_form(serial: str, scans: list[dict], a: str, b: str) -> str:
    return (f"<form class='compare' method='get' action='/vergleich/{quote(serial)}'>"
            f"<label>Von <select name='a'>{_scan_options(scans, a)}</select></label>"
            f"<label>bis <select name='b'>{_scan_options(scans, b)}</select></label>"
            f"<button>Vergleichen</button></form>")


def render_compare(serial: str, scans: list[dict], devices: dict, a: str, b: str) -> str | None:
    """Any two scans of one device side by side. None if a name is not a scan of this device."""
    by_name = {s["dir"].name: s for s in scans}
    if a not in by_name or b not in by_name:
        return None
    old, new = sorted((by_name[a], by_name[b]), key=lambda s: s["meta"]["started"])
    name = scans[-1]["name"]
    if old is new:
        body = "<p class='muted' style='margin:0'>Zweimal derselbe Scan, bitte zwei verschiedene wählen.</p>"
    else:
        body = (f"<h3 style='margin:14px 0 6px;font-size:1rem'>Apps, Rechte und Konten</h3>"
                f"{_diff_html(compute_diff(old['data'], new['data']), old, new)}"
                f"<h3 style='margin:14px 0 6px;font-size:1rem'>Befunde</h3>{_findings_diff_html(old, new)}")
    page = (f"<div class='panel'><p style='margin:0 0 8px'><a href='/device/{quote(serial)}'>← {escape(name)}</a></p>"
            f"<h2 style='font-size:1.3rem;margin:0'>Vergleich: {escape(name)}</h2>"
            f"<div class='muted small'>{escape(local_time(old['meta']['started']))} → "
            f"{escape(local_time(new['meta']['started']))} · "
            f"<a href='/report/{escape(old['dir'].name)}'>Bericht alt</a> · "
            f"<a href='/report/{escape(new['dir'].name)}'>Bericht neu</a></div>"
            f"{_compare_form(serial, scans, old['dir'].name, new['dir'].name)}{body}</div>")
    return _page(f"FamCheck – Vergleich {name}", "", page, devices)


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
    when = local_time(d["at"])[:10]
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


def _finding_html(serial: str, f: dict, token: str, all_findings: list[dict], rank: int, props: dict) -> str:
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
            f"{guides.steps_html(f, props, all_findings)}{_fix_hint(serial, f, all_findings)}{_decision_html(f)}{form}</div></details>")


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


SAFE_SERIAL = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


def _copy_box(command: str, text: str) -> str:
    """A command to paste into the terminal. The dashboard itself never runs anything on the phone."""
    return (f"<div class='decision'>{text}</div><div class='copy'><code>{escape(command)}</code>"
            f"<button type='button' data-copy='{escape(command)}'>Kopieren</button></div>")


def _command(sub: str, serial: str, *args: str) -> str:
    # Serial and package name come from the phone. Only strictly checked values may end up in a command the user
    # pastes into a terminal; a serial like "x; Remove-Item ..." is left out (famcheck then asks for the device).
    target = f" --serial {serial}" if SAFE_SERIAL.match(serial) else ""
    return " ".join(("python -m famcheck", sub + target) + args)


def _fix_hint(serial: str, f: dict, all_findings: list[dict]) -> str:
    kind = fix.fix_kind(f, all_findings)
    if fix.removable(f, all_findings) and fix.PACKAGE_RE.match(f["package"]):
        return _copy_box(_command("remove", serial, f["package"]),
                         "App entfernen: Befehl kopieren, im Terminal (famcheck-Ordner) einfügen und Enter. "
                         "FamCheck zeigt die App und fragt vor dem Löschen nach. Nicht umkehrbar.")
    if kind == "auto":
        return _copy_box(_command("fix", serial),
                         "Behebbar im Terminal, mit Rückfrage und umkehrbar: Befehl kopieren, einfügen, Enter.")
    if kind == "blocked" and f.get("package"):
        return ("<div class='decision'>Bewusst keine automatische Änderung: App mit kritischem Befund. "
                "Erst die Sicherheit der betroffenen Person klären.</div>")
    return ""


def _rename_form(serial: str, name: str, token: str) -> str:
    if not token:
        return ""
    return (f"<details class='rename'><summary>Umbenennen</summary>"
            f"<form method='post' action='/rename'><input type='hidden' name='token' value='{escape(token)}'>"
            f"<input type='hidden' name='serial' value='{escape(serial)}'>"
            f"<input type='text' name='name' maxlength='{MAX_NAME}' value='{escape(name)}' aria-label='Neuer Name'>"
            f"<button>Speichern</button></form><div class='muted small'>Gilt für alle Scans dieses Geräts. "
            f"Leer lassen = Name aus dem Scan.</div></details>")


def render_device(serial: str, scans: list[dict], devices: dict, now: datetime | None = None,
                  token: str = "", connected: list[dict] | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    last = scans[-1]
    props = last["data"]["props"]
    w = _worst(last["counting"])
    active = [f for f in last["triaged"] if f["decision_state"] != "suppressed"]
    hidden = [f for f in last["triaged"] if f["decision_state"] == "suppressed"]
    rank = {id(f): i for i, f in enumerate(last["triaged"])}
    findings = (_toolbar(last["triaged"]) + "<div data-findings>"
                + ("".join(_finding_html(serial, f, token, last["findings"], rank[id(f)], props) for f in active)
                   or "<p class='muted' style='margin:0'>Keine offenen Befunde.</p>") + "</div>")
    if hidden:
        findings += (f"<details class='triaged'><summary>Eingeordnet ({len(hidden)}), zählen nicht zur Ampel</summary>"
                     "<div data-findings>"
                     + "".join(_finding_html(serial, f, token, last["findings"], rank[id(f)], props) for f in hidden)
                     + "</div></details>")
    def compare_link(prev, cur):
        if not prev:
            return ""
        url = f"/vergleich/{quote(serial)}?a={quote(prev['dir'].name)}&amp;b={quote(cur['dir'].name)}"
        return f" · <a href='{url}'>Vergleich</a>"

    history = "".join(
        f"<tr><td class='num'>{escape(local_time(s['meta']['started']))}</td>"
        f"<td>{_chips(s['findings'])}</td><td class='small'>{_change_line(s['diff'])}</td>"
        f"<td style='white-space:nowrap'><a href='/report/{escape(s['dir'].name)}'>Bericht</a>{compare_link(prev, s)}</td></tr>"
        for prev, s in reversed(list(zip([None] + scans, scans))))
    compare = (f"<p class='muted small' style='margin:0 0 6px'>Zwei beliebige Scans vergleichen:</p>"
               f"{_compare_form(serial, scans, scans[-2]['dir'].name, last['dir'].name)}"
               if len(scans) > 1 else "")
    diff = (_diff_html(last["diff"], scans[-2], last) if last["diff"] is not None
            else "<p class='muted' style='margin:0'>Erst ein Scan vorhanden, noch kein Vergleich möglich.</p>")
    plugged_in = any(d["serial"] == serial and d["state"] == "device" for d in connected or [])
    rescan = _scan_button(serial, "Jetzt neu scannen", token, f"/device/{serial}") if token and plugged_in else ""
    body = (f"<div class='panel'><p style='margin:0 0 8px'><a href='/'>← Übersicht</a></p>"
            f"<h2 style='font-size:1.3rem;margin:0'>{escape(last['name'])}</h2>"
            f"<div class='muted small'>{escape(props.get('ro.product.manufacturer', ''))} "
            f"{escape(props.get('ro.product.model', ''))} · Android {escape(props.get('ro.build.version.release', '?'))} · "
            f"Patch <span class='num'>{escape(props.get('ro.build.version.security_patch', '?'))}</span> · "
            f"<span class='mono'>{escape(serial)}</span> · Letzter Scan {_ago(_started(last), now)}</div>"
            f"{_rename_form(serial, last['name'], token)}{guides.cleanup_html(props)}{rescan}"
            f"<div class='state s-{w}' style='margin-top:12px'><span class='big d-{w}'>{ICON[w]}</span>{HEADLINE[w]}</div>"
            f"{tiles(last['counting'], interactive=True)}</div>"
            f"<div class='panel'><h2>Seit letztem Scan</h2>{diff}</div>"
            f"<div class='panel'><h2>Befunde</h2><p class='muted small' style='margin:0 0 6px'>Einordnen ändert nichts "
            f"am Handy, nur wie FamCheck den Befund zählt. „Bekannt“ gilt, bis sich der Befund verändert, "
            f"„Erledigt“ bis zum nächsten Scan. Klick auf einen Befund zeigt Details.</p>{findings}</div>"
            f"{_uploads_html(last['data'])}"
            f"<div class='panel'><h2>Alle Scans</h2><p class='muted small' style='margin:0 0 6px'>Ohne Einordnung, "
            f"so wie gescannt.</p>{compare}<div class='scroll'><table><tr><th>Zeit</th><th>Befunde</th>"
            f"<th>Änderungen</th><th></th></tr>{history}</table></div></div>")
    return _page(f"FamCheck – {last['name']}", "", body, devices)


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
        for extra in ("decisions.json", "devices.json"):
            f = cases_root / extra
            if f.is_file():
                h.update(f"{extra}:{f.stat().st_mtime_ns}".encode())
    return h.hexdigest()[:16]

LOCKED_PAGE = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>FamCheck – Anmeldung nötig</title>
<style>%CSS%</style></head><body><main><div class="panel"><h2>Anmeldung nötig</h2>
<p>Das Dashboard zeigt private Daten und öffnet sich nur über den Link, den <code>famcheck serve</code> oder
<code>famcheck watch</code> beim Start im Terminal anzeigt und im Browser öffnet.</p>
<p class="muted small">Nach jedem Neustart des Dashboards gilt ein neuer Link.</p></div></main></body></html>"""


def _start_scan(scan, serial: str, label: str, cases_root: Path) -> str | None:
    """Starts a scan in the background. Returns an error text or None. A scan only reads the phone;
    fixing and removing stay in the terminal, where the [j/N] question cannot be faked by a web page."""
    import threading
    from .adb import is_locked, list_devices
    try:
        if not any(d["serial"] == serial and d["state"] == "device" for d in list_devices()):
            return "Dieses Handy ist nicht (mehr) angeschlossen oder nicht freigegeben."
    except Exception as e:
        return f"adb nicht erreichbar: {e}"
    if not LIVE.scan_lock.acquire(blocking=False):
        return "Es läuft schon ein Scan. Bitte warten, bis er fertig ist."

    # the live box shows up right away, before the first answer from the phone
    LIVE.begin(serial, label)
    LIVE.line("Prüfe, ob das Handy entsperrt ist ...")

    def run():
        try:
            if is_locked(serial):
                LIVE.line("Das Handy ist gesperrt. Bitte entsperren und noch einmal „Jetzt scannen“ klicken.")
                LIVE.end(error="Handy gesperrt")
                return
            scan(serial, label, cases_root)
        except Exception:
            pass  # scan_device already put the error into the live box
        finally:
            LIVE.scan_lock.release()

    threading.Thread(target=run, daemon=True).start()
    return None


def _connected(scan) -> list[dict] | None:
    if scan is None:
        return None
    from .adb import list_devices
    try:
        return list_devices()
    except Exception:
        return None  # no adb: no scan buttons, the rest of the dashboard works


def make_handler(cases_root: Path, port: int, scan=None):
    """scan: function(serial, label, cases_root) for the "Jetzt scannen" button; None hides the button."""
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
            # same-origin: nothing ever goes to foreign sites (VirusTotal/Play links), but plain forms still send
            # their real Origin; with no-referrer browsers send "Origin: null" and the origin check refused them
            self.send_header("Referrer-Policy", "same-origin")
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
            if path == "/api/live":
                return self._send(200, json.dumps(LIVE.snapshot()), "application/json")

            devices = load_cases(cases_root)

            if path == "/":
                return self._send(200, render_overview(devices, token=token, connected=_connected(scan)))
            if path == "/verlauf":
                return self._send(200, render_history(devices))
            if path.startswith("/device/"):
                serial = path[len("/device/"):]
                if serial in devices:
                    return self._send(200, render_device(serial, devices[serial], devices, token=token,
                                                         connected=_connected(scan)))
            if path.startswith("/vergleich/"):
                serial = path[len("/vergleich/"):]
                query = parse_qs(self.path.partition("?")[2])
                if serial in devices:
                    page = render_compare(serial, devices[serial], devices,
                                          query.get("a", [""])[0], query.get("b", [""])[0])
                    if page:
                        return self._send(200, page)
            if path.startswith("/report/"):
                name = path[len("/report/"):]
                known = {s["dir"].name: s["dir"] for scans in devices.values() for s in scans}
                if name in known:  # only exact case-folder names, no path traversal
                    found = next(sc for scans in devices.values() for sc in scans if sc["dir"].name == name)
                    # rendered fresh from the JSON files; the stored report.html stays untouched (its hash is logged)
                    return self._send(200, render_html(found["meta"], found["data"], found["findings"],
                                                       back=f"/device/{quote(found['meta']['serial'])}"))
            self._send(404, "Nicht gefunden", "text/plain")

        def do_POST(self):
            if self.headers.get("Host") not in allowed_hosts:
                return self._send(403, "Forbidden", "text/plain")
            origin = self.headers.get("Origin")
            if origin and origin not in allowed_origins:
                return self._send(403, "Fremde Herkunft", "text/plain")
            if not self._logged_in():
                return self._send(401, LOCKED_PAGE.replace("%CSS%", CSS))
            path = unquote(self.path.split("?")[0])
            if path not in ("/decide", "/rename", "/scan"):
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
            serial = form.get("serial", "")
            if path == "/scan":  # the device may be new, so no scan of it may exist yet
                if scan is None:
                    return self._send(404, "Nicht gefunden", "text/plain")
                from .watch import _known_label
                label = _known_label(cases_root, serial) or next(
                    (d["model"] for d in _connected(scan) or [] if d["serial"] == serial and d["model"]), serial)
                error = _start_scan(scan, serial, label, cases_root)
                if error:
                    return self._send(409, error, "text/plain; charset=utf-8")
                back = form.get("back", "/")
                self.send_response(303)  # only back to our own pages, never to an address from the form
                self.send_header("Location", back if back == "/" else f"/device/{quote(serial)}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if serial not in devices:
                return self._send(400, "Unbekanntes Gerät", "text/plain")
            anchor = ""
            if path == "/rename":
                save_name(cases_root, serial, form.get("name", ""))
            else:
                key, status = form.get("key", ""), form.get("status", "")
                finding = next((f for f in devices[serial][-1]["findings"] if decisions.finding_key(f) == key), None)
                if finding is None or (status not in decisions.STATUSES and status != "reset"):
                    return self._send(400, "Unbekannter Befund oder Status", "text/plain")
                decisions.record(cases_root, serial, finding, status, form.get("note", ""))
                anchor = "#" + _anchor(finding)

            self.send_response(303)  # back to the page, so a reload does not resend the form
            self.send_header("Location", f"/device/{quote(serial)}{anchor}")
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


def create_server(cases_root: Path, port: int, scan=None) -> DashboardServer:
    try:
        return DashboardServer(("127.0.0.1", port), make_handler(cases_root, port, scan))
    except OSError as e:
        raise SystemExit(PORT_BUSY.format(port=port)) from e


def start_background(cases_root: Path, port: int, scan=None) -> ThreadingHTTPServer:
    """Starts the dashboard in a daemon thread (used by 'watch'). The login link is
    server.RequestHandlerClass.login_url."""
    import threading
    server = create_server(cases_root, port, scan)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def serve(cases_root: Path, port: int, open_browser: bool = True, scan=None):
    server = create_server(cases_root, port, scan)
    url = server.RequestHandlerClass.login_url
    print(f"FamCheck-Dashboard: {url}\n(Link gilt bis zum Beenden, Strg+C zum Beenden)")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
