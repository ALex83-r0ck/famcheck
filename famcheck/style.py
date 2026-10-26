"""Shared look of dashboard and scan report: colors (light/dark), severity names, small HTML parts."""

from html import escape

SEV_KEY = {"KRITISCH": "crit", "HOCH": "high", "MITTEL": "mid", "NIEDRIG": "low"}
SEV_LABEL = {"crit": "Kritisch", "high": "Hoch", "mid": "Mittel", "low": "Niedrig", "ok": "OK"}
HEADLINE = {"crit": "Sofort ansehen", "high": "Dringend ansehen", "mid": "Etwas prüfen",
            "low": "Kleinigkeiten", "ok": "Alles in Ordnung"}
ICON = {"crit": "!", "high": "!", "mid": "?", "low": "i", "ok": "✓"}

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
.banner{background:var(--mid-soft);color:var(--fg);border:1px solid var(--mid);border-radius:10px;padding:10px 14px}
.banner b{color:var(--mid)}
.triage-toggle{grid-column:2;margin-top:4px}
.triage-toggle summary{cursor:pointer;color:var(--accent);font-size:.82rem;width:max-content}
.triage{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:6px}
.triage input[type=text]{flex:1 1 200px;min-width:0;font:inherit;font-size:.85rem;padding:5px 8px;border:1px solid var(--line);
border-radius:6px;background:var(--surface);color:var(--fg)}
.triage button{font:inherit;font-size:.8rem;padding:5px 10px;border:1px solid var(--line);border-radius:6px;
background:var(--sunken);color:var(--fg);cursor:pointer}
.triage button:hover{border-color:var(--accent)}
.triage button:focus-visible,.triage input:focus-visible{outline:3px solid var(--accent);outline-offset:1px}
.decision{grid-column:2;font-size:.82rem;margin-top:4px}
.decision.warn{color:var(--high);font-weight:600}
.decision code{font-family:var(--mono);font-size:.95em;background:var(--sunken);padding:1px 5px;border-radius:4px}
details.triaged summary{cursor:pointer;color:var(--muted);font-size:.9rem;margin-top:8px}
details.triaged .finding{opacity:.75}
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


def worst(findings: list[dict]) -> str:
    keys = [SEV_KEY[f["severity"]] for f in findings if f["severity"] in SEV_KEY]
    return min(keys, key=list(HEADLINE).index) if keys else "ok"


def chips(findings: list[dict]) -> str:
    out = []
    for sev, key in SEV_KEY.items():
        n = sum(f["severity"] == sev for f in findings)
        if n:
            out.append(f"<span class='chip s-{key}'>{SEV_LABEL[key]} {n}</span>")
    return " ".join(out) or "<span class='chip s-ok'>Keine Befunde</span>"


def uploads_html(data: dict, top: int = 8) -> str:
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
