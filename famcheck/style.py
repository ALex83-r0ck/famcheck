"""Shared look of dashboard and scan report: colors (light/dark), severity names, small HTML parts."""

from datetime import datetime, tzinfo
from html import escape

SEV_KEY = {"KRITISCH": "crit", "HOCH": "high", "MITTEL": "mid", "NIEDRIG": "low"}
SEV_LABEL = {"crit": "Kritisch", "high": "Hoch", "mid": "Mittel", "low": "Niedrig", "ok": "OK"}
HEADLINE = {"crit": "Sofort ansehen", "high": "Dringend ansehen", "mid": "Etwas prüfen",
            "low": "Kleinigkeiten", "ok": "Alles in Ordnung"}
ICON = {"crit": "!", "high": "!", "mid": "?", "low": "i", "ok": "✓"}

_TOKENS_DARK = """--bg:#12171c;--surface:#1b2229;--sunken:#151b21;--fg:#e4e9ee;--muted:#93a1ad;--line:#2c353e;
--accent:#7aa7ff;--shadow:0 1px 2px rgba(0,0,0,.3);--crit:#f0857c;--high:#f29a5c;--mid:#e3b84f;--low:#86a9e0;--ok:#6cc488;
--crit-soft:#3a1f1d;--high-soft:#3a2617;--mid-soft:#352b13;--low-soft:#1d2a3d;--ok-soft:#1a3122;color-scheme:dark"""

CSS = """
:root{--bg:#f4f6f8;--surface:#fff;--sunken:#f5f7fa;--fg:#18212b;--muted:#5d6b78;--line:#e5e9ef;
--accent:#2563eb;--shadow:0 1px 2px rgba(16,24,40,.06),0 4px 16px rgba(16,24,40,.06);--crit:#b3261e;--high:#c4520f;--mid:#a87400;--low:#3f6fb5;--ok:#2f7d45;
--crit-soft:#fbe7e5;--high-soft:#fcebdf;--mid-soft:#fbf1d9;--low-soft:#e5edf8;--ok-soft:#e3f2e7;
--mono:ui-monospace,"Cascadia Mono",Consolas,monospace}
@media (prefers-color-scheme:dark){:root{""" + _TOKENS_DARK + """}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1080px;margin:0 auto;padding:32px 16px 56px;display:grid;gap:24px}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
a:focus-visible{outline:3px solid var(--accent);outline-offset:2px;border-radius:4px}
h1{font-size:1.7rem;margin:0;letter-spacing:-.02em} h2{font-size:1.2rem;margin:0 0 12px}
.muted{color:var(--muted)} .small{font-size:.85rem} .mono{font-family:var(--mono);font-size:.85em}
.num{font-variant-numeric:tabular-nums}
.top{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:12px}
.nav{display:flex;gap:6px}
.nav a{padding:7px 16px;border-radius:999px;font-weight:600;color:var(--fg)}
.nav a[aria-current=page]{background:var(--accent);border-color:var(--accent);color:var(--surface)}
.nav a:hover{text-decoration:none}
.summary{display:flex;flex-wrap:wrap;gap:6px}
.chip{display:inline-flex;align-items:center;font-size:.78rem;font-weight:600;border-radius:999px;padding:2px 10px;white-space:nowrap}
.s-crit{color:var(--crit);background:var(--crit-soft)} .s-high{color:var(--high);background:var(--high-soft)}
.s-mid{color:var(--mid);background:var(--mid-soft)} .s-low{color:var(--low);background:var(--low-soft)}
.s-ok{color:var(--ok);background:var(--ok-soft)}
.dot{width:12px;height:12px;border-radius:50%;display:inline-block;flex:none}
.d-crit{background:var(--crit)} .d-high{background:var(--high)} .d-mid{background:var(--mid)}
.d-low{background:var(--low)} .d-ok{background:var(--ok)}
.panel{background:var(--surface);border-radius:16px;padding:24px;min-width:0;box-shadow:var(--shadow)}
.state{display:flex;align-items:center;gap:12px;border-radius:14px;padding:14px 16px;font-weight:600;font-size:1.05rem}
.state .big{width:30px;height:30px;border-radius:50%;display:grid;place-items:center;color:var(--surface);flex:none}
.meta{font-size:.82rem;color:var(--muted);display:grid;gap:2px}
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
details.fx{--sv:var(--muted);border-left:4px solid var(--sv);background:var(--sunken);border-radius:10px;
padding:0 14px;margin:8px 0}
details.fx[data-sev=crit]{--sv:var(--crit)} details.fx[data-sev=high]{--sv:var(--high)}
details.fx[data-sev=mid]{--sv:var(--mid)} details.fx[data-sev=low]{--sv:var(--low)}
details.fx>summary{display:flex;gap:10px;align-items:center;padding:12px 0;cursor:pointer;list-style:none}
details.fx>summary::-webkit-details-marker{display:none}
details.fx>summary::after{content:"\\25B8";margin-left:auto;color:var(--muted)}
details.fx[open]>summary::after{content:"\\25BE"}
details.fx>summary:focus-visible{outline:3px solid var(--accent);outline-offset:2px;border-radius:4px}
details.fx .fbody{padding:0 0 12px;display:grid;gap:4px}
details.fx .fbody .a{font-size:.85rem;color:var(--muted)}
details.fx .fbody .decision{grid-column:auto}
details.fx[hidden]{display:none}
.tag{font-size:.72rem;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:0 7px;white-space:nowrap}
.tag.warn{color:var(--high);border-color:var(--high);font-weight:600}
.js-only{display:none}
html.js .js-only{display:flex}
.toolbar{flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 10px}
.toolbar .sevs{display:flex;flex-wrap:wrap;gap:6px}
.toolbar button.chip{border:0;cursor:pointer;font:inherit;font-size:.75rem;font-weight:600}
.toolbar button.chip[aria-pressed=false]{opacity:.35;text-decoration:line-through}
.toolbar input[type=search],.toolbar select,.toolbar .btn{font:inherit;font-size:.85rem;padding:5px 9px;border:1px solid var(--line);
border-radius:6px;background:var(--surface);color:var(--fg)}
.toolbar input[type=search]{flex:1 1 180px;min-width:0}
.toolbar .btn{cursor:pointer;background:var(--sunken)}
.toolbar :focus-visible{outline:3px solid var(--accent);outline-offset:1px}
#fc-toast{position:fixed;right:max(16px,env(safe-area-inset-right));bottom:16px;max-width:min(420px,calc(100vw - 32px));
background:var(--fg);color:var(--bg);padding:10px 14px;border-radius:8px;font-size:.9rem;z-index:10}
#fc-toast.err{background:var(--crit);color:#fff}
#fc-bar{position:fixed;left:0;right:0;bottom:0;display:flex;gap:12px;align-items:center;justify-content:center;
flex-wrap:wrap;padding:10px 16px;background:var(--surface);border-top:2px solid var(--accent);z-index:9}
#fc-bar button{font:inherit;padding:5px 12px;border-radius:6px;border:1px solid var(--accent);background:var(--accent);
color:var(--surface);cursor:pointer}
details.triaged summary{cursor:pointer;color:var(--muted);font-size:.9rem;margin-top:8px}
details.triaged .finding{opacity:.75}
.finding{--sv:var(--muted);display:grid;grid-template-columns:auto 1fr;gap:4px 10px;padding:12px 14px;margin:8px 0;
border-left:4px solid var(--sv);background:var(--sunken);border-radius:10px}
.finding[data-sev=crit]{--sv:var(--crit)} .finding[data-sev=high]{--sv:var(--high)}
.finding[data-sev=mid]{--sv:var(--mid)} .finding[data-sev=low]{--sv:var(--low)}
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
.apps-bar{flex-wrap:wrap;gap:6px;align-items:center;margin:0 0 10px}
.apps-bar button,.apps-bar select{font:inherit;font-size:.8rem;padding:4px 10px;border:1px solid var(--line);
border-radius:999px;background:var(--sunken);color:var(--fg);cursor:pointer}
.apps-bar button[aria-pressed=true]{background:var(--accent);border-color:var(--accent);color:var(--surface)}
.apps-bar :focus-visible{outline:3px solid var(--accent);outline-offset:1px}
tr.app-new td{background:var(--high-soft)}
tr[hidden]{display:none}
.applinks{font-size:.78rem;margin-left:6px;white-space:nowrap}
td.num{white-space:nowrap}
.compare{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:0 0 10px;font-size:.88rem}
.compare select,.compare button{font:inherit;font-size:.85rem;padding:5px 9px;border:1px solid var(--line);
border-radius:6px;background:var(--surface);color:var(--fg)}
.compare button{background:var(--accent);border-color:var(--accent);color:var(--surface);cursor:pointer}
.compare :focus-visible{outline:3px solid var(--accent);outline-offset:1px}
.steps{font-size:.85rem;color:var(--fg);background:var(--surface);border-radius:8px;padding:8px 12px;margin-top:6px}
.steps ol,.cleanup ol{margin:4px 0;padding-left:1.4em}
.steps li,.cleanup li{margin:2px 0}
.finding .steps{grid-column:2}
.cleanup{margin-top:6px}
.cleanup summary{cursor:pointer;color:var(--accent);font-size:.82rem;width:max-content;max-width:100%}
.cleanup ol{font-size:.88rem}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:14px}
.tile{display:grid;gap:2px;text-align:left;border:0;border-radius:14px;padding:14px 16px;font:inherit;cursor:pointer}
.tile b{font-size:2rem;line-height:1.1} .tile span{font-size:.85rem;font-weight:600}
.tile.zero{opacity:.45}
a.tile{text-decoration:none}
.tile:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
@media (max-width:560px){.tiles{grid-template-columns:repeat(2,1fr)}}
.copy{display:flex;gap:8px;align-items:center;margin-top:6px;font-size:.85rem;flex-wrap:wrap}
.copy code{flex:1 1 260px;min-width:0;overflow-x:auto;white-space:nowrap;font-family:var(--mono);padding:7px 10px;
border-radius:8px;background:var(--surface);border:1px solid var(--line)}
.copy button{font:inherit;padding:7px 14px;border-radius:8px;border:0;background:var(--accent);color:var(--surface);
cursor:pointer;font-weight:600}
.copy button{display:none} html.js .copy button{display:inline-block}
.copy button:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.hero{display:grid;gap:10px}
.hero h2{font-size:1.5rem;margin:0;letter-spacing:-.01em}
.hero p{margin:0;color:var(--muted)}
.hero .tiles{margin-top:6px}
.two{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(0,1fr);gap:24px;align-items:start}
.dev-list,.side{display:grid;gap:16px;min-width:0}
@media (max-width:860px){.two{grid-template-columns:1fr}}
.dev{background:var(--surface);border-radius:16px;box-shadow:var(--shadow);padding:20px;display:grid;gap:12px;
border-top:5px solid var(--sv);min-width:0}
.dev h3{margin:0;font-size:1.15rem}
.dev h3 a{color:var(--fg)}
.todo{margin:0;padding:0;list-style:none;display:grid;gap:6px;font-size:.9rem}
.todo li{display:flex;gap:8px;align-items:baseline;min-width:0;overflow-wrap:anywhere}
.btn-p{display:block;background:var(--accent);color:var(--surface);border-radius:999px;padding:9px 16px;
font-weight:600;text-align:center}
.btn-p:hover{text-decoration:none;filter:brightness(1.08)}
.feed{display:grid;gap:10px;font-size:.9rem}
.feed>div{display:flex;gap:10px;align-items:baseline;min-width:0;overflow-wrap:anywhere}
.feed time{color:var(--muted);font-size:.78rem;flex:none;width:6.5em;white-space:nowrap}
.steps3{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.steps3 div{background:var(--sunken);border-radius:12px;padding:12px;font-size:.86rem}
.steps3 b{display:block;font-size:1.4rem;color:var(--accent)}
.steps3 code{font-family:var(--mono);font-size:.9em}
.side .steps3{grid-template-columns:1fr}
.side .steps3 div{display:flex;gap:12px;align-items:center}
.side .steps3 b{font-size:1.2rem}
.live{border-left:5px solid var(--accent)}
.live.done{border-left-color:var(--ok)} .live.failed{border-left-color:var(--crit)}
.live-head{display:flex;flex-wrap:wrap;gap:12px;align-items:center}
.live.running .live-head b::before{content:"";display:inline-block;width:.8em;height:.8em;margin-right:8px;
border:2px solid var(--accent);border-right-color:transparent;border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){.live.running .live-head b::before{animation:none}}
.live-head button{font:inherit;font-size:.85rem;padding:4px 12px;border:1px solid var(--line);border-radius:999px;
background:var(--sunken);color:var(--fg);cursor:pointer;margin-left:auto}
.live pre{margin:10px 0 0;max-height:220px;overflow:auto;background:var(--sunken);border-radius:8px;padding:10px 12px;
font-family:var(--mono);font-size:.8rem;line-height:1.5;white-space:pre-wrap;overflow-wrap:anywhere}
.scan-now{margin-top:8px}
.scan-now button{font:inherit;font-weight:600;padding:8px 16px;border:0;border-radius:999px;background:var(--accent);
color:var(--surface);cursor:pointer;width:100%}
.scan-now button:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.panel .scan-now button{width:auto}
.connected{display:grid;gap:6px;margin-top:14px;border-top:1px dashed var(--line);padding-top:12px}
.connected .scan-now button{width:100%}
.rename{margin-top:6px}
.rename summary{cursor:pointer;color:var(--accent);font-size:.82rem;width:max-content}
.rename form{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}
.rename input{font:inherit;font-size:.9rem;padding:5px 8px;border:1px solid var(--line);border-radius:6px;
background:var(--surface);color:var(--fg);flex:1 1 200px;min-width:0;max-width:320px}
.rename button{font:inherit;font-size:.85rem;padding:5px 12px;border:1px solid var(--accent);border-radius:6px;
background:var(--accent);color:var(--surface);cursor:pointer}
"""


TILES = (("crit", "Kritisch"), ("high", "Hoch"), ("mid", "Mittel"), ("low", "Niedrig"))


def tiles(findings: list[dict], interactive: bool = False) -> str:
    """Four big numbers per severity. interactive: buttons that filter the list (dashboard, needs app.js)."""
    counts = {k: 0 for k, _ in TILES}
    for f in findings:
        k = SEV_KEY.get(f["severity"])
        if k:
            counts[k] += 1
    tag, attr = ("button type='button'", "data-sev-only") if interactive else ("div", "data-sev")
    end = "button" if interactive else "div"
    return ("<div class='tiles'>" + "".join(
        f"<{tag} class='tile s-{k}{' zero' if not counts[k] else ''}' {attr}='{k}' "
        f"aria-label='{counts[k]} {label}'><b>{counts[k]}</b><span>{label}</span></{end}>"
        for k, label in TILES) + "</div>")


def local_time(iso: str, tz: tzinfo | None = None) -> str:
    """'30.10.2026 13:20' in the PC's time zone. The data files keep UTC (no jumps at daylight saving)."""
    try:
        return datetime.fromisoformat(iso).astimezone(tz).strftime("%d.%m.%Y %H:%M")
    except (TypeError, ValueError):
        return iso


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


# Special uids in Android's network statistics. -1 is the sum over all apps, not an app.
UID_TOTAL = -1
SPECIAL_UIDS = {0: "System (Kernel)", -4: "inzwischen deinstallierte Apps", -5: "Hotspot / Tethering"}


def upload_name(u: dict) -> str:
    return SPECIAL_UIDS.get(u["uid"]) or ", ".join(u["packages"])


def uploads_html(data: dict, top: int = 8) -> str:
    uploads = [u for u in data.get("uploads") or [] if u["uid"] != UID_TOTAL]  # also cleans older scans
    if not uploads:
        return ""
    third_party = data["apps"]
    days = data.get("uploads_days")
    installed_chip = " <span class='chip s-low'>installiert</span>"
    rows = "".join(
        f"<tr><td class='mono'>{escape(upload_name(u))}"
        f"{installed_chip if any(p in third_party for p in u['packages']) else ''}</td>"
        f"<td class='num'>{u['tx'] / 1048576:,.1f} MB</td><td class='num'>{u['tx_bg'] / 1048576:,.1f} MB</td></tr>"
        for u in uploads[:top])
    period = f"letzte ~{days:.0f} Tage" if days else "erfasster Zeitraum"
    return (f"<div class='panel'><h2>Größte Uploads ({period})</h2>"
            f"<p class='muted small' style='margin:0 0 8px'>Wie viele Daten jede App ins Internet geschickt hat. "
            f"„Hintergrund“ heißt: ohne dass die App offen war.</p>"
            f"<div class='scroll'><table><tr><th>App</th><th>Gesamt</th><th>Davon Hintergrund</th></tr>"
            f"{rows}</table></div></div>")
