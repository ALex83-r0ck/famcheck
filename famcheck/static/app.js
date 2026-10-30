// FamCheck dashboard: filter and sort findings, expand/collapse, live update, triage without page reload.
// Progressive enhancement: every page also works without this file.
// Security: no inline code (CSP script-src 'self'); text is only set via textContent; the only HTML inserted
// is the dashboard's own server-rendered page (already escaped there).
(function () {
  "use strict";
  document.documentElement.classList.add("js");

  const SEVS = ["crit", "high", "mid", "low", "info"];
  const POLL_MS = 5000;
  const state = { sev: new Set(SEVS), q: "", sort: "rank" };
  let lastVersion = null;
  let pollStopped = false;

  try {
    const saved = JSON.parse(sessionStorage.getItem("famcheck-filter") || "null");
    if (saved) {
      state.sev = new Set(saved.sev);
      state.q = saved.q || "";
      state.sort = saved.sort || "rank";
    }
  } catch (e) { /* storage blocked: defaults */ }

  function save() {
    try {
      sessionStorage.setItem("famcheck-filter", JSON.stringify({ sev: [...state.sev], q: state.q, sort: state.sort }));
    } catch (e) { /* ignore */ }
  }

  // ---- small UI helpers ---------------------------------------------------------------------------
  let toastTimer = null;
  function toast(text, isError) {
    let el = document.getElementById("fc-toast");
    if (!el) {
      el = document.createElement("div");
      el.id = "fc-toast";
      el.setAttribute("role", "status");
      document.body.appendChild(el);
    }
    el.textContent = text;
    el.className = isError ? "err" : "";
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, isError ? 8000 : 3000);
  }

  function bar(text, buttonText, onClick) {
    let el = document.getElementById("fc-bar");
    if (!el) {
      el = document.createElement("div");
      el.id = "fc-bar";
      el.setAttribute("role", "status");
      document.body.appendChild(el);
    }
    el.replaceChildren();
    const span = document.createElement("span");
    span.textContent = text;
    el.appendChild(span);
    if (buttonText) {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = buttonText;
      b.addEventListener("click", onClick);
      el.appendChild(b);
    }
    el.hidden = false;
  }

  function hideBar() {
    const el = document.getElementById("fc-bar");
    if (el) el.hidden = true;
  }

  // ---- filter, search, sort -------------------------------------------------------------------------
  function compare(a, b) {
    if (state.sort === "title") return a.dataset.title.localeCompare(b.dataset.title, "de");
    if (state.sort === "pkg") {
      return (a.dataset.pkg || "￿").localeCompare(b.dataset.pkg || "￿") || a.dataset.rank - b.dataset.rank;
    }
    return a.dataset.rank - b.dataset.rank;
  }

  function applyFilters() {
    const lists = document.querySelectorAll("[data-findings]");
    if (!lists.length) return;
    let shown = 0;
    let total = 0;
    lists.forEach((list) => {
      const items = [...list.querySelectorAll(":scope > details.fx")];
      items.sort(compare).forEach((el) => list.appendChild(el));
      items.forEach((el) => {
        total += 1;
        const visible = state.sev.has(el.dataset.sev) && (!state.q || el.dataset.search.includes(state.q));
        el.hidden = !visible;
        if (visible) shown += 1;
      });
    });
    document.querySelectorAll("[data-sev-toggle]").forEach((b) => {
      b.setAttribute("aria-pressed", String(state.sev.has(b.dataset.sevToggle)));
    });
    const search = document.getElementById("f-search");
    if (search && document.activeElement !== search) search.value = state.q;
    const sort = document.getElementById("f-sort");
    if (sort) sort.value = state.sort;
    const count = document.getElementById("f-count");
    if (count) count.textContent = shown === total ? `${total} Befunde` : `${shown} von ${total} Befunden`;
  }

  document.addEventListener("click", (e) => {
    const toggle = e.target.closest("[data-sev-toggle]");
    if (toggle) {
      const sev = toggle.dataset.sevToggle;
      if (state.sev.has(sev)) state.sev.delete(sev); else state.sev.add(sev);
      save();
      applyFilters();
      return;
    }
    const expand = e.target.closest("[data-expand]");
    if (expand) {
      const open = expand.dataset.expand === "open";
      document.querySelectorAll("details.fx:not([hidden])").forEach((d) => { d.open = open; });
      if (open) document.querySelectorAll("details.triaged").forEach((d) => { d.open = true; });
    }
  });

  // tiles: show only one severity, a second click shows all again
  document.addEventListener("click", (e) => {
    const tile = e.target.closest("[data-sev-only]");
    if (!tile) return;
    const sev = tile.dataset.sevOnly;
    state.sev = state.sev.size === 1 && state.sev.has(sev) ? new Set(SEVS) : new Set([sev]);
    save();
    applyFilters();
    const list = document.querySelector("[data-findings]");
    if (list) list.closest(".panel").scrollIntoView({ behavior: "smooth", block: "start" });
  });

  // copy a terminal command; the dashboard never runs anything itself
  document.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-copy]");
    if (!b) return;
    const text = b.dataset.copy;
    try {
      await navigator.clipboard.writeText(text);
    } catch (err) {
      const code = b.parentElement.querySelector("code");
      const range = document.createRange();
      range.selectNodeContents(code);
      getSelection().removeAllRanges();
      getSelection().addRange(range);
      if (!document.execCommand("copy")) {
        toast("Kopieren nicht möglich, Befehl ist markiert: Strg+C drücken", true);
        return;
      }
    }
    toast("Kopiert. Im Terminal (famcheck-Ordner) mit Rechtsklick einfügen und Enter drücken.");
  });

  document.addEventListener("input", (e) => {
    if (e.target.id === "f-search") {
      state.q = e.target.value.trim().toLowerCase();
      save();
      applyFilters();
    }
  });

  document.addEventListener("change", (e) => {
    if (e.target.id === "f-sort") {
      state.sort = e.target.value;
      save();
      applyFilters();
    }
  });

  // ---- app table (report page): filter by one property, sort --------------------------------------------
  const apps = { filter: "all", sort: "installed" };

  function applyAppFilter() {
    const table = document.querySelector("table[data-apps]");
    if (!table) return;
    const rows = [...table.querySelectorAll("tr[data-app]")];
    const body = rows.length ? rows[0].parentNode : null;
    rows.sort((a, b) => apps.sort === "name"
      ? a.dataset.name.localeCompare(b.dataset.name)
      : b.dataset.installed.localeCompare(a.dataset.installed) || a.dataset.name.localeCompare(b.dataset.name));
    rows.forEach((r) => {
      body.appendChild(r);
      r.hidden = apps.filter !== "all" && !(apps.filter in r.dataset);
    });
    document.querySelectorAll("[data-app-filter]").forEach((b) => {
      b.setAttribute("aria-pressed", String(b.dataset.appFilter === apps.filter));
    });
    const sort = document.getElementById("app-sort");
    if (sort) sort.value = apps.sort;
  }

  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-app-filter]");
    if (!b) return;
    apps.filter = b.dataset.appFilter;
    applyAppFilter();
  });

  document.addEventListener("change", (e) => {
    if (e.target.id !== "app-sort") return;
    apps.sort = e.target.value;
    applyAppFilter();
  });

  // ---- swap in fresh page content, keeping what the user had open -----------------------------------
  function openState() {
    return {
      ids: new Set([...document.querySelectorAll("details.fx[open]")].map((d) => d.id)),
      triaged: [...document.querySelectorAll("details.triaged")].some((d) => d.open),
    };
  }

  function swap(html, keep) {
    const doc = new DOMParser().parseFromString(html, "text/html");
    const fresh = doc.querySelector("main");
    const current = document.querySelector("main");
    if (!fresh || !current) return false;
    const y = window.scrollY;
    current.replaceWith(document.importNode(fresh, true));
    keep.ids.forEach((id) => {
      const d = document.getElementById(id);
      if (d) d.open = true;
    });
    if (keep.triaged) document.querySelectorAll("details.triaged").forEach((d) => { d.open = true; });
    document.title = doc.title;
    applyFilters();
    applyAppFilter();
    renderLive();
    window.scrollTo(0, y);
    return true;
  }

  async function refresh() {
    const r = await fetch(location.pathname, { credentials: "same-origin", cache: "no-store" });
    if (r.status === 401) return restarted();
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    swap(await r.text(), openState());
    hideBar();
  }

  function restarted() {
    pollStopped = true;
    bar("Das Dashboard wurde neu gestartet. Bitte den neuen Link aus dem Terminal öffnen.");
  }

  // ---- triage without reload ------------------------------------------------------------------------
  document.addEventListener("submit", async (e) => {
    const form = e.target.closest("form.triage");
    if (!form) return;
    e.preventDefault();
    const data = new URLSearchParams(new FormData(form));
    const button = e.submitter;
    if (button && button.name) data.set(button.name, button.value);
    const finding = form.closest("details.fx");
    const keep = openState();
    if (finding) keep.ids.add(finding.id);
    const buttons = form.querySelectorAll("button");
    buttons.forEach((b) => { b.disabled = true; });
    try {
      const r = await fetch(form.action, { method: "POST", body: data, credentials: "same-origin" });
      if (r.status === 401) return restarted();
      if (!r.ok) throw new Error((await r.text()).slice(0, 200));
      const label = button ? button.textContent : "Einordnung";
      const moved = button && (button.value === "ok" || button.value === "done");
      if (moved) keep.triaged = true;  // the finding moves into the "Eingeordnet" group; keep it visible
      swap(await r.text(), keep);
      toast(`Gespeichert: ${label}` + (moved ? ", steht jetzt unter „Eingeordnet“" : ""));
      lastVersion = await version();  // our own change is not "new data"
    } catch (err) {
      buttons.forEach((b) => { b.disabled = false; });
      toast(`Nicht gespeichert: ${err.message}`, true);
    }
  });

  // ---- "Am Handy öffnen": opens a screen on the phone, the change is made there by a tap ----------------
  document.addEventListener("submit", async (e) => {
    const form = e.target.closest("form.phone");
    if (!form) return;
    e.preventDefault();
    const button = form.querySelector("button");
    button.disabled = true;
    try {
      const r = await fetch(form.action, { method: "POST", body: new URLSearchParams(new FormData(form)),
                                           credentials: "same-origin" });
      if (r.status === 401) return restarted();
      if (!r.ok) throw new Error((await r.text()).slice(0, 200));
      const uninstall = form.querySelector("[name=what]").value === "uninstall";
      toast(uninstall ? "Am Handy erscheint jetzt „Deinstallieren?“. Dort mit OK bestätigen oder abbrechen."
                      : "Am Handy geöffnet. Falls gesperrt: entsperren, dann dort weitermachen.");
    } catch (err) {
      toast(err.message, true);
    } finally {
      button.disabled = false;
    }
  });

  // ---- live update ----------------------------------------------------------------------------------
  async function version() {
    const r = await fetch("/api/version", { credentials: "same-origin", cache: "no-store" });
    if (r.status === 401) {
      restarted();
      throw new Error("abgemeldet");
    }
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return (await r.json()).version;
  }

  function busy() {
    const a = document.activeElement;
    return a && a.matches("input[type=text], input[type=search], textarea, select") && a.value !== "";
  }

  async function poll() {
    if (pollStopped) return;
    try {
      const v = await version();
      if (lastVersion && v !== lastVersion) {
        if (busy()) {
          bar("Neue Scan-Daten sind da.", "Jetzt anzeigen", () => { refresh().catch(() => {}); });
        } else {
          await refresh();
          toast("Neue Daten geladen");
        }
      }
      lastVersion = v;
    } catch (e) {
      if (!pollStopped) bar("Keine Verbindung zum Dashboard. Läuft famcheck noch?");
      setTimeout(() => { hideBarIfConnected(); }, POLL_MS);
    }
    setTimeout(poll, document.hidden ? POLL_MS * 3 : POLL_MS);
  }

  async function hideBarIfConnected() {
    try {
      await version();
      hideBar();
    } catch (e) { /* still offline */ }
  }

  // ---- live box: what the running scan is doing (read only, text via textContent) -------------------
  const live = { snap: null, shownId: null, closedId: null, first: true };
  const RECENT_MS = 20000;  // a scan that ended this shortly before the page loaded is still shown

  function renderLive() {
    const box = document.getElementById("live");
    const s = live.snap;
    if (!box || !s) return;
    // finished scans from before this page was opened are not shown, nor the one the user closed
    const show = s.running || (s.id === live.shownId && s.id !== live.closedId);
    box.hidden = !show;
    if (!show) return;
    live.shownId = s.id;
    box.className = "panel live" + (s.running ? " running" : s.error ? " failed" : " done");
    box.replaceChildren();
    const head = document.createElement("div");
    head.className = "live-head";
    const title = document.createElement("b");
    title.textContent = (s.running ? "Scan läuft: " : s.error ? "Scan abgebrochen: " : "Scan fertig: ") + (s.label || "");
    head.appendChild(title);
    if (!s.running) {
      if (!s.error && s.serial) {
        const a = document.createElement("a");
        a.href = "/device/" + encodeURIComponent(s.serial);
        a.textContent = "Ergebnis ansehen";
        head.appendChild(a);
      }
      const close = document.createElement("button");
      close.type = "button";
      close.textContent = "Schließen";
      close.addEventListener("click", () => { live.closedId = s.id; renderLive(); });
      head.appendChild(close);
    }
    const log = document.createElement("pre");
    log.textContent = s.lines.join("\n") + (s.error ? "\n" + s.error : "");
    box.append(head, log);
    log.scrollTop = log.scrollHeight;
  }

  async function pollLive() {
    try {
      const r = await fetch("/api/live", { credentials: "same-origin", cache: "no-store" });
      if (r.ok) {
        const s = await r.json();
        const recent = s.finished && Date.now() - Date.parse(s.finished) < RECENT_MS;
        if (s.running || (live.first && recent)) live.shownId = s.id;  // older finished scans stay hidden
        live.first = false;
        live.snap = s;
        renderLive();
      }
    } catch (e) { /* the version poll reports lost connections */ }
    if (!pollStopped) setTimeout(pollLive, live.snap && live.snap.running ? 1000 : 4000);
  }

  // ---- start ----------------------------------------------------------------------------------------
  function start() {
    applyFilters();
    applyAppFilter();
    const target = location.hash && document.getElementById(location.hash.slice(1));
    if (target && target.matches("details.fx")) {
      target.open = true;
      const group = target.closest("details.triaged");
      if (group) group.open = true;
      target.scrollIntoView({ block: "center" });
    }
    poll();
    pollLive();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
