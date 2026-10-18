"use strict";
// ai-footprint dashboard, "Mission Control" design. Renders the run's JSON document.
// Every collected string is inserted as text nodes; nothing is parsed as markup.
(() => {
  const DOC = JSON.parse(document.getElementById("audit-data").textContent);
  const V = DOC.views || {};
  const HOST = DOC.host || {};
  const FIGS = V.figures || { machine: [], tools: {} };
  const TOOLS = (DOC.tools || []).filter((t) => t.installed);
  const TOOL_BY = Object.fromEntries(TOOLS.map((t) => [t.name, t]));
  const LENSES = V.lenses || [];
  const LENS_BY = Object.fromEntries(LENSES.map((l) => [l.id, l]));
  const COLUMNS = TOOLS.map((t) => t.name).concat(["host"]);
  const EXPOSURES = [];
  for (const t of TOOLS) for (const e of t.exposures || []) EXPOSURES.push(e);
  for (const e of DOC.host_exposures || []) EXPOSURES.push(e);
  const EXP_BY = Object.fromEntries(EXPOSURES.map((e) => [e.id, e]));
  const SEARCH = new WeakMap();
  const SVGNS = "http://www.w3.org/2000/svg";

  const PAGES = [
    { id: "overview", label: "Overview" },
    { id: "signals", label: "Signals" },
    { id: "keys", label: "Keys" },
    { id: "tools", label: "Tools" },
    { id: "checklist", label: "Checklist" },
    { id: "extensions", label: "Extensions" },
    { id: "network", label: "Network" },
    { id: "machine", label: "Machine" },
    { id: "method", label: "Method" },
    { id: "data", label: "Data" },
  ];

  // --- text ------------------------------------------------------------------------------

  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const HOME_RE =
    HOST.home && HOST.home.length > 1 ? new RegExp(escapeRe(HOST.home) + "(?=/|$|[^\\w.-])", "g") : null;
  const TIME_RE = /\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d(?:\.\d+)?)?(?:Z|[+-]\d\d:?\d\d)?/g;

  function fmtTime(stamp) {
    const zoned = /(Z|[+-]\d\d:?\d\d)$/.test(stamp) ? stamp : stamp + "Z";
    const d = new Date(zoned);
    if (Number.isNaN(d.getTime())) return stamp;
    return d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
  }

  /** Display form of any value: home as ~, ISO timestamps as YYYY-MM-DD HH:MM UTC. */
  function tidy(value) {
    let s = value == null ? "" : String(value);
    if (HOME_RE) s = s.replace(HOME_RE, "~");
    return s.replace(TIME_RE, fmtTime);
  }

  /** Text with `backtick` spans as <code>, as nodes. */
  function rich(text) {
    const parts = String(text == null ? "" : text).split("`");
    if (parts.length % 2 === 0) parts[parts.length - 2] += "`" + parts.pop();
    const out = [];
    parts.forEach((p, i) => {
      if (!p) return;
      if (i % 2) out.push(h("code", null, p));
      else out.push(...breakable(tidy(p)));
    });
    return out;
  }

  function toolName(name) {
    if (name === "host") return "Host";
    return TOOL_BY[name] ? TOOL_BY[name].display_name : String(name);
  }

  /** Same units and rounding as the Python fsinfo.human_size, so tables agree with figures. */
  function fmtBytes(n) {
    if (typeof n !== "number") return n == null ? "" : String(n);
    let value = n;
    for (const unit of ["B", "KB", "MB", "GB", "TB"]) {
      if (value < 1000 || unit === "TB") {
        return unit === "B" || unit === "KB" ? `${value.toFixed(0)} ${unit}` : `${value.toFixed(1)} ${unit}`;
      }
      value /= 1000;
    }
    return `${n} B`;
  }

  const LONG_RUN = /\S{24,}/g;
  const SEPARATOR = /([/._:=|,@-])/;

  /**
   * Text as nodes with line-break points after separators inside long runs (paths, ids), so
   * a long path wraps at its slashes and ordinary words are never split.
   */
  function breakable(text) {
    const nodes = [];
    let last = 0;
    for (const match of text.matchAll(LONG_RUN)) {
      if (match.index > last) nodes.push(document.createTextNode(text.slice(last, match.index)));
      for (const piece of match[0].split(SEPARATOR)) {
        if (!piece) continue;
        nodes.push(document.createTextNode(piece));
        if (piece.length === 1 && SEPARATOR.test(piece)) nodes.push(document.createElement("wbr"));
      }
      last = match.index + match[0].length;
    }
    if (last < text.length) nodes.push(document.createTextNode(text.slice(last)));
    return nodes;
  }

  // --- DOM -------------------------------------------------------------------------------

  function append(el, kids) {
    for (const k of kids) {
      if (k == null || k === false) continue;
      if (Array.isArray(k)) append(el, k);
      else if (typeof k === "string" || typeof k === "number") el.append(...breakable(tidy(k)));
      else el.appendChild(k);
    }
  }

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "href") el.setAttribute("href", String(v).startsWith("#") ? String(v) : "#");
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    append(el, kids);
    return el;
  }

  const ICONS = {
    overview: ["M3.5 3.5h7v7h-7z", "M13.5 3.5h7v4h-7z", "M13.5 10.5h7v10h-7z", "M3.5 13.5h7v7h-7z"],
    signals: ["M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z", "M12 3v4", "M12 17v4", "M3 12h4", "M17 12h4"],
    keys: ["M8 15a4 4 0 1 1 0-8a4 4 0 0 1 0 8z", "M11.5 11h9", "M17.5 11v3.5", "M20.5 11v2.5"],
    tools: ["M4 7.5l8-4.5 8 4.5v9l-8 4.5-8-4.5z", "M4 7.5l8 4.5 8-4.5", "M12 12v9"],
    checklist: ["M10 6h10", "M10 12h10", "M10 18h10", "M3.5 6l1.5 1.5L8 4.5", "M3.5 12l1.5 1.5L8 10.5", "M4 17.5h3v1H4z"],
    extensions: ["M9 2.5v5", "M15 2.5v5", "M5.5 7.5h13v3.5a6.5 6.5 0 0 1-13 0z", "M12 17.5v4"],
    network: ["M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z", "M3 12h18", "M12 3c2.6 2.6 3.8 5.6 3.8 9s-1.2 6.4-3.8 9", "M12 3c-2.6 2.6-3.8 5.6-3.8 9s1.2 6.4 3.8 9"],
    machine: ["M3 4.5h18v11H3z", "M8 20h8", "M12 15.5V20"],
    method: ["M9 3h6", "M10 3v6.5L4.6 18.7A1.5 1.5 0 0 0 5.9 21h12.2a1.5 1.5 0 0 0 1.3-2.3L14 9.5V3", "M7.2 15h9.6"],
    data: [
      "M8 3.5H7a2 2 0 0 0-2 2v4a2 2 0 0 1-2 2.5a2 2 0 0 1 2 2.5v4a2 2 0 0 0 2 2h1",
      "M16 3.5h1a2 2 0 0 1 2 2v4a2 2 0 0 0 2 2.5a2 2 0 0 0-2 2.5v4a2 2 0 0 1-2 2h-1",
    ],
    search: ["M11 4a7 7 0 1 0 0 14a7 7 0 1 0 0-14z", "M20 20l-4-4"],
    close: ["M6 6l12 12", "M18 6L6 18"],
    copy: ["M9 9h11v11H9z", "M5 15H4V4h11v1"],
    check: ["M5 12.5l4.5 4.5L19 7.5"],
    x: ["M7 7l10 10", "M17 7L7 17"],
    chev: ["M9.5 6l6 6-6 6"],
    up: ["M7 14l5-5 5 5"],
    down: ["M7 10l5 5 5-5"],
    prev: ["M14.5 6l-6 6 6 6"],
    logo: [
      "M12 2.5a9.5 9.5 0 1 0 0 19a9.5 9.5 0 1 0 0-19z",
      "M12 7.5a4.5 4.5 0 1 0 0 9a4.5 4.5 0 1 0 0-9z",
      "M12 12l6.7-6.7",
    ],
  };

  function icon(name, cls) {
    const svg = document.createElementNS(SVGNS, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("class", "ic" + (cls ? " " + cls : ""));
    svg.setAttribute("aria-hidden", "true");
    for (const d of ICONS[name] || []) {
      const p = document.createElementNS(SVGNS, "path");
      p.setAttribute("d", d);
      svg.appendChild(p);
    }
    return svg;
  }

  // --- filter ----------------------------------------------------------------------------

  function flatText(v, out) {
    if (v == null) return out;
    if (Array.isArray(v)) v.forEach((x) => flatText(x, out));
    else if (typeof v === "object") Object.values(v).forEach((x) => flatText(x, out));
    else out.push(tidy(v));
    return out;
  }

  /** Register an element as one filterable item, matched against the given values. */
  function mark(el, ...values) {
    el.setAttribute("data-f", "");
    SEARCH.set(el, flatText(values, []).join(" ").toLowerCase());
    return el;
  }

  const nomatch = () => h("p", { class: "nomatch" }, "Nothing here matches the filter.");

  function applyFilter() {
    const q = filterInput.value.trim().toLowerCase();
    let total = 0;
    let shown = 0;
    for (const el of main.querySelectorAll("[data-f]")) {
      const hit = !q || (SEARCH.get(el) || "").includes(q);
      el.hidden = !hit;
      total += 1;
      if (hit) shown += 1;
    }
    for (const g of main.querySelectorAll("[data-fgroup]")) {
      const items = Array.from(g.querySelectorAll("[data-f]"));
      const none = items.length > 0 && items.every((i) => i.hidden);
      if (g.getAttribute("data-fgroup") === "hide") g.hidden = !!q && items.every((i) => i.hidden);
      else g.classList.toggle("is-nomatch", none);
    }
    filterCount.textContent = q ? shown + " of " + total : "";
  }

  // --- routing ---------------------------------------------------------------------------

  let route = { page: "overview", arg: "", params: new URLSearchParams() };

  function safeDecode(s) {
    try {
      return decodeURIComponent(s);
    } catch (err) {
      console.warn("Could not decode route part", s, err);
      return s;
    }
  }

  function parseHash() {
    const raw = location.hash.slice(1);
    const qi = raw.indexOf("?");
    const path = qi < 0 ? raw : raw.slice(0, qi);
    const parts = path.split("/").map(safeDecode);
    const page = PAGES.some((p) => p.id === parts[0]) ? parts[0] : "overview";
    return { page, arg: parts.slice(1).join("/"), params: new URLSearchParams(qi < 0 ? "" : raw.slice(qi + 1)) };
  }

  function hrefFor(page, arg, params) {
    let s = "#" + page;
    if (arg) s += "/" + encodeURIComponent(arg);
    const q = params ? params.toString() : "";
    return q ? s + "?" + q : s;
  }

  /** Link that opens a finding's detail panel over the current view. */
  function findingHref(id) {
    const p = new URLSearchParams(route.params);
    p.set("f", id);
    return hrefFor(route.page, route.arg, p);
  }

  // --- shared pieces ---------------------------------------------------------------------

  function panel(title, aside, ...body) {
    return h(
      "section",
      { class: "panel" },
      h("header", { class: "panel-head" }, h("h2", { class: "label" }, title), aside ? h("div", { class: "panel-aside" }, aside) : null),
      h("div", { class: "panel-body" }, body),
    );
  }

  function pageHead(title, sub, ...extra) {
    return h(
      "div",
      { class: "page-head" },
      h("div", { class: "page-titles" }, h("h1", { class: "page-title" }, title), sub ? h("p", { class: "page-sub" }, sub) : null),
      extra,
    );
  }

  const chip = (text, cls) => h("span", { class: "chip" + (cls ? " " + cls : "") }, text);
  const empty = (text) => h("p", { class: "empty" }, text || "None recorded.");

  function yesNo(v, concern) {
    if (v === true) return h("span", { class: "flag" + (concern ? " flag-exp" : "") }, "yes");
    if (v === false) return h("span", { class: "flag flag-dim" }, "no");
    return h("span", { class: "dim" }, "not recorded");
  }

  function figTone(f) {
    if (f.value === "found") return " tone-exp";
    if (f.value === "not checked") return " tone-na";
    return "";
  }

  /** A figure tile. data-figure / data-figure-value let the layout check compare it with the data. */
  function statTile(f, scope, href) {
    const label = h("div", { class: "stat-label" }, f.label, href ? icon("chev", "stat-go") : null);
    const value = h("div", { class: "stat-value num" + figTone(f), "data-figure-value": "" }, f.display);
    const body = [label, value, h("div", { class: "stat-detail" }, f.detail)];
    const attrs = { class: href ? "stat stat-link" : "stat", href: href || null, "data-figure": scope + ":" + f.id };
    return mark(h(href ? "a" : "div", attrs, body), f.label, f.display, f.detail);
  }

  function kv(pairs) {
    const rows = pairs.filter((p) => p && p[1] != null && p[1] !== "" && !(Array.isArray(p[1]) && !p[1].length));
    return h(
      "dl",
      { class: "kv" },
      rows.map(([k, v, cls]) => h("div", { class: "kv-row" }, h("dt", null, k), h("dd", { class: cls || null }, v))),
    );
  }

  /** A table; at narrow widths CSS stacks each row into a labelled card. */
  function table(cols, rows, opts) {
    const o = opts || {};
    if (!rows.length) return empty(o.empty);
    const body = rows.map((r) =>
      mark(
        h("tr", null, cols.map((c) => h("td", { class: c.cls || null, "data-label": c.label }, h("div", { class: "cell-v" }, c.cell(r))))),
        o.search ? o.search(r) : r,
      ),
    );
    return h(
      "div",
      { class: "table-wrap", "data-fgroup": "note" },
      h(
        "table",
        { class: "tbl" + (o.cls ? " " + o.cls : "") },
        h("thead", null, h("tr", null, cols.map((c) => h("th", { scope: "col", class: c.cls || null }, c.label)))),
        h("tbody", null, body),
      ),
      nomatch(),
    );
  }

  const mono = (v) => h("span", { class: "mono" }, v == null ? "" : v);

  function stateOf(c) {
    if ((c.exposures || []).length || c.exposed) return "review";
    if (c.unchecked) return "unchecked";
    return "clear";
  }

  function stateBadge(state) {
    if (state === "review") return h("span", { class: "state s-exp" }, h("span", { class: "dot" }), "Review");
    if (state === "clear") return h("span", { class: "state s-clear" }, icon("check"), "Clear");
    return h("span", { class: "state s-na" }, h("span", { class: "ring" }), "Not checked");
  }

  function fixSummary(e) {
    if (!e.fix) return h("span", { class: "dim" }, "No fix listed");
    const labels = (V.fix_labels || {})[e.id] || [];
    return h(
      "div",
      { class: "fixsum" },
      h(
        "span",
        { class: "fixdots", "aria-hidden": "true" },
        labels.map((l) => h("span", { class: "fd tone-" + (l.tone || "neutral") })),
      ),
      h("span", { class: "fixsum-t" }, e.fix.summary),
    );
  }

  /** Findings as rows; selecting a row opens the detail panel. */
  function findingTable(list, opts) {
    const o = opts || {};
    if (!list.length) return empty("No signals.");
    const cols = [{ key: "label", label: "Signal" }];
    if (o.tool !== false) cols.push({ key: "tool", label: "Tool" });
    if (o.lens !== false) cols.push({ key: "position", label: "Position" });
    cols.push({ key: "evidence", label: "Evidence", cls: "c-num" }, { key: "fix", label: "Fix" });
    const head = cols.map((c) => h("th", { scope: "col", class: c.cls || null }, o.sortable && c.key !== "fix" ? sortButton(c) : c.label));
    const rows = list.map((e) => findingRow(e, o));
    return h(
      "div",
      { class: "table-wrap", "data-fgroup": "note" },
      h("table", { class: "tbl ftable" }, h("thead", null, h("tr", null, head)), h("tbody", null, rows)),
      nomatch(),
    );
  }

  function findingRow(e, o) {
    const href = findingHref(e.id);
    const lens = LENS_BY[e.lens] ? LENS_BY[e.lens].title : e.lens;
    const tr = h(
      "tr",
      { class: "frow" },
      h("td", { "data-label": "Signal", class: "c-label" }, h("a", { class: "row-link", href }, e.label), h("div", { class: "mono-sub" }, e.id)),
      o.tool !== false ? h("td", { "data-label": "Tool" }, chip(toolName(e.tool))) : null,
      o.lens !== false ? h("td", { "data-label": "Position", class: "c-lens" }, lens) : null,
      h("td", { "data-label": "Evidence", class: "c-num num" }, String((e.evidence || []).length)),
      h("td", { "data-label": "Fix", class: "c-fix" }, fixSummary(e)),
    );
    tr.dataset.id = e.id;
    tr.addEventListener("click", (ev) => {
      if (!ev.target.closest("a, button")) location.hash = href;
    });
    return mark(tr, e.label, e.id, toolName(e.tool), lens, e.statement, e.evidence, e.fix && e.fix.summary);
  }

  /** Attacker-position switcher over a `lenses` view ([{lens, points[]}]). */
  function lensPanel(lensData) {
    const byId = {};
    for (const x of lensData || []) byId[x.lens] = x.points || [];
    const first = LENSES.find((l) => (byId[l.id] || []).length) || LENSES[0];
    let active = first ? first.id : "";
    const tabs = h("div", { class: "seg seg-wrap", role: "tablist", "aria-label": "Attacker position" });
    const body = h("div", { class: "lens-body", role: "tabpanel" });
    const draw = (focus) => {
      tabs.replaceChildren(
        ...LENSES.map((l) =>
          h(
            "button",
            {
              type: "button",
              role: "tab",
              class: "seg-btn",
              "aria-selected": String(l.id === active),
              tabindex: l.id === active ? "0" : "-1",
              onclick: () => {
                active = l.id;
                draw(true);
              },
              onkeydown: (ev) => moveTab(ev, l.id),
            },
            h("span", null, l.title),
            h("span", { class: "seg-n num" }, String((byId[l.id] || []).length)),
          ),
        ),
      );
      const lens = LENS_BY[active] || {};
      const points = byId[active] || [];
      body.replaceChildren(
        h("p", { class: "lens-q" }, lens.question),
        points.length
          ? h("ul", { class: "points", "data-fgroup": "note" }, points.map(pointRow), nomatch())
          : empty("Nothing recorded from this position."),
      );
      if (focus) tabs.querySelector('[aria-selected="true"]').focus();
      applyFilter();
    };
    const moveTab = (ev, id) => {
      const step = ev.key === "ArrowRight" ? 1 : ev.key === "ArrowLeft" ? -1 : 0;
      if (!step) return;
      ev.preventDefault();
      const i = LENSES.findIndex((l) => l.id === id);
      active = LENSES[(i + step + LENSES.length) % LENSES.length].id;
      draw(true);
    };
    draw(false);
    return h("div", { class: "lens-panel" }, tabs, body);
  }

  function pointRow(p) {
    const link =
      p.exposure_id && EXP_BY[p.exposure_id]
        ? h("a", { class: "point-link", href: findingHref(p.exposure_id) }, "Open signal", icon("chev"))
        : null;
    return mark(
      h("li", { class: "point" }, h("span", { class: "point-tool" }, p.tool), h("p", { class: "point-text" }, rich(p.text)), link),
      p.tool,
      p.text,
    );
  }

  // --- overview --------------------------------------------------------------------------

  function hero() {
    const meta = [
      ["OS", HOST.os],
      ["Arch", HOST.arch],
      ["User", HOST.user],
      ["Generated", DOC.generated_at],
      ["Auditor", DOC.auditor_version],
    ];
    return h(
      "div",
      { class: "hero" },
      h(
        "div",
        { class: "hero-id" },
        h("p", { class: "hero-kicker" }, "AI tool footprint"),
        h("h1", { class: "hero-host" }, HOST.hostname),
      ),
      h(
        "dl",
        { class: "hero-meta" },
        meta.filter((m) => m[1] != null && m[1] !== "").map(([k, v]) => h("div", null, h("dt", null, k), h("dd", { class: "mono" }, v))),
      ),
    );
  }

  function findingsGrid() {
    const m = V.signals_matrix || {};
    const grid = h("div", { class: "fgrid", role: "table", "aria-label": "Signals by attacker position and tool" });
    grid.style.setProperty("--cols", String(COLUMNS.length));
    grid.appendChild(
      h(
        "div",
        { class: "fg-row fg-head", role: "row" },
        h("div", { class: "fg-corner", role: "columnheader" }, "Attacker position"),
        COLUMNS.map((c, ci) => h("div", { class: "fg-col", role: "columnheader", "data-c": ci }, toolName(c))),
      ),
    );
    LENSES.forEach((l, ri) => {
      const counts = m[l.id] || {};
      const cells = COLUMNS.map((c, ci) => gridCell(l, c, counts[c], ri, ci));
      const head = h(
        "div",
        { class: "fg-lens", role: "rowheader", "data-r": ri },
        h("span", { class: "fg-lens-t" }, l.title),
        h("span", { class: "fg-lens-q" }, l.question),
      );
      grid.appendChild(mark(h("div", { class: "fg-row", role: "row" }, head, cells), l.title, l.question));
    });
    const cross = (ev) => {
      const cell = ev.target.closest(".fg-cell");
      for (const el of grid.querySelectorAll(".is-x")) el.classList.remove("is-x");
      if (!cell) return;
      for (const el of grid.querySelectorAll('[data-r="' + cell.dataset.r + '"].fg-lens, [data-c="' + cell.dataset.c + '"].fg-col')) {
        el.classList.add("is-x");
      }
    };
    grid.addEventListener("mouseover", cross);
    grid.addEventListener("focusin", cross);
    grid.addEventListener("mouseleave", () => grid.querySelectorAll(".is-x").forEach((el) => el.classList.remove("is-x")));
    return h("div", { "data-fgroup": "note" }, grid, nomatch());
  }

  function gridCell(lens, col, n, ri, ci) {
    const has = typeof n === "number";
    const level = !has || n === 0 ? 0 : n === 1 ? 1 : n === 2 ? 2 : n < 5 ? 3 : 4;
    const kids = [h("span", { class: "fg-cell-tool" }, toolName(col)), h("span", { class: "fg-n num", "data-cell-value": "" }, has ? String(n) : "–")];
    const attrs = { class: "fg-cell heat-" + level, role: "cell", "data-r": ri, "data-c": ci, "data-cell": lens.id + ":" + col };
    if (!has || n === 0) return h("div", attrs, kids);
    const p = new URLSearchParams({ lens: lens.id, tool: col });
    attrs.href = hrefFor("signals", "", p);
    attrs["aria-label"] = toolName(col) + ", " + lens.title + ": " + n + " signals";
    return h("a", attrs, kids);
  }

  function pageOverview() {
    const links = { tools: "#tools", signals: "#signals", checks: "#checklist", api_keys: "#keys", autostart: "#extensions/mcp" };
    const machine = V.machine || {};
    const summary = h(
      "div",
      { class: "summary" },
      h("ul", { class: "headline", "data-fgroup": "note" }, (machine.headline || []).map((s) => mark(h("li", null, rich(s)), s)), nomatch()),
      machine.proof ? h("p", { class: "proof" }, icon("check"), h("span", null, rich(machine.proof))) : null,
    );
    return [
      hero(),
      h("section", { class: "stats", "aria-label": "This machine", "data-fgroup": "note" }, (FIGS.machine || []).map((f) => statTile(f, "machine", links[f.id])), nomatch()),
      h(
        "div",
        { class: "ov-split" },
        panel("Signals grid", h("span", { class: "hint" }, "Select a cell to list those signals"), findingsGrid()),
        panel("Summary", null, summary),
      ),
      panel("By attacker position", null, lensPanel(machine.lenses)),
      h("h2", { class: "label strip-label" }, "Tools"),
      h("div", { class: "tool-strip", "data-fgroup": "note" }, TOOLS.map(toolCard), nomatch()),
    ];
  }

  function toolCard(t) {
    const figs = (FIGS.tools || {})[t.name] || [];
    return mark(
      h(
        "section",
        { class: "panel tool-card" },
        h(
          "header",
          { class: "panel-head" },
          h("h3", { class: "tool-card-name" }, t.display_name),
          h("a", { class: "btn-ghost", href: "#tools/" + encodeURIComponent(t.name), "aria-label": "Open " + t.display_name }, "Open", icon("chev")),
        ),
        h(
          "dl",
          { class: "figlist" },
          figs.map((f) =>
            h(
              "div",
              { class: "figrow", "data-figure": t.name + ":" + f.id },
              h("dt", null, f.label),
              h("dd", { class: "figrow-v num" + figTone(f), "data-figure-value": "" }, f.display),
              h("dd", { class: "figrow-d" }, f.detail),
            ),
          ),
        ),
      ),
      t.display_name,
      figs.map((f) => [f.label, f.display, f.detail]),
    );
  }

  // --- findings --------------------------------------------------------------------------

  const sort = { key: "position", dir: 1 };
  let findingOrder = EXPOSURES.slice();

  function sortKeyOf(e, key) {
    if (key === "label") return String(e.label || "").toLowerCase();
    if (key === "tool") return COLUMNS.indexOf(e.tool);
    if (key === "evidence") return (e.evidence || []).length;
    return LENSES.findIndex((l) => l.id === e.lens);
  }

  function sortFindings(list) {
    const idx = new Map(EXPOSURES.map((e, i) => [e.id, i]));
    const byPos = (a, b) => sortKeyOf(a, "position") - sortKeyOf(b, "position") || COLUMNS.indexOf(a.tool) - COLUMNS.indexOf(b.tool);
    return list.slice().sort((a, b) => {
      const ka = sortKeyOf(a, sort.key);
      const kb = sortKeyOf(b, sort.key);
      const c = ka < kb ? -1 : ka > kb ? 1 : 0;
      return c * sort.dir || byPos(a, b) || idx.get(a.id) - idx.get(b.id);
    });
  }

  function sortButton(c) {
    const on = sort.key === c.key;
    return h(
      "button",
      {
        type: "button",
        class: "sort" + (on ? " is-on" : ""),
        "aria-sort": on ? (sort.dir > 0 ? "ascending" : "descending") : null,
        onclick: () => {
          sort.dir = on ? -sort.dir : 1;
          sort.key = c.key;
          renderPage();
          renderDrawer(openId);
        },
      },
      c.label,
      icon(on && sort.dir < 0 ? "down" : "up"),
    );
  }

  function filterChips(label, current, options, make) {
    return h(
      "div",
      { class: "chips-row" },
      h("span", { class: "chips-label" }, label),
      h(
        "div",
        { class: "chips" },
        options.map(([value, text]) =>
          h("a", { class: "fchip", href: make(value), "aria-current": value === current ? "true" : null }, text),
        ),
      ),
    );
  }

  function pageFindings() {
    const lens = route.params.get("lens") || "";
    const tool = route.params.get("tool") || "";
    const list = sortFindings(EXPOSURES.filter((e) => (!lens || e.lens === lens) && (!tool || e.tool === tool)));
    findingOrder = list;
    const make = (k, v) => () => {
      const p = new URLSearchParams();
      const next = { lens, tool, [k]: v };
      if (next.lens) p.set("lens", next.lens);
      if (next.tool) p.set("tool", next.tool);
      return hrefFor("signals", "", p);
    };
    const sub = list.length === EXPOSURES.length ? list.length + " signals" : list.length + " of " + EXPOSURES.length + " signals";
    return [
      pageHead("Signals", sub),
      h(
        "div",
        { class: "filters" },
        filterChips("Position", lens, [["", "All"]].concat(LENSES.map((l) => [l.id, l.title])), (v) => make("lens", v)()),
        filterChips("Tool", tool, [["", "All"]].concat(COLUMNS.map((c) => [c, toolName(c)])), (v) => make("tool", v)()),
      ),
      h("section", { class: "panel panel-flush" }, findingTable(list, { sortable: true })),
    ];
  }

  // --- keys ------------------------------------------------------------------------------

  const KEY_TYPES = ["API key", "OAuth login", "Password", "Secret"];

  /** Stored keys and logins: each value appears once, with every place that holds it. */
  function keyTable(rows) {
    return table(
      [
        { label: "Provider", cell: (k) => h("span", { class: "strong" }, k.provider) },
        { label: "Type", cell: (k) => chip(k.kind) },
        {
          label: "Key",
          cls: "c-path",
          cell: (k) => [
            mono(k.shown),
            k.length ? h("div", { class: "sub" }, k.length + " characters") : null,
            h("div", { class: "sub mono" }, "fingerprint " + k.fingerprints.join(", ")),
          ],
        },
        {
          label: "Belongs to",
          cell: (k) => (k.owner ? [h("div", null, k.owner), h("div", { class: "sub" }, "from " + k.owner_source)] : h("span", { class: "dim" }, "not recorded on disk")),
        },
        {
          label: "Stored in",
          cls: "c-path",
          cell: (k) =>
            k.locations.map((l) =>
              h(
                "div",
                { class: "key-loc" },
                h("div", null, chip(l.tool), " ", l.store, l.readable_by_others ? [" ", chip("readable by other accounts", "chip-exp")] : null),
                h("div", { class: "sub mono" }, l.location),
              ),
            ),
        },
        { label: "Keeps working", cell: (k) => k.lifetime },
      ],
      rows,
      {
        empty: "No stored keys or logins.",
        search: (k) => [k.provider, k.kind, k.shown, k.owner, k.owner_source, k.used_by, k.locations.map((l) => [l.store, l.location])],
      },
    );
  }

  function pageKeys() {
    const all = V.keys || [];
    const kind = route.params.get("type") || "";
    const tool = route.params.get("tool") || "";
    const rows = all.filter((k) => (!kind || k.kind === kind) && (!tool || k.used_by.includes(toolName(tool))));
    const make = (key, value) => {
      const p = new URLSearchParams();
      const next = { type: kind, tool, [key]: value };
      if (next.type) p.set("type", next.type);
      if (next.tool) p.set("tool", next.tool);
      return hrefFor("keys", "", p);
    };
    const kinds = KEY_TYPES.filter((t) => all.some((k) => k.kind === t));
    const sub = rows.length === all.length ? all.length + " stored" : rows.length + " of " + all.length + " stored";
    return [
      pageHead("Keys", sub),
      h(
        "p",
        { class: "page-note" },
        "Every API key, login and password the audited tools store, by provider. Values are never kept: only the start, the last four characters of values 20 characters or longer, and a fingerprint that marks the same value stored in several places.",
      ),
      h(
        "div",
        { class: "filters" },
        filterChips("Type", kind, [["", "All"]].concat(kinds.map((t) => [t, t])), (v) => make("type", v)),
        filterChips("Tool", tool, [["", "All"]].concat(TOOLS.map((t) => [t.name, t.display_name])), (v) => make("tool", v)),
      ),
      h("section", { class: "panel panel-flush" }, keyTable(rows)),
    ];
  }

  // --- finding detail panel --------------------------------------------------------------

  const drawer = h("aside", { class: "drawer", role: "dialog", "aria-modal": "true", "aria-labelledby": "drawer-title" });
  const scrim = h("div", { class: "scrim", onclick: () => closeDrawer() });
  let openId = null;
  let returnFocus = null;

  function closeDrawer() {
    const p = new URLSearchParams(route.params);
    p.delete("f");
    location.hash = hrefFor(route.page, route.arg, p);
  }

  function renderDrawer(id) {
    const e = id ? EXP_BY[id] : null;
    for (const tr of main.querySelectorAll("tr.frow")) tr.classList.toggle("is-sel", !!e && tr.dataset.id === e.id);
    drawer.classList.toggle("is-open", !!e);
    scrim.classList.toggle("is-open", !!e);
    document.body.classList.toggle("has-drawer", !!e);
    if (!e) {
      if (openId && returnFocus && document.contains(returnFocus)) returnFocus.focus({ preventScroll: true });
      openId = null;
      return;
    }
    if (!openId) returnFocus = document.activeElement;
    drawer.replaceChildren(...drawerContent(e));
    if (openId !== id) {
      drawer.scrollTop = 0;
      drawer.querySelector(".drawer-close").focus({ preventScroll: true });
    }
    openId = id;
  }

  function drawerNav(e) {
    const order = findingOrder.some((x) => x.id === e.id) ? findingOrder : sortFindings(EXPOSURES);
    const i = order.findIndex((x) => x.id === e.id);
    const prev = order[i - 1];
    const next = order[i + 1];
    const step = (x, ic, label) =>
      x ? h("a", { class: "icon-btn", href: findingHref(x.id), "aria-label": label + ": " + x.label }, icon(ic)) : h("span", { class: "icon-btn is-off", "aria-hidden": "true" }, icon(ic));
    return h(
      "div",
      { class: "drawer-nav" },
      h("span", { class: "drawer-pos num" }, i + 1 + " / " + order.length),
      step(prev, "prev", "Previous signal"),
      step(next, "chev", "Next signal"),
      h("button", { type: "button", class: "icon-btn drawer-close", "aria-label": "Close signal", onclick: closeDrawer }, icon("close")),
    );
  }

  function drawerContent(e) {
    const lens = LENS_BY[e.lens] || { title: e.lens, question: "" };
    const cites = (DOC.checklist || []).filter((c) => (c.exposures || []).includes(e.id));
    return [
      h("header", { class: "drawer-head" }, h("div", { class: "drawer-tags" }, chip(toolName(e.tool)), chip(lens.title, "chip-lens")), drawerNav(e)),
      h(
        "div",
        { class: "drawer-body" },
        h("h2", { class: "drawer-title", id: "drawer-title" }, e.label),
        h("p", { class: "mono-sub" }, e.id),
        h("p", { class: "statement" }, rich(e.statement)),
        h("p", { class: "lens-q drawer-q" }, lens.question),
        dSection("Evidence", (e.evidence || []).length, (e.evidence || []).length ? h("ul", { class: "evidence" }, e.evidence.map((x) => h("li", null, rich(x)))) : empty()),
        dSection("Fix", null, fixBlock(e)),
        dSection(
          "Checklist",
          cites.length,
          cites.length
            ? h("ul", { class: "cites" }, cites.map((c) => h("li", null, h("span", { class: "dim" }, c.scope), h("span", null, c.check))))
            : empty("No checklist row cites this signal."),
        ),
      ),
    ];
  }

  function dSection(title, count, body) {
    return h(
      "section",
      { class: "dsec" },
      h("h3", { class: "label" }, title, count != null ? h("span", { class: "count num" }, String(count)) : null),
      body,
    );
  }

  function fixBlock(e) {
    if (!e.fix) return empty("No fix listed for this signal.");
    const labels = (V.fix_labels || {})[e.id] || [];
    const vals = e.fix.validations || [];
    const steps = (e.fix.commands || []).map((cmd, i) => {
      const val = vals.find((v) => v.command === cmd.text) || vals[i];
      return fixStep(cmd, labels[i], val, e.id + "-" + i);
    });
    return [h("p", { class: "fix-summary" }, rich(e.fix.summary)), h("ol", { class: "steps" }, steps)];
  }

  function fixStep(cmd, label, val, key) {
    const body = cmd.manual
      ? h("div", { class: "manual" }, h("span", { class: "manual-tag" }, "Manual step"), h("p", null, rich(cmd.text)))
      : h("div", { class: "code" }, h("pre", null, h("code", null, document.createTextNode(cmd.text))), copyButton(cmd.text));
    const checks = (val && val.checks) || [];
    const listId = "chk-" + key.replace(/[^\w-]/g, "_");
    const list = h(
      "ul",
      { class: "checks", id: listId, hidden: true },
      checks.map((c) =>
        h("li", { class: c.passed ? "ok" : "bad" }, icon(c.passed ? "check" : "x"), h("span", { class: "chk-n" }, c.name), h("span", { class: "chk-d" }, c.detail)),
      ),
    );
    const toggle = checks.length
      ? h(
          "button",
          {
            type: "button",
            class: "chk-toggle",
            "aria-expanded": "false",
            "aria-controls": listId,
            onclick: (ev) => {
              const btn = ev.currentTarget;
              const open = btn.getAttribute("aria-expanded") !== "true";
              btn.setAttribute("aria-expanded", String(open));
              list.hidden = !open;
            },
          },
          icon("chev"),
          "Checks",
          h("span", { class: "count num" }, String(checks.length)),
        )
      : null;
    const badge = label ? h("span", { class: "badge tone-" + (label.tone || "neutral") }, label.label) : null;
    return h("li", { class: "step" }, body, h("div", { class: "step-meta" }, badge, toggle), list);
  }

  function copyButton(text) {
    const t = h("span", null, "Copy");
    const b = h("button", { type: "button", class: "copy", "aria-label": "Copy command" }, icon("copy"), t);
    b.addEventListener("click", async () => {
      let ok = false;
      try {
        await navigator.clipboard.writeText(text);
        ok = true;
      } catch (err) {
        console.warn("Clipboard write failed", err);
      }
      t.textContent = ok ? "Copied" : "Copy failed";
      b.classList.toggle("is-done", ok);
      setTimeout(() => {
        t.textContent = "Copy";
        b.classList.remove("is-done");
      }, 1600);
    });
    return b;
  }

  // --- tools -----------------------------------------------------------------------------

  function pageTools() {
    const t = TOOL_BY[route.arg] || TOOLS[0];
    if (!t) return [pageHead("Tools", null), empty("No installed tools in this audit.")];
    const vt = (V.tools || {})[t.name] || {};
    const figs = (FIGS.tools || {})[t.name] || [];
    const switcher = h(
      "nav",
      { class: "seg tool-switch", "aria-label": "Tool" },
      TOOLS.map((x) => h("a", { class: "seg-btn", href: "#tools/" + encodeURIComponent(x.name), "aria-current": x === t ? "page" : null }, x.display_name)),
    );
    const sections = toolSections(t, vt);
    const toc = h(
      "nav",
      { class: "toc", "aria-label": "Sections" },
      h("span", { class: "label" }, "On this page"),
      sections.map((s) =>
        h("button", { type: "button", class: "toc-btn", onclick: () => document.getElementById(s.id).scrollIntoView({ block: "start" }) }, s.title),
      ),
    );
    const body = sections.map((s) => h("section", { class: "panel tsec", id: s.id, "data-fgroup": "hide" }, h("header", { class: "panel-head" }, h("h2", { class: "label" }, s.title)), h("div", { class: "panel-body" }, s.body)));
    return [
      pageHead(t.display_name, null, switcher),
      (vt.headline || []).length ? h("ul", { class: "headline headline-tool" }, vt.headline.map((s) => mark(h("li", null, rich(s)), s))) : null,
      h("section", { class: "stats", "aria-label": t.display_name + " figures", "data-fgroup": "note" }, figs.map((f) => statTile(f, t.name)), nomatch()),
      h("div", { class: "tool-layout" }, toc, h("div", { class: "tool-main" }, body)),
    ];
  }

  function toolSections(t, vt) {
    const s = (id, title, body) => ({ id: "sec-" + id, title, body });
    return [
      s("signals", "Signals", findingTable(EXPOSURES.filter((e) => e.tool === t.name), { tool: false })),
      s("positions", "By attacker position", lensPanel(vt.lenses)),
      s("questions", "Your questions", answers(vt.answers || [])),
      s("keys", "Keys", keyTable((V.keys || []).filter((k) => k.used_by.includes(t.display_name)))),
      s("credentials", "Credentials", (t.credentials || []).length ? t.credentials.map(credentialCard) : empty()),
      s("files", "Files on disk", artifactsTable(t.artifacts || [])),
      s("extensions", "Extensions", extensionTable(t.extensions || [], false)),
      s("settings", "Settings", settingsTable(t.settings || [])),
      s("network", "Network", networkBlock(t)),
      s("secrets", "Secrets at rest", secretsBlock(t.secret_scan)),
      s("instructions", "Instruction files", instructionsTable(t.instructions || [])),
      s("account", "Account", accountTable(t.account || [])),
      s("runtime", "Runtime and other records", runtimeBlock(t)),
    ];
  }

  function answers(list) {
    if (!list.length) return empty();
    return h(
      "div",
      { class: "answers" },
      list.map((a, i) => {
        const hasMore = (a.headers || []).length || (a.links || []).length;
        if (!hasMore) {
          return mark(h("div", { class: "qa qa-inline" }, h("span", { class: "qa-q" }, a.question), h("span", { class: "qa-a" }, rich(a.text || "No answer recorded."))), a.question, a.text);
        }
        return mark(answerAccordion(a, i), a.question, a.text, a.rows, a.links);
      }),
    );
  }

  function answerAccordion(a, i) {
    const id = "ans-" + i;
    const rows = a.rows || [];
    const body = h(
      "div",
      { class: "qa-body", id, hidden: true },
      a.text ? h("p", null, rich(a.text)) : null,
      (a.headers || []).length
        ? table(
            a.headers.map((hd, ci) => ({ label: hd, cell: (r) => rich(r[ci]) })),
            rows,
            { cls: "tbl-compact", empty: "No rows." },
          )
        : null,
      (a.links || []).length
        ? h("div", { class: "qa-links" }, a.links.map(([pid, label]) => h("a", { class: "btn-ghost", href: ["mcp", "skills", "plugins"].includes(pid) ? "#extensions/" + pid : "#" + pid }, label, icon("chev"))))
        : null,
    );
    const btn = h(
      "button",
      {
        type: "button",
        class: "qa-btn",
        "aria-expanded": "false",
        "aria-controls": id,
        onclick: () => {
          const open = btn.getAttribute("aria-expanded") !== "true";
          btn.setAttribute("aria-expanded", String(open));
          body.hidden = !open;
        },
      },
      icon("chev"),
      h("span", { class: "qa-q" }, a.question),
      rows.length ? h("span", { class: "count num" }, rows.length + (rows.length === 1 ? " row" : " rows")) : null,
    );
    return h("div", { class: "qa" }, btn, body);
  }

  /** How long a copied credential keeps working, as written in views.credentials. */
  function lifetime(c) {
    const toolOf = TOOLS.find((t) => (t.credentials || []).includes(c));
    const row = (V.credentials || []).find((r) => toolOf && r.tool === toolOf.name && r.provider === c.provider);
    return row ? row.lifetime : null;
  }

  function credentialCard(c) {
    return mark(
      h(
        "article",
        { class: "cred" },
        h(
          "header",
          { class: "cred-head" },
          h("h3", { class: "cred-name" }, c.provider),
          chip(c.store),
          c.readable_by_others ? chip("Readable by other accounts", "chip-exp") : null,
        ),
        kv([
          ["Location", mono(c.location), "wrap"],
          ["Keeps working", lifetime(c)],
          ["Protection", c.protection],
          ["Readable by others", yesNo(c.readable_by_others, true)],
          ["Live check", c.live_check],
        ]),
        (c.tokens || []).length ? h("div", { class: "tokens" }, c.tokens.map(tokenCard)) : null,
      ),
      c,
    );
  }

  function tokenCard(t) {
    const claims = Object.entries(t.claims || {});
    return h(
      "div",
      { class: "token" },
      h("div", { class: "token-head" }, h("span", { class: "mono token-field" }, t.field), h("span", { class: "dim" }, t.kind), t.expired === true ? chip("expired", "chip-na") : null),
      kv([
        ["Description", t.description],
        ["Prefix", t.prefix ? mono(t.prefix) : null],
        ["Last four", t.last4 ? mono(t.last4) : null],
        ["Length", t.length != null ? mono(String(t.length)) : null],
        ["Fingerprint", t.fingerprint ? mono(t.fingerprint) : null],
        ["Issuer", t.issuer],
        ["Audience", t.audience],
        ["Algorithm", t.algorithm],
        ["Key id", t.key_id],
        ["Issued", t.issued_at],
        ["Expires", t.expires_at || "none recorded"],
        ["Expired", t.expired == null ? null : yesNo(t.expired)],
        ["Scopes", (t.scopes || []).length ? h("span", { class: "chips" }, t.scopes.map((x) => chip(x, "chip-mono"))) : null],
        ["Signature", t.signature],
      ]),
      claims.length
        ? h(
            "details",
            { class: "claims" },
            h("summary", null, "Claims", h("span", { class: "count num" }, String(claims.length))),
            kv(claims.map(([k, v]) => [k, mono(typeof v === "object" ? JSON.stringify(v) : String(v)), "wrap"])),
          )
        : null,
    );
  }

  function accessFlags(a) {
    const flags = [];
    if (a.other_readable) flags.push(chip("other-readable", "chip-exp"));
    if (a.group_writable) flags.push(chip("group-writable", "chip-exp"));
    if (a.other_writable) flags.push(chip("other-writable", "chip-exp"));
    return flags.length ? h("span", { class: "chips" }, flags) : h("span", { class: "dim" }, "owner only");
  }

  function artifactsTable(list) {
    return table(
      [
        { label: "Item", cell: (a) => [h("div", null, a.label), h("div", { class: "sub" }, a.description)] },
        { label: "Path", cls: "c-path", cell: (a) => mono(a.path) },
        { label: "Category", cell: (a) => a.category },
        { label: "Size", cls: "c-num", cell: (a) => (a.exists ? mono(fmtBytes(a.size_bytes)) : h("span", { class: "dim" }, "missing")) },
        { label: "Files", cls: "c-num", cell: (a) => mono(a.file_count == null ? "" : String(a.file_count)) },
        { label: "Mode", cell: (a) => mono(a.mode) },
        { label: "Owner", cell: (a) => a.owner },
        { label: "Access", cell: accessFlags },
        { label: "Dates", cell: (a) => mono([a.oldest, a.newest].filter(Boolean).join(" to ")) },
      ],
      list,
    );
  }

  function extensionFlags(x) {
    const flags = [
      x.autostart ? chip("starts automatically") : null,
      x.dangling ? chip("target missing", "chip-exp") : null,
    ].filter(Boolean);
    return flags.length ? h("span", { class: "chips" }, flags) : "—";
  }

  function extensionTable(list, withUsers) {
    const cols = [
      {
        label: "Name",
        cell: (x) => [
          h("div", { class: "mono strong" }, x.name),
          x.group && x.kind === "skill" ? h("div", { class: "sub" }, x.group) : null,
          h("div", { class: "sub mono" }, x.detail),
          x.identity && x.identity !== x.detail ? h("div", { class: "sub mono" }, x.identity) : null,
        ],
      },
      { label: "Kind", cell: (x) => [chip(x.kind), x.access ? h("div", { class: "sub mono" }, x.access) : null] },
    ];
    if (withUsers) cols.push({ label: "Used by", cell: (x) => h("span", { class: "chips" }, (x.used_by || []).map((u) => chip(u))) });
    cols.push(
      { label: "Source", cell: (x) => x.source },
      { label: "Flags", cell: extensionFlags },
      { label: "Notes", cell: (x) => [x.notes ? h("div", { class: "note-exp" }, x.notes) : null, h("div", { class: "sub" }, x.description)] },
    );
    return table(cols, list, { empty: "No extensions recorded." });
  }

  function settingsTable(list) {
    return table(
      [
        { label: "Key", cell: (s) => h("span", { class: "mono strong" + (s.concern ? " tone-exp" : "") }, s.key) },
        { label: "Value", cls: "c-path", cell: (s) => mono(s.value) },
        { label: "Note", cell: (s) => s.note },
        { label: "Flagged", cell: (s) => (s.concern ? chip("flagged", "chip-exp") : h("span", { class: "dim" }, "no")) },
      ],
      list,
    );
  }

  function networkBlock(t) {
    return [
      h("h3", { class: "sublabel" }, "Endpoints"),
      table(
        [
          { label: "Host", cell: (e) => mono(e.host) },
          { label: "Purpose", cell: (e) => e.purpose },
          { label: "Source", cell: (e) => e.source },
          { label: "Count", cls: "c-num", cell: (e) => mono(String(e.count)) },
        ],
        t.endpoints || [],
        { empty: "No endpoints recorded." },
      ),
      h("h3", { class: "sublabel" }, "Fingerprint"),
      table(
        [
          { label: "Label", cell: (f) => f.label },
          { label: "Value", cls: "c-path", cell: (f) => mono(f.value) },
        ],
        t.fingerprint || [],
        { empty: "No network fingerprint recorded." },
      ),
    ];
  }

  function secretsBlock(scan) {
    if (!scan) return empty("No secret scan recorded.");
    return [
      kv([
        ["Roots", h("span", { class: "chips" }, (scan.roots || []).map((r) => chip(r, "chip-mono")))],
        ["Not scanned", (scan.excluded || []).length ? h("span", { class: "chips" }, scan.excluded.map((r) => chip(r, "chip-mono"))) : "none"],
        ["Files scanned", mono(String(scan.files_scanned))],
        ["Bytes scanned", mono(fmtBytes(scan.bytes_scanned))],
        ["Seconds", mono(String(scan.seconds))],
        ["Unreadable", (scan.unreadable || []).length ? h("span", { class: "chips" }, scan.unreadable.map((r) => chip(r, "chip-mono"))) : "none"],
      ]),
      h("h3", { class: "sublabel" }, "Secret kinds found"),
      table(
        [
          { label: "Kind", cell: (k) => [h("div", null, k.label), h("div", { class: "sub mono" }, k.kind)] },
          { label: "Distinct", cls: "c-num", cell: (k) => mono(String(k.unique)) },
          { label: "Files", cls: "c-num", cell: (k) => mono(String(k.files)) },
          { label: "Locations", cls: "c-path", cell: (k) => (k.locations || []).map((l) => h("div", { class: "mono" }, l)) },
          { label: "Last 4", cell: (k) => h("span", { class: "chips" }, (k.last4 || []).map((l) => chip(l, "chip-mono"))) },
        ],
        scan.kinds || [],
        { empty: "No secret values found." },
      ),
      h("h3", { class: "sublabel" }, "Current credential found in history"),
      (scan.current_credential_hits || []).length
        ? h("ul", { class: "plain" }, scan.current_credential_hits.map((x) => mark(h("li", { class: "note-exp" }, x), x)))
        : empty("None."),
      h("h3", { class: "sublabel" }, "Markers"),
      table(
        [
          { label: "Marker", cell: (m) => [h("div", null, m.label), h("div", { class: "sub mono" }, m.marker)] },
          { label: "Count", cls: "c-num", cell: (m) => mono(String(m.count)) },
          { label: "Files", cls: "c-path", cell: (m) => (m.files || []).map((f) => h("div", { class: "mono" }, f)) },
        ],
        scan.markers || [],
        { empty: "No markers recorded." },
      ),
    ];
  }

  function instructionsTable(list) {
    return table(
      [
        { label: "Path", cls: "c-path", cell: (i) => mono(i.path) },
        { label: "Scope", cell: (i) => i.scope },
        { label: "Loaded by", cell: (i) => h("span", { class: "chips" }, (i.loaded_by || []).map((n) => chip(toolName(n)))) },
        { label: "Size", cls: "c-num", cell: (i) => mono(fmtBytes(i.size_bytes)) },
        { label: "Mode", cell: (i) => mono(i.mode) },
        { label: "Other readable", cell: (i) => yesNo(i.other_readable, true) },
        { label: "Markers", cell: (i) => ((i.markers || []).length ? i.markers.map((m) => h("div", { class: "note-exp" }, m)) : h("span", { class: "dim" }, "none")) },
      ],
      list,
    );
  }

  function accountTable(list) {
    return table(
      [
        { label: "Topic", cell: (a) => chip(a.topic, a.concern ? "chip-exp" : null) },
        { label: "Record", cell: (a) => h("p", { class: "cell-p" }, rich(a.text)) },
        { label: "Source", cell: (a) => h("span", { class: "sub" }, rich(a.source)) },
      ],
      list,
    );
  }

  function runtimeBlock(t) {
    const stats = Object.entries(t.stats || {});
    return [
      h("h3", { class: "sublabel" }, "Binaries"),
      table(
        [
          { label: "Path", cls: "c-path", cell: (b) => [mono(b.path), b.resolved && b.resolved !== b.path ? h("div", { class: "sub mono" }, b.resolved) : null] },
          { label: "Version", cell: (b) => mono(b.version) },
          { label: "Signer", cell: (b) => [h("div", null, b.signer), h("div", { class: "sub mono" }, b.team_id)] },
          { label: "Owner / mode", cell: (b) => mono([b.owner, b.mode].filter(Boolean).join(" ")) },
          { label: "Writable dirs", cls: "c-path", cell: (b) => (b.writable_dirs || []).map((d) => h("div", { class: "mono note-exp" }, d)) },
        ],
        t.binaries || [],
        { empty: "No binary found on PATH." },
      ),
      h("h3", { class: "sublabel" }, "Usage records"),
      stats.length ? kv(stats.map(([k, v]) => [k, mono(String(v))])) : empty(),
      h("h3", { class: "sublabel" }, "Trusted folders"),
      (t.trusted_folders || []).length ? h("ul", { class: "plain" }, t.trusted_folders.map((f) => mark(h("li", { class: "mono" }, f), f))) : empty(),
      h("h3", { class: "sublabel" }, "Provider programs"),
      table(
        [
          { label: "Program", cell: (p) => p.name },
          { label: "Status", cell: (p) => p.status },
          { label: "Evidence", cell: (p) => (p.evidence || []).map((x) => h("div", { class: "sub" }, x)) },
        ],
        t.programs || [],
      ),
      h("h3", { class: "sublabel" }, "Running processes"),
      table(
        [
          { label: "PID", cls: "c-num", cell: (p) => mono(String(p.pid)) },
          { label: "Parent", cls: "c-num", cell: (p) => mono(String(p.ppid == null ? "" : p.ppid)) },
          { label: "Started", cell: (p) => mono(p.started) },
          { label: "Command", cls: "c-path", cell: (p) => mono(p.command) },
        ],
        t.processes || [],
        { empty: "No running processes recorded." },
      ),
      h("h3", { class: "sublabel" }, "Background services"),
      (t.daemons || []).length ? h("pre", { class: "rawbox" }, JSON.stringify(t.daemons, null, 2)) : empty("No background services recorded."),
    ];
  }

  // --- checklist -------------------------------------------------------------------------

  const STATES = [
    ["", "All"],
    ["review", "Review"],
    ["clear", "Clear"],
    ["unchecked", "Not checked"],
  ];

  function pageChecklist() {
    const all = DOC.checklist || [];
    const want = STATES.some((s) => s[0] === route.arg) ? route.arg : "";
    const rows = all.filter((c) => !want || stateOf(c) === want);
    const seg = h(
      "nav",
      { class: "seg", "aria-label": "Check state" },
      STATES.map(([id, label]) =>
        h(
          "a",
          { class: "seg-btn seg-" + (id || "all"), href: id ? "#checklist/" + id : "#checklist", "aria-current": id === want ? "page" : null },
          id ? stateDot(id) : null,
          label,
          h("span", { class: "seg-n num" }, String(id ? all.filter((c) => stateOf(c) === id).length : all.length)),
        ),
      ),
    );
    const scopes = [];
    for (const c of rows) if (!scopes.includes(c.scope)) scopes.push(c.scope);
    return [
      pageHead("Checklist", rows.length + " checks listed", seg),
      scopes.length
        ? scopes.map((sc) => {
            const list = rows.filter((c) => c.scope === sc);
            return h("section", { class: "panel panel-flush", "data-fgroup": "hide" }, h("header", { class: "panel-head" }, h("h2", { class: "label" }, sc), h("span", { class: "count num" }, list.length + " checks")), checkTable(list));
          })
        : empty("No checks in this state."),
    ];
  }

  function stateDot(id) {
    if (id === "review") return h("span", { class: "dot" });
    if (id === "clear") return icon("check");
    return h("span", { class: "ring" });
  }

  function checkTable(list) {
    return table(
      [
        { label: "State", cls: "c-state", cell: (c) => stateBadge(stateOf(c)) },
        { label: "Check", cell: (c) => h("span", { class: "strong-ish" }, c.check) },
        { label: "Result", cell: checkResult },
      ],
      list,
      { cls: "ctable", search: (c) => [c.scope, c.check, c.unchecked, (c.exposures || []).map((id) => (EXP_BY[id] ? EXP_BY[id].label : id))] },
    );
  }

  function checkResult(c) {
    const st = stateOf(c);
    if (st === "review") {
      return h(
        "div",
        { class: "chips" },
        (c.exposures || []).map((id) => (EXP_BY[id] ? h("a", { class: "flink", href: findingHref(id) }, EXP_BY[id].label, icon("chev")) : mono(id))),
      );
    }
    if (st === "unchecked") return h("span", { class: "reason" }, rich(c.unchecked));
    return h("span", { class: "dim" }, "No signal");
  }

  // --- extensions ------------------------------------------------------------------------

  const EXT_TABS = [
    { id: "mcp", label: "MCP servers", kinds: ["mcp", "connector"] },
    { id: "skills", label: "Skills", kinds: ["skill"] },
    { id: "plugins", label: "Plugins", kinds: ["plugin"] },
    { id: "other", label: "Hooks and other", kinds: null },
  ];

  function extTab(x) {
    const hit = EXT_TABS.find((t) => t.kinds && t.kinds.includes(x.kind));
    return hit ? hit.id : "other";
  }

  function pageExtensions() {
    const all = V.extensions || [];
    const tab = EXT_TABS.find((t) => t.id === route.arg) || EXT_TABS[0];
    const list = all.filter((x) => extTab(x) === tab.id);
    const seg = h(
      "nav",
      { class: "seg", "aria-label": "Extension kind" },
      EXT_TABS.map((t) =>
        h(
          "a",
          { class: "seg-btn", href: "#extensions/" + t.id, "aria-current": t === tab ? "page" : null },
          t.label,
          h("span", { class: "seg-n num" }, String(all.filter((x) => extTab(x) === t.id).length)),
        ),
      ),
    );
    const sentence = (V.pages || {})[tab.id];
    let body;
    if (tab.id === "skills" && list.length) {
      const groups = [];
      for (const x of list) if (!groups.includes(x.group)) groups.push(x.group);
      body = groups.map((g) => h("section", { class: "panel panel-flush", "data-fgroup": "hide" }, h("header", { class: "panel-head" }, h("h2", { class: "label" }, g)), extensionTable(list.filter((x) => x.group === g), true)));
    } else {
      body = h("section", { class: "panel panel-flush" }, extensionTable(list, true));
    }
    return [pageHead("Extensions", null, seg), sentence ? h("p", { class: "lede" }, rich(sentence)) : null, body];
  }

  // --- machine ---------------------------------------------------------------------------

  function pageMachine() {
    const vh = V.host || {};
    const facts = HOST.facts || [];
    const topics = (vh.questions || []).map((q) => q.topic);
    const loose = facts.filter((f) => !topics.includes(f.topic));
    const across = (vh.across || []).filter((id) => EXP_BY[id]).map((id) => EXP_BY[id]);
    const extraHost = (DOC.host_exposures || []).filter((e) => !(vh.across || []).includes(e.id));
    const others = (HOST.other_users || []).map((u) => u + " (" + ((HOST.other_user_groups || {})[u] || []).join(", ") + ")");
    return [
      pageHead("This machine", vh.scope),
      panel(
        "Host",
        null,
        kv([
          ["Hostname", mono(HOST.hostname)],
          ["OS", HOST.os],
          ["Kernel", mono(HOST.kernel)],
          ["Arch", mono(HOST.arch)],
          ["User", mono(HOST.user + " (uid " + HOST.uid + ")")],
          ["Home", h("span", { class: "mono" }, document.createTextNode(HOST.home || ""))],
          ["Home mode", mono(HOST.home_mode)],
          ["Other accounts", others.length ? h("span", { class: "chips" }, others.map((o) => chip(o, "chip-exp"))) : "none"],
        ]),
      ),
      panel("Questions", null, h("div", { class: "hq-list", "data-fgroup": "note" }, (vh.questions || []).map((q) => hostQuestion(q, facts)), nomatch())),
      panel("Signals across tools", null, findingTable(across.concat(extraHost), { tool: false })),
      loose.length ? panel("Other facts", null, factList(loose)) : null,
      panel("PATH", null, pathTable(HOST.path_entries || [])),
    ];
  }

  function hostQuestion(q, facts) {
    const mine = facts.filter((f) => f.topic === q.topic);
    const review = q.status === "review";
    const link = q.finding_id && EXP_BY[q.finding_id] ? h("a", { class: "point-link", href: findingHref(q.finding_id) }, "Open signal", icon("chev")) : null;
    return mark(
      h(
        "article",
        { class: "hq" },
        h("div", { class: "hq-head" }, h("h3", { class: "hq-q" }, q.question), h("span", { class: "state " + (review ? "s-exp" : "s-clear") }, review ? h("span", { class: "dot" }) : icon("check"), q.status)),
        h("p", { class: "hq-a" }, rich(q.answer)),
        mine.length ? factList(mine) : null,
        link,
      ),
      q.question,
      q.answer,
      q.status,
      mine,
    );
  }

  function factList(list) {
    return h(
      "ul",
      { class: "facts" },
      list.map((f) =>
        h("li", { class: f.concern ? "is-concern" : null }, h("span", { class: "fact-n" }, f.name), h("span", { class: "fact-d" }, rich(f.detail)), f.path ? h("span", { class: "mono sub" }, f.path) : null),
      ),
    );
  }

  function pathTable(list) {
    return table(
      [
        { label: "#", cls: "c-num", cell: (p) => mono(String(p.index)) },
        { label: "Path", cls: "c-path", cell: (p) => mono(p.path) },
        { label: "Exists", cell: (p) => yesNo(p.exists) },
        { label: "Owner", cell: (p) => mono([p.owner, p.group].filter(Boolean).join(":")) },
        { label: "Mode", cell: (p) => mono(p.mode) },
        { label: "Group writable", cell: (p) => yesNo(p.group_writable, true) },
        { label: "Other writable", cell: (p) => yesNo(p.other_writable, true) },
      ],
      list,
      { empty: "No PATH entries recorded." },
    );
  }

  // --- method ----------------------------------------------------------------------------

  // --- network: where each tool connected when started idle ---------------------------------

  const CONNECTION_COLS = [
    { label: "Host", cell: (c) => mono(c.host) },
    { label: "Address", cell: (c) => mono(c.address + " " + c.transport + "/" + c.port) },
    { label: "Named by", cell: (c) => c.named_by },
    { label: "Process", cell: (c) => mono(c.processes.join(", ")) },
    { label: "First packet", cls: "c-num", cell: (c) => mono(c.first_second.toFixed(1) + " s") },
    { label: "Packets", cls: "c-num", cell: (c) => mono(String(c.packets)) },
    { label: "Bytes", cls: "c-num", cell: (c) => mono(fmtBytes(c.bytes)) },
  ];

  function networkTool(t, view) {
    const n = view || {};
    const body = [h("p", { class: "lede" }, rich(n.summary))];
    if (n.captured) {
      body.push(
        kv([
          ["Launched", mono((n.command || []).join(" "))],
          ["Environment", (n.switches || []).length ? h("span", { class: "chips" }, n.switches.map((s) => chip(s, "chip-mono"))) : "no off-switch or proxy variables set"],
          ["Stopped afterwards", (n.stopped || []).length ? h("span", { class: "chips" }, n.stopped.map((s) => chip(s, "chip-mono"))) : "nothing left running"],
          ["Local packets", mono(String(n.local_packets) + " (loopback, link-local and multicast; not listed)")],
        ]),
        h("h3", { class: "sublabel" }, "Connections observed"),
        table(CONNECTION_COLS, n.observed || [], { empty: "No packets to any host off this machine." }),
        h("h3", { class: "sublabel" }, "Names looked up"),
        (n.lookups || []).length ? h("span", { class: "chips" }, n.lookups.map((s) => chip(s, "chip-mono"))) : empty("No DNS lookups were attributed to its processes."),
      );
    }
    body.push(
      h("h3", { class: "sublabel" }, n.captured ? "Named in the binary, not observed in this capture" : "Named in the binary"),
      table([{ label: "Host", cell: (u) => mono(u.host) }, { label: "Purpose", cell: (u) => u.purpose }], n.unobserved || [], { empty: "None." }),
    );
    return panel(t.display_name, null, body);
  }

  function pageNetwork() {
    const net = V.network || {};
    const tool = route.params.get("tool") || "";
    const shown = TOOLS.filter((t) => !tool || t.name === tool);
    const make = (value) => {
      const p = new URLSearchParams();
      if (value) p.set("tool", value);
      return hrefFor("network", "", p);
    };
    const sub = net.started_at ? "captured " + fmtTime(net.started_at) : "not captured";
    const parts = [
      pageHead("Network", sub),
      h("p", { class: "page-note" }, rich(net.method ? net.method + "; file `" + net.capture_file + "`." : net.how)),
      h("div", { class: "filters" }, filterChips("Tool", tool, [["", "All"]].concat(TOOLS.map((t) => [t.name, t.display_name])), make)),
      shown.map((t) => networkTool(t, (net.tools || {})[t.name])),
    ];
    if ((net.unattributed || []).length) {
      parts.push(
        panel(
          "Not attributed",
          null,
          h("p", { class: "lede" }, rich(net.unattributed_note)),
          table(CONNECTION_COLS, net.unattributed),
        ),
      );
    }
    return parts;
  }

  function pageMethod() {
    const vals = [
      ["Probe validation", DOC.probe_validation],
      ["Claim validation", DOC.claim_validation],
      ["Option validation", DOC.option_validation],
      ["Report validation", DOC.report_validation],
      ["Figure validation", DOC.figure_validation],
    ];
    return [
      pageHead("How it was measured", null),
      h("p", { class: "lede lede-big" }, rich(V.method)),
      panel(
        "Run",
        null,
        kv([
          ["Generated", mono(DOC.generated_at)],
          ["Auditor version", mono(DOC.auditor_version)],
          ["Live checks", yesNo(DOC.live)],
          ["Secret scan", yesNo(DOC.scanned)],
        ]),
      ),
      panel(
        "Commands executed",
        h("span", { class: "count num" }, (DOC.executed || []).length + " commands"),
        table(
          [
            { label: "Command", cls: "c-path", cell: (x) => mono((x.argv || []).join(" ")) },
            { label: "Exit", cls: "c-num", cell: (x) => h("span", { class: "mono" + (x.returncode === 0 ? "" : " tone-warn") }, String(x.returncode)) },
            { label: "Purpose", cell: (x) => rich(x.purpose) },
          ],
          DOC.executed || [],
          { cls: "tbl-compact" },
        ),
      ),
      vals.map(([title, list]) => panel(title, h("span", { class: "count num" }, (list || []).length + " entries"), validationList(list || []))),
    ];
  }

  function validationList(list) {
    if (!list.length) return empty();
    return h(
      "div",
      { class: "vals", "data-fgroup": "note" },
      list.map((v) =>
        mark(
          h(
            "div",
            { class: "val" },
            h("div", { class: "mono val-cmd" }, v.command),
            h("ul", { class: "checks" }, (v.checks || []).map((c) => h("li", { class: c.passed ? "ok" : "bad" }, icon(c.passed ? "check" : "x"), h("span", { class: "chk-n" }, c.name), h("span", { class: "chk-d" }, c.detail)))),
          ),
          v,
        ),
      ),
      nomatch(),
    );
  }

  // --- raw data --------------------------------------------------------------------------

  function jsonNode(key, val) {
    const keyNode = key == null ? null : h("span", { class: "jt-k" }, document.createTextNode(String(key)));
    if (val === null || typeof val !== "object") {
      const kind = val === null ? "null" : typeof val;
      const text = typeof val === "string" ? JSON.stringify(val) : String(val);
      return h("div", { class: "jt-leaf" }, keyNode, h("span", { class: "jt-v jt-" + kind }, document.createTextNode(text)));
    }
    const keys = Object.keys(val);
    const isArr = Array.isArray(val);
    const kids = h("div", { class: "jt-kids", hidden: true });
    let built = false;
    const btn = h(
      "button",
      {
        type: "button",
        class: "jt-btn",
        "aria-expanded": "false",
        onclick: () => {
          const open = btn.getAttribute("aria-expanded") !== "true";
          if (open && !built) {
            for (const k of keys) kids.appendChild(jsonNode(k, val[k]));
            built = true;
          }
          btn.setAttribute("aria-expanded", String(open));
          kids.hidden = !open;
        },
      },
      icon("chev"),
      keyNode,
      h("span", { class: "jt-meta" }, isArr ? "[" + keys.length + "]" : "{" + keys.length + "}"),
    );
    return h("div", { class: "jt-node" }, btn, kids);
  }

  function pageData() {
    const rows = Object.keys(DOC).map((k) => {
      const node = jsonNode(k, DOC[k]);
      node.setAttribute("data-f", "");
      SEARCH.set(node, (k + " " + JSON.stringify(DOC[k])).toLowerCase());
      return node;
    });
    return [
      pageHead("Raw data", "The full document this page renders. Values are shown exactly as recorded."),
      h("section", { class: "panel jt", "data-fgroup": "note" }, rows, nomatch()),
    ];
  }

  // --- shell -----------------------------------------------------------------------------

  const filterInput = h("input", {
    id: "q",
    type: "search",
    class: "filter-input",
    placeholder: "Filter this view",
    "aria-label": "Filter what this view lists",
    autocomplete: "off",
    spellcheck: "false",
  });
  const filterCount = h("span", { class: "filter-count num", "aria-live": "polite" });
  const tabs = h(
    "nav",
    { class: "tabs", "aria-label": "Pages" },
    PAGES.map((p) => h("a", { class: "tab", href: "#" + p.id, "data-page": p.id }, icon(p.id), h("span", null, p.label))),
  );
  const topbar = h(
    "header",
    { class: "topbar" },
    h("a", { class: "brand", href: "#overview", "aria-label": "Overview" }, icon("logo", "brand-ic"), h("span", { class: "brand-name" }, "ai-footprint"), h("span", { class: "brand-host mono" }, HOST.hostname)),
    tabs,
    h("label", { class: "filter" }, icon("search"), filterInput, filterCount, h("kbd", { class: "kbd" }, "/")),
  );
  const main = h("main", { class: "main", id: "main" });
  filterInput.addEventListener("input", applyFilter);

  const RENDER = {
    overview: pageOverview,
    signals: pageFindings,
    keys: pageKeys,
    tools: pageTools,
    checklist: pageChecklist,
    extensions: pageExtensions,
    network: pageNetwork,
    machine: pageMachine,
    method: pageMethod,
    data: pageData,
  };

  function renderPage() {
    findingOrder = sortFindings(EXPOSURES);
    main.replaceChildren();
    append(main, [RENDER[route.page]()]);
    for (const a of tabs.querySelectorAll(".tab")) {
      if (a.dataset.page === route.page) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
    applyFilter();
  }

  let lastKey = null;
  let lastPage = null;

  function onRoute() {
    route = parseHash();
    const rest = new URLSearchParams(route.params);
    const f = rest.get("f");
    rest.delete("f");
    const key = route.page + "/" + route.arg + "?" + rest.toString();
    if (key !== lastKey) {
      if (route.page !== lastPage) filterInput.value = "";
      const moved = lastKey !== null && key.split("?")[0] !== lastKey.split("?")[0];
      renderPage();
      if (moved || (lastPage && route.page !== lastPage)) window.scrollTo(0, 0);
      lastKey = key;
      lastPage = route.page;
    }
    renderDrawer(f);
  }

  document.addEventListener("keydown", (ev) => {
    const typing = ev.target.closest && ev.target.closest("input, textarea, select");
    if (ev.key === "Escape" && openId) {
      ev.preventDefault();
      closeDrawer();
    } else if (ev.key === "Escape" && ev.target === filterInput && filterInput.value) {
      filterInput.value = "";
      applyFilter();
    } else if (ev.key === "/" && !typing && !ev.metaKey && !ev.ctrlKey) {
      ev.preventDefault();
      filterInput.focus();
    }
  });

  document.body.append(topbar, main, scrim, drawer);
  window.addEventListener("hashchange", onRoute);
  onRoute();
})();
