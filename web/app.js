"use strict";

const TOKEN = document.querySelector('meta[name="nattowok-token"]').content;
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const state = {
  data: null,
  tab: "devices",
  filter: "all",
  sort: "ip",
  query: "",
  openDevice: null,
  pollTimer: null,
  // Live mode: id -> { up, rtt, since, changed, everUp }
  live: { on: false, timer: null, status: {} },
};

// ---------- helpers ----------

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

async function api(path, options = {}) {
  const resp = await fetch(path, {
    ...options,
    headers: { "x-nattowok-token": TOKEN, ...(options.body ? { "content-type": "application/json" } : {}), ...(options.headers || {}) },
  });
  if (!resp.ok) {
    let msg = resp.statusText;
    try { msg = (await resp.json()).error || msg; } catch (_) { /* not JSON */ }
    throw new Error(msg);
  }
  const type = resp.headers.get("content-type") || "";
  return type.includes("application/json") ? resp.json() : resp;
}

let toastTimer;
function toast(message, action) {
  const el = $("#toast");
  $("#toast-text").textContent = message;
  const btn = $("#toast-action");
  btn.hidden = !action;
  if (action) {
    btn.textContent = action.label;
    btn.onclick = () => { el.hidden = true; action.run(); };
  }
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), action ? 9000 : 3200);
}

function secondsAgo(ms) {
  const s = Math.round((Date.now() - ms) / 1000);
  return s < 60 ? `${s}s ago` : `${Math.floor(s / 60)} min ago`;
}

function ago(iso) {
  if (!iso) return "never";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  if (s < 86400 * 30) return `${Math.floor(s / 86400)} days ago`;
  return new Date(iso).toLocaleDateString();
}

function when(iso) {
  return iso ? new Date(iso).toLocaleString() : "—";
}

const KIND_LABELS = {
  router: "Router / access point", computer: "Computer", phone: "Phone", tablet: "Tablet", wearable: "Wearable",
  tv: "TV / streaming", speaker: "Speaker / voice assistant", printer: "Printer / scanner", camera: "Camera",
  smart_home: "Smart home", game_console: "Game console", nas: "Network storage",
  server: "Server / single-board computer", virtual_machine: "Virtual machine", unknown: "Unknown",
};

const ICONS = {
  router: '<path d="M4 15h16v4H4z"/><path d="M8 17h.01M12 17h.01"/><path d="M8 11a6 6 0 0 1 8 0M5.5 8.5a10 10 0 0 1 13 0"/>',
  computer: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  phone: '<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/>',
  tablet: '<rect x="4.5" y="2.5" width="15" height="19" rx="2.5"/><path d="M11 18.5h2"/>',
  wearable: '<rect x="7" y="6" width="10" height="12" rx="3"/><path d="M9 6l1-3h4l1 3M9 18l1 3h4l1-3"/>',
  tv: '<rect x="2.5" y="5" width="19" height="12" rx="2"/><path d="M8 21h8M9 2l3 3 3-3"/>',
  speaker: '<rect x="6" y="2.5" width="12" height="19" rx="3"/><circle cx="12" cy="14" r="3.5"/><path d="M12 7h.01"/>',
  printer: '<path d="M7 8V3h10v5"/><rect x="3" y="8" width="18" height="9" rx="2"/><path d="M7 14h10v7H7z"/>',
  camera: '<path d="M3 7h12l3-2v14l-3-2H3z"/><circle cx="9" cy="12" r="2.5"/>',
  smart_home: '<path d="M3 11l9-7 9 7"/><path d="M5 10v10h14V10"/><path d="M10 20v-5h4v5"/>',
  game_console: '<path d="M6 8h12a4 4 0 0 1 4 4l-1 5a2 2 0 0 1-3.5 1L15 16H9l-2.5 2A2 2 0 0 1 3 17l-1-5a4 4 0 0 1 4-4z"/><path d="M7 11v3M5.5 12.5h3M16 12h.01M18 13.5h.01"/>',
  nas: '<rect x="4" y="3" width="16" height="7" rx="1.5"/><rect x="4" y="14" width="16" height="7" rx="1.5"/><path d="M8 6.5h.01M8 17.5h.01"/>',
  server: '<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 7h6M9 11h6M12 17h.01"/>',
  virtual_machine: '<rect x="3" y="3" width="13" height="13" rx="2" stroke-dasharray="2 2"/><rect x="8" y="8" width="13" height="13" rx="2"/>',
  unknown: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.3-1 .9-1 1.7M12 17h.01"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
  book: '<path d="M4 4h6a2 2 0 0 1 2 2v14a2 2 0 0 0-2-2H4zM20 4h-6a2 2 0 0 0-2 2v14a2 2 0 0 1 2-2h6z"/>',
};

function icon(kind) {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[kind] || ICONS.unknown}</svg>`;
}

function name(d) {
  return d.custom_name || d.name;
}

function activeFindings(d) {
  return (d.findings || []).filter((f) => !f.ignored && f.severity !== "info");
}

function worstSeverity(findings) {
  const order = ["info", "low", "medium", "high"];
  return findings.reduce((w, f) => (order.indexOf(f.severity) > order.indexOf(w) ? f.severity : w), "info");
}

// ---------- data ----------

async function refresh() {
  try {
    state.data = await api("/api/state");
  } catch (e) {
    toast(`Couldn't reach NattoWok: ${e.message}`);
    return;
  }
  render();
  schedulePoll();
}

function schedulePoll() {
  clearTimeout(state.pollTimer);
  const busy = state.data?.scan?.running || state.data?.doctor?.running;
  state.pollTimer = setTimeout(refresh, busy ? 800 : 20000);
}

// ---------- rendering ----------

function render() {
  const d = state.data;
  const report = d.report;
  renderHeader(d);
  renderStats(report);
  renderDevices(report);
  renderSecurity(report);
  renderDoctor(d);
  renderTimeline(d.events);
  if (state.openDevice) {
    const dev = report?.devices.find((x) => x.id === state.openDevice);
    const a = document.activeElement;
    const editing = $("#drawer").contains(a) && (a.tagName === "TEXTAREA" || (a.tagName === "INPUT" && a.type !== "checkbox"));
    if (dev && !editing) renderDrawer(dev);
  }
}

function renderHeader(d) {
  const net = d.report?.network;
  if (net) {
    const via = net.interface_label || net.interface;
    $("#net-label").textContent = `${net.scan_range} via ${via}${d.report ? ` · scanned ${ago(d.report.finished_at)}` : ""}`;
  }
  const scan = d.scan;
  const btn = $("#scan-btn");
  btn.disabled = scan.running;
  btn.querySelector(".scan-label").textContent = scan.running ? "Scanning…" : "Scan network";
  const job = scan.running ? scan : d.doctor.running ? d.doctor : null;
  $("#progress").hidden = !job;
  if (job) {
    $("#progress-fill").style.width = `${Math.round(job.progress * 100)}%`;
    $("#progress-text").textContent = `${job.phase}…`;
  }
  if (scan.error && !scan.running && state.lastError !== scan.error) {
    state.lastError = scan.error;
    toast(scan.error);
  }
}

function renderStats(report) {
  const el = $("#stats");
  if (!report) {
    el.innerHTML = "";
    return;
  }
  const online = report.devices.filter((x) => x.online);
  const fresh = online.filter((x) => x.is_new).length;
  const unreviewed = online.filter((x) => !x.trusted && !x.is_self && !x.is_gateway).length;
  const score = report.health_score;
  const scoreClass = score >= 85 ? "good" : score >= 60 ? "warn" : "bad";
  el.innerHTML = `
    <button class="stat" data-goto-filter="online"><div class="label">Devices online</div><div class="value">${online.length}</div><div class="sub">${report.devices.length - online.length} known but offline</div></button>
    <button class="stat ${fresh ? "bad" : ""}" data-goto-filter="new"><div class="label">New since last scan</div><div class="value">${fresh}</div><div class="sub">${fresh ? "Check these are yours" : "Nothing new joined"}</div></button>
    <button class="stat ${unreviewed ? "warn" : "good"}" data-goto-filter="unreviewed"><div class="label">Not reviewed</div><div class="value">${unreviewed}</div><div class="sub">${unreviewed ? "Mark the ones you know" : "All devices reviewed"}</div></button>
    <button class="stat ${scoreClass}" data-goto-tab="security"><div class="label">Health score</div><div class="value">${score}<small style="font-size:14px;color:var(--muted)">/100</small></div><div class="sub">${score >= 85 ? "Looking good" : "See Security tab"}</div></button>`;
  $("#notes").innerHTML = (report.notes || []).map((n) => `<div class="note">ⓘ ${esc(n)}</div>`).join("");

  const tdc = $("#tab-devices-count");
  tdc.textContent = online.length || "";
  const issues = report.devices.flatMap(activeFindings).length + report.findings.filter((f) => !f.ignored && f.severity !== "info").length;
  const tsc = $("#tab-security-count");
  tsc.textContent = issues || "";
  tsc.classList.toggle("alert", issues > 0);
}

function matches(d) {
  switch (state.filter) {
    case "online": if (!d.online) return false; break;
    case "offline": if (d.online) return false; break;
    case "new": if (!d.is_new) return false; break;
    case "unreviewed": if (d.trusted || d.is_self || d.is_gateway || !d.online) return false; break;
    case "issues": if (!activeFindings(d).length) return false; break;
  }
  if (!state.query) return true;
  const q = state.query.toLowerCase();
  return [name(d), d.name, d.ip, d.mac, d.vendor, d.hostname, d.model, d.netbios_name, KIND_LABELS[d.kind], ...(d.tags || [])]
    .some((v) => v && String(v).toLowerCase().includes(q));
}

function ipKey(ip) {
  return ip.split(".").reduce((acc, o) => acc * 256 + Number(o), 0);
}

function sorted(devices) {
  const by = {
    ip: (a, b) => ipKey(a.ip) - ipKey(b.ip),
    name: (a, b) => name(a).localeCompare(name(b)),
    kind: (a, b) => (KIND_LABELS[a.kind] || "").localeCompare(KIND_LABELS[b.kind] || "") || ipKey(a.ip) - ipKey(b.ip),
    seen: (a, b) => new Date(b.last_seen || 0) - new Date(a.last_seen || 0),
  }[state.sort];
  // Online devices always come first.
  return [...devices].sort((a, b) => (b.online - a.online) || by(a, b));
}

function deviceRow(d) {
  const issues = activeFindings(d);
  const badges = [];
  if (d.is_self) badges.push('<span class="badge good">This computer</span>');
  if (d.is_gateway) badges.push('<span class="badge info">Router</span>');
  if (d.is_new) badges.push('<span class="badge new">New</span>');
  if (issues.length) badges.push(`<span class="badge ${worstSeverity(issues)}">${issues.length} issue${issues.length > 1 ? "s" : ""}</span>`);
  if (d.trusted && !d.is_self) badges.push('<span class="badge trusted" title="You marked this as yours">✓ Trusted</span>');
  if (d.possible_match) badges.push(`<span class="badge info">Looks like ${esc(d.possible_match.name)}?</span>`);
  const what = [d.model || KIND_LABELS[d.kind], d.vendor || (d.private_mac ? "Private address" : null)].filter(Boolean);
  const meta = [...new Set(what)].join(" · ");
  const status = state.live.on ? liveCell(d)
    : d.online ? `<span>${d.latency_ms != null ? `${d.latency_ms} ms` : ""}</span>`
    : `<span>seen ${esc(ago(d.last_seen))}</span>`;
  const right = `<span class="mono">${esc(d.ip)}</span>${status}`;
  const live = state.live.status[d.id];
  const flash = state.live.on && live?.changed && Date.now() - live.changed < 15000 ? (live.up ? "flash-up" : "flash-down") : "";
  return `<button class="device ${d.online ? "" : "offline"} ${flash}" data-device="${esc(d.id)}">
      <div class="kind-icon">${icon(d.kind)}</div>
      <div style="min-width:0">
        <div class="title"><span class="name">${esc(name(d))}</span>${badges.join("")}</div>
        <div class="meta">${esc(meta)}${d.online ? "" : " · offline"}</div>
      </div>
      <div class="right">${right}</div>
    </button>`;
}

function liveCell(d) {
  if (d.is_self) return '<span class="live on">● this computer</span>';
  const s = state.live.status[d.id];
  if (!s) return '<span class="live">checking…</span>';
  if (s.up) return `<span class="live on">● answering${s.rtt != null ? ` · ${s.rtt} ms` : ""}</span>`;
  if (s.everUp) return `<span class="live off">● stopped answering ${secondsAgo(s.since)}</span>`;
  return '<span class="live" title="Offline, or it doesn\'t answer quick checks, so live mode can\'t follow it">○ not answering</span>';
}

async function livePoll() {
  if (!state.live.on) return;
  try {
    const r = await api("/api/presence");
    const now = Date.now();
    for (const [id, rtt] of Object.entries(r.devices)) {
      const up = rtt !== null;
      const prev = state.live.status[id];
      if (!prev) {
        state.live.status[id] = { up, rtt, since: now, changed: null, everUp: up };
        continue;
      }
      if (prev.up !== up) {
        prev.since = now;
        prev.changed = now;
        const d = state.data?.report?.devices.find((x) => x.id === id);
        if (d && !up && prev.everUp) {
          toast(`${name(d)} just stopped answering. Is that what you unplugged?`, { label: "Name it", run: () => openDrawer(d.id) });
        } else if (d && up) {
          toast(`${name(d)} is answering again`, { label: "Open", run: () => openDrawer(d.id) });
        }
      }
      prev.up = up;
      prev.rtt = rtt;
      prev.everUp ||= up;
    }
    if (state.data) renderDevices(state.data.report);
  } catch (e) {
    toast(`Live check failed: ${e.message}`);
  }
  if (state.live.on) state.live.timer = setTimeout(livePoll, 2000);
}

function setLive(on) {
  state.live.on = on;
  clearTimeout(state.live.timer);
  state.live.status = {};
  $("#live-btn").setAttribute("aria-pressed", String(on));
  $("#live-btn").classList.toggle("active", on);
  $("#live-banner").hidden = !on;
  document.body.classList.toggle("live-on", on);
  if (on) livePoll();
  if (state.data) renderDevices(state.data.report);
}

function renderDevices(report) {
  const list = $("#device-list");
  if (!report) {
    const scanning = state.data.scan.running;
    list.innerHTML = `<div class="empty">${icon("globe")}<h3>${scanning ? "Scanning your network for the first time…" : "No scan yet"}</h3>
      <p>${scanning ? "This takes about 15 seconds. NattoWok asks each device who it is; nothing is sent outside your network." : "Press <strong>Scan network</strong> to see everything connected to your network."}</p></div>`;
    $("#review-banner").hidden = true;
    return;
  }
  const shown = sorted(report.devices.filter(matches));
  list.innerHTML = shown.length
    ? shown.map(deviceRow).join("")
    : `<div class="empty"><h3>No devices match</h3><p>Try another filter or search.</p></div>`;

  const unreviewed = report.devices.filter((x) => x.online && !x.trusted && !x.is_self && !x.is_gateway).length;
  const banner = $("#review-banner");
  banner.hidden = !(state.filter === "unreviewed" && unreviewed > 0);
  banner.innerHTML = `<span>Recognise all ${unreviewed} of these? Mark them trusted, and NattoWok will point out anything new that joins later.</span>
    <button class="btn small primary" id="trust-all">They're all mine</button>`;
}

function findingCard(f, devices) {
  const dev = f.device_id ? devices.find((d) => d.id === f.device_id) : null;
  return `<div class="finding ${f.severity} ${f.ignored ? "ignored" : ""}">
    <h3><span class="badge ${f.severity}">${esc(f.severity)}</span>${esc(f.title)}</h3>
    <p>${esc(f.explanation)}</p>
    <p class="fix"><strong>What to do:</strong> ${esc(f.fix)}</p>
    <div class="row">
      <span>${dev ? `<a data-device="${esc(dev.id)}">${esc(name(dev))} · ${esc(dev.ip)}</a>` : ""}</span>
      ${f.ignored
        ? `<button class="btn small" data-unignore="${esc(f.id)}">Restore warning</button>`
        : `<button class="btn small ghost" data-ignore="${esc(f.id)}" title="Hide this warning; it won't count against your score">This is fine, dismiss</button>`}
    </div>
  </div>`;
}

function renderSecurity(report) {
  const el = $("#tab-security");
  if (!report) {
    el.innerHTML = `<div class="empty"><h3>Run a scan first</h3></div>`;
    return;
  }
  const all = [...report.findings, ...report.devices.flatMap((d) => d.findings || [])];
  const order = { high: 0, medium: 1, low: 2, info: 3 };
  const active = all.filter((f) => !f.ignored).sort((a, b) => order[a.severity] - order[b.severity]);
  const ignored = all.filter((f) => f.ignored);
  const score = report.health_score;
  const color = score >= 85 ? "var(--good)" : score >= 60 ? "var(--warn)" : "var(--bad)";
  const serious = active.filter((f) => f.severity !== "info").length;
  el.innerHTML = `
    <div class="score-hero">
      <div class="ring" style="--p:${score};--c:${color}"><span>${score}</span></div>
      <div>
        <h2 style="margin:0">${serious ? `${serious} thing${serious > 1 ? "s" : ""} worth fixing` : "No security problems found"}</h2>
        <p style="margin:4px 0 0;color:var(--muted)">Every warning explains what it means and what to do. If something is intentional, dismiss it and it won't nag you again.</p>
      </div>
    </div>
    ${active.map((f) => findingCard(f, report.devices)).join("") || ""}
    ${ignored.length ? `<h4 class="day">Dismissed (${ignored.length})</h4>${ignored.map((f) => findingCard(f, report.devices)).join("")}` : ""}`;
}

const HOPS = [
  { id: "local", label: "This computer", icon: "computer" },
  { id: "router", label: "Router", icon: "router" },
  { id: "internet", label: "Internet", icon: "globe" },
  { id: "dns", label: "DNS", icon: "book" },
];

function renderDoctor(d) {
  const el = $("#tab-doctor");
  const diag = d.diagnosis;
  const running = d.doctor.running;
  const intro = `<div class="banner" style="background:var(--surface-2)">
      <span><strong>Is the internet slow or broken?</strong> The doctor tests each step between you and the internet and tells you which one is the problem, and what to try.</span>
      <button class="btn primary" id="doctor-btn" ${running ? "disabled" : ""}>${running ? "Diagnosing…" : diag ? "Run again" : "Diagnose my connection"}</button>
    </div>`;
  if (!diag) {
    el.innerHTML = intro + (d.doctor.error ? `<p class="badge bad">${esc(d.doctor.error)}</p>` : "");
    return;
  }
  const byId = Object.fromEntries(diag.checks.map((c) => [c.id, c]));
  const chain = HOPS.map((h) => {
    const c = byId[h.id];
    const ms = c?.latency?.received ? `${c.latency.avg_ms} ms` : h.id === "dns" ? (diag.dns.find((x) => x.configured)?.median_ms ?? "") + (diag.dns.find((x) => x.configured)?.median_ms != null ? " ms" : "") : "";
    return `<div class="hop ${c ? c.status : ""}"><div class="dot">${icon(h.icon)}</div><div class="label">${h.label}</div><div class="ms">${esc(ms)}</div></div>`;
  }).join("");
  const checks = diag.checks.map((c) => `<div class="check">
      <div class="head"><strong>${esc(c.title)}</strong><span class="badge ${{ pass: "good", warn: "warn", fail: "bad", skip: "" }[c.status]}">${esc(c.status)}</span></div>
      <p>${esc(c.detail)}</p>
      ${c.latency && c.latency.received ? `<p class="mono" style="color:var(--muted)">min ${c.latency.min_ms} · avg ${c.latency.avg_ms} · max ${c.latency.max_ms} ms · jitter ${c.latency.jitter_ms} ms · loss ${c.latency.loss_pct}%</p>` : ""}
      ${c.advice ? `<p class="advice">💡 ${esc(c.advice)}</p>` : ""}
    </div>`).join("");
  const maxMs = Math.max(1, ...diag.dns.map((x) => x.median_ms || 0));
  const dns = diag.dns.length ? `<h4 class="day">DNS speed comparison</h4><table class="dns-table"><thead><tr><th>Server</th><th>Answer time</th><th style="width:40%"></th></tr></thead><tbody>
      ${[...diag.dns].sort((a, b) => (a.median_ms ?? 1e9) - (b.median_ms ?? 1e9)).map((x) => `<tr>
        <td>${esc(x.label)} <span class="mono" style="color:var(--muted)">${esc(x.server)}</span> ${x.configured ? '<span class="badge info">in use</span>' : ""}</td>
        <td>${x.median_ms != null ? `${x.median_ms} ms` : "no answer"}${x.failures ? ` <span class="badge warn">${x.failures} failed</span>` : ""}</td>
        <td><div class="bar" style="width:${x.median_ms != null ? Math.max(2, (x.median_ms / maxMs) * 100) : 0}%"></div></td></tr>`).join("")}
      </tbody></table>` : "";
  el.innerHTML = `${intro}
    <div class="verdict ${diag.status}"><h2>${esc(diag.headline)}</h2><p>${esc(diag.summary)}</p></div>
    <div class="chain">${chain}</div>
    ${checks}${dns}
    <p class="note">Checked ${esc(ago(diag.at))}.</p>`;
}

function renderTimeline(events) {
  const el = $("#tab-timeline");
  if (!events.length) {
    el.innerHTML = `<div class="empty"><h3>Nothing yet</h3><p>After your second scan, this shows devices that joined, left, changed address or opened new ports.</p></div>`;
    return;
  }
  let lastDay = "";
  const html = events.map((e) => {
    const day = new Date(e.at).toLocaleDateString(undefined, { weekday: "long", month: "short", day: "numeric" });
    const head = day !== lastDay ? `<div class="day">${esc(day)}</div>` : "";
    lastDay = day;
    const time = new Date(e.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const msg = e.device_id ? `<a data-device="${esc(e.device_id)}">${esc(e.message)}</a>` : esc(e.message);
    return `${head}<div class="event ${esc(e.kind)}"><span class="time">${esc(time)}</span><span class="ev-dot"></span><span>${msg}</span></div>`;
  }).join("");
  el.innerHTML = html;
  const recent = events.filter((e) => ["new_device", "new_finding", "new_open_port"].includes(e.kind) && Date.now() - new Date(e.at) < 86400000).length;
  $("#tab-timeline-count").textContent = recent || "";
}

// ---------- device drawer ----------

function webLinks(d) {
  const httpPorts = { 80: "http", 81: "http", 8080: "http", 8000: "http", 8123: "http", 5000: "http", 3000: "http", 443: "https", 8443: "https", 5001: "https", 9443: "https", 32400: "http" };
  return (d.open_ports || []).filter((p) => httpPorts[p.port]).map((p) => {
    const scheme = httpPorts[p.port];
    const port = (scheme === "http" && p.port === 80) || (scheme === "https" && p.port === 443) ? "" : `:${p.port}`;
    return `<a class="btn small" target="_blank" rel="noopener noreferrer" href="${scheme}://${esc(d.ip)}${port}/">Open ${scheme === "https" ? "secure " : ""}web page${port}</a>`;
  });
}

function renderDrawer(d) {
  const ev = d.evidence || [];
  const kv = [
    ["Type", KIND_LABELS[d.kind]],
    ["Model", d.model],
    ["IP address", d.ip],
    ["MAC address", d.mac],
    ["Manufacturer", d.vendor || (d.private_mac ? "Hidden. This device uses a private Wi-Fi address, so its maker isn't visible. That's a normal privacy feature on phones and laptops." : null)],
    ["Hostname", d.hostname],
    ["Windows name", d.netbios_name],
    ["UPnP name", d.upnp?.friendly_name],
    ["Response time", d.latency_ms != null ? `${d.latency_ms} ms` : null],
    ["First seen", when(d.first_seen)],
    ["Last seen", d.online ? "Now" : `${when(d.last_seen)} (${ago(d.last_seen)})`],
  ].filter(([, v]) => v);
  const issues = d.findings || [];
  const links = webLinks(d);
  $("#drawer-body").innerHTML = `
    <div class="drawer-head">
      <div class="kind-icon">${icon(d.kind)}</div>
      <div style="flex:1;min-width:0">
        <input class="name-input" id="dev-name" value="${esc(name(d))}" aria-label="Device name" placeholder="${esc(d.name)}">
        <div style="color:var(--muted);font-size:14px">${esc(KIND_LABELS[d.kind])}${d.online ? "" : " · offline"}</div>
      </div>
      <button class="btn ghost icon-only close" id="drawer-close" aria-label="Close">✕</button>
    </div>
    ${d.possible_match ? `<div class="match-card">
      <strong>Is this ${esc(d.possible_match.name)}?</strong>
      <p>It looks like a device you've seen before that's now offline. Devices can come back under a new hardware address, for example when a phone changes its private Wi-Fi address.</p>
      <ul>${d.possible_match.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
      <div class="actions"><button class="btn small primary" id="match-yes">Yes, same device</button><button class="btn small" id="match-no">No, it's a different one</button></div>
    </div>` : ""}
    <label class="switch"><input type="checkbox" id="dev-trusted" ${d.trusted ? "checked" : ""}> I recognise this device</label>

    <div class="section">
      <h4>Why we think it's a ${esc((KIND_LABELS[d.kind] || "").toLowerCase())}</h4>
      ${d.kind === "unknown"
        ? `<p style="font-size:14px">This device didn't reveal much about itself. Try <strong>Check all ports</strong> below, or open its web page if it has one.</p>
          <p style="font-size:14px"><strong>Still a mystery?</strong> Turn on <strong>Live</strong> above the device list, then unplug or switch off things one at a time. When this one stops answering, you've found it. Type a name at the top; it'll be remembered when you plug it back in.</p>`
        : `<div class="confidence"><span>${d.confidence}% sure</span><div class="meter"><div style="width:${d.confidence}%"></div></div></div>`}
      <ul class="evidence">${ev.map((e) => `<li><span class="src">${esc(e.source)}</span><span>${esc(e.detail)}</span></li>`).join("")}</ul>
    </div>

    ${issues.length ? `<div class="section"><h4>Security</h4>${issues.map((f) => findingCard(f, [])).join("")}</div>` : ""}

    <div class="section"><h4>Details</h4><dl class="kv">${kv.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl></div>

    <div class="section">
      <h4>Open services</h4>
      ${(d.open_ports || []).length
        ? `<ul class="ports">${d.open_ports.map((p) => `<li><span class="mono">${p.port}</span><span>${esc(p.service)}</span><span></span>${p.banner ? `<span class="banner-text">${esc(p.banner)}</span>` : ""}</li>`).join("")}</ul>`
        : `<p style="font-size:14px;color:var(--muted)">None of the common ports are open.</p>`}
      ${links.length ? `<div class="actions" style="margin-top:8px">${links.join("")}</div>` : ""}
    </div>

    ${(d.advertised || []).length ? `<div class="section"><h4>Announces itself as</h4><ul class="ports">${d.advertised.map((a) => `<li><span class="mono">${a.port ?? ""}</span><span>${esc(a.description)}</span><span></span>${a.instance ? `<span class="banner-text">${esc(a.instance)}</span>` : ""}</li>`).join("")}</ul></div>` : ""}

    <div class="section">
      <h4>Your notes</h4>
      <input class="tags-input" id="dev-tags" placeholder="Tags, comma separated (e.g. kids, upstairs)" value="${esc((d.tags || []).join(", "))}">
      <textarea id="dev-notes" placeholder="Anything worth remembering: where it is, who owns it…" style="margin-top:8px">${esc(d.notes || "")}</textarea>
    </div>

    <div class="section">
      <h4>Actions</h4>
      <div class="actions">
        <button class="btn small" id="act-copy">Copy IP</button>
        ${d.mac ? `<button class="btn small" id="act-wake" title="Send a Wake-on-LAN packet">Wake up</button>` : ""}
        ${d.online ? `<button class="btn small" id="act-deep">Check all ports</button>` : ""}
        ${!d.is_self ? `<button class="btn small danger" id="act-forget">Forget device</button>` : ""}
      </div>
    </div>`;
  wireDrawer(d);
}

async function saveDevice(id, patch) {
  try {
    await api(`/api/devices/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(patch) });
    await refresh();
  } catch (e) {
    toast(`Couldn't save: ${e.message}`);
  }
}

function wireDrawer(d) {
  $("#drawer-close").onclick = closeDrawer;
  const yes = $("#match-yes");
  if (yes) yes.onclick = async () => {
    try {
      const r = await api(`/api/devices/${encodeURIComponent(d.id)}/merge`, { method: "POST", body: JSON.stringify({ other: d.possible_match.id }) });
      toast(`Got it: this is ${r.name}. Its name and history carry over.`);
      await refresh();
    } catch (e) { toast(e.message); }
  };
  const no = $("#match-no");
  if (no) no.onclick = async () => {
    try {
      await api(`/api/devices/${encodeURIComponent(d.id)}/not-same`, { method: "POST", body: JSON.stringify({ other: d.possible_match.id }) });
      toast("Noted. Give this one its own name.");
      await refresh();
      $("#dev-name")?.focus();
    } catch (e) { toast(e.message); }
  };
  const nameInput = $("#dev-name");
  nameInput.onchange = () => {
    const v = nameInput.value.trim();
    saveDevice(d.id, { custom_name: v === d.name ? "" : v }).then(() => toast("Name saved"));
  };
  nameInput.onkeydown = (e) => e.key === "Enter" && nameInput.blur();
  $("#dev-trusted").onchange = (e) => saveDevice(d.id, { trusted: e.target.checked });
  $("#dev-tags").onchange = (e) => saveDevice(d.id, { tags: e.target.value.split(",") });
  $("#dev-notes").onchange = (e) => saveDevice(d.id, { notes: e.target.value });
  $("#act-copy").onclick = async () => {
    try { await navigator.clipboard.writeText(d.ip); toast(`Copied ${d.ip}`); } catch (_) { toast(d.ip); }
  };
  const wake = $("#act-wake");
  if (wake) wake.onclick = async () => {
    try { await api(`/api/devices/${encodeURIComponent(d.id)}/wake`, { method: "POST" }); toast("Wake-up packet sent. Give it a minute to boot."); } catch (e) { toast(e.message); }
  };
  const deep = $("#act-deep");
  if (deep) deep.onclick = async () => {
    deep.disabled = true;
    deep.textContent = "Checking ~1,100 ports…";
    try {
      const ports = await api(`/api/devices/${encodeURIComponent(d.id)}/deep-scan`, { method: "POST" });
      toast(`${ports.length} open port${ports.length === 1 ? "" : "s"} found`);
      await refresh();
    } catch (e) { toast(e.message); deep.disabled = false; }
  };
  const forget = $("#act-forget");
  if (forget) forget.onclick = async () => {
    if (!confirm(`Forget ${name(d)}? Its name, notes and history will be removed. If it's still connected it will show up as new next scan.`)) return;
    try { await api(`/api/devices/${encodeURIComponent(d.id)}`, { method: "DELETE" }); closeDrawer(); await refresh(); } catch (e) { toast(e.message); }
  };
}

function openDrawer(id) {
  const d = state.data.report?.devices.find((x) => x.id === id);
  if (!d) return;
  state.openDevice = id;
  renderDrawer(d);
  const drawer = $("#drawer");
  drawer.classList.add("open");
  drawer.setAttribute("aria-hidden", "false");
  $("#scrim").hidden = false;
  drawer.focus();
}

function closeDrawer() {
  state.openDevice = null;
  $("#drawer").classList.remove("open");
  $("#drawer").setAttribute("aria-hidden", "true");
  $("#scrim").hidden = true;
}

// ---------- events ----------

function selectTab(tab) {
  state.tab = tab;
  $$(".tabs [role=tab]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === tab)));
  $$(".tab-panel").forEach((p) => (p.hidden = p.id !== `tab-${tab}`));
}

function setFilter(filter) {
  state.filter = filter;
  $$("#filters .chip").forEach((c) => c.classList.toggle("active", c.dataset.filter === filter));
  if (state.data) renderDevices(state.data.report);
}

document.addEventListener("click", async (e) => {
  const t = e.target.closest("[data-device],[data-tab],[data-filter],[data-goto-filter],[data-goto-tab],[data-ignore],[data-unignore],[data-export],#trust-all,#doctor-btn");
  if (!t) {
    if (!e.target.closest(".menu")) $("#export-menu").hidden = true;
    return;
  }
  if (t.dataset.device) return openDrawer(t.dataset.device);
  if (t.dataset.tab) return selectTab(t.dataset.tab);
  if (t.dataset.filter) return setFilter(t.dataset.filter);
  if (t.dataset.gotoFilter) { selectTab("devices"); return setFilter(t.dataset.gotoFilter); }
  if (t.dataset.gotoTab) return selectTab(t.dataset.gotoTab);
  if (t.dataset.export) {
    $("#export-menu").hidden = true;
    try {
      const resp = await api(`/api/export/${t.dataset.export}`);
      const blob = await resp.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = (resp.headers.get("content-disposition") || "").match(/filename="([^"]+)"/)?.[1] || `network.${t.dataset.export}`;
      a.click();
      URL.revokeObjectURL(a.href);
    } catch (err) { toast(err.message); }
    return;
  }
  try {
    if (t.dataset.ignore) { await api(`/api/findings/${encodeURIComponent(t.dataset.ignore)}/ignore`, { method: "POST" }); toast("Dismissed"); }
    if (t.dataset.unignore) await api(`/api/findings/${encodeURIComponent(t.dataset.unignore)}/ignore`, { method: "DELETE" });
    if (t.id === "trust-all") { const r = await api("/api/trust-all", { method: "POST" }); toast(`Marked ${r.trusted} devices as trusted`); }
    if (t.id === "doctor-btn") await api("/api/doctor", { method: "POST" });
    await refresh();
  } catch (err) { toast(err.message); }
});

$("#scan-btn").onclick = async () => {
  try { await api("/api/scan", { method: "POST" }); } catch (e) { toast(e.message); }
  refresh();
};
$("#export-btn").onclick = () => {
  const m = $("#export-menu");
  m.hidden = !m.hidden;
  $("#export-btn").setAttribute("aria-expanded", String(!m.hidden));
};
$("#scrim").onclick = closeDrawer;
$("#live-btn").onclick = () => setLive(!state.live.on);
$("#live-stop").onclick = () => setLive(false);
$("#search").oninput = (e) => { state.query = e.target.value.trim(); renderDevices(state.data?.report); };
$("#sort").onchange = (e) => { state.sort = e.target.value; renderDevices(state.data?.report); };

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeDrawer();
  if (e.key === "/" && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) {
    e.preventDefault();
    selectTab("devices");
    $("#search").focus();
  }
});

// Theme: follow the system unless the person chose one.
function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}
try { applyTheme(localStorage.getItem("nattowok-theme")); } catch (_) { /* storage blocked */ }
$("#theme-btn").onclick = () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  applyTheme(next);
  try { localStorage.setItem("nattowok-theme", next); } catch (_) { /* storage blocked */ }
};

refresh();
