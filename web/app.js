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

function until(iso) {
  const s = (new Date(iso).getTime() - Date.now()) / 1000;
  if (s < 60) return "soon";
  if (s < 3600) return `in ${Math.round(s / 60)} min`;
  return `in ${Math.round(s / 3600)} h`;
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
  wifi: '<path d="M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M2 9a15 15 0 0 1 20 0"/><path d="M12 19.5h.01"/>',
  book: '<path d="M4 4h6a2 2 0 0 1 2 2v14a2 2 0 0 0-2-2H4zM20 4h-6a2 2 0 0 0-2 2v14a2 2 0 0 1 2-2h6z"/>',
};

function icon(kind) {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[kind] || ICONS.unknown}</svg>`;
}

function name(d) {
  return d.custom_name || d.name;
}

// A device's own findings plus network-wide ones about it (e.g. a port the
// router forwards to it).
function deviceFindings(d) {
  const network = (state.data?.report?.findings || []).filter((f) => f.device_id === d.id);
  return [...(d.findings || []), ...network];
}

function activeFindings(d) {
  return deviceFindings(d).filter((f) => !f.ignored && f.severity !== "info");
}

function mappingsFor(d) {
  return (state.data?.report?.exposure?.mappings || []).filter((m) => m.enabled && m.internal_ip === d.ip);
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
  const busy = state.data?.scan?.running || state.data?.doctor?.running || state.data?.speed?.running;
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

function renderSettings(d) {
  const s = d.settings || {};
  const menu = $("#settings-menu");
  if (!menu.contains(document.activeElement)) {
    const auto = $("#set-auto");
    if (![...auto.options].some((o) => Number(o.value) === s.auto_scan_minutes)) {
      auto.add(new Option(`Every ${s.auto_scan_minutes} minutes`, s.auto_scan_minutes));
    }
    auto.value = String(s.auto_scan_minutes || 0);
    $("#set-notify").checked = !!s.notifications;
  }
  $("#settings-dot").hidden = !s.auto_scan_minutes;
  const alerts = s.alerts || [];
  $("#alert-list").innerHTML = alerts.length
    ? alerts.map((a, i) => `<li><span>${esc(a)}</span><button class="btn small ghost" data-alert-remove="${i}" aria-label="Remove">✕</button></li>`).join("")
      + `<li><button class="btn small" id="alert-test">Send a test alert</button></li>`
      + (s.auto_scan_minutes ? "" : `<li class="hint">Alerts come from automatic scans; turn on "Scan automatically" above.</li>`)
    : `<li class="hint">None yet.</li>`;
  $("#set-bg").innerHTML = d.service_mode
    ? "✓ NattoWok runs in the background, so it keeps watching after you close this tab and starts again when you log in."
    : "Automatic scans run while NattoWok is open. To keep watching after you close it, and after restarts, run <code>nattowok service install</code> once.";
}

function renderHeader(d) {
  renderSettings(d);
  const net = d.report?.network;
  if (net) {
    const via = net.interface_label || net.interface;
    const next = d.next_scan_at ? ` · next scan ${until(d.next_scan_at)}` : "";
    $("#net-label").textContent = `${net.scan_range} via ${via}${d.report ? ` · scanned ${ago(d.report.finished_at)}` : ""}${next}`;
  }
  const scan = d.scan;
  const btn = $("#scan-btn");
  btn.disabled = scan.running;
  btn.querySelector(".scan-label").textContent = scan.running ? "Scanning…" : "Scan network";
  const job = scan.running ? scan : d.doctor.running ? d.doctor : d.speed?.running ? d.speed : null;
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
  const issues = [...report.findings, ...report.devices.flatMap((d) => d.findings || [])]
    .filter((f) => !f.ignored && f.severity !== "info").length;
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

  const unreviewed = report.devices.filter(needsReview).length;
  const banner = $("#review-banner");
  banner.hidden = !(["all", "unreviewed"].includes(state.filter) && unreviewed > 0 && !state.live.on);
  banner.innerHTML = `<span><strong>${unreviewed} device${unreviewed > 1 ? "s" : ""} to review.</strong> Going through them takes about a minute, and lets NattoWok tell you when something new joins.</span>
    <span class="actions"><button class="btn small primary" id="review-start">Review one by one</button>
    <button class="btn small" id="trust-all">They're all mine</button></span>`;
}

// ---------- guided review ----------

// Online, not yours yet, and not already marked as unrecognised.
function needsReview(x) {
  return x.online && !x.trusted && !x.is_self && !x.is_gateway && !(x.tags || []).includes("unrecognised");
}

const review = { queue: [], i: 0, mine: 0, skipped: 0, unknown: [] };

function kindOptions(d) {
  const detected = d.detected_kind || d.kind;
  const auto = `<option value="auto" ${d.detected_kind ? "" : "selected"}>${esc(KIND_LABELS[detected])} (detected)</option>`;
  const choices = Object.entries(KIND_LABELS)
    .map(([k, label]) => `<option value="${k}" ${d.detected_kind && d.kind === k ? "selected" : ""}>${esc(label)}</option>`)
    .join("");
  return `${auto}<optgroup label="It's actually a…">${choices}</optgroup>`;
}

function startReview() {
  const report = state.data?.report;
  if (!report) return;
  review.queue = report.devices.filter(needsReview).map((x) => x.id);
  Object.assign(review, { i: 0, mine: 0, skipped: 0, unknown: [] });
  if (!review.queue.length) return toast("Nothing left to review");
  $("#review").showModal();
  renderReview();
}

function nextReview() {
  review.i += 1;
  renderReview();
}

function renderReview() {
  const dlg = $("#review");
  if (review.i >= review.queue.length) return renderReviewDone();
  const d = state.data.report.devices.find((x) => x.id === review.queue[review.i]);
  if (!d) return nextReview();
  const n = review.queue.length;
  const clues = (d.evidence || []).slice(0, 2).map((e) => esc(e.detail)).join(" · ");
  dlg.innerHTML = `
    <div class="review-head"><span class="hint">Device ${review.i + 1} of ${n}</span>
      <button class="btn ghost icon-only" id="rv-close" aria-label="Close review">✕</button></div>
    <div class="meter"><div style="width:${Math.round((review.i / n) * 100)}%"></div></div>
    <div class="review-card">
      <div class="kind-icon">${icon(d.kind)}</div>
      <div style="min-width:0;flex:1">
        <label class="hint" for="rv-name">Name it something you'll recognise</label>
        <input class="name-input" id="rv-name" value="${esc(name(d))}">
        <p class="rv-meta">${esc([d.model, d.vendor || (d.private_mac ? "private Wi-Fi address" : null), d.ip].filter(Boolean).join(" · "))}</p>
        ${clues ? `<p class="hint">Why we think so: ${clues}</p>` : `<p class="hint">It didn't reveal much about itself.</p>`}
        <label class="rv-kind">Type <select id="rv-kind">${kindOptions(d)}</select></label>
      </div>
    </div>
    <div class="review-actions">
      <button class="btn primary" id="rv-yes">Yes, it's mine</button>
      <button class="btn" id="rv-find">Not sure, help me find it</button>
      <button class="btn" id="rv-no">I don't recognise it</button>
      <button class="btn ghost" id="rv-skip">Skip</button>
    </div>`;
  const nameInput = $("#rv-name");
  nameInput.onkeydown = (e) => { if (e.key === "Enter") $("#rv-yes").click(); };
  $("#rv-close").onclick = () => { dlg.close(); refresh(); };
  $("#rv-skip").onclick = () => { review.skipped += 1; nextReview(); };
  $("#rv-yes").onclick = async () => {
    const patch = { trusted: true };
    const typed = nameInput.value.trim();
    if (typed && typed !== name(d)) patch.custom_name = typed;
    const kind = $("#rv-kind").value;
    if (kind !== (d.detected_kind ? d.kind : "auto")) patch.kind = kind;
    try {
      await api(`/api/devices/${encodeURIComponent(d.id)}`, { method: "PATCH", body: JSON.stringify(patch) });
      review.mine += 1;
      nextReview();
    } catch (e) { toast(`Couldn't save: ${e.message}`); }
  };
  $("#rv-no").onclick = async () => {
    try {
      await api(`/api/devices/${encodeURIComponent(d.id)}`, { method: "PATCH", body: JSON.stringify({ tags: [...(d.tags || []), "unrecognised"] }) });
      review.unknown.push(name(d));
      nextReview();
    } catch (e) { toast(`Couldn't save: ${e.message}`); }
  };
  $("#rv-find").onclick = () => {
    dlg.close();
    selectTab("devices");
    setFilter("all");
    setLive(true);
    const row = document.querySelector(`.device[data-device="${CSS.escape(d.id)}"]`);
    row?.scrollIntoView({ block: "center" });
    row?.classList.add("flash-up");
    toast(`Unplug or switch off things one at a time. When "${name(d)}" stops answering, you've found it.`, {
      label: "Back to review",
      run: () => { setLive(false); dlg.showModal(); renderReview(); },
    });
  };
  nameInput.focus();
  nameInput.select();
}

function renderReviewDone() {
  const dlg = $("#review");
  const unknown = review.unknown.length
    ? `<div class="panel warn"><h3>About the ${review.unknown.length} you don't recognise</h3>
        <p>${esc(review.unknown.join(", "))}</p>
        <ol>
          <li>Ask the others at home: a new TV, a guest's phone or a smart plug is the usual answer.</li>
          <li>Try <strong>Live</strong> mode and unplug things one at a time to see which box it is.</li>
          <li>If nobody owns it, change your Wi-Fi password. Your own devices will ask for the new one, and strangers are locked out.</li>
          <li>Turn on alerts (the bell, top right) so you hear about newcomers.</li>
        </ol>
        ${routerHelp("wifi_security")}</div>`
    : "";
  dlg.innerHTML = `
    <div class="review-head"><strong>All done</strong><button class="btn ghost icon-only" id="rv-close" aria-label="Close review">✕</button></div>
    <p>${review.mine} marked as yours${review.skipped ? `, ${review.skipped} skipped` : ""}${review.unknown.length ? `, ${review.unknown.length} not recognised` : ""}. From now on, anything new that joins will stand out.</p>
    ${unknown}
    <div class="review-actions"><button class="btn primary" id="rv-done">Done</button></div>`;
  const close = () => { dlg.close(); refresh(); };
  $("#rv-close").onclick = close;
  $("#rv-done").onclick = close;
}

// Brand-specific steps for a router setting, collapsed until wanted.
function routerHelp(topic) {
  const g = state.data?.report?.router_guide;
  const step = topic && g?.steps?.[topic];
  if (!step) return "";
  const where = g.generic ? "How to find this on your router" : `How to do this on your ${g.brand}`;
  const app = g.app ? ` You can also use the ${esc(g.app)}.` : "";
  return `<details class="router-steps"><summary>${esc(where)}</summary>
    <p>${esc(step)}${app}</p>
    <p class="hint">Menu names vary between firmware versions.</p>
    <a class="btn small" href="${esc(g.admin_url)}" target="_blank" rel="noopener noreferrer">Open router settings</a></details>`;
}

function findingCard(f, devices) {
  const dev = f.device_id ? devices.find((d) => d.id === f.device_id) : null;
  return `<div class="finding ${f.severity} ${f.ignored ? "ignored" : ""}">
    <h3><span class="badge ${f.severity}">${esc(f.severity)}</span>${esc(f.title)}</h3>
    <p>${esc(f.explanation)}</p>
    <p class="fix"><strong>What to do:</strong> ${esc(f.fix)}</p>
    ${routerHelp(f.topic)}
    <div class="row">
      <span>${dev ? `<a data-device="${esc(dev.id)}">${esc(name(dev))} · ${esc(dev.ip)}</a>` : ""}</span>
      ${f.ignored
        ? `<button class="btn small" data-unignore="${esc(f.id)}">Restore warning</button>`
        : `<button class="btn small ghost" data-ignore="${esc(f.id)}" title="Hide this warning; it won't count against your score">This is fine, dismiss</button>`}
    </div>
  </div>`;
}

function exposurePanel(report) {
  const exp = report.exposure;
  if (!exp) {
    return `<div class="panel"><h3>Open to the internet</h3>
      <p>Your router didn't share a list of open ports. Usually that means automatic port opening (UPnP) is off, which is good.
      Ports forwarded by hand in the router's settings can't be seen from inside your network by any scanner; check the router's "Port forwarding" page for those.</p></div>`;
  }
  const mappings = exp.mappings.filter((m) => m.enabled);
  const byIp = (ip) => report.devices.find((d) => d.ip === ip && d.online);
  const address = exp.external_ip
    ? `<p>Your internet address: <span class="mono">${esc(exp.external_ip)}</span>${exp.shared_address ? ' <span class="badge info">shared by your provider</span>' : ""}</p>`
    : "";
  const shared = exp.shared_address
    ? "<p>Your provider shares one public address between many customers, so even forwarded ports usually can't be reached from outside.</p>"
    : "";
  if (!mappings.length) {
    return `<div class="panel good"><h3>Open to the internet: nothing</h3>${address}
      <p>Your router isn't forwarding any ports, so nothing on your network can be reached directly from the internet.</p>${shared}</div>`;
  }
  const rows = mappings.map((m) => {
    const d = m.internal_ip && byIp(m.internal_ip);
    const who = d ? `<a data-device="${esc(d.id)}">${esc(name(d))}</a>` : esc(m.internal_ip || "?");
    const ports = m.external_port === m.internal_port ? `${m.external_port}` : `${m.external_port} → ${m.internal_port}`;
    const expires = m.lease_seconds ? `for ${Math.round(m.lease_seconds / 60)} min` : "until removed";
    return `<tr><td>${who}</td><td class="mono">${esc(ports)} ${esc(m.protocol)}</td><td>${esc(m.description || "—")}</td><td>${esc(expires)}</td></tr>`;
  }).join("");
  return `<div class="panel warn"><h3>Open to the internet: ${mappings.length} port${mappings.length > 1 ? "s" : ""}</h3>${address}
    <p>Apps and devices asked your router (via UPnP) to let the internet connect to them directly. Games and video calls often do this; cameras and remote-access tools are riskier. Each one is explained below.</p>${shared}
    <table class="dns-table"><thead><tr><th>Device</th><th>Port</th><th>Opened by</th><th>Open</th></tr></thead><tbody>${rows}</tbody></table></div>`;
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
    ${exposurePanel(report)}
    ${active.map((f) => findingCard(f, report.devices)).join("") || ""}
    ${ignored.length ? `<h4 class="day">Dismissed (${ignored.length})</h4>${ignored.map((f) => findingCard(f, report.devices)).join("")}` : ""}`;
}

const HOPS = [
  { id: "local", label: "This computer", icon: "computer" },
  { id: "wifi", label: "Wi-Fi", icon: "wifi" },
  { id: "router", label: "Router", icon: "router" },
  { id: "internet", label: "Internet", icon: "globe" },
  { id: "dns", label: "DNS", icon: "book" },
];

function speedPanel(d) {
  const job = d.speed || {};
  const history = d.speed_history || [];
  const last = history[0];
  const button = `<button class="btn ${last ? "" : "primary"}" id="speed-btn" ${job.running ? "disabled" : ""}>${job.running ? "Testing…" : last ? "Test again" : "Test my speed"}</button>`;
  const head = `<div class="speed-head"><div><h3>Speed and lag under load</h3>
    <p class="hint">Measures download and upload speed, and how much delay grows while the line is busy (the reason calls stutter while someone streams). Uses Cloudflare's speed test: about 15 seconds and up to ~450 MB of data.</p></div>${button}</div>`;
  if (job.error && !job.running) return `<div class="panel">${head}<p class="badge bad">${esc(job.error)}</p></div>`;
  if (!last) return `<div class="panel">${head}</div>`;
  const busyMs = Math.max(last.loaded_down_ms, last.loaded_up_ms);
  const gradeClass = { A: "good", B: "good", C: "warn", D: "bad", F: "bad" }[last.grade];
  const tiles = `<div class="speed-tiles">
    <div><span class="label">Download</span><span class="big">${last.download_mbps}</span><span class="unit">Mbps</span></div>
    <div><span class="label">Upload</span><span class="big">${last.upload_mbps}</span><span class="unit">Mbps</span></div>
    <div><span class="label">Delay when idle</span><span class="big">${last.idle_ms}</span><span class="unit">ms</span></div>
    <div><span class="label">Delay when busy</span><span class="big">${busyMs}</span><span class="unit">ms</span></div>
    <div><span class="label">Responsiveness</span><span class="big"><span class="badge ${gradeClass}" style="font-size:20px;padding:2px 12px">${esc(last.grade)}</span></span><span class="unit">grade</span></div>
  </div>`;
  const older = history.slice(1, 6).map((r) => `<tr><td>${esc(new Date(r.at).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }))}</td><td>${r.download_mbps}</td><td>${r.upload_mbps}</td><td>${Math.max(r.loaded_down_ms, r.loaded_up_ms)} ms</td><td>${esc(r.grade)}</td></tr>`).join("");
  return `<div class="panel">${head}${tiles}
    <p>${esc(last.verdict)}</p>
    ${last.advice ? `<p class="advice-box">💡 ${esc(last.advice)}</p>` : ""}
    ${["C", "D", "F"].includes(last.grade) ? routerHelp("sqm") : ""}
    <p class="hint">Tested ${esc(ago(last.at))} · used ${Math.round(last.data_used_mb)} MB${last.location ? ` · Cloudflare ${esc(last.location)}` : ""}</p>
    ${older ? `<table class="dns-table"><thead><tr><th>Earlier</th><th>↓ Mbps</th><th>↑ Mbps</th><th>Busy delay</th><th>Grade</th></tr></thead><tbody>${older}</tbody></table>` : ""}
  </div>`;
}

function renderDoctor(d) {
  const el = $("#tab-doctor");
  const diag = d.diagnosis;
  const running = d.doctor.running;
  const intro = `<div class="banner" style="background:var(--surface-2)">
      <span><strong>Is the internet slow or broken?</strong> The doctor tests each step between you and the internet and tells you which one is the problem, and what to try.</span>
      <button class="btn primary" id="doctor-btn" ${running ? "disabled" : ""}>${running ? "Diagnosing…" : diag ? "Run again" : "Diagnose my connection"}</button>
    </div>`;
  if (!diag) {
    el.innerHTML = intro + (d.doctor.error ? `<p class="badge bad">${esc(d.doctor.error)}</p>` : "") + speedPanel(d);
    return;
  }
  const byId = Object.fromEntries(diag.checks.map((c) => [c.id, c]));
  const hops = HOPS.filter((h) => h.id !== "wifi" || byId.wifi);
  const configuredDns = diag.dns.find((x) => x.configured)?.median_ms;
  const wifiReading = diag.wifi ? (diag.wifi.rssi_dbm != null ? `${diag.wifi.rssi_dbm} dBm` : diag.wifi.signal_percent != null ? `${diag.wifi.signal_percent}%` : "") : "";
  const chain = hops.map((h) => {
    const c = byId[h.id];
    const ms = c?.latency?.received ? `${c.latency.avg_ms} ms`
      : h.id === "dns" && configuredDns != null ? `${configuredDns} ms`
      : h.id === "wifi" ? wifiReading : "";
    return `<div class="hop ${c ? c.status : ""}"><div class="dot">${icon(h.icon)}</div><div class="label">${h.label}</div><div class="ms">${esc(ms)}</div></div>`;
  }).join("");
  const checks = diag.checks.map((c) => `<div class="check">
      <div class="head"><strong>${esc(c.title)}</strong><span class="badge ${{ pass: "good", warn: "warn", fail: "bad", skip: "" }[c.status]}">${esc(c.status)}</span></div>
      <p>${esc(c.detail)}</p>
      ${c.latency && c.latency.received ? `<p class="mono" style="color:var(--muted)">min ${c.latency.min_ms} · avg ${c.latency.avg_ms} · max ${c.latency.max_ms} ms · jitter ${c.latency.jitter_ms} ms · loss ${c.latency.loss_pct}%</p>` : ""}
      ${c.advice ? `<p class="advice">💡 ${esc(c.advice)}</p>` : ""}
      ${routerHelp(c.topic)}
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
    <div class="chain" style="grid-template-columns:repeat(${hops.length},1fr)">${chain}</div>
    ${checks}${dns}
    <p class="note">Checked ${esc(ago(diag.at))}.</p>
    ${speedPanel(d)}`;
}

// ---------- presence ----------

const HOUR = 3600000;
const DAY = 24 * HOUR;

function fmtTime(ms) {
  return new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

// "6:00 PM" today, "Fri 6:00 PM" this week, a date otherwise.
function fmtWhen(ms) {
  const d = new Date(ms);
  const today = new Date();
  if (d.toDateString() === today.toDateString()) return fmtTime(ms);
  if (today - d < 6 * DAY) return `${d.toLocaleDateString(undefined, { weekday: "short" })} ${fmtTime(ms)}`;
  return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function fmtSpan(ms) {
  const m = Math.round(ms / 60000);
  return m < 60 ? `${m} min` : `${Math.floor(m / 60)} h ${m % 60 ? `${m % 60} min` : ""}`.trim();
}

// Periods NattoWok was scanning: consecutive scans no further apart than the watch gap.
function watchedWindows() {
  const gap = (state.data?.watch_gap_hours || 6) * HOUR;
  const log = (state.data?.scan_log || []).map((t) => new Date(t).getTime()).sort((a, b) => a - b);
  const out = [];
  for (let i = 0; i < log.length; i++) {
    const end = i + 1 < log.length && log[i + 1] - log[i] <= gap ? log[i + 1] : log[i];
    const last = out[out.length - 1];
    if (last && log[i] <= last[1]) last[1] = Math.max(last[1], end);
    else out.push([log[i], end]);
  }
  return out;
}

function sessionsOf(d) {
  return (d.presence || []).map((p) => [new Date(p.from).getTime(), new Date(p.to).getTime()]);
}

// Plain-language summary of when a device is usually around.
function presenceSummary(d) {
  const sessions = sessionsOf(d);
  const watched = watchedWindows();
  if (!watched.length) return "Not enough scans yet to show a pattern.";
  const days = new Set();
  const hourDays = Array.from({ length: 24 }, () => new Set());
  for (const [a, b] of sessions) {
    for (let t = a; t <= b; t += 15 * 60000) {
      const dt = new Date(t);
      hourDays[dt.getHours()].add(dt.toDateString());
    }
  }
  for (const [a, b] of watched) {
    for (let t = a; t <= b; t += HOUR) days.add(new Date(t).toDateString());
  }
  const n = Math.max(1, days.size);
  const usual = hourDays.map((s) => s.size / n >= 0.5);
  // Longest run of usual hours, wrapping past midnight (e.g. 18:00 to 08:00).
  let best = { start: 0, len: 0 };
  for (let start = 0; start < 24; start++) {
    if (!usual[start] || usual[(start + 23) % 24]) continue;
    let len = 0;
    while (len < 24 && usual[(start + len) % 24]) len++;
    if (len > best.len) best = { start, len };
  }
  const hh = (h) => `${String(h % 24).padStart(2, "0")}:00`;
  let pattern;
  if (!sessions.length) pattern = "Not seen online in the last week.";
  else if (usual.every(Boolean)) pattern = "Online around the clock.";
  else if (!best.len) pattern = "Online now and then, with no regular pattern.";
  else pattern = `Usually online between ${hh(best.start)} and ${hh(best.start + best.len)}.`;
  const last = sessions[sessions.length - 1];
  const now = d.online && last ? ` Online since ${fmtWhen(last[0])}.` : "";
  return pattern + now;
}

// A week of rows, one per day, 24 hours wide: online, offline (watched) and not-watching.
function presenceChart(d) {
  const sessions = sessionsOf(d);
  const watched = watchedWindows();
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const minWidth = 0.6; // percent: a single sighting still shows up
  const rows = [];
  for (let i = 6; i >= 0; i--) {
    const start = today.getTime() - i * DAY;
    const end = start + DAY;
    const seg = (a, b, cls, tip) => {
      const from = Math.max(a, start);
      const to = Math.min(b, end);
      if (to < from || from >= end) return "";
      const left = ((from - start) / DAY) * 100;
      const width = Math.max(minWidth, ((to - from) / DAY) * 100);
      return `<span class="seg ${cls}" style="left:${left.toFixed(2)}%;width:${Math.min(width, 100 - left).toFixed(2)}%" data-tip="${esc(tip)}"></span>`;
    };
    const watchedSegs = watched.map(([a, b]) => seg(a, b, "watched", `Watching ${fmtTime(Math.max(a, start))}–${fmtTime(Math.min(b, end))}: not online`)).join("");
    const onlineSegs = sessions.map(([a, b]) => seg(a, b, "online", `Online ${fmtWhen(a)} – ${fmtWhen(b)}${b > a ? ` (${fmtSpan(b - a)})` : ""}`)).join("");
    // The rest of today hasn't happened yet.
    const future = end > Date.now() ? seg(Date.now(), end, "future", "Later today") : "";
    const label = i === 0 ? "Today" : new Date(start).toLocaleDateString(undefined, { weekday: "short" });
    rows.push(`<div class="pres-row"><span class="pres-day">${esc(label)}</span><div class="pres-track" data-tip="NattoWok wasn't scanning">${watchedSegs}${onlineSegs}${future}</div></div>`);
  }
  const axis = `<div class="pres-row axis"><span class="pres-day"></span><div class="pres-axis"><span>00</span><span>06</span><span>12</span><span>18</span><span>24</span></div></div>`;
  const key = `<div class="pres-key"><span><i class="sw online"></i>Online</span><span><i class="sw watched"></i>Offline</span><span><i class="sw"></i>Not scanning</span></div>`;
  return `<div class="presence" role="img" aria-label="${esc(presenceSummary(d))}">${rows.join("")}${axis}</div>${key}`;
}

const PERSON_KINDS = ["phone", "tablet", "wearable"];

function whosHome(report) {
  if (!report) return "";
  const people = report.devices.filter((d) => PERSON_KINDS.includes(d.kind) && (d.trusted || d.custom_name));
  if (!people.length) {
    return `<div class="panel"><h3>Who's home</h3><p>Phones are a good stand-in for people. Name your household's phones (or mark them trusted) and this shows who's home and since when.</p></div>`;
  }
  people.sort((a, b) => b.online - a.online || name(a).localeCompare(name(b)));
  const chips = people.map((d) => {
    const s = sessionsOf(d);
    const last = s[s.length - 1];
    const since = d.online && last ? `home since ${fmtWhen(last[0])}` : `away · last seen ${ago(d.last_seen)}`;
    return `<a class="person ${d.online ? "home" : "away"}" data-device="${esc(d.id)}"><span class="pdot"></span><strong>${esc(name(d))}</strong><span>${esc(since)}</span></a>`;
  }).join("");
  return `<div class="panel"><h3>Who's home</h3><div class="people">${chips}</div><p class="hint">Based on when their phones are on the Wi-Fi. Phones that sleep deeply can briefly look away.</p></div>`;
}

function renderTimeline(events) {
  const el = $("#tab-timeline");
  const home = whosHome(state.data?.report);
  if (!events.length) {
    el.innerHTML = `${home}<div class="empty"><h3>Nothing yet</h3><p>After your second scan, this shows devices that joined, left, changed address or opened new ports.</p></div>`;
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
  el.innerHTML = home + html;
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
  const issues = deviceFindings(d);
  const exposed = mappingsFor(d);
  const links = webLinks(d);
  $("#drawer-body").innerHTML = `
    <div class="drawer-head">
      <div class="kind-icon">${icon(d.kind)}</div>
      <div style="flex:1;min-width:0">
        <input class="name-input" id="dev-name" value="${esc(name(d))}" aria-label="Device name" placeholder="${esc(d.name)}">
        <div class="kind-line"><select id="dev-kind" aria-label="Device type">${kindOptions(d)}</select>${d.online ? "" : " · offline"}</div>
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

    ${exposed.length ? `<div class="section"><h4>Reachable from the internet</h4><ul class="ports">${exposed.map((m) => `<li><span class="mono">${m.external_port}</span><span>${esc(m.protocol)} → port ${m.internal_port}</span><span></span>${m.description ? `<span class="banner-text">Opened by "${esc(m.description)}"</span>` : ""}</li>`).join("")}</ul></div>` : ""}
    ${issues.length ? `<div class="section"><h4>Security</h4>${issues.map((f) => findingCard(f, [])).join("")}</div>` : ""}

    ${!d.is_self ? `<div class="section"><h4>When it's around</h4><p style="font-size:14px;margin:0 0 8px">${esc(presenceSummary(d))}</p>${presenceChart(d)}</div>` : ""}

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
  $("#dev-kind").onchange = (e) => saveDevice(d.id, { kind: e.target.value }).then(() => toast("Type saved"));
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
  const t = e.target.closest("[data-device],[data-tab],[data-filter],[data-goto-filter],[data-goto-tab],[data-ignore],[data-unignore],[data-export],#trust-all,#review-start,#doctor-btn,#speed-btn");
  if (!e.target.closest(".menu")) {
    $("#export-menu").hidden = true;
    $("#settings-menu").hidden = true;
  }
  if (!t) return;
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
    if (t.id === "review-start") return startReview();
    if (t.id === "trust-all") { const r = await api("/api/trust-all", { method: "POST" }); toast(`Marked ${r.trusted} devices as trusted`); }
    if (t.id === "doctor-btn") await api("/api/doctor", { method: "POST" });
    if (t.id === "speed-btn") await api("/api/speedtest", { method: "POST" });
    await refresh();
  } catch (err) { toast(err.message); }
});

$("#scan-btn").onclick = async () => {
  try { await api("/api/scan", { method: "POST" }); } catch (e) { toast(e.message); }
  refresh();
};
$("#settings-btn").onclick = () => {
  const m = $("#settings-menu");
  m.hidden = !m.hidden;
  $("#export-menu").hidden = true;
  $("#settings-btn").setAttribute("aria-expanded", String(!m.hidden));
};
async function saveSettings(patch) {
  try {
    await api("/api/settings", { method: "PATCH", body: JSON.stringify(patch) });
    await refresh();
  } catch (e) { toast(`Couldn't save: ${e.message}`); }
}
$("#set-auto").onchange = (e) => saveSettings({ auto_scan_minutes: Number(e.target.value) }).then(() =>
  toast(Number(e.target.value) ? "Automatic scans on" : "Automatic scans off"));
$("#set-notify").onchange = (e) => saveSettings({ notifications: e.target.checked });
const ALERT_FIELDS = {
  ntfy: `<p class="hint">Install the free ntfy app, then subscribe to the address below. Keep it private: anyone who knows it can read your alerts.</p>
    <input id="af-url" class="tags-input" aria-label="ntfy address">`,
  telegram: `<p class="hint">Create a bot with @BotFather, send it a message, then enter its token and your chat id.</p>
    <input id="af-token" class="tags-input" placeholder="Bot token (123456:ABC…)" aria-label="Bot token">
    <input id="af-chat" class="tags-input" placeholder="Chat id" aria-label="Chat id">`,
  discord: `<p class="hint">Channel settings → Integrations → Webhooks → New Webhook → Copy URL.</p>
    <input id="af-url" class="tags-input" placeholder="https://discord.com/api/webhooks/…" aria-label="Discord webhook address">`,
  webhook: `<p class="hint">NattoWok POSTs JSON with a title, message and the events. For Home Assistant, use an automation with a webhook trigger.</p>
    <input id="af-url" class="tags-input" placeholder="http://homeassistant.local:8123/api/webhook/…" aria-label="Webhook address">`,
};
$("#alert-kind").onchange = (e) => {
  const kind = e.target.value;
  $("#alert-fields").innerHTML = kind ? `${ALERT_FIELDS[kind]}<button class="btn small primary" id="alert-save">Save</button>` : "";
  if (kind === "ntfy") {
    const bytes = crypto.getRandomValues(new Uint8Array(10));
    $("#af-url").value = `https://ntfy.sh/nattowok-${[...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
  }
  $("#alert-save")?.addEventListener("click", async () => {
    const target = kind === "telegram"
      ? { kind, bot_token: $("#af-token").value.trim(), chat_id: $("#af-chat").value.trim() }
      : kind === "discord" ? { kind, webhook_url: $("#af-url").value.trim() } : { kind, url: $("#af-url").value.trim() };
    try {
      await api("/api/alerts", { method: "POST", body: JSON.stringify(target) });
      $("#alert-kind").value = "";
      $("#alert-fields").innerHTML = "";
      toast("Saved. Send a test to check it arrives.");
      await refresh();
    } catch (err) { toast(err.message); }
  });
};
$("#alert-list").onclick = async (e) => {
  const remove = e.target.closest("[data-alert-remove]");
  try {
    if (remove) {
      await api(`/api/alerts/${remove.dataset.alertRemove}`, { method: "DELETE" });
      await refresh();
    } else if (e.target.id === "alert-test") {
      const results = await api("/api/alerts/test", { method: "POST" });
      const failed = results.filter((r) => r.error);
      toast(failed.length ? failed.map((r) => r.error).join(" · ") : "Test sent. Check your phone.");
    }
  } catch (err) { toast(err.message); }
};
$("#set-test").onclick = async () => {
  try { await api("/api/notify-test", { method: "POST" }); toast("Test notification sent"); } catch (e) { toast(e.message); }
};
$("#export-btn").onclick = () => {
  const m = $("#export-menu");
  m.hidden = !m.hidden;
  $("#settings-menu").hidden = true;
  $("#export-btn").setAttribute("aria-expanded", String(!m.hidden));
};
$("#scrim").onclick = closeDrawer;
// One shared tooltip for chart segments.
document.addEventListener("mousemove", (e) => {
  const tip = $("#chart-tip");
  const target = e.target.closest?.("[data-tip]");
  if (!target) { tip.hidden = true; return; }
  tip.textContent = target.dataset.tip;
  tip.hidden = false;
  const x = Math.min(e.clientX + 12, window.innerWidth - tip.offsetWidth - 8);
  tip.style.left = `${x}px`;
  tip.style.top = `${e.clientY + 14}px`;
});
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
