"use strict";

const state = {
  session: null,
  snapshot: null,
  view: "overview",
  telemetry: [],
  telemetryFilter: "all",
  listing: null,
  selectedPaths: new Set(),
  safariVisits: [],
  toastTimer: null,
  statusTimer: null,
  statusRequest: null,
  statusFailed: false,
  jobsTimer: null,
  jobsRequest: null,
  archivesRequest: null,
  archivesRefreshQueued: false,
  jobStates: new Map(),
  exportSubmitting: false,
  cancellingJobs: new Set(),
  privateGeneration: 0,
  auditRequestID: 0,
  filesRequestID: 0,
  previewRequestID: 0,
  probeRequestID: 0,
  safariRequestID: 0,
  sessionTimer: null,
};

const viewLabels = {
  overview: ["SYSTEM OVERVIEW", "Operations"],
  telemetry: ["COLLECTED SIGNALS", "Telemetrie"],
  files: ["ON-DEMAND PRIVATE ACCESS", "Datei-Explorer"],
  safari: ["ON-DEMAND PRIVATE ACCESS", "Safari Inspection"],
  exports: ["CONTROLLED DATA TRANSFER", "Exporte"],
};

const byId = (id) => document.getElementById(id);

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  restoreSession();
});

function bindEvents() {
  byId("login-form").addEventListener("submit", login);
  byId("logout-button").addEventListener("click", logout);
  byId("refresh-button").addEventListener("click", refreshCollectors);
  byId("private-button").addEventListener("click", togglePrivateSession);
  byId("navigation").addEventListener("click", (event) => {
    const button = event.target.closest("[data-view]");
    if (button) switchView(button.dataset.view);
  });
  document.querySelectorAll(".open-unlock").forEach((button) => button.addEventListener("click", openUnlock));
  byId("unlock-form").addEventListener("submit", unlockPrivate);
  byId("unlock-close").addEventListener("click", (event) => {
    event.preventDefault();
    byId("unlock-dialog").close();
  });
  byId("telemetry-reload").addEventListener("click", loadTelemetry);
  byId("audit-reload").addEventListener("click", loadAudit);
  document.querySelectorAll("[data-telemetry-filter]").forEach((button) =>
    button.addEventListener("click", () => {
      state.telemetryFilter = button.dataset.telemetryFilter;
      document
        .querySelectorAll("[data-telemetry-filter]")
        .forEach((item) => item.classList.toggle("active", item === button));
      renderTelemetryList();
    }),
  );
  byId("path-form").addEventListener("submit", (event) => {
    event.preventDefault();
    loadFiles(byId("path-input").value);
  });
  byId("file-parent").addEventListener("click", () => {
    if (state.listing?.parent) loadFiles(state.listing.parent);
  });
  byId("show-hidden").addEventListener("change", renderFiles);
  byId("select-all-files").addEventListener("change", selectAllFiles);
  byId("probe-selection").addEventListener("click", probeSelection);
  byId("export-selection").addEventListener("click", startExport);
  byId("file-preview-close").addEventListener("click", clearFilePreview);
  byId("safari-form").addEventListener("submit", (event) => {
    event.preventDefault();
    loadSafari();
  });
  byId("safari-search").addEventListener("input", renderSafari);
  byId("jobs-reload").addEventListener("click", loadJobs);
  byId("archives-reload").addEventListener("click", loadArchives);
}

async function restoreSession() {
  try {
    state.session = await api("/api/session", { allowUnauthorized: true });
    showApp();
  } catch (_) {
    showLogin();
  }
}

async function login(event) {
  event.preventDefault();
  const username = byId("login-username").value;
  const passwordInput = byId("login-password");
  byId("login-error").textContent = "";
  try {
    state.session = await api("/api/login", {
      method: "POST",
      body: { username, password: passwordInput.value },
      skipCSRF: true,
    });
    passwordInput.value = "";
    showApp();
  } catch (error) {
    passwordInput.value = "";
    byId("login-error").textContent = error.message;
  }
}

async function logout() {
  try {
    await api("/api/logout", { method: "POST", body: {} });
  } catch (_) {
    // a locally expired session still needs the same cleanup.
  }
  state.session = null;
  showLogin();
}

function showLogin() {
  stopTimers();
  state.statusFailed = false;
  clearPrivateData();
  byId("app-view").classList.add("hidden");
  byId("login-view").classList.remove("hidden");
  setTimeout(() => byId("login-username").focus(), 0);
}

function showApp() {
  byId("login-view").classList.add("hidden");
  byId("app-view").classList.remove("hidden");
  byId("unlock-minutes").textContent = `${state.session.private_ttl_minutes} Minuten`;
  updatePrivateUI();
  switchView("overview");
  loadStatus();
  loadHealthHistory();
  stopTimers();
  state.statusTimer = window.setInterval(loadStatus, Math.max(2, state.session.refresh_seconds) * 1000);
  state.sessionTimer = window.setInterval(sessionTick, 1000);
}

function stopTimers() {
  for (const key of ["statusTimer", "jobsTimer", "sessionTimer"]) {
    if (state[key]) window.clearInterval(state[key]);
    state[key] = null;
  }
}

function switchView(name) {
  if (!viewLabels[name]) return;
  state.view = name;
  document
    .querySelectorAll(".view")
    .forEach((view) => view.classList.toggle("active-view", view.id === `view-${name}`));
  document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === name));
  byId("view-kicker").textContent = viewLabels[name][0];
  byId("view-title").textContent = viewLabels[name][1];
  if (name === "telemetry" && state.telemetry.length === 0) loadTelemetry();
  if (name === "overview" && privateActive()) loadAudit();
  if (privateActive()) {
    if (name === "files" && !state.listing) loadFiles(state.session.managed_home);
    if (name === "exports") {
      loadJobs();
      loadArchives();
    }
  }
  updateJobPolling();
}

async function loadStatus() {
  if (!state.session) return;
  if (state.statusRequest) return state.statusRequest;
  state.statusRequest = (async () => {
    try {
      const snapshot = await api("/api/status", { timeoutMs: 40000 });
      if (!state.session) return;
      const recovered = state.statusFailed;
      state.statusFailed = false;
      state.snapshot = snapshot;
      renderStatus(snapshot);
      if (recovered) toast("Live-Status ist wieder erreichbar.");
    } catch (error) {
      if (!state.session) return;
      const firstFailure = !state.statusFailed;
      state.statusFailed = true;
      renderStatusFailure(error);
      if (firstFailure) toast(`Status nicht verfügbar: ${safeText(error.message)}`, true);
    } finally {
      state.statusRequest = null;
    }
  })();
  return state.statusRequest;
}

function renderStatusFailure(error) {
  const hasSnapshot = Boolean(state.snapshot);
  setStatus("mac-state", "mac-state-dot", hasSnapshot ? "STALE" : "UNBEKANNT", "warn");
  setStatus("node-state", "node-state-dot", "NICHT ERREICHBAR", "bad");
  setStatus("integrity-state", "integrity-dot", "NICHT VERIFIZIERT", "warn");
  setStatus("security-state", "security-dot", "NICHT VERIFIZIERT", "warn");
  setDot(byId("sidebar-mesh-dot"), "bad");
  byId("sidebar-mesh").textContent = "Status nicht erreichbar";
  byId("mac-online-pill").textContent = hasSnapshot ? "STALE" : "UNBEKANNT";
  byId("mac-online-pill").className = "pill warn";
  const lastGood = state.snapshot?.collected_at ? ` · letzter Snapshot ${formatTime(state.snapshot.collected_at)}` : "";
  byId("last-update").textContent = `STATUSFEHLER${lastGood}`;
  renderAlerts([`Live-Status konnte nicht aktualisiert werden: ${safeText(error.message)}`]);
}

function renderStatus(snapshot) {
  const now = Date.now();
  const health = snapshot.mac?.health || null;
  const fields = parseSnapshot(health?.snapshot || snapshot.mac?.last_online_health?.snapshot || "");
  const healthAge = health?.timestamp ? (now - Date.parse(normalizeCompactTime(health.timestamp))) / 1000 : Infinity;
  const macOnline = health?.state === "online" && healthAge < 150;
  const meshOnline = Boolean(snapshot.node?.warp_service_active && snapshot.node?.warp_connected);
  const integrity = fields.integrity_state || "not_reported";
  const security = snapshot.mac?.security;
  const securityOK = Boolean(security && security.posture_rc === 0 && security.telemetry_rc === 0);

  setStatus(
    "mac-state",
    "mac-state-dot",
    macOnline ? "ONLINE" : health?.state === "online" ? "STALE" : "OFFLINE",
    macOnline ? "good" : "bad",
  );
  byId("mac-last-check").textContent = health?.timestamp
    ? `Check ${formatTime(health.timestamp)} · SSH rc ${health.ssh_rc}`
    : "Kein Health-Check";
  setStatus("node-state", "node-state-dot", "ONLINE", "good");
  byId("node-host").textContent =
    `${safeText(snapshot.node?.hostname || "–")} · ${safeText(snapshot.node?.mesh_ip || "keine Mesh-IP")}`;
  setStatus(
    "integrity-state",
    "integrity-dot",
    integrity.toUpperCase().replaceAll("_", " "),
    integrity === "healthy" ? "good" : integrity === "drift" ? "bad" : "warn",
  );
  byId("integrity-detail").textContent =
    `${safeText(fields.integrity_mode || "alert-only")} · ${safeText(fields.integrity_release || "kein Release")}`;
  setStatus("security-state", "security-dot", securityOK ? "HEALTHY" : "DEGRADED", securityOK ? "good" : "warn");
  byId("security-detail").textContent = security?.timestamp
    ? `Capture ${formatTime(security.timestamp)}`
    : "Kein Capture";
  setDot(byId("sidebar-mesh-dot"), meshOnline ? "good" : "bad");
  byId("sidebar-mesh").textContent = meshOnline ? safeText(snapshot.node.mesh_ip || "Verbunden") : "Getrennt";
  byId("last-update").textContent = `SNAPSHOT ${formatTime(snapshot.collected_at)}`;

  const pill = byId("mac-online-pill");
  pill.textContent = macOnline ? "ONLINE" : "OFFLINE";
  pill.className = `pill ${macOnline ? "good" : "bad"}`;

  renderDefinitions(byId("mac-metrics"), [
    ["Console User", fields.console || "–"],
    ["Aktive Nutzer", trimComma(fields.users) || "–"],
    ["Uptime", fields.uptime || "–"],
    ["Root Disk", compactDisk(fields.disk)],
    ["Mesh-Adresse", meshFromField(fields.mesh)],
    ["Gatekeeper", fields.gatekeeper || "–"],
    ["Remote Login", fields.remote_login || "–"],
    ["Integrity Check", fields.integrity_checked_at ? formatTime(fields.integrity_checked_at) : "–"],
    ["Geprüfte Dateien", fields.integrity_checked_files || "–"],
  ]);

  const memoryUsed = Math.max(0, (snapshot.node.memory_total_bytes || 0) - (snapshot.node.memory_available_bytes || 0));
  renderDefinitions(byId("node-metrics"), [
    ["Uptime", formatDuration(snapshot.node.uptime_seconds || 0)],
    ["Load", `${number(snapshot.node.load_1)} / ${number(snapshot.node.load_5)} / ${number(snapshot.node.load_15)}`],
    ["Memory", `${formatBytes(memoryUsed)} / ${formatBytes(snapshot.node.memory_total_bytes)}`],
    ["Root Disk", `${snapshot.node.root_used_percent || 0}% · ${formatBytes(snapshot.node.root_used_bytes)}`],
    ["WARP", meshOnline ? "connected" : "disconnected"],
    ["Fail2ban", snapshot.node.fail2ban_active ? "active" : "inactive"],
    ["Time Sync", snapshot.node.ntp_synchronized ? "synchronized" : "unsynced"],
    ["Auto Updates", snapshot.node.auto_updates_enabled ? "enabled" : "disabled"],
    ["Public SSH", safeText(snapshot.node.public_ssh || "unknown").replaceAll("_", " ")],
    ["Monitor Data", formatBytes(snapshot.storage?.monitor_bytes || 0)],
    ["Retrieved", `${snapshot.retrieval?.archive_count || 0} · ${formatBytes(snapshot.retrieval?.archive_bytes || 0)}`],
  ]);

  const alerts = statusAlerts(snapshot, macOnline, meshOnline, integrity, securityOK);
  renderAlerts(alerts);
  renderEvents(snapshot.events || []);
  byId("raw-status").textContent = JSON.stringify(snapshot, null, 2);
}

function statusAlerts(snapshot, macOnline, meshOnline, integrity, securityOK) {
  const alerts = [];
  if (!macOnline) alerts.push("Der Managed Mac antwortet aktuell nicht frisch auf den Health-Check.");
  if (!meshOnline) alerts.push("Der Control Node ist nicht mit dem Cloudflare Mesh verbunden.");
  if (integrity !== "healthy") alerts.push(`Endpoint-Integrität meldet ${integrity.replaceAll("_", " ")}.`);
  if (!securityOK) alerts.push("Der letzte Security-Capture fehlt oder enthält einen Fehler.");
  if (snapshot.node?.reboot_required) alerts.push("Der Control Node hat einen ausstehenden Reboot.");
  if (snapshot.node?.public_ssh === "open_bootstrap")
    alerts.push("Öffentliches Bootstrap-SSH ist weiterhin erreichbar.");
  for (const [label, timer] of [
    ["Health", snapshot.timers?.control_node],
    ["Security", snapshot.timers?.security],
  ]) {
    if (!timer?.active || timer?.service_result === "failed" || timer?.exec_main_status !== 0)
      alerts.push(`${label}-Timer ist nicht gesund.`);
  }
  return alerts;
}

function renderAlerts(alerts) {
  const container = byId("alerts");
  container.replaceChildren();
  byId("alert-count").textContent = String(alerts.length);
  if (!alerts.length) {
    container.className = "alert-list empty-state";
    container.textContent = "Keine aktiven Hinweise.";
    return;
  }
  container.className = "alert-list";
  for (const alert of alerts) {
    const item = document.createElement("div");
    item.className = "alert-item";
    item.textContent = safeText(alert);
    container.append(item);
  }
}

function renderEvents(events) {
  const container = byId("events");
  container.replaceChildren();
  if (!events.length) {
    container.className = "event-list empty-state";
    container.textContent = "Noch keine Events empfangen.";
    return;
  }
  container.className = "event-list";
  for (const event of events.slice(-12).reverse()) {
    const row = document.createElement("div");
    row.className = "event-item";
    const time = document.createElement("time");
    time.textContent = formatTime(event.timestamp);
    const message = document.createElement("span");
    message.textContent = safeText(event.message || "");
    row.append(time, message);
    container.append(row);
  }
}

async function loadHealthHistory() {
  try {
    const data = await api("/api/health-history?limit=120");
    const timeline = byId("health-timeline");
    timeline.replaceChildren();
    const history = data.history || [];
    const padded = Array(Math.max(0, 120 - history.length))
      .fill(null)
      .concat(history);
    for (const record of padded) {
      const bar = document.createElement("span");
      bar.className = record ? (record.state === "online" ? "online" : "offline") : "empty";
      if (record?.timestamp) bar.title = `${formatTime(record.timestamp)} · ${record.state}`;
      timeline.append(bar);
    }
    byId("timeline-caption").textContent = `${history.length} letzte Checks`;
  } catch (_) {
    byId("timeline-caption").textContent = "History nicht verfügbar";
  }
}

async function loadAudit() {
  const container = byId("audit-events");
  if (!privateActive()) {
    container.className = "event-list empty-state";
    container.textContent = "Private Daten entsperren, um das Audit-Protokoll anzuzeigen.";
    return;
  }
  const generation = state.privateGeneration;
  const requestID = ++state.auditRequestID;
  container.className = "event-list empty-state";
  container.textContent = "Lade Audit-Protokoll …";
  try {
    const data = await api("/api/audit?limit=100");
    if (!privateActive() || generation !== state.privateGeneration || requestID !== state.auditRequestID) return;
    const records = data.records || [];
    container.replaceChildren();
    if (!records.length) {
      container.textContent = "Noch keine Dashboard-Aktivität protokolliert.";
      return;
    }
    container.className = "event-list";
    for (const record of records) {
      const row = document.createElement("div");
      row.className = "event-item audit-item";
      const time = document.createElement("time");
      time.textContent = formatTime(record.timestamp);
      const message = document.createElement("span");
      const outcome = record.success ? "OK" : "FEHLER";
      const actor = record.username ? ` · ${safeText(record.username)}` : "";
      const details =
        record.details && Object.keys(record.details).length ? ` · ${JSON.stringify(record.details)}` : "";
      message.textContent = `${outcome} · ${safeText(record.event || "event")}${actor} · ${safeText(record.remote_ip || "unknown")}${safeText(details)}`;
      row.append(time, message);
      container.append(row);
    }
  } catch (error) {
    if (privateActive() && generation === state.privateGeneration && requestID === state.auditRequestID) {
      container.textContent = `Audit nicht verfügbar: ${safeText(error.message)}`;
    }
  }
}

async function refreshCollectors() {
  const button = byId("refresh-button");
  button.disabled = true;
  button.textContent = "…";
  try {
    await api("/api/refresh", { method: "POST", body: {} });
    toast("Health- und Security-Collector wurden aktualisiert.");
    await Promise.all([loadStatus(), loadHealthHistory()]);
    if (state.view === "telemetry") await loadTelemetry();
  } catch (error) {
    toast(`Aktualisierung fehlgeschlagen: ${error.message}`, true);
  } finally {
    button.disabled = false;
    button.textContent = "↻";
  }
}

async function loadTelemetry() {
  const list = byId("telemetry-list");
  list.className = "capture-list empty-state";
  list.textContent = "Lade Captures …";
  try {
    const data = await api("/api/telemetry");
    state.telemetry = data.captures || [];
    renderTelemetryList();
  } catch (error) {
    list.textContent = error.message;
  }
}

function renderTelemetryList() {
  const list = byId("telemetry-list");
  list.replaceChildren();
  const captures = state.telemetry.filter(
    (capture) => state.telemetryFilter === "all" || capture.kind === state.telemetryFilter,
  );
  if (!captures.length) {
    list.className = "capture-list empty-state";
    list.textContent = "Keine passenden Captures.";
    return;
  }
  list.className = "capture-list";
  for (const capture of captures) {
    const button = document.createElement("button");
    button.className = "capture-item";
    button.dataset.captureId = capture.id;
    const label = document.createElement("b");
    label.textContent = capture.kind === "posture" ? "Security Posture" : "Runtime Telemetry";
    const size = document.createElement("span");
    size.textContent = formatBytes(capture.bytes);
    const time = document.createElement("small");
    time.textContent = formatTime(capture.captured_at);
    button.append(label, size, time);
    button.addEventListener("click", () => openTelemetry(capture, button));
    list.append(button);
  }
}

async function openTelemetry(capture, button) {
  document.querySelectorAll(".capture-item").forEach((item) => item.classList.toggle("active", item === button));
  byId("telemetry-title").textContent = capture.kind === "posture" ? "Security Posture" : "Runtime Telemetry";
  byId("telemetry-kind").textContent = capture.kind.toUpperCase();
  byId("telemetry-size").textContent = `${formatTime(capture.captured_at)} · ${formatBytes(capture.bytes)}`;
  byId("telemetry-document").textContent = "Lade unveränderte Collector-Ausgabe …";
  try {
    const documentData = await api(`/api/telemetry/view?id=${encodeURIComponent(capture.id)}`);
    byId("telemetry-document").textContent =
      safeText(documentData.text || "") + (documentData.truncated ? "\n\n[Ausgabe am Serverlimit gekürzt]" : "");
  } catch (error) {
    byId("telemetry-document").textContent = `Fehler: ${error.message}`;
  }
}

function openUnlock() {
  byId("unlock-error").textContent = "";
  byId("unlock-password").value = "";
  byId("unlock-dialog").showModal();
  setTimeout(() => byId("unlock-password").focus(), 0);
}

async function togglePrivateSession() {
  if (!privateActive()) {
    openUnlock();
    return;
  }
  try {
    await api("/api/private/lock", { method: "POST", body: {} });
  } finally {
    state.session.private_active = false;
    state.session.private_until = "";
    clearPrivateData();
    updatePrivateUI();
    toast("Private Daten wurden wieder gesperrt.");
  }
}

async function unlockPrivate(event) {
  event.preventDefault();
  if (event.submitter?.value === "cancel") {
    byId("unlock-dialog").close();
    return;
  }
  const input = byId("unlock-password");
  byId("unlock-error").textContent = "";
  try {
    state.session = await api("/api/private/unlock", { method: "POST", body: { password: input.value } });
    input.value = "";
    byId("unlock-dialog").close();
    updatePrivateUI();
    toast(`Private Daten sind für maximal ${state.session.private_ttl_minutes} Minuten freigegeben.`);
    if (state.view === "overview") loadAudit();
    if (state.view === "files") loadFiles(state.session.managed_home);
    if (state.view === "exports") {
      loadJobs();
      loadArchives();
    }
  } catch (error) {
    input.value = "";
    byId("unlock-error").textContent = error.message;
  }
}

function privateActive() {
  return Boolean(
    state.session?.private_active &&
      state.session.private_until &&
      Date.now() < Date.parse(state.session.private_until),
  );
}

function sessionTick() {
  if (!state.session) return;
  if (state.session.private_active && !privateActive()) {
    state.session.private_active = false;
    state.session.private_until = "";
    clearPrivateData();
    updatePrivateUI();
    toast("Private Daten wurden automatisch gesperrt.");
    return;
  }
  updatePrivateButton();
}

function updatePrivateUI() {
  const active = privateActive();
  document.querySelectorAll(".private-view").forEach((view) => {
    view.querySelector(".private-gate").classList.toggle("hidden", active);
    view.querySelector(".private-content").classList.toggle("hidden", !active);
  });
  document.querySelectorAll(".private-nav i").forEach((label) => {
    label.textContent = active ? "OPEN" : "LOCK";
  });
  updatePrivateButton();
  updateJobPolling();
}

function updatePrivateButton() {
  const button = byId("private-button");
  const small = button.querySelector("small");
  if (!privateActive()) {
    button.classList.remove("unlocked");
    small.textContent = "Gesperrt";
    return;
  }
  const seconds = Math.max(0, Math.ceil((Date.parse(state.session.private_until) - Date.now()) / 1000));
  button.classList.add("unlocked");
  small.textContent = `Offen ${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

function clearPrivateData() {
  state.privateGeneration += 1;
  state.jobStates.clear();
  state.cancellingJobs.clear();
  state.exportSubmitting = false;
  byId("export-selection").textContent = "Export starten";
  state.listing = null;
  state.selectedPaths.clear();
  state.safariVisits = [];
  byId("file-table-body").replaceChildren();
  byId("safari-table-body").replaceChildren();
  byId("export-jobs").replaceChildren();
  byId("archive-list").replaceChildren();
  byId("audit-events").className = "event-list empty-state";
  byId("audit-events").textContent = "Private Daten entsperren, um das Audit-Protokoll anzuzeigen.";
  byId("path-input").value = "";
  byId("safari-search").value = "";
  byId("safari-summary").textContent = "Noch nicht abgefragt";
  byId("probe-result").classList.add("hidden");
  byId("probe-selection").textContent = "Größe prüfen";
  clearFilePreview();
  updateSelectionUI();
}

async function loadFiles(path) {
  if (!privateActive()) return;
  const generation = state.privateGeneration;
  const requestID = ++state.filesRequestID;
  byId("file-table-body").replaceChildren();
  byId("file-empty").classList.remove("hidden");
  byId("file-empty").textContent = "Lade Verzeichnis …";
  try {
    const listing = await api(`/api/files/list?path=${encodeURIComponent(path || state.session.managed_home)}`);
    if (!privateActive() || generation !== state.privateGeneration || requestID !== state.filesRequestID) return;
    state.listing = listing;
    state.selectedPaths.clear();
    byId("path-input").value = state.listing.path;
    byId("file-parent").disabled = !state.listing.parent;
    byId("probe-result").classList.add("hidden");
    clearFilePreview();
    renderFiles();
  } catch (error) {
    if (privateActive() && generation === state.privateGeneration && requestID === state.filesRequestID) {
      byId("file-empty").textContent = safeText(error.message);
    }
  }
}

function visibleEntries() {
  if (!state.listing) return [];
  const showHidden = byId("show-hidden").checked;
  return state.listing.entries.filter((entry) => showHidden || !entry.hidden);
}

function renderFiles() {
  const body = byId("file-table-body");
  body.replaceChildren();
  const entries = visibleEntries();
  byId("file-empty").classList.toggle("hidden", entries.length > 0);
  byId("file-empty").textContent = entries.length ? "" : "Dieser Ordner ist leer.";
  for (const entry of entries) {
    const row = document.createElement("tr");
    if (entry.hidden) row.classList.add("file-hidden");
    const checkCell = document.createElement("td");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = state.selectedPaths.has(entry.path);
    checkbox.disabled = !entry.readable || !["file", "directory"].includes(entry.type);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) state.selectedPaths.add(entry.path);
      else state.selectedPaths.delete(entry.path);
      updateSelectionUI();
    });
    checkCell.append(checkbox);

    const nameCell = document.createElement("td");
    const name = document.createElement("button");
    name.className = "file-name";
    name.disabled = !entry.readable || !["directory", "file"].includes(entry.type);
    const icon = document.createElement("span");
    icon.className = "file-icon";
    icon.textContent = entry.type === "directory" ? "[D]" : entry.type === "symlink" ? "[@]" : "[F]";
    const text = document.createElement("span");
    text.textContent = safeText(entry.name);
    name.append(icon, text);
    if (entry.type === "directory" && entry.readable) name.addEventListener("click", () => loadFiles(entry.path));
    if (entry.type === "file" && entry.readable) name.addEventListener("click", () => previewFile(entry));
    nameCell.append(name);
    row.append(
      checkCell,
      nameCell,
      cell(entry.type),
      cell(entry.type === "file" ? formatBytes(entry.bytes) : "–"),
      cell(formatTime(entry.modified_at)),
      cell(entry.mode || "–"),
    );
    body.append(row);
  }
  updateSelectionUI();
}

async function previewFile(entry) {
  if (!privateActive()) return;
  const generation = state.privateGeneration;
  const requestID = ++state.previewRequestID;
  const panel = byId("file-preview");
  panel.classList.remove("hidden");
  byId("file-preview-name").textContent = safeText(entry.name);
  byId("file-preview-meta").textContent = "Lade begrenzte Vorschau …";
  byId("file-preview-content").textContent = "";
  try {
    const preview = await api("/api/files/preview", { method: "POST", body: { path: entry.path } });
    if (!privateActive() || generation !== state.privateGeneration || requestID !== state.previewRequestID) return;
    const suffix = preview.truncated ? " · auf 512 KiB gekürzt" : "";
    byId("file-preview-meta").textContent = `${safeText(preview.mime)} · ${formatBytes(preview.bytes)}${suffix}`;
    if (preview.kind === "text") {
      byId("file-preview-content").textContent = safeText(preview.text);
    } else {
      const pairs = String(preview.hex_preview || "").match(/.{1,2}/g) || [];
      byId("file-preview-content").textContent =
        `Binärdatei – Inhalt für vollständige Analyse gezielt exportieren.\n\nErste ${pairs.length} Bytes (Hex):\n${pairs.join(" ")}`;
    }
  } catch (error) {
    if (privateActive() && generation === state.privateGeneration && requestID === state.previewRequestID) {
      byId("file-preview-meta").textContent = "Vorschau fehlgeschlagen";
      byId("file-preview-content").textContent = safeText(error.message);
    }
  }
}

function clearFilePreview() {
  state.previewRequestID += 1;
  byId("file-preview").classList.add("hidden");
  byId("file-preview-name").textContent = "Dateivorschau";
  byId("file-preview-meta").textContent = "";
  byId("file-preview-content").textContent = "";
}

function selectAllFiles() {
  const checked = byId("select-all-files").checked;
  for (const entry of visibleEntries()) {
    if (entry.readable && ["file", "directory"].includes(entry.type)) {
      if (checked) state.selectedPaths.add(entry.path);
      else state.selectedPaths.delete(entry.path);
    }
  }
  renderFiles();
}

function updateSelectionUI() {
  const count = state.selectedPaths.size;
  byId("selection-count").textContent = String(count);
  byId("probe-selection").disabled = count === 0;
  byId("export-selection").disabled = count === 0 || state.exportSubmitting;
  if (!state.listing) byId("select-all-files").checked = false;
}

async function probeSelection() {
  const paths = [...state.selectedPaths];
  if (!privateActive() || !paths.length) return;
  const generation = state.privateGeneration;
  const requestID = ++state.probeRequestID;
  const button = byId("probe-selection");
  button.disabled = true;
  const results = [];
  try {
    for (let index = 0; index < paths.length; index += 1) {
      button.textContent = `Prüfe ${index + 1}/${paths.length}`;
      const result = await api("/api/files/probe", { method: "POST", body: { path: paths[index] } });
      if (!privateActive() || generation !== state.privateGeneration || requestID !== state.probeRequestID) return;
      results.push(result);
    }
    const files = results.reduce((sum, item) => sum + item.files, 0);
    const directories = results.reduce((sum, item) => sum + item.directories, 0);
    const bytes = results.reduce((sum, item) => sum + item.bytes, 0);
    const unreadable = results.reduce((sum, item) => sum + item.unreadable, 0);
    const result = byId("probe-result");
    result.textContent = `${paths.length} Auswahl(en) · ${files.toLocaleString("de-DE")} Dateien · ${directories.toLocaleString("de-DE")} Ordner · ${formatBytes(bytes)} · ${unreadable} nicht lesbar`;
    result.classList.remove("hidden");
  } catch (error) {
    if (privateActive() && generation === state.privateGeneration && requestID === state.probeRequestID) {
      toast(`Prüfung fehlgeschlagen: ${safeText(error.message)}`, true);
    }
  } finally {
    if (generation === state.privateGeneration && requestID === state.probeRequestID) {
      button.textContent = "Größe prüfen";
      button.disabled = state.selectedPaths.size === 0;
    }
  }
}

async function startExport() {
  const button = byId("export-selection");
  const paths = [...state.selectedPaths];
  if (!privateActive() || !paths.length || state.exportSubmitting) return;
  const generation = state.privateGeneration;
  const listed = paths
    .slice(0, 5)
    .map((path) => `• ${path}`)
    .join("\n");
  const remainder = paths.length > 5 ? `\n… und ${paths.length - 5} weitere` : "";
  const confirmed = window.confirm(
    `Export wirklich starten?\n\n${listed}${remainder}\n\nDie Auswahl wird auf dem Mac archiviert und gedrosselt zum Control Node übertragen. Exporte laufen einzeln im Hintergrund; das Dashboard bleibt bedienbar. Die private Ansicht kann sich dabei sperren – der Job läuft weiter und erscheint nach erneutem Entsperren.`,
  );
  if (!confirmed) return;
  state.exportSubmitting = true;
  updateSelectionUI();
  button.textContent = "Wird gestartet …";
  try {
    const job = await api("/api/export-jobs", { method: "POST", body: { paths }, timeoutMs: 20000 });
    if (!privateActive() || generation !== state.privateGeneration) return;
    toast(`Exportjob ${job.id.slice(0, 8)} wurde eingereiht.`);
    state.selectedPaths.clear();
    renderFiles();
    switchView("exports");
    loadJobs();
  } catch (error) {
    if (!privateActive() || generation !== state.privateGeneration) return;
    toast(`Export konnte nicht starten: ${exportErrorMessage(error.message)}`, true);
    if (String(error.message).includes("Zeitüberschreitung")) {
      switchView("exports");
      loadJobs();
    }
  } finally {
    if (generation !== state.privateGeneration) return;
    state.exportSubmitting = false;
    button.textContent = "Export starten";
    updateSelectionUI();
  }
}

async function loadSafari() {
  if (!privateActive()) return;
  const generation = state.privateGeneration;
  const requestID = ++state.safariRequestID;
  const hours = Number(byId("safari-hours").value);
  const limit = Number(byId("safari-limit").value);
  byId("safari-empty").classList.remove("hidden");
  byId("safari-empty").textContent = "Erzeuge konsistenten Read-only-Snapshot …";
  byId("safari-table-body").replaceChildren();
  try {
    const data = await api(`/api/safari?hours=${hours}&limit=${limit}`);
    if (!privateActive() || generation !== state.privateGeneration || requestID !== state.safariRequestID) return;
    state.safariVisits = data.visits || [];
    byId("safari-summary").textContent =
      `${data.returned} Besuche · ${hours}h${data.truncated ? " · Limit erreicht" : ""}`;
    renderSafari();
  } catch (error) {
    if (privateActive() && generation === state.privateGeneration && requestID === state.safariRequestID) {
      byId("safari-empty").textContent = safeText(error.message);
      toast(`Safari-Abfrage fehlgeschlagen: ${safeText(error.message)}`, true);
    }
  }
}

function renderSafari() {
  const query = byId("safari-search").value.trim().toLocaleLowerCase("de");
  const visits = state.safariVisits.filter(
    (visit) => !query || `${visit.domain} ${visit.title} ${visit.url}`.toLocaleLowerCase("de").includes(query),
  );
  const body = byId("safari-table-body");
  body.replaceChildren();
  byId("safari-empty").classList.toggle("hidden", visits.length > 0);
  byId("safari-empty").textContent = state.safariVisits.length
    ? "Keine Treffer für diesen Filter."
    : "Abfrage bewusst starten.";
  for (const visit of visits) {
    const row = document.createElement("tr");
    const urlCell = cell(safeText(visit.url || ""));
    urlCell.title = safeText(visit.url || "");
    row.append(
      cell(formatTime(visit.visited_at)),
      cell(safeText(visit.domain || "–")),
      cell(safeText(visit.title || "–")),
      urlCell,
    );
    body.append(row);
  }
}

async function loadJobs() {
  if (!privateActive()) return;
  if (state.jobsRequest) return state.jobsRequest;
  const generation = state.privateGeneration;
  state.jobsRequest = (async () => {
    const container = byId("export-jobs");
    try {
      const data = await api("/api/export-jobs");
      if (!privateActive() || generation !== state.privateGeneration) return;
      const jobs = data.jobs || [];
      const visibleIDs = new Set(jobs.map((job) => job.id));
      for (const id of state.jobStates.keys()) {
        if (!visibleIDs.has(id)) state.jobStates.delete(id);
      }
      container.replaceChildren();
      if (!jobs.length) {
        container.className = "job-list empty-state";
        container.textContent = "Keine Jobs in dieser Sitzung.";
        return;
      }
      container.className = "job-list";
      for (const job of jobs) {
        if (!["queued", "running"].includes(job.state)) state.cancellingJobs.delete(job.id);
        notifyJobTransition(job);
        container.append(renderJob(job));
      }
    } catch (error) {
      if (privateActive() && generation === state.privateGeneration) {
        container.className = "job-list empty-state";
        container.textContent = `Jobs konnten nicht geladen werden: ${safeText(error.message)}`;
      }
    }
  })();
  try {
    return await state.jobsRequest;
  } finally {
    state.jobsRequest = null;
  }
}

function renderJob(job) {
  const item = document.createElement("div");
  item.className = "job-item";
  const name = document.createElement("b");
  name.title = job.current_path || job.paths.join(", ");
  name.textContent = job.current_path || (job.paths.length === 1 ? job.paths[0] : `${job.paths.length} Auswahlen`);
  const status = document.createElement("span");
  status.className = `job-state ${job.state}`;
  status.textContent = jobStateLabel(job.state);
  const progress = document.createElement("progress");
  progress.max = Math.max(1, job.paths.length);
  if (job.state === "running") progress.removeAttribute("value");
  else progress.value = Math.min(job.results.length, progress.max);
  progress.setAttribute("aria-label", `${job.results.length} von ${job.paths.length} Exporten fertig`);
  const detail = document.createElement("small");
  const details = [`${job.results.length}/${job.paths.length} fertig`, jobTiming(job)];
  if (job.error && job.state !== "cancelled") details.push(exportErrorMessage(job.error));
  detail.textContent = details.filter(Boolean).join(" · ");
  item.append(name, status, progress, detail);
  if (job.results.length) {
    const results = document.createElement("div");
    results.className = "job-results";
    for (const result of job.results) {
      const archive = document.createElement("span");
      archive.textContent = `Archiv: ${safeText(result.archive)}${result.archive_bytes ? ` (${formatBytes(result.archive_bytes)})` : ""}`;
      results.append(archive);
    }
    item.append(results);
  }
  if (["queued", "running"].includes(job.state)) {
    const cancel = document.createElement("button");
    cancel.className = "text-button job-cancel";
    cancel.textContent = state.cancellingJobs.has(job.id) ? "Wird abgebrochen …" : "Abbrechen";
    cancel.disabled = state.cancellingJobs.has(job.id);
    cancel.addEventListener("click", () => cancelJob(job, cancel));
    item.append(cancel);
  }
  return item;
}

function exportErrorMessage(value) {
  const message = safeText(value);
  if (message.includes("an identical export job is already pending"))
    return "Genau diese Auswahl wird bereits exportiert.";
  if (message.includes("too many pending export jobs"))
    return "Die Export-Warteschlange ist voll. Bitte einen laufenden Job abwarten oder abbrechen.";
  if (message.includes("Insufficient Control Node storage") || message.includes("insufficient free space for export"))
    return "Zu wenig freier Speicher für diesen Export; bestehende Daten bleiben unverändert.";
  if (message.includes("selection exceeds 50 GiB limit"))
    return "Die Auswahl überschreitet das Limit von 50 GiB pro Exportpfad.";
  if (message === "context canceled") return "Der Export wurde abgebrochen.";
  if (message.includes("Zeitüberschreitung"))
    return "Der Server hat den Start nicht rechtzeitig bestätigt. Bitte zuerst die Jobliste prüfen; identische Doppelstarts werden verhindert.";
  return message;
}

function jobStateLabel(value) {
  return (
    { queued: "Wartet", running: "Läuft", complete: "Fertig", failed: "Fehlgeschlagen", cancelled: "Abgebrochen" }[
      value
    ] || safeText(value)
  );
}

function jobTiming(job) {
  if (job.state === "queued") return `Eingereiht ${formatTime(job.created_at)}`;
  const start = Date.parse(job.started_at || job.created_at);
  const end = Date.parse(job.completed_at || new Date().toISOString());
  if (!Number.isFinite(start) || !Number.isFinite(end)) return "";
  const seconds = Math.max(0, Math.floor((end - start) / 1000));
  const duration = seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return ["complete", "failed", "cancelled"].includes(job.state) ? `Dauer ${duration}` : `Läuft seit ${duration}`;
}

function notifyJobTransition(job) {
  const previous = state.jobStates.get(job.id);
  state.jobStates.set(job.id, job.state);
  if (!previous || previous === job.state) return;
  const shortID = job.id.slice(0, 8);
  if (job.state === "complete") {
    toast(`Exportjob ${shortID} ist fertig. Das Archiv steht zum Download bereit.`);
    void reloadArchivesAfterJob();
  }
  if (job.state === "failed")
    toast(`Exportjob ${shortID} ist fehlgeschlagen: ${exportErrorMessage(job.error || "unbekannter Fehler")}`, true);
  if (job.state === "cancelled") toast(`Exportjob ${shortID} wurde abgebrochen.`);
}

async function reloadArchivesAfterJob() {
  if (state.archivesRefreshQueued) return;
  state.archivesRefreshQueued = true;
  try {
    const pending = state.archivesRequest;
    if (pending) await pending;
    if (privateActive() && state.view === "exports") await loadArchives();
  } finally {
    state.archivesRefreshQueued = false;
  }
}

async function cancelJob(job, button) {
  if (state.cancellingJobs.has(job.id)) return;
  if (!window.confirm(`Exportjob ${job.id.slice(0, 8)} wirklich abbrechen?`)) return;
  state.cancellingJobs.add(job.id);
  button.disabled = true;
  button.textContent = "Wird abgebrochen …";
  let accepted = false;
  try {
    await api("/api/export-jobs/cancel", { method: "POST", body: { id: job.id }, timeoutMs: 20000 });
    accepted = true;
    toast("Exportjob wird kontrolliert abgebrochen.");
    await loadJobs();
  } catch (error) {
    state.cancellingJobs.delete(job.id);
    toast(`Abbruch fehlgeschlagen: ${exportErrorMessage(error.message)}`, true);
  } finally {
    if (!accepted && button.isConnected) {
      button.disabled = false;
      button.textContent = "Abbrechen";
    }
  }
}

async function loadArchives() {
  if (!privateActive()) return;
  if (state.archivesRequest) return state.archivesRequest;
  const generation = state.privateGeneration;
  state.archivesRequest = (async () => {
    const container = byId("archive-list");
    try {
      const data = await api("/api/archives");
      if (!privateActive() || generation !== state.privateGeneration) return;
      const archives = (data.archives || []).filter((archive) => !archive.manifest);
      container.replaceChildren();
      if (!archives.length) {
        container.className = "archive-list empty-state";
        container.textContent = "Keine Archive vorhanden.";
        return;
      }
      container.className = "archive-list";
      for (const archive of archives) {
        const item = document.createElement("div");
        item.className = "archive-item";
        const name = document.createElement("b");
        name.textContent = safeText(archive.name);
        const detail = document.createElement("small");
        detail.textContent = `${formatBytes(archive.bytes)} · ${formatTime(archive.modified_at)}`;
        const download = document.createElement("a");
        download.className = "button";
        download.textContent = "Download";
        download.href = `/api/archives/download?name=${encodeURIComponent(archive.name)}`;
        download.download = archive.name.split("/").pop() || "plntir-export.tar.gz";
        download.addEventListener("click", () =>
          toast("Download an den Browser übergeben. Den Fortschritt zeigt der Browser."),
        );
        item.append(name, detail, download);
        container.append(item);
      }
    } catch (error) {
      if (privateActive() && generation === state.privateGeneration) {
        container.className = "archive-list empty-state";
        container.textContent = `Archive konnten nicht geladen werden: ${safeText(error.message)}`;
      }
    }
  })();
  try {
    return await state.archivesRequest;
  } finally {
    state.archivesRequest = null;
  }
}

function updateJobPolling() {
  if (state.jobsTimer) window.clearInterval(state.jobsTimer);
  state.jobsTimer = null;
  if (state.view === "exports" && privateActive()) state.jobsTimer = window.setInterval(loadJobs, 5000);
}

async function api(endpoint, options = {}) {
  const method = options.method || "GET";
  const headers = { Accept: "application/json" };
  const request = { method, headers, credentials: "same-origin" };
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    request.body = JSON.stringify(options.body);
  }
  if (method !== "GET" && method !== "HEAD" && !options.skipCSRF && state.session?.csrf)
    headers["X-Plntir-CSRF"] = state.session.csrf;
  const controller = options.timeoutMs ? new AbortController() : null;
  const timeout = controller ? window.setTimeout(() => controller.abort(), options.timeoutMs) : null;
  if (controller) request.signal = controller.signal;
  let response;
  try {
    response = await fetch(endpoint, request);
  } catch (error) {
    if (error?.name === "AbortError") throw new Error("Zeitüberschreitung beim Serverabruf");
    throw error;
  } finally {
    if (timeout) window.clearTimeout(timeout);
  }
  let data = {};
  try {
    data = await response.json();
  } catch (_) {
    data = {};
  }
  if (response.status === 401 && !options.allowUnauthorized) {
    state.session = null;
    showLogin();
  }
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function parseSnapshot(snapshot) {
  const result = {};
  for (const line of String(snapshot).split("\n")) {
    const separator = line.indexOf("=");
    if (separator > 0) result[line.slice(0, separator)] = line.slice(separator + 1).trim();
  }
  return result;
}

function renderDefinitions(container, pairs) {
  container.replaceChildren();
  for (const [label, value] of pairs) {
    const wrapper = document.createElement("div");
    const term = document.createElement("dt");
    term.textContent = label;
    const definition = document.createElement("dd");
    definition.textContent = safeText(String(value));
    definition.title = safeText(String(value));
    wrapper.append(term, definition);
    container.append(wrapper);
  }
}

function setStatus(textId, dotId, label, statusClass) {
  byId(textId).textContent = label;
  setDot(byId(dotId), statusClass);
}

function setDot(element, statusClass) {
  element.className = `status-dot ${statusClass}`;
}

function cell(value) {
  const element = document.createElement("td");
  element.textContent = value;
  element.title = value;
  return element;
}

function trimComma(value) {
  return String(value || "").replace(/,+$/, "");
}

function compactDisk(value) {
  const fields = String(value || "")
    .trim()
    .split(/\s+/);
  return fields.length >= 5 ? `${fields[4]} · ${fields[2]}K / ${fields[1]}K` : value || "–";
}

function meshFromField(value) {
  const match = String(value || "").match(/inet\s+([0-9.]+)/);
  return match ? match[1] : String(value || "").trim() || "–";
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let numberValue = bytes;
  let index = 0;
  while (numberValue >= 1024 && index < units.length - 1) {
    numberValue /= 1024;
    index += 1;
  }
  return `${numberValue.toLocaleString("de-DE", { maximumFractionDigits: index ? 1 : 0 })} ${units[index]}`;
}

function formatDuration(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return days ? `${days}d ${hours}h` : `${hours}h ${minutes}m`;
}

function number(value) {
  return (Number(value) || 0).toFixed(2);
}

function normalizeCompactTime(value) {
  const text = String(value || "");
  if (/^[0-9]{8}T[0-9]{6}Z$/.test(text))
    return `${text.slice(0, 4)}-${text.slice(4, 6)}-${text.slice(6, 11)}:${text.slice(11, 13)}:${text.slice(13, 15)}Z`;
  return text;
}

function formatTime(value) {
  if (!value) return "–";
  const parsed = new Date(normalizeCompactTime(value));
  if (Number.isNaN(parsed.getTime())) return safeText(String(value));
  return new Intl.DateTimeFormat("de-DE", {
    dateStyle: "short",
    timeStyle: "medium",
    timeZone: "Europe/Berlin",
  }).format(parsed);
}

function safeText(value) {
  return String(value ?? "")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
    .replace(/[\u202a-\u202e\u2066-\u2069]/g, "");
}

function toast(message, error = false) {
  const element = byId("toast");
  element.textContent = safeText(message);
  element.className = `toast visible${error ? " error" : ""}`;
  if (state.toastTimer) window.clearTimeout(state.toastTimer);
  state.toastTimer = window.setTimeout(() => {
    element.className = "toast";
  }, 4500);
}
