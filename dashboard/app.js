/**
 * CyberDefense SOC Dashboard Application Logic
 * Real-time WebSocket event streaming, LLM investigation rendering, and simulation file ingestion.
 */

// Global State
const state = {
  alerts: [],
  firewallRules: [],
  selectedFile: null,
  selectedPreset: "data/synthetic/enterprise_mixed_traffic_with_false_positives.log",
  speedMultiplier: 10,
  currentFilter: "all",
  ws: null,
  eventCount: 0,
};

// DOM Elements
const elements = {
  // Metrics
  defconValue: document.getElementById("defconValue"),
  defconSub: document.getElementById("defconSub"),
  pendingAlertsCount: document.getElementById("pendingAlertsCount"),
  criticalAlertsCount: document.getElementById("criticalAlertsCount"),
  containmentCount: document.getElementById("containmentCount"),
  totalAlertsSub: document.getElementById("totalAlertsSub"),
  llmProviderLabel: document.getElementById("llmProviderLabel"),

  // Alert Feed
  alertsList: document.getElementById("alertsList"),
  emptyAlertsState: document.getElementById("emptyAlertsState"),
  alertCountBadge: document.getElementById("alertCountBadge"),
  filterTabs: document.querySelectorAll(".tab-btn"),

  // Containment Table
  firewallBody: document.getElementById("firewallBody"),

  // Terminal
  logTerminal: document.getElementById("logTerminal"),
  clearTerminalBtn: document.getElementById("clearTerminalBtn"),
  streamFpsTag: document.getElementById("streamFpsTag"),

  // Simulation Modal
  simModal: document.getElementById("simModal"),
  openSimModalBtn: document.getElementById("openSimModalBtn"),
  closeSimModalBtn: document.getElementById("closeSimModalBtn"),
  cancelSimBtn: document.getElementById("cancelSimBtn"),
  startSimBtn: document.getElementById("startSimBtn"),
  resetSystemBtn: document.getElementById("resetSystemBtn"),

  // Custom File Picker
  browseFileBtn: document.getElementById("browseFileBtn"),
  logFileInput: document.getElementById("logFileInput"),
  dropzone: document.getElementById("dropzone"),
  selectedFileName: document.getElementById("selectedFileName"),

  // Presets & Speeds
  presetRadios: document.querySelectorAll('input[name="scenarioRadio"]'),
  presetOptions: document.querySelectorAll(".preset-option"),
  speedButtons: document.querySelectorAll(".speed-btn"),
  toastContainer: document.getElementById("toastContainer"),
};

// ── Initialization ─────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  initWebSocket();
  fetchInitialData();
  setupEventListeners();
  initMagneticButtons();
});

// ── WebSocket Client ───────────────────────────────────────────

function setLinkStatus(stateName, label) {
  const pill = document.getElementById("wsStatusPill");
  const text = document.getElementById("wsStatusLabel");
  if (pill) pill.dataset.state = stateName;
  if (text) text.textContent = label;
}

function initWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  setLinkStatus("connecting", "LINK HANDSHAKE");
  state.ws = new WebSocket(wsUrl);

  state.ws.onopen = () => {
    setLinkStatus("live", "LINK ACTIVE");
    appendTerminalLine("[WS] Connected to CyberDefense Real-Time SOC Telemetry Stream.", "log-system");
  };

  state.ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      handleWebSocketMessage(msg);
    } catch (e) {
      console.error("WS Parse Error:", e);
    }
  };

  state.ws.onclose = () => {
    setLinkStatus("down", "LINK DOWN · RETRY 3S");
    appendTerminalLine("[WS] Connection lost. Retrying in 3 seconds...", "log-system");
    setTimeout(initWebSocket, 3000);
  };
}

function handleWebSocketMessage(msg) {
  const { type, data } = msg;

  if (type === "log_event") {
    state.eventCount++;
    elements.streamFpsTag.textContent = `${state.eventCount} ev`;
    renderStreamedLog(data);
  } else if (type === "alert_generated") {
    upsertAlert(data);
    showToast(`Tier 1 alert generated · ${data.attack_type}`, "danger");
    refreshStatus();
  } else if (type === "alert_investigated") {
    upsertAlert(data);
    showToast(`LLM investigation ready · ${data.investigation_report?.title || data.id}`, "info");
    refreshStatus();
  } else if (type === "action_executed") {
    showToast(`Mitigated · ${data.message}`, "success");
    fetchFirewallRules();
    refreshStatus();
  }
}

// ── API Fetchers ───────────────────────────────────────────────

async function fetchInitialData() {
  await Promise.all([refreshStatus(), fetchAlerts(), fetchFirewallRules()]);
}

async function refreshStatus() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) return;
    const data = await res.json();

    elements.llmProviderLabel.textContent = `LLM: ${data.llm_provider?.toUpperCase() || "GEMINI"}`;
    elements.pendingAlertsCount.textContent = data.total_alerts - data.actioned_alerts;
    elements.criticalAlertsCount.textContent = data.critical_alerts;
    elements.totalAlertsSub.textContent = `${data.total_alerts} Total Alerts Flagged`;
    elements.containmentCount.textContent = data.active_firewall_rules;

    // Update DEFCON Level
    const defconCard = document.getElementById("defconCard");
    const defconFlag = document.getElementById("defconFlag");
    const applyDefcon = (level, color, sub, flag) => {
      elements.defconValue.textContent = `DEFCON ${level}`;
      elements.defconValue.style.color = color;
      elements.defconSub.textContent = sub;
      if (defconCard) defconCard.dataset.level = String(level);
      if (defconFlag) defconFlag.textContent = flag;
    };

    if (data.critical_alerts > 0) {
      applyDefcon(1, "var(--accent-crimson)", "HOST PENETRATED / ACTIVE EXFIL", "CRITICAL");
    } else if (data.high_alerts > 0) {
      applyDefcon(2, "var(--accent-amber)", "ACTIVE INTRUSION ATTEMPTS", "HOSTILE");
    } else if (data.total_alerts > 0) {
      applyDefcon(3, "var(--accent-cyan)", "RECONNAISSANCE DETECTED", "ELEVATED");
    } else {
      applyDefcon(5, "var(--accent-emerald)", "SYSTEM NORMAL", "NOMINAL");
    }
  } catch (e) {
    console.error("Error refreshing status:", e);
  }
}

async function fetchAlerts() {
  try {
    const res = await fetch("/api/alerts");
    if (!res.ok) return;
    state.alerts = await res.json();
    renderAlerts();
  } catch (e) {
    console.error("Error fetching alerts:", e);
  }
}

async function fetchFirewallRules() {
  try {
    const res = await fetch("/api/firewall/rules");
    if (!res.ok) return;
    state.firewallRules = await res.json();
    renderFirewallRules();
  } catch (e) {
    console.error("Error fetching firewall rules:", e);
  }
}

// ── Feed Loading / Error States ─────────────────────────────────

const SKELETON_MARKUP = document.getElementById("alertsSkeleton")
  ? document.getElementById("alertsSkeleton").innerHTML
  : "";
let feedWatchdog = null;

function showSkeleton() {
  const sk = document.getElementById("alertsSkeleton");
  if (!sk) return;
  sk.className = "alerts-skeleton";
  sk.innerHTML = SKELETON_MARKUP;
}

function dismissSkeleton() {
  clearTimeout(feedWatchdog);
  const sk = document.getElementById("alertsSkeleton");
  if (sk) sk.remove();
}

function showFeedError() {
  const sk = document.getElementById("alertsSkeleton");
  if (!sk) return;
  sk.className = "load-error";
  sk.innerHTML = `
    <h3>Alert feed unreachable</h3>
    <p>The SOC API did not answer within 8 seconds. The console keeps listening on the telemetry socket &mdash; retry once the service is reachable.</p>
    <button type="button" class="btn btn-ghost btn-sm" id="retryAlertsBtn">Retry connection</button>
  `;
  const retry = document.getElementById("retryAlertsBtn");
  if (retry) {
    retry.addEventListener("click", () => {
      showSkeleton();
      startFeedWatchdog();
      fetchAlerts();
    });
  }
}

function startFeedWatchdog() {
  clearTimeout(feedWatchdog);
  feedWatchdog = setTimeout(showFeedError, 8000);
}

startFeedWatchdog();

// ── Rendering Components ───────────────────────────────────────

function upsertAlert(newAlert) {
  const index = state.alerts.findIndex((a) => a.id === newAlert.id);
  if (index >= 0) {
    state.alerts[index] = newAlert;
  } else {
    state.alerts.unshift(newAlert);
  }
  renderAlerts();
}

function renderAlerts() {
  dismissSkeleton();

  const filtered = state.alerts.filter((alert) => {
    if (state.currentFilter === "pending") {
      return alert.status === "PENDING" || alert.status === "REVIEWED" || alert.status === "INVESTIGATING";
    }
    if (state.currentFilter === "critical") {
      return alert.severity === "CRITICAL" || alert.severity === "HIGH";
    }
    if (state.currentFilter === "false_positive") {
      return Boolean(alert.investigation_report?.is_false_positive || alert.investigation_report?.verdict === "FALSE_POSITIVE");
    }
    if (state.currentFilter === "actioned") {
      return alert.status === "ACTIONED" || alert.status === "RESOLVED";
    }
    return true;
  });

  elements.alertCountBadge.textContent = `${filtered.length} alerts`;

  if (filtered.length === 0) {
    const isFilterMiss = state.currentFilter !== "all" && state.alerts.length > 0;
    const emptyTitle = elements.emptyAlertsState.querySelector("#emptyTitle");
    const emptyDesc = elements.emptyAlertsState.querySelector("#emptyDesc");
    if (emptyTitle) {
      emptyTitle.textContent = isFilterMiss
        ? "No alerts match this view"
        : "Perimeter Secure · No Active Alerts";
    }
    if (emptyDesc) {
      emptyDesc.innerHTML = isFilterMiss
        ? "The engine has flagged alerts in this session, but none sit in this filter. Switch back to <strong>All</strong> to review the full detection history."
        : "Open <strong>Launch Temporary Simulation</strong> above to ingest a custom <code>.log</code> or <code>.txt</code> file and watch autonomous detection and LLM threat investigation run end to end.";
    }

    elements.emptyAlertsState.style.display = "block";
    elements.alertsList.innerHTML = "";
    elements.alertsList.appendChild(elements.emptyAlertsState);
    return;
  }

  elements.emptyAlertsState.style.display = "none";
  elements.alertsList.innerHTML = "";

  filtered.forEach((alert) => {
    const inv = alert.investigation_report;
    const isFp = Boolean(inv?.is_false_positive || inv?.verdict === "FALSE_POSITIVE");
    const activeBlockRule = state.firewallRules.find(
      (r) => r.type === "BLOCK_IP" && r.target === alert.source_ip && r.status !== "REMOVED"
    );
    const isPreMitigated = Boolean(
      alert.admin_action === "ALREADY_BLOCKED" ||
      inv?.verdict === "PRE_MITIGATED" ||
      (activeBlockRule && alert.admin_action !== "BLOCK_IP" && alert.admin_action !== "ISOLATE_HOST")
    );
    const isAlreadyBlocked = isPreMitigated;
    const isActioned = alert.status === "ACTIONED" || alert.status === "RESOLVED" || alert.status === "DISMISSED";

    const card = document.createElement("div");
    card.className = `alert-card ${alert.severity.toLowerCase()} ${isFp ? "false-positive" : ""}`;

    card.innerHTML = `
      <div class="alert-card-header">
        <div class="badge-row">
          <span class="sev-badge sev-${alert.severity}">${alert.severity}</span>
          ${isFp ? `<span class="badge-fp">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
              <path d="m9 12 2 2 4-4"></path>
            </svg>
            FALSE POSITIVE · AUTO-DISMISSED</span>` : ""}
          ${isAlreadyBlocked ? `<span class="badge-fp badge-premitigated">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <rect x="4" y="10" width="16" height="11" rx="2"></rect>
              <path d="M8 10V7a4 4 0 0 1 8 0v3"></path>
            </svg>
            PRE-MITIGATED · ALREADY BLOCKED</span>` : ""}
          <span class="mitre-badge">${alert.attack_type} · ${alert.mitre_id}</span>
          ${inv?.correlated_alert_ids?.length ? `<span class="count-badge">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M10 13a5 5 0 0 0 7.07 0l2.83-2.83a5 5 0 0 0-7.07-7.07L11.5 4.43"></path>
              <path d="M14 11a5 5 0 0 0-7.07 0L4.1 13.83a5 5 0 0 0 7.07 7.07L12.5 19.57"></path>
            </svg>
            ${inv.correlated_alert_ids.length} Correlated</span>` : ""}
        </div>
        <span class="alert-timestamp">${new Date(alert.timestamp).toLocaleTimeString()}</span>
      </div>

      <div class="alert-headline">${inv?.title || alert.rule_summary}</div>

      <div class="alert-meta-bar">
        <span><strong>SRC IP</strong> ${alert.source_ip || "N/A"}</span>
        <span><strong>TARGET</strong> ${alert.target || "N/A"}</span>
        <span><strong>STATUS</strong> ${alert.status}</span>
      </div>

      <div class="tier1-flag"><span class="t1-label">TIER 1 TRIGGER</span>${alert.rule_summary}</div>

      <!-- Tier 2 LLM Investigation Report Card -->
      ${inv ? `
        <div class="llm-investigation-box">
          <div class="llm-investigation-header">
            <span class="llm-tag">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <rect x="7" y="7" width="10" height="10" rx="2"></rect>
                <path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4"></path>
              </svg>
              TIER 2 · LLM INVESTIGATION REPORT
            </span>
          </div>

          <div class="llm-mitre">${inv.mitre_mapping}</div>

          <p class="llm-summary">${inv.executive_summary}</p>
          <div class="llm-justification">
            <strong>Why ${inv.severity}:</strong> ${inv.severity_justification}
          </div>

          ${isFp ? `
            <div class="fp-auto-dismissed-banner">
              <div class="fp-banner-title">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                  <path d="m9 12 2 2 4-4"></path>
                </svg>
                TIER 2 AUTO-TRIAGE: VERIFIED BENIGN (FALSE POSITIVE)
              </div>
              <div class="fp-banner-desc">
                Tier 1 flagged this activity via naive threshold. Tier 2 analyzed entity context, source origin (${alert.source_ip}), and legitimate operational behavior, automatically dismissing the alert to prevent analyst fatigue.
              </div>
            </div>
          ` : isAlreadyBlocked ? `
            <div class="already-blocked-banner">
              <div class="already-blocked-title">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <rect x="4" y="10" width="16" height="11" rx="2"></rect>
                  <path d="M8 10V7a4 4 0 0 1 8 0v3"></path>
                </svg>
                ACTIVE CONTAINMENT · IP ALREADY BLOCKED
              </div>
              <div class="already-blocked-desc">
                Source IP <code>${alert.source_ip}</code> is already blocked in active firewall perimeter rules ${activeBlockRule ? `(Rule: ${activeBlockRule.rule_id})` : ""}. Ingress traffic is automatically intercepted and dropped without requiring manual analyst action.
              </div>
            </div>
          ` : isActioned ? `
            <div class="action-taken-badge">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="m5 13 4 4L19 7"></path>
              </svg>
              MITIGATED: ${alert.admin_action} ${alert.actioned_at ? `(${new Date(alert.actioned_at).toLocaleTimeString()})` : ""}
            </div>
          ` : `
            <div class="action-buttons-group">
              <button type="button" class="act-btn act-btn-block" data-act-btn="true" data-alert-id="${alert.id}" data-action="BLOCK_IP" data-target="${(alert.source_ip || '').replace(/"/g, '&quot;')}" onclick="executeAction('${alert.id}', 'BLOCK_IP', '${alert.source_ip || ''}')">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" aria-hidden="true">
                  <circle cx="12" cy="12" r="9"></circle>
                  <path d="m5.6 5.6 12.8 12.8"></path>
                </svg>
                Block IP (${alert.source_ip || 'Source'})
              </button>
              <button type="button" class="act-btn act-btn-isolate" data-act-btn="true" data-alert-id="${alert.id}" data-action="ISOLATE_HOST" data-target="${(alert.target || '').replace(/"/g, '&quot;')}" onclick="executeAction('${alert.id}', 'ISOLATE_HOST', '${(alert.target || '').replace(/'/g, "\\'")}')">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <path d="M3 10.5 12 3l9 7.5"></path>
                  <path d="M5 9.7V20h14V9.7"></path>
                  <path d="M9.5 20v-5.2h5V20"></path>
                </svg>
                Isolate Host
              </button>
              <button type="button" class="act-btn act-btn-reset" data-act-btn="true" data-alert-id="${alert.id}" data-action="FORCE_PASSWORD_RESET" data-target="admin" onclick="executeAction('${alert.id}', 'FORCE_PASSWORD_RESET', 'admin')">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <circle cx="8" cy="14.5" r="4"></circle>
                  <path d="m10.9 11.6 7.6-7.6"></path>
                  <path d="m15.4 7.1 2 2"></path>
                  <path d="m18 4.5 2 2"></path>
                </svg>
                Reset Password
              </button>
              <button type="button" class="act-btn act-btn-dismiss" data-act-btn="true" data-alert-id="${alert.id}" data-action="DISMISS" data-target="" onclick="executeAction('${alert.id}', 'DISMISS', '')">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" aria-hidden="true">
                  <path d="M18 6 6 18"></path>
                  <path d="m6 6 12 12"></path>
                </svg>
                Dismiss
              </button>
            </div>
          `}
        </div>
      ` : `
        <div class="llm-pending">Tier 2 LLM investigation reasoning in progress&hellip;</div>
      `}
    `;

    elements.alertsList.appendChild(card);
  });
}

function renderFirewallRules() {
  if (state.firewallRules.length === 0) {
    elements.firewallBody.innerHTML = `<tr><td colspan="4" class="empty-table-msg">No active firewall blocks or host quarantines</td></tr>`;
    return;
  }

  elements.firewallBody.innerHTML = state.firewallRules
    .map(
      (rule) => `
    <tr>
      <td class="rule-id">${rule.rule_id}</td>
      <td><span class="type-chip">${rule.type}</span></td>
      <td><strong>${rule.target}</strong></td>
      <td>
        ${rule.type === "BLOCK_IP" ? `
          <button class="btn btn-ghost btn-sm" onclick="unblockIp('${rule.target}')">Unblock</button>
        ` : `<span class="rule-active">Active</span>`}
      </td>
    </tr>
  `
    )
    .join("");
}

function renderStreamedLog(event) {
  const line = document.createElement("div");
  line.className = "log-line";

  let colorClass = "log-conn";
  if (event.event_type === "AUTH_LOGIN") colorClass = "log-auth";
  if (event.event_type === "PRIV_CHANGE") colorClass = "log-priv";
  if (event.event_type === "DATA_TRANSFER") colorClass = "log-data";

  line.innerHTML = `
    <span>${new Date(event.timestamp).toLocaleTimeString()}</span>
    <span class="${colorClass}">[${event.event_type}]</span>
    <span>${event.source_ip}:${event.source_port} -&gt; ${event.dest_ip}:${event.dest_port}</span>
    <span class="log-meta">| ${event.user} | ${event.status} | ${event.details}</span>
  `;

  elements.logTerminal.appendChild(line);
  elements.logTerminal.scrollTop = elements.logTerminal.scrollHeight;
}

function appendTerminalLine(text, styleClass = "") {
  const line = document.createElement("div");
  line.className = `log-line ${styleClass}`;
  line.textContent = text;
  elements.logTerminal.appendChild(line);
  elements.logTerminal.scrollTop = elements.logTerminal.scrollHeight;
}

// ── Action Handlers ───────────────────────────────────────────

window.executeAction = async function (alertId, actionType, target) {
  try {
    const res = await fetch(`/api/alerts/${alertId}/action`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action_type: actionType,
        target: target || "",
        reason: "Admin executed recommendation from investigation report",
        admin_user: "soc_lead",
      }),
    });

    if (res.ok) {
      const data = await res.json();
      showToast(`Action ${actionType} executed successfully`, "success");
      if (data && data.alert) {
        upsertAlert(data.alert);
      }
      await fetchAlerts();
      await fetchFirewallRules();
      await refreshStatus();
    } else {
      const err = await res.json().catch(() => ({}));
      showToast(err.detail || "Failed to execute action", "danger");
    }
  } catch (e) {
    console.error("Action error:", e);
    showToast("Error executing action: " + (e.message || "Network error"), "danger");
  }
};

window.unblockIp = async function (ip) {
  try {
    const res = await fetch(`/api/firewall/unblock/${ip}`, { method: "POST" });
    if (res.ok) {
      showToast(`IP ${ip} unblocked`, "info");
      await fetchFirewallRules();
      await refreshStatus();
    } else {
      showToast("Failed to unblock IP", "danger");
    }
  } catch (e) {
    console.error("Unblock error:", e);
  }
};

// ── Event Listeners & Simulation Modal ────────────────────────

function setupEventListeners() {
  // Delegated event listener for alert containment action buttons
  elements.alertsList.addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-act-btn]");
    if (!btn) return;
    const alertId = btn.dataset.alertId;
    const actionType = btn.dataset.action;
    const target = btn.dataset.target;
    if (alertId && actionType) {
      btn.disabled = true;
      btn.style.opacity = "0.6";
      await executeAction(alertId, actionType, target);
      btn.disabled = false;
      btn.style.opacity = "1";
    }
  });

  // Modal toggles
  elements.openSimModalBtn.addEventListener("click", () => {
    elements.simModal.classList.add("open");
  });
  elements.closeSimModalBtn.addEventListener("click", () => {
    elements.simModal.classList.remove("open");
  });
  elements.cancelSimBtn.addEventListener("click", () => {
    elements.simModal.classList.remove("open");
  });

  // User-requested "Select File" button click triggers native file picker!
  elements.browseFileBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    elements.logFileInput.click();
  });

  // Dropzone click also triggers native file picker
  elements.dropzone.addEventListener("click", () => {
    elements.logFileInput.click();
  });

  // File input change handler (handles selected .log or .txt file)
  elements.logFileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (file) {
      state.selectedFile = file;
      elements.selectedFileName.textContent = `Selected · ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
      elements.selectedFileName.style.color = "var(--accent-emerald)";
      showToast(`Loaded ${file.name}`, "info");
    }
  });

  // Drag and drop for dropzone
  elements.dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    elements.dropzone.classList.add("dragover");
  });
  elements.dropzone.addEventListener("dragleave", () => {
    elements.dropzone.classList.remove("dragover");
  });
  elements.dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    elements.dropzone.classList.remove("dragover");
    const file = e.dataTransfer.files[0];
    if (file) {
      state.selectedFile = file;
      elements.selectedFileName.textContent = `Selected · ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
      elements.selectedFileName.style.color = "var(--accent-emerald)";
      showToast(`Dropped ${file.name}`, "info");
    }
  });

  // Preset radio selection
  elements.presetRadios.forEach((radio) => {
    radio.addEventListener("change", (e) => {
      state.selectedPreset = e.target.value;
      state.selectedFile = null;
      elements.selectedFileName.textContent = "No file selected (using preset)";
      elements.selectedFileName.style.color = "var(--text-dim)";

      elements.presetOptions.forEach((opt) => opt.classList.remove("active"));
      radio.closest(".preset-option").classList.add("active");
    });
  });

  // Speed multiplier buttons
  elements.speedButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      elements.speedButtons.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      state.speedMultiplier = parseFloat(btn.dataset.speed);
    });
  });

  // Launch Simulation button
  elements.startSimBtn.addEventListener("click", async () => {
    elements.simModal.classList.remove("open");

    // Case 1: Custom user uploaded file (.log or .txt)
    if (state.selectedFile) {
      appendTerminalLine(`[SIM] Uploading custom file '${state.selectedFile.name}'...`, "log-system");
      const formData = new FormData();
      formData.append("file", state.selectedFile);
      formData.append("auto_start", "true");
      formData.append("speed_multiplier", state.speedMultiplier);

      try {
        const res = await fetch("/api/simulation/upload", {
          method: "POST",
          body: formData,
        });
        const data = await res.json();
        if (res.ok) {
          showToast(`Simulation started with ${state.selectedFile.name}`, "success");
          appendTerminalLine(`[SIM] Ingesting ${data.events_count} events from ${state.selectedFile.name}`, "log-system");
        } else {
          showToast(data.detail || "Upload error", "danger");
        }
      } catch (err) {
        showToast("Error uploading file", "danger");
      }
    }
    // Case 2: Selected preset scenario
    else {
      appendTerminalLine(`[SIM] Launching preset scenario: ${state.selectedPreset}...`, "log-system");
      try {
        const res = await fetch("/api/simulation/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            scenario_path: state.selectedPreset,
            speed_multiplier: state.speedMultiplier,
            instant: state.speedMultiplier === 0,
          }),
        });
        const data = await res.json();
        if (res.ok) {
          showToast(`Simulation running: ${data.events_queued} events queued`, "success");
        } else {
          showToast(data.detail || "Simulation error", "danger");
        }
      } catch (err) {
        showToast("Error starting simulation", "danger");
      }
    }
  });

  // Filter tabs
  elements.filterTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      elements.filterTabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      state.currentFilter = tab.dataset.filter;
      renderAlerts();
    });
  });

  // Clear terminal
  elements.clearTerminalBtn.addEventListener("click", () => {
    elements.logTerminal.innerHTML = '<div class="log-line log-system">[SYS] Telemetry terminal cleared.</div>';
    state.eventCount = 0;
    elements.streamFpsTag.textContent = "0 ev";
  });

  // Reset system
  elements.resetSystemBtn.addEventListener("click", async () => {
    if (!confirm("Reset all alerts, containment firewall rules, and simulation memory?")) return;
    try {
      await fetch("/api/simulation/reset", { method: "POST" });
      state.alerts = [];
      state.firewallRules = [];
      state.eventCount = 0;
      renderAlerts();
      renderFirewallRules();
      await refreshStatus();
      elements.logTerminal.innerHTML = '<div class="log-line log-system">[SYS] System state reset to initial baselines.</div>';
      showToast("System state reset", "info");
    } catch (e) {
      showToast("Reset failed", "danger");
    }
  });
}

function showToast(message, type = "info") {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.textContent = message;
  elements.toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 4000);
}

// ── Magnetic micro-physics (pointer-capable devices only) ────────
// Transforms are written straight to the style attribute inside a rAF
// flush, so no React-style state round-trip happens per pointer move.
function initMagneticButtons() {
  if (!window.matchMedia("(hover: hover) and (pointer: fine)").matches) return;

  const PULL_X = 3.5;
  const PULL_Y = 3;
  let active = null;
  let queued = null;
  let frame = 0;

  const release = (el) => {
    if (el && el.isConnected) {
      el.style.removeProperty("--mx");
      el.style.removeProperty("--my");
    }
    if (el && el === active) active = null;
  };

  const apply = () => {
    frame = 0;
    const event = queued;
    queued = null;
    if (!event) return;

    const target = event.target instanceof Element ? event.target.closest(".btn-primary, .act-btn") : null;

    if (target !== active) {
      release(active);
      active = target;
    }
    if (!target || target.disabled) return;

    const box = target.getBoundingClientRect();
    const nx = (event.clientX - (box.left + box.width / 2)) / Math.max(box.width / 2, 1);
    const ny = (event.clientY - (box.top + box.height / 2)) / Math.max(box.height / 2, 1);
    const dx = Math.max(-PULL_X, Math.min(PULL_X, nx * PULL_X));
    const dy = Math.max(-PULL_Y, Math.min(PULL_Y, ny * PULL_Y));

    target.style.setProperty("--mx", `${dx.toFixed(2)}px`);
    target.style.setProperty("--my", `${dy.toFixed(2)}px`);
  };

  document.addEventListener(
    "pointermove",
    (event) => {
      queued = event;
      if (!frame) frame = requestAnimationFrame(apply);
    },
    { passive: true }
  );

  document.addEventListener("pointerleave", () => {
    queued = null;
    release(active);
  });
  window.addEventListener("blur", () => {
    queued = null;
    release(active);
  });
}
