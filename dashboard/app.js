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
});

// ── WebSocket Client ───────────────────────────────────────────

function initWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  state.ws = new WebSocket(wsUrl);

  state.ws.onopen = () => {
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
    showToast(`🚨 Tier 1 Alert: ${data.attack_type}`, "danger");
    refreshStatus();
  } else if (type === "alert_investigated") {
    upsertAlert(data);
    showToast(`🧠 LLM Investigation Ready: ${data.investigation_report?.title || data.id}`, "info");
    refreshStatus();
  } else if (type === "action_executed") {
    showToast(`🛡️ Mitigated: ${data.message}`, "success");
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
    if (data.critical_alerts > 0) {
      elements.defconValue.textContent = "DEFCON 1";
      elements.defconValue.style.color = "var(--accent-crimson)";
      elements.defconSub.textContent = "HOST PENETRATED / ACTIVE EXFIL";
    } else if (data.high_alerts > 0) {
      elements.defconValue.textContent = "DEFCON 2";
      elements.defconValue.style.color = "var(--accent-amber)";
      elements.defconSub.textContent = "ACTIVE INTRUSION ATTEMPTS";
    } else if (data.total_alerts > 0) {
      elements.defconValue.textContent = "DEFCON 3";
      elements.defconValue.style.color = "var(--accent-cyan)";
      elements.defconSub.textContent = "RECONNAISSANCE DETECTED";
    } else {
      elements.defconValue.textContent = "DEFCON 5";
      elements.defconValue.style.color = "var(--accent-emerald)";
      elements.defconSub.textContent = "SYSTEM NORMAL";
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
          ${isFp ? `<span class="badge-fp">🛡️ FALSE POSITIVE · AUTO-DISMISSED</span>` : ""}
          ${isAlreadyBlocked ? `<span class="badge-fp" style="background:rgba(0,243,255,0.12);color:var(--accent-cyan);border-color:rgba(0,243,255,0.35);">🔒 PRE-MITIGATED · ALREADY BLOCKED</span>` : ""}
          <span class="mitre-badge">${alert.attack_type} · ${alert.mitre_id}</span>
          ${inv?.correlated_alert_ids?.length ? `<span class="count-badge">🔗 ${inv.correlated_alert_ids.length} Correlated</span>` : ""}
        </div>
        <span class="alert-timestamp">${new Date(alert.timestamp).toLocaleTimeString()}</span>
      </div>

      <div class="alert-headline">${inv?.title || alert.rule_summary}</div>

      <div class="alert-meta-bar">
        <span><strong>SRC IP:</strong> ${alert.source_ip || "N/A"}</span>
        <span><strong>TARGET:</strong> ${alert.target || "N/A"}</span>
        <span><strong>STATUS:</strong> ${alert.status}</span>
      </div>

      <div class="tier1-flag">
        <span style="color:var(--text-dim);font-family:var(--font-mono);">⚡ Tier 1 Trigger:</span> ${alert.rule_summary}
      </div>

      <!-- Tier 2 LLM Investigation Report Card -->
      ${inv ? `
        <div class="llm-investigation-box">
          <div class="llm-investigation-header">
            <span class="llm-tag">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 2a4 4 0 0 1 4 4c0 1.5-.8 2.8-2 3.5V11h-4V9.5C8.8 8.8 8 7.5 8 6a4 4 0 0 1 4-4z"></path>
                <path d="M9 18h6v3a1 1 0 0 1-1 1h-4a1 1 0 0 1-1-1v-3z"></path>
                <path d="M10 14h4v4h-4z"></path>
              </svg>
              TIER 2 LLM INVESTIGATION REPORT
            </span>
            <span style="font-size:0.7rem;font-family:var(--font-mono);color:#c7d2fe;">${inv.mitre_mapping}</span>
          </div>

          <p class="llm-summary">${inv.executive_summary}</p>
          <div class="llm-justification">
            <strong>Why ${inv.severity}:</strong> ${inv.severity_justification}
          </div>

          ${isFp ? `
            <div class="fp-auto-dismissed-banner">
              <div class="fp-banner-title">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
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
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                  <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                </svg>
                ACTIVE CONTAINMENT · IP ALREADY BLOCKED
              </div>
              <div class="already-blocked-desc">
                Source IP <code>${alert.source_ip}</code> is already blocked in active firewall perimeter rules ${activeBlockRule ? `(Rule: ${activeBlockRule.rule_id})` : ""}. Ingress traffic is automatically intercepted and dropped without requiring manual analyst action.
              </div>
            </div>
          ` : isActioned ? `
            <div class="action-taken-badge">
              ✓ MITIGATED: ${alert.admin_action} ${alert.actioned_at ? `(${new Date(alert.actioned_at).toLocaleTimeString()})` : ""}
            </div>
          ` : `
            <div class="action-buttons-group">
              <button type="button" class="act-btn act-btn-block" data-act-btn="true" data-alert-id="${alert.id}" data-action="BLOCK_IP" data-target="${(alert.source_ip || '').replace(/"/g, '&quot;')}" onclick="executeAction('${alert.id}', 'BLOCK_IP', '${alert.source_ip || ''}')">
                🚫 Block IP (${alert.source_ip || 'Source'})
              </button>
              <button type="button" class="act-btn act-btn-isolate" data-act-btn="true" data-alert-id="${alert.id}" data-action="ISOLATE_HOST" data-target="${(alert.target || '').replace(/"/g, '&quot;')}" onclick="executeAction('${alert.id}', 'ISOLATE_HOST', '${(alert.target || '').replace(/'/g, "\\'")}')">
                🏠 Isolate Host
              </button>
              <button type="button" class="act-btn act-btn-reset" data-act-btn="true" data-alert-id="${alert.id}" data-action="FORCE_PASSWORD_RESET" data-target="admin" onclick="executeAction('${alert.id}', 'FORCE_PASSWORD_RESET', 'admin')">
                🔑 Reset Password
              </button>
              <button type="button" class="act-btn act-btn-dismiss" data-act-btn="true" data-alert-id="${alert.id}" data-action="DISMISS" data-target="" onclick="executeAction('${alert.id}', 'DISMISS', '')">
                Dismiss
              </button>
            </div>
          `}
        </div>
      ` : `
        <div style="font-size:0.78rem;font-family:var(--font-mono);color:#818cf8;">
          ⏳ Tier 2 LLM investigation reasoning in progress...
        </div>
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
      <td style="color:var(--accent-cyan);font-weight:700;">${rule.rule_id}</td>
      <td><span class="sev-badge sev-HIGH">${rule.type}</span></td>
      <td><strong>${rule.target}</strong></td>
      <td>
        ${rule.type === "BLOCK_IP" ? `
          <button class="btn btn-secondary btn-sm" onclick="unblockIp('${rule.target}')">Unblock</button>
        ` : `<span style="color:var(--accent-emerald);">Active</span>`}
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
    <span style="color:#64748b;">${new Date(event.timestamp).toLocaleTimeString()}</span>
    <span class="${colorClass}">[${event.event_type}]</span>
    <span>${event.source_ip}:${event.source_port} -> ${event.dest_ip}:${event.dest_port}</span>
    <span style="color:#cbd5e1;">| ${event.user} | ${event.status} | ${event.details}</span>
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
      elements.selectedFileName.textContent = `✓ Selected File: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
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
      elements.selectedFileName.textContent = `✓ Selected File: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
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
