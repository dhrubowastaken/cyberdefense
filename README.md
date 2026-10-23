# 🛡️ CyberDefense // Agentic SOAR-Lite

> **Autonomous Threat Investigation & Human-in-the-Loop Incident Response**  
> *Combining high-speed rule detection (Tier 1) with an LLM-powered SOC Analyst (Tier 2) to reduce incident triage time from 30 minutes to 2 minutes.*

---

## ⚡ The Novelty: Why We're Not Just "Another Splunk"

### Legacy SIEMs / SOARs (Splunk, QRadar, Sentinel)
```text
Logs → Rules Fire → Raw Alert Dumped on Screen → Human Analyst spends 20–30 min manually reading logs, correlating IPs, and deciding severity
```

### CyberDefense (Our System)
```text
Logs → Tier 1 Rules (<1ms) → Tier 2 LLM Agent Correlates & Investigates → Structured Report (Severity Justification + Recommended Actions) → Admin approves in 2 min
```

| Capability | Splunk / Traditional SIEM | CyberDefense (Us) |
|---|---|---|
| **Threat Detection** | ✅ Rule & threshold matching | ✅ Rule & threshold matching (<1ms) |
| **Output** | Raw alert log line | Natural language investigation report |
| **Contextual Investigation** | ❌ Manual analyst investigation | ✅ **LLM investigates context autonomously** |
| **Cross-Alert Correlation** | ❌ Manual mental correlation | ✅ **"Port scan + brute force from same IP = kill chain"** |
| **Severity Justification** | ❌ Static rule severity | ✅ **Contextual reasoning ("Why this is Critical")** |
| **Containment Action** | Complex manual playbooks | ✅ **1-Click Human-in-the-Loop containment** |
| **Triage Time** | ~20–30 minutes per alert | **~2 minutes per alert** |

---

## 🏗️ System Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        DATA & TELEMETRY INGESTION                      │
│   • Custom .log / .txt / .csv File Uploads     • Synthetic Attack Gen  │
│   • Benchmark Datasets (CICIDS-2017)           • Asynchronous Streamer │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ LogEvent Stream
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  ⚡ TIER 1: RULE DETECTION ENGINE (<1ms)               │
│   • BruteForceDetector (T1110)       • PortScanDetector (T1046)        │
│   • PrivilegeEscalation (T1068)      • DataExfiltration (T1041)        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Flagged Alerts + Evidence
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 🧠 TIER 2: LLM INVESTIGATION AGENT ⭐                 │
│   • Cross-Alert Correlator (Links multi-stage attacks from same IP)    │
│   • Senior SOC Analyst Prompting Engine                                │
│   • Pluggable Backends: Google Gemini 2.0 Flash / Ollama / Local Mock  │
│   • Produces: Executive Summary, Impact Analysis, Prioritized Actions  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ WebSocket Broadcast
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│               👤 TIER 3: HUMAN-IN-THE-LOOP RESPONSE DASHBOARD          │
│   • Dark SOC Aesthetics with Real-Time Telemetry Stream & DEFCON Bar   │
│   • Investigation Report Cards with MITRE ATT&CK Mapping               │
│   • 1-Click Action Buttons: [Block IP] [Isolate Host] [Reset Password] │
│   • Active Firewall Perimeter & Append-Only Audit Trail (data/audit)   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Exact Runtime Code Flow (Step-by-Step)

Here is exactly what happens in the code when you start the system:

```text
1. Terminal Execution
   └─> `uv run python -m cyberdefense` (or `uv run cyberdefense`)
       └─> Calls `cyberdefense.__main__.py:main()`
           └─> Loads typed settings from `config.yaml` + `.env` via `config.py`
           └─> Boots `uvicorn` on `127.0.0.1:8000` hosting `api.server:app`

2. Server Initialization (FastAPI Lifespan)
   └─> `api.server:lifespan` runs
       └─> Calls `app_core.initialize()` in `main.py`
           └─> Wires internal `EventBus`:
               • "alert_generated"   ──> triggers LLM investigation
               • "log_event"         ──> broadcasts to WebSockets
               • "alert_investigated"──> pushes rich cards to UI
               • "action_executed"   ──> updates Active Containment

3. Dashboard Connection
   └─> User opens `http://127.0.0.1:8000` in browser
       └─> `dashboard/app.js` connects to WebSocket at `/ws`
       └─> Subscribes to live log events and alert notifications

4. Simulation Launch (Custom File or Preset)
   └─> User clicks "Launch Temporary Simulation"
   └─> Option A: User clicks "📁 Select File" (.log or .txt file)
       └─> Browser posts file to `/api/simulation/upload`
   └─> Option B: User selects a preset attack chain (e.g. `attack_chain_full.log`)
       └─> Browser posts to `/api/simulation/start`
   └─> `data/log_parser.py` parses lines into typed `LogEvent` objects
   └─> `data/log_monitor.py` streams events sequentially through `app_core`

5. Tier 1 Detection
   └─> `trigger_agent.py` receives each `LogEvent`
   └─> Dispatches across `BruteForceDetector`, `PortScanDetector`, `PrivilegeEscalationDetector`, `DataExfiltrationDetector`
   └─> Threshold crossed?
       └─> Creates `Alert` model with evidence events attached
       └─> Publishes "alert_generated" on `EventBus`

6. Tier 2 LLM Investigation
   └─> `investigation_agent.py` catches the alert
   └─> `correlator.py` checks past alerts:
       "Did 192.168.1.105 perform a port scan before brute forcing ssh?" -> YES
   └─> Formats contextual prompt in `prompts.py`
   └─> Calls `GeminiProvider` (or local `OllamaProvider` / `MockProvider`)
   └─> Parses JSON into `InvestigationReport`:
       • Executive Summary
       • Severity Justification ("Why CRITICAL")
       • Recommended Actions (Priority 1: Block IP, Priority 2: Force Password Reset)
   └─> Pushes "alert_investigated" through WebSocket to Dashboard

7. Tier 3 Human-in-the-Loop Mitigation
   └─> Admin reviews report on Dashboard and clicks [🚫 Block IP]
   └─> Sends `POST /api/alerts/{id}/action`
   └─> `action_executor.py` executes:
       • `firewall_sim.py`: Adds IP to active firewall rules
       • `audit_log.py`: Appends immutable entry to `data/audit.jsonl`
   └─> Dashboard table updates in real time
```

---

## 🚀 Quickstart Guide

### Prerequisites
- Python 3.11+
- [uv](https://github.com/astral-sh/uv) installed (`curl -LsSf https://astral.sh/uv/install.sh` or `winget install astral-sh.uv`)

### 1. Installation
Clone the repository and install all dependencies in seconds with `uv`:
```bash
git clone https://github.com/your-repo/cyberdefense.git
cd cyberdefense
uv sync
```

### 2. Interactive Setup CLI
Configure your LLM provider (Gemini, Ollama, or Offline Mock), API keys, and detection thresholds:
```bash
uv run python setup.py
```

### 3. Launch the SOC Platform
```bash
uv run python -m cyberdefense
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.

---

## 🧪 Testing & Verification

Run the comprehensive automated test suite (18 unit & integration tests):
```bash
uv run pytest -v
```

All subsystems are tested:
- `test_models.py`: Pydantic v2 data models and serialization
- `test_data_parser.py`: `.log`, `.txt`, and `.csv` parsing
- `test_detection.py`: All 4 Tier 1 detection modules
- `test_llm_investigation.py`: Prompt builder, JSON parser, correlator, and LLM agent
- `test_response_firewall.py`: Stateful firewall and action executor
- `test_api_and_simulation.py`: REST routes, WebSocket, and custom file upload endpoint

---

## 🎯 MITRE ATT&CK Matrix Mapping

| Attack Type | MITRE Technique | Tactic | Detection Rule | Automated Response |
|---|---|---|---|---|
| **Port Scan** | `T1046` | Discovery | ≥10 unique destination ports probed in 60s | Edge perimeter rate limit / block |
| **SSH Brute Force** | `T1110.001` | Credential Access | ≥5 failed logins in 300s (or failure followed by login) | Block IP + Password Reset |
| **Privilege Escalation** | `T1068` / `T1548` | Privilege Escalation | Sudo/su invocation to root from low-privilege account | Kill session + Host isolation |
| **Data Exfiltration** | `T1041` / `T1048` | Exfiltration | ≥100MB outbound egress to external destination in 600s | Sever egress connection + Quarantine host |

---

## 📁 Repository Structure

```text
cyberdefense/
├── pyproject.toml              # Dependencies & project metadata (uv)
├── config.yaml                 # Active configuration (thresholds, LLM, ports)
├── setup.py                    # Interactive terminal setup CLI
├── README.md                   # Project documentation
├── data/
│   ├── synthetic/              # Pre-generated sample attack scenarios (.log, .txt)
│   ├── uploads/                # Temporary uploaded simulation logs
│   └── audit.jsonl             # Append-only SOAR mitigation audit trail
├── dashboard/                  # Frontend Web UI (Vanilla HTML/CSS/JS)
│   ├── index.html              # Modern dark-mode SOC dashboard
│   ├── style.css               # Glassmorphism, telemetry terminals, neon accents
│   └── app.js                  # WebSocket client, file picker, HITL actions
├── src/cyberdefense/
│   ├── __main__.py             # CLI entrypoint (`python -m cyberdefense`)
│   ├── config.py               # Pydantic Settings & YAML loader
│   ├── main.py                 # Core system orchestrator
│   ├── models/                 # LogEvent, Alert, Action, InvestigationReport
│   ├── data/                   # LogParser, SyntheticGenerator, LogMonitor
│   ├── engine/                 # Tier 1 EventBus, TriggerAgent, Rule Modules
│   ├── llm/                    # Tier 2 InvestigationAgent, Correlator, Providers
│   ├── response/               # Tier 3 FirewallSim, ActionExecutor, AuditLogger
│   └── api/                    # FastAPI Server, REST Routes, WebSockets
└── tests/                      # Pytest automated test suite (18 tests)
```
