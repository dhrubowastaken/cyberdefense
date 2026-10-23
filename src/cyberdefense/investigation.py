"""
CyberDefense Tier 2 Threat Investigation Engine
===============================================
Combines the LLM reasoning pipeline, prompt construction, dynamic model resolution,
multi-provider connectors (Mock, Gemini, Ollama), cross-alert correlator, and the
InvestigationAgent into a single, clean, easily understandable module.

Key Capabilities:
  - Automated False Positive Discrimination: Discerns benign internal activity
    (scheduled database backups, human typos, vulnerability scanners, sysadmin updates)
    from true malicious cyber attacks.
  - Multi-Provider Support: Offline deterministic MockProvider, Google Gemini API,
    and local Ollama integration.
  - Cross-Alert Correlation: Links reconnaissance, credential access, privilege escalation,
    and exfiltration into unified attack narratives.
  - Human-in-the-Loop Decision Support: Generates actionable containment recommendations
    ready for one-click admin execution.
"""

from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timedelta
import json
import logging
import os
from pathlib import Path
import re
from typing import Any

from cyberdefense.models import (
    Alert,
    AlertStatus,
    Severity,
    ActionType,
    LogEvent,
    InvestigationReport,
    RecommendedAction,
)
from cyberdefense.config import settings
from cyberdefense.event_bus import bus

logger = logging.getLogger("cyberdefense.investigation")


# ══════════════════════════════════════════════════════════════════
# 1. PROMPT ENGINEERING & PARSING
# ══════════════════════════════════════════════════════════════════

INVESTIGATION_SYSTEM_PROMPT = """
You are a Senior Security Operations Center (SOC) Analyst with 10 years of experience in threat triage, digital forensics, and incident response. You specialize in the MITRE ATT&CK framework.

Your job is to INVESTIGATE security alerts triggered by Tier 1 rule engines, DISCRIMINATE TRUE ATTACKS FROM FALSE POSITIVES, and synthesize a concise, structured investigation report.

CRITICAL RESPONSIBILITY - FALSE POSITIVE DISCRIMINATION:
Rule engines are naive threshold counters and trigger many FALSE POSITIVES. You must determine if an alert is a REAL THREAT or a BENIGN / AUTHORIZED EVENT:
- FALSE POSITIVES include:
  * Internal scheduled backups (e.g. high-volume transfers to internal NAS/storage servers like 10.0.0.200 or user 'backup-svc').
  * Legitimate employee password typos (e.g. internal user 'sarah' on 10.0.0.45 failing 5-6 times due to caps lock, then succeeding from her assigned workstation).
  * Authorized internal vulnerability scanners (e.g. Nessus/Qualys scanner on 10.0.0.10 probing ports).
  * System administrator routine maintenance (e.g. sysadmin 'john' running 'sudo apt update' or standard package upgrades).
- TRUE THREATS include:
  * External untrusted IPs (e.g. foreign IPs, 192.168.1.105, 198.51.100.x) scanning ports, brute forcing credentials, or exfiltrating data to external C2 IPs (e.g. 203.0.113.88).
  * Privilege escalation attempts spawning unauthorized root shells (/bin/bash, SUID abuse) or web server (www-data) hijacking.

When you evaluate an alert:
1. DETERMINE VERDICT: Is this a "CONFIRMED_THREAT" or a "FALSE_POSITIVE"?
2. ASSESS SEVERITY: If FALSE_POSITIVE, severity MUST be "LOW". If CONFIRMED_THREAT, assess true severity ("HIGH" or "CRITICAL").
3. RECOMMEND ACTIONS:
   - For FALSE_POSITIVE: The primary action MUST be "DISMISS" with clear explanation why it is safe.
   - For CONFIRMED_THREAT: Recommend prioritized containment ("BLOCK_IP", "ISOLATE_HOST", "KILL_SESSION", "FORCE_PASSWORD_RESET").

You MUST respond strictly in valid JSON format matching this schema:
{
    "verdict": "CONFIRMED_THREAT|FALSE_POSITIVE",
    "is_false_positive": true|false,
    "title": "Short descriptive incident headline (e.g. 'False Positive: Routine Database Backup' or 'Critical: Active Root Breach')",
    "executive_summary": "1-3 sentences explaining what happened, whether it is malicious or benign, and the current status.",
    "severity": "LOW|MEDIUM|HIGH|CRITICAL",
    "severity_justification": "Why this specific severity is warranted, referencing internal/external IP context and user behavior.",
    "mitre_mapping": "MITRE ATT&CK technique IDs (or 'N/A - Benign Operational Activity' if false positive)",
    "attack_narrative": "Chronological walkthrough of the events.",
    "recommended_actions": [
        {
            "action": "BLOCK_IP|FORCE_PASSWORD_RESET|ISOLATE_HOST|KILL_SESSION|RATE_LIMIT|REVOKE_PRIVILEGES|QUARANTINE_DATA|DISMISS",
            "priority": 1,
            "reason": "Clear justification for why this action is recommended."
        }
    ],
    "correlated_alert_ids": ["string ids if applicable"]
}
Do NOT wrap your JSON in conversational markdown intro/outro. Output ONLY the JSON object.
"""


def build_investigation_prompt(
    alert: Alert,
    related_events: list[LogEvent] | None = None,
    other_alerts: list[Alert] | None = None,
) -> str:
    """Format a comprehensive contextual prompt for the LLM analyst."""
    evidence_lines = []
    for idx, e in enumerate(alert.evidence_events[:15], 1):
        evidence_lines.append(
            f"  {idx}. [{e.timestamp.strftime('%H:%M:%S')}] {e.event_type.value} | "
            f"{e.source_ip}:{e.source_port} -> {e.dest_ip}:{e.dest_port} | "
            f"user='{e.user}' status='{e.status}' | {e.details}"
        )

    related_lines = []
    if related_events:
        for idx, e in enumerate(related_events[:10], 1):
            related_lines.append(
                f"  - [{e.timestamp.strftime('%H:%M:%S')}] {e.event_type.value} "
                f"from {e.source_ip} to port {e.dest_port}: {e.details}"
            )

    other_alert_lines = []
    if other_alerts:
        for a in other_alerts:
            if a.id != alert.id:
                other_alert_lines.append(
                    f"  - Alert {a.id} [{a.attack_type.value}]: {a.rule_summary} (Severity: {a.severity.value})"
                )

    prompt = f"""
INVESTIGATE SECURITY ALERT:
----------------------------
Alert ID: {alert.id}
Timestamp: {alert.timestamp.isoformat()}Z
Detected Attack Type: {alert.attack_type.value} (MITRE ID: {alert.mitre_id})
Primary Source IP: {alert.source_ip}
Target: {alert.target}
Rule Engine Flag: {alert.rule_summary}
Rule Engine Metadata: {json.dumps(alert.rule_metadata)}

FLAGGED EVIDENCE EVENTS ({len(alert.evidence_events)} events):
{chr(10).join(evidence_lines) if evidence_lines else "  No raw events attached."}

SURROUNDING EVENTS FROM SAME SOURCE/NETWORK:
{chr(10).join(related_lines) if related_lines else "  None recorded."}

OTHER RECENT ACTIVE ALERTS:
{chr(10).join(other_alert_lines) if other_alert_lines else "  None active."}

Analyze this activity, correlate the evidence, and produce the structured JSON investigation report.
"""
    return prompt.strip()


def parse_llm_json_response(raw_text: str) -> dict[str, Any]:
    """Robustly parse JSON response from LLM, stripping markdown fences if present."""
    text = raw_text.strip()

    if "```" in text:
        match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
        if match:
            text = match.group(1).strip()

    try:
        return json.loads(text)
    except Exception:
        match = re.search(r"(\{.*\})", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except Exception:
                pass

        return {
            "title": "Automated Threat Investigation",
            "executive_summary": raw_text[:300],
            "severity": "MEDIUM",
            "severity_justification": "Analysis extracted from raw analyst output.",
            "mitre_mapping": "Generic Tactic",
            "recommended_actions": [
                {"action": "BLOCK_IP", "priority": 1, "reason": "Precautionary mitigation."}
            ],
            "correlated_alert_ids": [],
        }


# ══════════════════════════════════════════════════════════════════
# 2. GEMINI MODEL RESOLUTION & DYNAMIC CACHING
# ══════════════════════════════════════════════════════════════════

CACHE_FILE = Path("data/.gemini_models_cache.json")
CACHE_TTL = timedelta(hours=12)

DEFAULT_FALLBACK_MODELS = [
    "gemini-3.5-flash-lite",
    "gemini-3-flash-preview",
    "gemini-3.8-flash",
    "gemini-flash-latest",
]


def fetch_available_gemini_models(api_key: str, force_refresh: bool = False) -> list[str]:
    """Query Google Gemini API for available non-retired models, caching results locally."""
    if not api_key or len(api_key.strip()) < 10:
        return DEFAULT_FALLBACK_MODELS

    if not force_refresh and CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                cached = json.load(f)
                cached_time = datetime.fromisoformat(cached.get("timestamp", "2000-01-01"))
                if datetime.utcnow() - cached_time < CACHE_TTL:
                    models = cached.get("models", [])
                    if models:
                        return models
        except Exception:
            pass

    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        all_models = client.models.list()

        discovered: list[str] = []
        for m in all_models:
            name = m.name.replace("models/", "")
            name_lower = name.lower()
            is_retired = any(ret in name_lower for ret in ("2.0", "2.5", "1.5", "1.0"))
            is_non_chat = any(skip in name_lower for skip in ("image", "tts", "embedding", "audio", "customtools"))
            if not is_retired and not is_non_chat and "gemini" in name_lower:
                discovered.append(name)

        if discovered:
            discovered.sort(key=lambda x: ("preview" in x, "flash" in x), reverse=True)
            try:
                CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
                with open(CACHE_FILE, "w", encoding="utf-8") as f:
                    json.dump({"timestamp": datetime.utcnow().isoformat(), "models": discovered}, f, indent=2)
            except Exception:
                pass
            return discovered
    except Exception as e:
        logger.debug(f"Failed to fetch models from Gemini API: {e}")

    return DEFAULT_FALLBACK_MODELS


def resolve_active_model(configured_model: str, api_key: str) -> str:
    """Resolve the best active Gemini model, auto-migrating if the configured model is retired."""
    name_lower = configured_model.lower()
    is_deprecated = any(dep in name_lower for dep in ("2.0", "2.5", "1.5", "1.0"))

    if not is_deprecated:
        return configured_model

    available = fetch_available_gemini_models(api_key)
    for model in available:
        if "flash" in model.lower() and "lite" in model.lower():
            return model
    for model in available:
        if "flash" in model.lower():
            return model

    return available[0] if available else "gemini-3.5-flash-lite"


# ══════════════════════════════════════════════════════════════════
# 3. LLM PROVIDERS (Mock, Gemini, Ollama)
# ══════════════════════════════════════════════════════════════════

class LLMProvider(ABC):
    """Abstract interface for threat investigation LLM providers."""

    @abstractmethod
    async def generate_investigation(self, prompt: str, system_prompt: str) -> str:
        """Analyze prompt and return raw string (JSON) investigation report."""
        pass


class MockProvider(LLMProvider):
    """Offline SOC Analyst simulation returning rich structured JSON reports with false-positive auto-triage."""

    def __init__(self):
        self.model_name = "mock-analyst-v2"

    async def generate_investigation(self, prompt: str, system_prompt: str) -> str:
        primary_section = prompt.split("OTHER RECENT ACTIVE ALERTS:")[0]
        prompt_lower = primary_section.lower()

        # False Positive 1: Scheduled Database Backup
        if "backup" in prompt_lower or "10.0.0.200" in prompt_lower:
            report = {
                "verdict": "FALSE_POSITIVE",
                "is_false_positive": True,
                "title": "False Positive: Scheduled Database Backup Synchronization",
                "executive_summary": "High outbound data volume detected originating from database host 10.0.0.5 destined for internal storage server 10.0.0.200 under service account 'backup-svc'. Verified as legitimate routine backup job.",
                "severity": "LOW",
                "severity_justification": "LOW: Traffic is contained completely within the internal trusted management subnet. Destination IP and user identity match authorized infrastructure backup policies.",
                "mitre_mapping": "N/A - Legitimate Enterprise Operational Activity",
                "attack_narrative": "Scheduled enterprise backup cron job executed at expected window.",
                "recommended_actions": [
                    {"action": "DISMISS", "priority": 1, "reason": "Authorized routine business operation. No security threat or data leakage detected."}
                ],
                "correlated_alert_ids": []
            }
            return json.dumps(report)

        # False Positive 2: Employee Password Typo / Caps-Lock
        if "sarah" in prompt_lower or "10.0.0.45" in prompt_lower:
            report = {
                "verdict": "FALSE_POSITIVE",
                "is_false_positive": True,
                "title": "False Positive: Legitimate Employee Authentication Typo",
                "executive_summary": "Authentication failure threshold crossed on internal workstation 10.0.0.45 for user 'sarah', followed immediately by successful authentication. Telemetry indicates human typing error (caps-lock/keypad typo) rather than automated credential access.",
                "severity": "LOW",
                "severity_justification": "LOW: Request originates from assigned employee workstation on corporate LAN during business hours. Single user targeted and immediate successful login without further anomaly.",
                "mitre_mapping": "N/A - Human User Error",
                "attack_narrative": "Internal employee mistyped credentials repeatedly before entering correct passphrase.",
                "recommended_actions": [
                    {"action": "DISMISS", "priority": 1, "reason": "Legitimate employee login typo from assigned workstation. Safe to dismiss."}
                ],
                "correlated_alert_ids": []
            }
            return json.dumps(report)

        # False Positive 3: Authorized Security Vulnerability Scanner
        if "nessus" in prompt_lower or "10.0.0.10" in prompt_lower:
            report = {
                "verdict": "FALSE_POSITIVE",
                "is_false_positive": True,
                "title": "False Positive: Authorized Internal Vulnerability Scan",
                "executive_summary": "Port scan threshold triggered by IP 10.0.0.10. IP belongs to internal authorized vulnerability scanner (Nessus/Qualys). No exploit attempts followed.",
                "severity": "LOW",
                "severity_justification": "LOW: Source IP is on enterprise approved scanner asset inventory list. Routine automated compliance assessment.",
                "mitre_mapping": "N/A - Authorized Security Audit",
                "attack_narrative": "Periodic vulnerability scan initiated by IT security compliance tool.",
                "recommended_actions": [
                    {"action": "DISMISS", "priority": 1, "reason": "Approved internal vulnerability scan. Auto-dismiss to prevent alert fatigue."}
                ],
                "correlated_alert_ids": []
            }
            return json.dumps(report)

        # False Positive 4: Sysadmin Routine Maintenance
        if "apt update" in prompt_lower or "apt-get" in prompt_lower or ("john" in prompt_lower and "10.0.0.50" in prompt_lower):
            report = {
                "verdict": "FALSE_POSITIVE",
                "is_false_positive": True,
                "title": "False Positive: Authorized System Administrator Maintenance",
                "executive_summary": "Privilege escalation flag triggered by authorized sysadmin 'john' on 10.0.0.50 executing standard package maintenance (apt-get update).",
                "severity": "LOW",
                "severity_justification": "LOW: Command executed matches expected maintenance playbooks by verified sysadmin on internal management terminal.",
                "mitre_mapping": "N/A - Legitimate System Administration",
                "attack_narrative": "Standard maintenance command invoked via authorized sudo profile.",
                "recommended_actions": [
                    {"action": "DISMISS", "priority": 1, "reason": "Authorized sysadmin software update. No suspicious activity found."}
                ],
                "correlated_alert_ids": []
            }
            return json.dumps(report)

        # True Threat: Brute Force & Credential Access
        if "brute_force" in prompt_lower or "login" in prompt_lower or "password" in prompt_lower:
            if "compromise" in prompt_lower or "success" in prompt_lower:
                report = {
                    "verdict": "CONFIRMED_THREAT",
                    "is_false_positive": False,
                    "title": "Coordinated SSH Credential Breach & Host Compromise",
                    "executive_summary": "Attacker successfully penetrated SSH authentication following automated password spraying from untrusted IP. A successful login occurred after multiple failed attempts, granting immediate access to high-privilege account assets.",
                    "severity": "CRITICAL",
                    "severity_justification": "CRITICAL: The attack succeeded. Access to the system has been established, presenting imminent risk of lateral movement and data tampering.",
                    "mitre_mapping": "T1110.001 (Password Guessing) -> T1078 (Valid Accounts). Successful transition to Initial Access.",
                    "attack_narrative": "1. Attacker initiated rapid succession authentication attempts.\n2. Target credentials discovered.\n3. Interactive SSH session opened with valid credentials.",
                    "recommended_actions": [
                        {"action": "BLOCK_IP", "priority": 1, "reason": "Immediately terminate active attack session and prevent secondary ingress."},
                        {"action": "FORCE_PASSWORD_RESET", "priority": 2, "reason": "Compromised credentials must be revoked immediately across all domain resources."},
                        {"action": "ISOLATE_HOST", "priority": 3, "reason": "Isolate the targeted host to contain the attacker and prevent lateral reconnaissance."}
                    ],
                    "correlated_alert_ids": []
                }
            else:
                report = {
                    "verdict": "CONFIRMED_THREAT",
                    "is_false_positive": False,
                    "title": "Targeted Authentication Brute Force Activity",
                    "executive_summary": "High-velocity authentication failures recorded against target services from external source. Pattern is consistent with dictionary attacks or automated password spraying.",
                    "severity": "HIGH",
                    "severity_justification": "HIGH: Deliberate external credential access attempts exceeding normal operational baseline thresholds.",
                    "mitre_mapping": "T1110.001 (Brute Force: Password Guessing). Early Credential Access phase.",
                    "attack_narrative": "Repeated unauthorized authentication probes originating from foreign IP address.",
                    "recommended_actions": [
                        {"action": "BLOCK_IP", "priority": 1, "reason": "Block source IP at edge perimeter to neutralize credential cracking."},
                        {"action": "RATE_LIMIT", "priority": 2, "reason": "Enforce dynamic authentication throttling on external endpoints."}
                    ],
                    "correlated_alert_ids": []
                }

        elif "port_scan" in prompt_lower or "probe" in prompt_lower:
            report = {
                "verdict": "CONFIRMED_THREAT",
                "is_false_positive": False,
                "title": "Network Service Discovery and Port Reconnaissance",
                "executive_summary": "Host was subjected to a systematic multi-port TCP probe from external untrusted source. Source is mapping open network services to identify potential vulnerabilities for exploitation.",
                "severity": "MEDIUM",
                "severity_justification": "MEDIUM: Reconnaissance phase activity. While no compromise has occurred yet, this precedes active exploitation.",
                "mitre_mapping": "T1046 (Network Service Discovery). Reconnaissance and Discovery tactic.",
                "attack_narrative": "Systematic TCP SYN/CONNECT scanning across critical infrastructure ports (SSH, HTTP, Database).",
                "recommended_actions": [
                    {"action": "BLOCK_IP", "priority": 1, "reason": "Proactively drop packets from reconnaissance source before exploitation occurs."},
                    {"action": "RATE_LIMIT", "priority": 2, "reason": "Apply rate-limiting firewall filters to connection attempts."}
                ],
                "correlated_alert_ids": []
            }

        elif "privilege" in prompt_lower or "sudo" in prompt_lower:
            report = {
                "verdict": "CONFIRMED_THREAT",
                "is_false_positive": False,
                "title": "Unauthorized Privilege Escalation to Root",
                "executive_summary": "Anomalous elevation of privileges detected. User executed unauthorized sudo commands or spawned privileged shells, attempting to achieve full administrative control.",
                "severity": "CRITICAL",
                "severity_justification": "CRITICAL: Unauthorized elevation to superuser privileges grants complete control over system binaries, configurations, and sensitive records.",
                "mitre_mapping": "T1068 (Exploitation for Privilege Escalation) -> T1548 (Abuse Elevation Control Mechanism). Privilege Escalation tactic.",
                "attack_narrative": "Attacker utilized hijacked shell context to execute privileged binary commands.",
                "recommended_actions": [
                    {"action": "KILL_SESSION", "priority": 1, "reason": "Immediately terminate interactive superuser process and revoke active sessions."},
                    {"action": "ISOLATE_HOST", "priority": 2, "reason": "Quarantine host to prevent deployment of rootkits or lateral spreading."},
                    {"action": "REVOKE_PRIVILEGES", "priority": 3, "reason": "Strip elevated privileges and audit local sudoers configuration."}
                ],
                "correlated_alert_ids": []
            }

        elif "exfil" in prompt_lower or "transfer" in prompt_lower:
            report = {
                "verdict": "CONFIRMED_THREAT",
                "is_false_positive": False,
                "title": "Mass Unauthorized Outbound Data Exfiltration",
                "executive_summary": "High-volume outbound data transfer detected flowing to an external, untrusted IP address. Traffic characteristics indicate automated bulk data exfiltration.",
                "severity": "CRITICAL",
                "severity_justification": "CRITICAL: Large volume data transfer exceeding enterprise safety thresholds directly jeopardizes intellectual property and confidential records.",
                "mitre_mapping": "T1041 (Exfiltration Over C2 Channel) / T1048 (Exfiltration Over Alternative Protocol). Exfiltration tactic.",
                "attack_narrative": "Mass bulk egress connection established after internal staging.",
                "recommended_actions": [
                    {"action": "BLOCK_IP", "priority": 1, "reason": "Instantly sever egress connection to the external C2 recipient."},
                    {"action": "ISOLATE_HOST", "priority": 2, "reason": "Cut network connectivity of the exfiltrating machine to stop ongoing transmission."}
                ],
                "correlated_alert_ids": []
            }

        else:
            report = {
                "verdict": "CONFIRMED_THREAT",
                "is_false_positive": False,
                "title": "Suspicious Security Anomaly Detected",
                "executive_summary": "Automated behavioral inspection detected telemetry deviating from expected operational baselines.",
                "severity": "MEDIUM",
                "severity_justification": "MEDIUM severity pending further contextual triage.",
                "mitre_mapping": "T1204 (User Execution) / Generic Discovery",
                "attack_narrative": "Unclassified abnormal activity logged by detection sensors.",
                "recommended_actions": [
                    {"action": "BLOCK_IP", "priority": 1, "reason": "Block source IP temporarily while investigating."}
                ],
                "correlated_alert_ids": []
            }

        return json.dumps(report)


class GeminiProvider(LLMProvider):
    """Integrates Google Gemini for automated SOC investigations with dynamic model resolution."""

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key or settings.llm.gemini.api_key or os.environ.get("GEMINI_API_KEY", "")
        configured_model = model or settings.llm.gemini.model or "gemini-3.5-flash-lite"
        self._fallback = MockProvider()
        self._client = None

        if self.api_key:
            try:
                from google import genai
                self._client = genai.Client(api_key=self.api_key)
                self.model_name = resolve_active_model(configured_model, self.api_key)
                logger.info(f"Initialized Gemini Client with active model '{self.model_name}'")
            except Exception as e:
                logger.warning(f"Failed to initialize google.genai Client: {e}. Will use fallback.")
                self.model_name = configured_model
        else:
            self.model_name = configured_model
            logger.info("No GEMINI_API_KEY configured. Running with intelligent local fallback.")

    async def generate_investigation(self, prompt: str, system_prompt: str) -> str:
        if not self._client:
            return await self._fallback.generate_investigation(prompt, system_prompt)

        from google.genai import types

        for attempt in range(2):
            try:
                response = self._client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=system_prompt,
                        temperature=settings.llm.gemini.temperature,
                        response_mime_type="application/json",
                    ),
                )
                return response.text
            except Exception as e:
                err_str = str(e)
                if ("404" in err_str or "NOT_FOUND" in err_str) and attempt == 0:
                    logger.warning(f"Model '{self.model_name}' returned 404/Retired. Fetching latest Gemini models...")
                    fresh_models = fetch_available_gemini_models(self.api_key, force_refresh=True)
                    if fresh_models:
                        for alt in fresh_models:
                            if alt != self.model_name and ("flash" in alt or "preview" in alt):
                                logger.info(f"Auto-switching Gemini model to '{alt}'...")
                                self.model_name = alt
                                break
                    continue

                logger.error(f"Gemini API call failed ({self.model_name}): {e}. Using intelligent fallback.")
                break

        return await self._fallback.generate_investigation(prompt, system_prompt)


class OllamaProvider(LLMProvider):
    """Integrates local Ollama models for 100% offline private threat investigation."""

    def __init__(self, model: str | None = None, base_url: str | None = None):
        self.model = model or settings.llm.ollama.model or "llama3"
        self.base_url = (base_url or settings.llm.ollama.base_url or "http://localhost:11434").rstrip("/")
        self.model_name = self.model
        self._fallback = MockProvider()

    async def generate_investigation(self, prompt: str, system_prompt: str) -> str:
        import httpx
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                res = await client.post(
                    f"{self.base_url}/api/chat",
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": prompt},
                        ],
                        "format": "json",
                        "stream": False,
                    },
                )
                if res.status_code == 200:
                    data = res.json()
                    return data.get("message", {}).get("content", "{}")
                else:
                    logger.warning(f"Ollama returned HTTP {res.status_code}. Using fallback.")
                    return await self._fallback.generate_investigation(prompt, system_prompt)
        except Exception as e:
            logger.info(f"Ollama unavailable at {self.base_url} ({e}). Using fallback.")
            return await self._fallback.generate_investigation(prompt, system_prompt)


def get_llm_provider(provider_name: str | None = None) -> LLMProvider:
    """Factory function returning the configured LLMProvider instance."""
    name = (provider_name or settings.llm.provider or "gemini").lower()
    if name == "gemini":
        return GeminiProvider()
    elif name == "ollama":
        return OllamaProvider()
    elif name in ("none", "mock"):
        return MockProvider()
    return GeminiProvider()


# ══════════════════════════════════════════════════════════════════
# 4. CROSS-ALERT CORRELATOR
# ══════════════════════════════════════════════════════════════════

class CrossAlertCorrelator:
    """Tracks active alerts and discovers correlation patterns across attack stages."""

    def __init__(self, correlation_window_seconds: int = 1800):
        self.window_seconds = correlation_window_seconds
        self._alerts: list[Alert] = []
        self._ip_alerts: dict[str, list[str]] = defaultdict(list)

    def register_alert(self, alert: Alert) -> list[str]:
        """Record an alert and return IDs of previously recorded correlated alerts."""
        cutoff = alert.timestamp - timedelta(seconds=self.window_seconds)
        self._alerts = [a for a in self._alerts if a.timestamp >= cutoff]

        correlated_ids: list[str] = []
        for prev in self._alerts:
            if prev.id == alert.id:
                continue
            if prev.source_ip == alert.source_ip and alert.source_ip:
                correlated_ids.append(prev.id)
            elif prev.target and alert.target and (prev.target in alert.target or alert.target in prev.target):
                if prev.id not in correlated_ids:
                    correlated_ids.append(prev.id)

        self._alerts.append(alert)
        self._ip_alerts[alert.source_ip].append(alert.id)
        return correlated_ids

    def get_recent_alerts(self, limit: int = 10) -> list[Alert]:
        """Return most recent alerts."""
        return self._alerts[-limit:]

    def reset(self) -> None:
        """Clear correlation state."""
        self._alerts.clear()
        self._ip_alerts.clear()


# ══════════════════════════════════════════════════════════════════
# 5. INVESTIGATION AGENT (Tier 2 Coordinator)
# ══════════════════════════════════════════════════════════════════

class InvestigationAgent:
    """
    Tier 2 Agentic SOC Analyst.
    Receives alerts from Tier 1, invokes LLM with full context, applies false-positive auto-triage,
    and publishes the resulting InvestigationReport to the SOC dashboard.
    """

    def __init__(self, provider: LLMProvider | None = None):
        self.provider = provider or get_llm_provider()
        self.correlator = CrossAlertCorrelator()
        self._investigations: list[InvestigationReport] = []

    async def investigate_alert(self, alert: Alert) -> InvestigationReport:
        """Perform comprehensive LLM investigation on a Tier 1 security alert."""
        logger.info(f"Starting Tier 2 LLM investigation for Alert {alert.id} ({alert.attack_type.value})")
        alert.status = AlertStatus.INVESTIGATING

        # 1. Correlate with historical / recent alerts
        correlated_ids = self.correlator.register_alert(alert)
        recent_alerts = self.correlator.get_recent_alerts(limit=5)

        # 2. Build structured prompt
        prompt = build_investigation_prompt(
            alert=alert,
            related_events=alert.evidence_events,
            other_alerts=recent_alerts,
        )

        # 3. Call LLM provider
        try:
            raw_response = await self.provider.generate_investigation(
                prompt=prompt,
                system_prompt=INVESTIGATION_SYSTEM_PROMPT,
            )
            parsed = parse_llm_json_response(raw_response)
        except Exception as e:
            logger.error(f"Error calling LLM provider: {e}", exc_info=True)
            parsed = {
                "title": f"Incident Investigation: {alert.attack_type.value}",
                "executive_summary": alert.rule_summary,
                "severity": alert.severity.value,
                "severity_justification": "Automated rule detection crossed security threshold.",
                "mitre_mapping": alert.mitre_id,
                "recommended_actions": [{"action": "BLOCK_IP", "priority": 1, "reason": "Precautionary mitigation."}],
                "correlated_alert_ids": correlated_ids,
            }

        # 4. Construct typed RecommendedAction list
        actions: list[RecommendedAction] = []
        raw_actions = parsed.get("recommended_actions", [])
        for act in raw_actions:
            act_type_str = act.get("action", "BLOCK_IP").upper()
            try:
                act_type = ActionType(act_type_str)
            except ValueError:
                act_type = ActionType.BLOCK_IP

            actions.append(
                RecommendedAction(
                    action=act_type,
                    priority=act.get("priority", 1),
                    reason=act.get("reason", "Recommended containment action."),
                    suggested_target=alert.source_ip,
                )
            )

        if not actions:
            actions.append(
                RecommendedAction(
                    action=ActionType.BLOCK_IP,
                    priority=1,
                    reason="Block offending source IP to neutralize threat.",
                    suggested_target=alert.source_ip,
                )
            )

        sev_str = parsed.get("severity", alert.severity.value).upper()
        try:
            severity = Severity(sev_str)
        except ValueError:
            severity = alert.severity

        merged_correlated = list(set(parsed.get("correlated_alert_ids", []) + correlated_ids))

        # Check false positive status
        is_fp = bool(parsed.get("is_false_positive", False) or parsed.get("verdict") == "FALSE_POSITIVE")
        verdict = "FALSE_POSITIVE" if is_fp else "CONFIRMED_THREAT"
        if is_fp:
            severity = Severity.LOW

        report = InvestigationReport(
            alert_id=alert.id,
            title=parsed.get("title", f"Investigation: {alert.attack_type.value}"),
            executive_summary=parsed.get("executive_summary", alert.rule_summary),
            severity=severity,
            severity_justification=parsed.get("severity_justification", "Contextual threat assessment."),
            mitre_mapping=parsed.get("mitre_mapping", alert.mitre_id),
            attack_narrative=parsed.get("attack_narrative", ""),
            correlated_alert_ids=merged_correlated,
            verdict=verdict,
            is_false_positive=is_fp,
            recommended_actions=actions,
            model_used=getattr(self.provider, "model_name", "llm-analyst"),
        )

        # 5. Attach report to alert and update status
        alert.investigation_report = report.model_dump()
        alert.severity = severity
        if is_fp:
            alert.status = AlertStatus.DISMISSED
            alert.admin_action = "AUTO_DISMISSED"
            alert.admin_notes = "Auto-triage: Tier 2 verified benign activity / false positive"
            logger.info(f"Tier 2 Auto-Triage: Alert {alert.id} classified as FALSE POSITIVE and auto-dismissed.")
        else:
            alert.status = AlertStatus.REVIEWED

        self._investigations.append(report)

        logger.info(
            f"Tier 2 Investigation complete for Alert {alert.id} -> '{report.title}' [{report.severity.value}] (Verdict: {verdict})"
        )

        # 6. Publish to EventBus for real-time WebSocket push
        await bus.publish("alert_investigated", alert)
        return report

    def reset(self) -> None:
        """Reset state."""
        self.correlator.reset()
        self._investigations.clear()
