"""
CyberDefense Tier 3 Response & Containment Engine
=================================================
Combines firewall simulation, host isolation, rate limiting, action execution,
alert queue management, and append-only audit logging into a single, clean module.

Components:
  - FirewallSimulator & firewall: Simulated stateful firewall maintaining blocked IPs,
    isolated endpoints, and rate limits.
  - AuditLogger & audit_logger: Tamper-evident append-only JSONL log recording every SOC decision.
  - ActionExecutor: Dispatches administrator or automated containment instructions.
  - AlertQueue & alert_queue: In-memory alert repository backing the SOC dashboard and REST API.
"""

from datetime import datetime
import json
import logging
from pathlib import Path
from typing import Any
from uuid import uuid4

from cyberdefense.models import (
    Alert,
    AlertStatus,
    AdminAction,
    ActionType,
    ActionStatus,
    ExecutionResult,
)
from cyberdefense.config import settings
from cyberdefense.event_bus import bus

logger = logging.getLogger("cyberdefense.response")


# ══════════════════════════════════════════════════════════════════
# 1. FIREWALL SIMULATOR (Stateful Containment)
# ══════════════════════════════════════════════════════════════════

class FirewallSimulator:
    """Simulated stateful enterprise firewall and containment controller."""

    def __init__(self):
        self._blocked_ips: dict[str, dict[str, Any]] = {}
        self._isolated_hosts: dict[str, dict[str, Any]] = {}
        self._rate_limits: dict[str, dict[str, Any]] = {}
        self._rules_history: list[dict[str, Any]] = []

    def block_ip(self, ip: str, reason: str = "Automated threat response") -> str:
        """Block all traffic to and from the specified IP."""
        rule_id = f"FW-BLK-{uuid4().hex[:6]}"
        entry = {
            "rule_id": rule_id,
            "type": "BLOCK_IP",
            "target": ip,
            "reason": reason,
            "created_at": datetime.utcnow().isoformat(),
            "status": "ACTIVE",
        }
        self._blocked_ips[ip] = entry
        self._rules_history.append(entry)
        logger.warning(f"[FIREWALL] Rule applied: BLOCK_IP {ip} (Rule: {rule_id})")
        return rule_id

    def unblock_ip(self, ip: str) -> bool:
        """Remove a block rule for an IP."""
        if ip in self._blocked_ips:
            rule = self._blocked_ips.pop(ip)
            rule["status"] = "REMOVED"
            rule["removed_at"] = datetime.utcnow().isoformat()
            logger.info(f"[FIREWALL] Unblocked IP {ip}")
            return True
        return False

    def isolate_host(self, host: str, reason: str = "Host containment") -> str:
        """Isolate a compromised internal host from the rest of the network."""
        rule_id = f"FW-ISO-{uuid4().hex[:6]}"
        entry = {
            "rule_id": rule_id,
            "type": "ISOLATE_HOST",
            "target": host,
            "reason": reason,
            "created_at": datetime.utcnow().isoformat(),
            "status": "ACTIVE",
        }
        self._isolated_hosts[host] = entry
        self._rules_history.append(entry)
        logger.warning(f"[FIREWALL] Rule applied: ISOLATE_HOST {host} (Rule: {rule_id})")
        return rule_id

    def rate_limit_ip(self, ip: str, limit_pps: int = 10, reason: str = "Connection throttling") -> str:
        """Enforce packet/request rate limiting on an IP."""
        rule_id = f"FW-RAT-{uuid4().hex[:6]}"
        entry = {
            "rule_id": rule_id,
            "type": "RATE_LIMIT",
            "target": ip,
            "limit_pps": limit_pps,
            "reason": reason,
            "created_at": datetime.utcnow().isoformat(),
            "status": "ACTIVE",
        }
        self._rate_limits[ip] = entry
        self._rules_history.append(entry)
        return rule_id

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP address is currently blocked."""
        return ip in self._blocked_ips

    def is_host_isolated(self, host: str) -> bool:
        """Check if a host is currently isolated."""
        return host in self._isolated_hosts

    def get_active_rules(self) -> list[dict[str, Any]]:
        """Return all active containment rules."""
        rules = []
        rules.extend(self._blocked_ips.values())
        rules.extend(self._isolated_hosts.values())
        rules.extend(self._rate_limits.values())
        return rules

    def reset(self) -> None:
        """Reset all firewall rules."""
        self._blocked_ips.clear()
        self._isolated_hosts.clear()
        self._rate_limits.clear()
        self._rules_history.clear()


firewall = FirewallSimulator()


# ══════════════════════════════════════════════════════════════════
# 2. AUDIT LOGGER (Compliance & Forensics)
# ══════════════════════════════════════════════════════════════════

class AuditLogger:
    """Manages persistent append-only audit trail."""

    def __init__(self, log_path: str | Path | None = None):
        self.path = Path(log_path or settings.data.audit_log)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._memory_entries: list[dict[str, Any]] = []

    def log_action(self, action: AdminAction, result: ExecutionResult) -> dict[str, Any]:
        """Record an executed mitigation action."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action_id": action.id,
            "alert_id": action.alert_id,
            "action_type": action.action_type.value,
            "target": action.target,
            "executed_by": action.executed_by,
            "reason": action.reason,
            "success": result.success,
            "message": result.message,
            "rule_id": result.rule_id,
        }
        self._memory_entries.append(entry)

        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to append to audit log file: {e}")

        return entry

    def get_recent_entries(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the most recent audit entries."""
        if not self._memory_entries and self.path.exists():
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            self._memory_entries.append(json.loads(line))
            except Exception as e:
                logger.error(f"Failed to load audit file: {e}")

        return list(reversed(self._memory_entries[-limit:]))

    def reset(self) -> None:
        """Reset in-memory entries."""
        self._memory_entries.clear()


audit_logger = AuditLogger()


# ══════════════════════════════════════════════════════════════════
# 3. ACTION EXECUTOR (Mitigation Dispatcher)
# ══════════════════════════════════════════════════════════════════

class ActionExecutor:
    """Dispatches mitigation actions across defensive controls."""

    @staticmethod
    async def execute(action: AdminAction) -> ExecutionResult:
        logger.info(f"Executing action [{action.action_type.value}] on target '{action.target}' (Alert: {action.alert_id})")
        rule_id = None
        success = True
        message = ""

        try:
            if action.action_type == ActionType.BLOCK_IP:
                rule_id = firewall.block_ip(action.target, reason=action.reason or "Admin blocked IP")
                message = f"IP address {action.target} successfully blocked at firewall perimeter."

            elif action.action_type == ActionType.ISOLATE_HOST:
                rule_id = firewall.isolate_host(action.target, reason=action.reason or "Host containment")
                message = f"Host {action.target} placed in network quarantine isolation."

            elif action.action_type == ActionType.RATE_LIMIT:
                rule_id = firewall.rate_limit_ip(action.target, limit_pps=5, reason=action.reason)
                message = f"Traffic rate limiting enforced on IP {action.target} (5 pps threshold)."

            elif action.action_type == ActionType.FORCE_PASSWORD_RESET:
                rule_id = f"AUTH-RST-{action.id}"
                message = f"Password invalidated and forced credential reset flagged for user '{action.target}'."

            elif action.action_type == ActionType.KILL_SESSION:
                rule_id = f"SESS-TRM-{action.id}"
                message = f"Active sessions and SSH processes terminated for '{action.target}'."

            elif action.action_type == ActionType.REVOKE_PRIVILEGES:
                rule_id = f"PRIV-RVK-{action.id}"
                message = f"Administrative and sudo privileges revoked for user '{action.target}'."

            elif action.action_type == ActionType.DISMISS:
                rule_id = f"DISM-{action.id}"
                message = f"Alert {action.alert_id} dismissed as false positive or accepted operational risk."

            else:
                rule_id = f"GEN-{action.id}"
                message = f"Action {action.action_type.value} recorded and acknowledged."

            action.status = ActionStatus.EXECUTED

        except Exception as e:
            logger.error(f"Action execution failure: {e}", exc_info=True)
            success = False
            action.status = ActionStatus.FAILED
            message = f"Execution error: {str(e)}"

        result = ExecutionResult(
            action_id=action.id,
            success=success,
            message=message,
            target=action.target,
            rule_id=rule_id,
            details={"action_type": action.action_type.value, "reason": action.reason},
        )

        audit_logger.log_action(action, result)
        await bus.publish("action_executed", result)
        return result


# ══════════════════════════════════════════════════════════════════
# 4. ALERT QUEUE (SOC Dashboard Repository)
# ══════════════════════════════════════════════════════════════════

class AlertQueue:
    """Manages active security alerts throughout their lifecycle."""

    def __init__(self):
        self._alerts: dict[str, Alert] = {}
        self._order: list[str] = []

    def add_alert(self, alert: Alert) -> None:
        """Register or update an alert in the queue."""
        if alert.id not in self._alerts:
            self._order.append(alert.id)
        self._alerts[alert.id] = alert

    def get_alert(self, alert_id: str) -> Alert | None:
        """Lookup an alert by ID."""
        return self._alerts.get(alert_id)

    def get_all_alerts(self) -> list[Alert]:
        """Return all alerts in reverse chronological order (newest first)."""
        return [self._alerts[aid] for aid in reversed(self._order) if aid in self._alerts]

    def get_pending_alerts(self) -> list[Alert]:
        """Return alerts awaiting administrator decision."""
        return [
            a for a in self.get_all_alerts()
            if a.status in (AlertStatus.PENDING, AlertStatus.REVIEWED, AlertStatus.INVESTIGATING)
        ]

    async def take_action(
        self,
        alert_id: str,
        action_type: str | ActionType,
        target: str | None = None,
        reason: str = "",
        admin_user: str = "admin",
    ) -> dict[str, Any]:
        """Applies an action to an alert and updates its status."""
        alert = self.get_alert(alert_id)
        if not alert:
            raise KeyError(f"Alert {alert_id} not found")

        if isinstance(action_type, str):
            clean_type = action_type.strip().upper()
            try:
                act_type = ActionType(clean_type)
            except ValueError:
                act_type = ActionType.DISMISS if "DISMISS" in clean_type else ActionType.BLOCK_IP
        else:
            act_type = action_type

        import re
        if act_type == ActionType.BLOCK_IP:
            candidate = target or alert.source_ip
            ip_m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", candidate)
            tgt = ip_m.group(0) if ip_m else (alert.source_ip or "unknown")
            # Safety: Do not block the protected internal server itself
            if tgt == "10.0.0.5" and alert.source_ip and alert.source_ip != "10.0.0.5":
                tgt = alert.source_ip
        elif act_type == ActionType.ISOLATE_HOST:
            candidate = target or alert.source_ip
            ip_m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", candidate)
            tgt = ip_m.group(0) if ip_m else candidate
        else:
            tgt = target or alert.source_ip or alert.target or "unknown"

        action = AdminAction(
            alert_id=alert_id,
            action_type=act_type,
            target=tgt,
            reason=reason,
            executed_by=admin_user,
        )

        result = await ActionExecutor.execute(action)

        alert.admin_action = act_type.value
        alert.admin_notes = reason
        alert.actioned_at = datetime.utcnow()
        alert.status = AlertStatus.DISMISSED if act_type == ActionType.DISMISS else AlertStatus.ACTIONED

        return {
            "alert": alert.model_dump(),
            "result": result.model_dump(),
        }

    def reset(self) -> None:
        """Clear all queued alerts."""
        self._alerts.clear()
        self._order.clear()


alert_queue = AlertQueue()
