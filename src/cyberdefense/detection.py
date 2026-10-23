"""
CyberDefense Tier 1 Detection Engine
====================================
Combines all rule-based detectors and the TriggerAgent coordinator into a single,
clean, easy-to-read module.

Architecture:
  - BaseDetectionModule: Abstract sliding-window detector.
  - PortScanDetector: Reconnaissance detection (MITRE T1046).
  - BruteForceDetector: Credential attack & breach detection (MITRE T1110).
  - PrivilegeEscalationDetector: Sudo/root escalation detection (MITRE T1068).
  - DataExfiltrationDetector: Abnormal outbound volume detection (MITRE T1041).
  - TriggerAgent: Dispatches incoming LogEvents across all detectors and publishes alerts.
"""

from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timedelta
import logging
from typing import Any

from cyberdefense.models import (
    LogEvent,
    EventType,
    Alert,
    AttackType,
    Severity,
    MITRE_MAPPING,
)
from cyberdefense.config import settings
from cyberdefense.event_bus import bus

logger = logging.getLogger("cyberdefense.detection")


# ══════════════════════════════════════════════════════════════════
# 1. BASE DETECTION MODULE
# ══════════════════════════════════════════════════════════════════

class BaseDetectionModule(ABC):
    """Abstract base class for sliding-window rule-based detectors."""

    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled
        self._event_buffer: deque[LogEvent] = deque(maxlen=2000)

    @abstractmethod
    def process_event(self, event: LogEvent) -> Alert | None:
        """Evaluate an incoming LogEvent. Returns an Alert if threshold is crossed, else None."""
        pass

    def record_event(self, event: LogEvent) -> None:
        """Store event in sliding buffer."""
        self._event_buffer.append(event)

    def prune_buffer(self, max_age_seconds: int, reference_time: datetime | None = None) -> None:
        """Remove events older than max_age_seconds."""
        now = reference_time or datetime.utcnow()
        cutoff = now - timedelta(seconds=max_age_seconds)
        while self._event_buffer and self._event_buffer[0].timestamp < cutoff:
            self._event_buffer.popleft()

    def reset(self) -> None:
        """Clear detection state and buffer."""
        self._event_buffer.clear()


# ══════════════════════════════════════════════════════════════════
# 2. PORT SCAN DETECTOR (MITRE ATT&CK T1046)
# ══════════════════════════════════════════════════════════════════

class PortScanDetector(BaseDetectionModule):
    """
    Detects vertical port scans and network sweeps.
    Flags an alert when a single source IP probes >= unique_port_threshold ports within window_seconds.
    """

    def __init__(self):
        super().__init__(name="PortScanDetector", enabled=settings.detection.port_scan.enabled)
        self.window_seconds = settings.detection.port_scan.window_seconds
        self.port_threshold = settings.detection.port_scan.unique_port_threshold
        # IP -> list of connection LogEvents in the current window
        self._ip_connections: dict[str, list[LogEvent]] = defaultdict(list)
        self._alerted_ips: set[str] = set()

    def process_event(self, event: LogEvent) -> Alert | None:
        if not self.enabled:
            return None

        # Accept CONNECTION or NETWORK_FLOW with valid destination port
        if event.event_type not in (EventType.CONNECTION, EventType.NETWORK_FLOW) or event.dest_port <= 0:
            return None

        src_ip = event.source_ip
        self.record_event(event)

        # Prune events outside sliding time window
        cutoff = event.timestamp - timedelta(seconds=self.window_seconds)
        self._ip_connections[src_ip] = [
            e for e in self._ip_connections[src_ip] if e.timestamp >= cutoff
        ]
        self._ip_connections[src_ip].append(event)

        unique_ports = {e.dest_port for e in self._ip_connections[src_ip]}
        port_count = len(unique_ports)

        # Trigger if threshold crossed and not already alerted in this window
        if port_count >= self.port_threshold and src_ip not in self._alerted_ips:
            self._alerted_ips.add(src_ip)
            sorted_ports = sorted(list(unique_ports))
            port_sample = ", ".join(map(str, sorted_ports[:10])) + ("..." if len(sorted_ports) > 10 else "")

            return Alert(
                attack_type=AttackType.PORT_SCAN,
                mitre_id=MITRE_MAPPING[AttackType.PORT_SCAN]["id"],
                severity=Severity.MEDIUM,
                source_ip=src_ip,
                target=f"{event.dest_ip} (ports: {port_sample})",
                rule_summary=f"Port reconnaissance: {port_count} unique ports probed within {self.window_seconds}s from {src_ip}",
                evidence_events=list(self._ip_connections[src_ip]),
                rule_metadata={
                    "unique_ports_count": port_count,
                    "threshold": self.port_threshold,
                    "window_seconds": self.window_seconds,
                    "ports_probed": sorted_ports,
                },
            )

        return None

    def reset(self) -> None:
        super().reset()
        self._ip_connections.clear()
        self._alerted_ips.clear()


# ══════════════════════════════════════════════════════════════════
# 3. BRUTE FORCE DETECTOR (MITRE ATT&CK T1110)
# ══════════════════════════════════════════════════════════════════

class BruteForceDetector(BaseDetectionModule):
    """
    Detects credential guessing, brute force, and credential compromise.
    Triggers HIGH severity on repeated failed logins, and CRITICAL severity if a login
    succeeds immediately after repeated failures.
    """

    def __init__(self):
        super().__init__(name="BruteForceDetector", enabled=settings.detection.brute_force.enabled)
        self.window_seconds = settings.detection.brute_force.window_seconds
        self.failed_threshold = settings.detection.brute_force.failed_login_threshold
        # IP -> list of failed LogEvents
        self._ip_failed_logins: dict[str, list[LogEvent]] = defaultdict(list)
        self._alerted_ips: set[str] = set()

    def process_event(self, event: LogEvent) -> Alert | None:
        if not self.enabled:
            return None

        # Only evaluate authentication attempts
        if event.event_type != EventType.AUTH_LOGIN:
            return None

        src_ip = event.source_ip
        self.record_event(event)

        # Sliding time window cleanup
        cutoff = event.timestamp - timedelta(seconds=self.window_seconds)
        self._ip_failed_logins[src_ip] = [
            e for e in self._ip_failed_logins[src_ip] if e.timestamp >= cutoff
        ]

        if event.status == "FAILURE":
            self._ip_failed_logins[src_ip].append(event)
            failed_count = len(self._ip_failed_logins[src_ip])

            if failed_count >= self.failed_threshold and src_ip not in self._alerted_ips:
                self._alerted_ips.add(src_ip)
                return Alert(
                    attack_type=AttackType.BRUTE_FORCE,
                    mitre_id=MITRE_MAPPING[AttackType.BRUTE_FORCE]["id"],
                    severity=Severity.HIGH,
                    source_ip=src_ip,
                    target=event.user or event.dest_ip,
                    rule_summary=f"Detected {failed_count} failed authentication attempts within {self.window_seconds}s from {src_ip}",
                    evidence_events=list(self._ip_failed_logins[src_ip]),
                    rule_metadata={
                        "failed_count": failed_count,
                        "threshold": self.failed_threshold,
                        "targeted_user": event.user,
                        "window_seconds": self.window_seconds,
                    },
                )

        elif event.status == "SUCCESS":
            # Critical pattern: If this IP previously accumulated failures and has now succeeded
            failed_count = len(self._ip_failed_logins.get(src_ip, []))
            if failed_count >= 3:
                evidence = list(self._ip_failed_logins.get(src_ip, [])) + [event]
                return Alert(
                    attack_type=AttackType.BRUTE_FORCE,
                    mitre_id=MITRE_MAPPING[AttackType.BRUTE_FORCE]["id"],
                    severity=Severity.CRITICAL,
                    source_ip=src_ip,
                    target=event.user or event.dest_ip,
                    rule_summary=f"CRITICAL: Successful login for '{event.user}' following {failed_count} failed attempts from {src_ip}",
                    evidence_events=evidence,
                    rule_metadata={
                        "failed_count": failed_count,
                        "compromise_suspected": True,
                        "user": event.user,
                    },
                )

        return None

    def reset(self) -> None:
        super().reset()
        self._ip_failed_logins.clear()
        self._alerted_ips.clear()


# ══════════════════════════════════════════════════════════════════
# 4. PRIVILEGE ESCALATION DETECTOR (MITRE ATT&CK T1068)
# ══════════════════════════════════════════════════════════════════

class PrivilegeEscalationDetector(BaseDetectionModule):
    """
    Detects unauthorized role changes, sudo execution, and root elevation.
    Flags HIGH or CRITICAL severity when sensitive accounts or commands are invoked.
    """

    def __init__(self):
        super().__init__(name="PrivilegeEscalationDetector", enabled=settings.detection.privilege_escalation.enabled)
        self.high_priv_users = set(settings.detection.privilege_escalation.high_priv_users)
        self.service_accounts = set(settings.detection.privilege_escalation.service_accounts)

    def process_event(self, event: LogEvent) -> Alert | None:
        if not self.enabled:
            return None

        is_priv_event = event.event_type == EventType.PRIV_CHANGE
        details_lower = event.details.lower()
        has_priv_keyword = any(
            k in details_lower
            for k in ("sudo", "/bin/su", "elevation", "privilege", "root access", "setuid")
        )

        if not (is_priv_event or has_priv_keyword):
            return None

        self.record_event(event)

        user = event.user.lower()
        is_elevating_to_root = any(h.lower() in details_lower for h in self.high_priv_users)

        severity = Severity.HIGH
        if is_elevating_to_root or user in [s.lower() for s in self.service_accounts]:
            severity = Severity.CRITICAL

        return Alert(
            attack_type=AttackType.PRIVILEGE_ESCALATION,
            mitre_id=MITRE_MAPPING[AttackType.PRIVILEGE_ESCALATION]["id"],
            severity=severity,
            source_ip=event.source_ip,
            target=f"User: {event.user} on {event.dest_ip}",
            rule_summary=f"Privilege escalation attempt detected: '{event.user}' invoked elevated privileges",
            evidence_events=[event],
            rule_metadata={
                "user": event.user,
                "command_or_details": event.details,
                "is_elevating_to_root": is_elevating_to_root,
            },
        )


# ══════════════════════════════════════════════════════════════════
# 5. DATA EXFILTRATION DETECTOR (MITRE ATT&CK T1041)
# ══════════════════════════════════════════════════════════════════

class DataExfiltrationDetector(BaseDetectionModule):
    """
    Detects abnormal outbound transfer volume to external hosts.
    Aggregates bytes transferred outbound per (source_ip, dest_ip) pair over window_seconds.
    """

    def __init__(self):
        super().__init__(name="DataExfiltrationDetector", enabled=settings.detection.data_exfiltration.enabled)
        self.window_seconds = settings.detection.data_exfiltration.window_seconds
        self.byte_threshold = settings.detection.data_exfiltration.byte_threshold
        # (src_ip, dst_ip) -> list of transfer LogEvents
        self._transfers: dict[tuple[str, str], list[LogEvent]] = defaultdict(list)
        self._alerted_pairs: set[tuple[str, str]] = set()

    def process_event(self, event: LogEvent) -> Alert | None:
        if not self.enabled:
            return None

        is_transfer = event.event_type == EventType.DATA_TRANSFER or event.bytes_transferred > 5_000_000
        if not is_transfer or event.bytes_transferred <= 0:
            return None

        self.record_event(event)

        pair = (event.source_ip, event.dest_ip)
        cutoff = event.timestamp - timedelta(seconds=self.window_seconds)

        self._transfers[pair] = [e for e in self._transfers[pair] if e.timestamp >= cutoff]
        self._transfers[pair].append(event)

        total_bytes = sum(e.bytes_transferred for e in self._transfers[pair])

        if total_bytes >= self.byte_threshold and pair not in self._alerted_pairs:
            self._alerted_pairs.add(pair)
            mb = total_bytes / (1024 * 1024)

            return Alert(
                attack_type=AttackType.DATA_EXFILTRATION,
                mitre_id=MITRE_MAPPING[AttackType.DATA_EXFILTRATION]["id"],
                severity=Severity.HIGH if mb < 200 else Severity.CRITICAL,
                source_ip=event.source_ip,
                target=f"External destination {event.dest_ip}",
                rule_summary=f"Mass data exfiltration: {mb:.1f}MB transferred to {event.dest_ip} within {self.window_seconds}s",
                evidence_events=list(self._transfers[pair]),
                rule_metadata={
                    "bytes_transferred": total_bytes,
                    "megabytes": round(mb, 2),
                    "threshold_bytes": self.byte_threshold,
                    "destination_ip": event.dest_ip,
                },
            )

        return None

    def reset(self) -> None:
        super().reset()
        self._transfers.clear()
        self._alerted_pairs.clear()


# ══════════════════════════════════════════════════════════════════
# 6. TRIGGER AGENT (Tier 1 Coordinator)
# ══════════════════════════════════════════════════════════════════

class TriggerAgent:
    """
    Tier 1 Rule-based Detection Coordinator.
    Feeds each incoming LogEvent through all active detection modules and publishes
    any resulting alerts to the EventBus.
    """

    def __init__(self):
        self.modules: list[BaseDetectionModule] = [
            BruteForceDetector(),
            PortScanDetector(),
            PrivilegeEscalationDetector(),
            DataExfiltrationDetector(),
        ]
        self._alerts_generated: list[Alert] = []

    async def handle_log_event(self, event: LogEvent) -> list[Alert]:
        """
        Evaluate a single event across all detection modules.
        Returns any newly triggered alerts and broadcasts them via EventBus.
        """
        alerts: list[Alert] = []
        for module in self.modules:
            if not module.enabled:
                continue
            try:
                alert = module.process_event(event)
                if alert:
                    logger.warning(f"Tier 1 Alert [{alert.attack_type.value}] from {alert.source_ip}: {alert.rule_summary}")
                    alerts.append(alert)
                    self._alerts_generated.append(alert)
                    # Publish to EventBus for Tier 2 investigation and dashboard push
                    await bus.publish("alert_generated", alert)
            except Exception as e:
                logger.error(f"Error in {module.name}: {e}", exc_info=True)

        return alerts

    def reset(self) -> None:
        """Reset state across all detection modules."""
        for module in self.modules:
            module.reset()
        self._alerts_generated.clear()

    @property
    def alerts_history(self) -> list[Alert]:
        return list(self._alerts_generated)
