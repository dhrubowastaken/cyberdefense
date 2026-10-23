"""Unit tests for Pydantic data models."""

from datetime import datetime
from cyberdefense.models import (
    LogEvent,
    EventType,
    Protocol,
    Alert,
    AttackType,
    Severity,
    ActionType,
    AdminAction,
    InvestigationReport,
    RecommendedAction,
)


def test_log_event_creation():
    event = LogEvent(
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.100",
        dest_ip="10.0.0.5",
        dest_port=22,
        protocol=Protocol.TCP,
        event_type=EventType.AUTH_LOGIN,
        user="admin",
        status="FAILURE",
        bytes_transferred=128,
        details="Authentication failed",
    )
    assert event.source_ip == "192.168.1.100"
    assert event.dest_port == 22
    assert event.status == "FAILURE"
    assert event.event_type == EventType.AUTH_LOGIN


def test_alert_creation():
    alert = Alert(
        attack_type=AttackType.BRUTE_FORCE,
        mitre_id="T1110",
        severity=Severity.HIGH,
        source_ip="192.168.1.105",
        target="admin",
        rule_summary="5 failed logins",
    )
    assert alert.attack_type == AttackType.BRUTE_FORCE
    assert alert.severity == Severity.HIGH
    assert alert.mitre_id == "T1110"


def test_investigation_report():
    report = InvestigationReport(
        alert_id="ALT-1234",
        title="Brute Force Compromise",
        executive_summary="Attacker brute forced admin",
        severity=Severity.CRITICAL,
        severity_justification="Access achieved",
        mitre_mapping="T1110.001",
        recommended_actions=[
            RecommendedAction(action=ActionType.BLOCK_IP, priority=1, reason="Stop attack")
        ],
    )
    assert report.severity == Severity.CRITICAL
    assert len(report.recommended_actions) == 1
    assert report.recommended_actions[0].action == ActionType.BLOCK_IP
