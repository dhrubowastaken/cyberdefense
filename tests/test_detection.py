"""Unit tests for Tier 1 rule-based detection modules."""

import pytest
from datetime import datetime, timedelta
from cyberdefense.models import LogEvent, EventType, Protocol, AttackType, Severity
from cyberdefense.detection import (
    BruteForceDetector,
    PortScanDetector,
    PrivilegeEscalationDetector,
    DataExfiltrationDetector,
)


def test_brute_force_detection():
    detector = BruteForceDetector()
    detector.failed_threshold = 3
    now = datetime.utcnow()

    # 2 failures -> No alert yet
    alert = detector.process_event(LogEvent(timestamp=now, source_ip="192.168.1.100", dest_port=22, event_type=EventType.AUTH_LOGIN, status="FAILURE", user="admin"))
    assert alert is None
    alert = detector.process_event(LogEvent(timestamp=now + timedelta(seconds=1), source_ip="192.168.1.100", dest_port=22, event_type=EventType.AUTH_LOGIN, status="FAILURE", user="admin"))
    assert alert is None

    # 3rd failure -> Triggers Alert!
    alert = detector.process_event(LogEvent(timestamp=now + timedelta(seconds=2), source_ip="192.168.1.100", dest_port=22, event_type=EventType.AUTH_LOGIN, status="FAILURE", user="admin"))
    assert alert is not None
    assert alert.attack_type == AttackType.BRUTE_FORCE
    assert alert.severity == Severity.HIGH


def test_port_scan_detection():
    detector = PortScanDetector()
    detector.port_threshold = 5
    now = datetime.utcnow()

    # Probe 5 different ports
    alert = None
    for p in [21, 22, 23, 25, 80]:
        alert = detector.process_event(LogEvent(timestamp=now, source_ip="192.168.1.55", dest_port=p, event_type=EventType.CONNECTION, status="CLOSED"))

    assert alert is not None
    assert alert.attack_type == AttackType.PORT_SCAN


def test_privilege_escalation_detection():
    detector = PrivilegeEscalationDetector()
    now = datetime.utcnow()

    alert = detector.process_event(LogEvent(
        timestamp=now,
        source_ip="192.168.1.55",
        dest_port=0,
        event_type=EventType.PRIV_CHANGE,
        user="www-data",
        status="SUCCESS",
        details="Elevated privileges to root via /bin/sudo",
    ))
    assert alert is not None
    assert alert.attack_type == AttackType.PRIVILEGE_ESCALATION
    assert alert.severity == Severity.CRITICAL


def test_data_exfiltration_detection():
    detector = DataExfiltrationDetector()
    detector.byte_threshold = 50_000_000
    now = datetime.utcnow()

    alert = detector.process_event(LogEvent(
        timestamp=now,
        source_ip="10.0.0.5",
        dest_ip="203.0.113.88",
        dest_port=443,
        event_type=EventType.DATA_TRANSFER,
        status="SUCCESS",
        bytes_transferred=60_000_000,
        details="Bulk database dump egress",
    ))
    assert alert is not None
    assert alert.attack_type == AttackType.DATA_EXFILTRATION
