"""Unit tests verifying preprocessed real-world logs against Tier 1 detection."""

from pathlib import Path
from cyberdefense.data_stream import LogParser
from cyberdefense.detection import (
    PortScanDetector,
    BruteForceDetector,
    PrivilegeEscalationDetector,
    DataExfiltrationDetector,
)
from cyberdefense.models import AttackType, Severity


def test_port_scan_log():
    file_path = Path("data/processed/1_port_scan.log")
    assert file_path.exists()
    events = LogParser.parse_file(file_path)
    assert len(events) >= 10

    detector = PortScanDetector()
    alerts = []
    for evt in events:
        alert = detector.process_event(evt)
        if alert:
            alerts.append(alert)

    assert len(alerts) >= 1
    assert alerts[0].attack_type == AttackType.PORT_SCAN


def test_brute_force_log():
    file_path = Path("data/processed/2_brute_force.log")
    assert file_path.exists()
    events = LogParser.parse_file(file_path)
    assert len(events) >= 6

    detector = BruteForceDetector()
    alerts = []
    for evt in events:
        alert = detector.process_event(evt)
        if alert:
            alerts.append(alert)

    assert len(alerts) >= 1
    assert any(a.attack_type == AttackType.BRUTE_FORCE for a in alerts)
    # Checks that critical compromise alert fired on the successful login
    assert any(a.severity == Severity.CRITICAL for a in alerts)


def test_privilege_escalation_log():
    file_path = Path("data/processed/3_privilege_escalation.log")
    assert file_path.exists()
    events = LogParser.parse_file(file_path)
    assert len(events) >= 3

    detector = PrivilegeEscalationDetector()
    alerts = []
    for evt in events:
        alert = detector.process_event(evt)
        if alert:
            alerts.append(alert)

    assert len(alerts) >= 1
    assert any(a.attack_type == AttackType.PRIVILEGE_ESCALATION for a in alerts)


def test_data_exfiltration_log():
    file_path = Path("data/processed/4_data_exfiltration.log")
    assert file_path.exists()
    events = LogParser.parse_file(file_path)
    assert len(events) >= 3

    detector = DataExfiltrationDetector()
    alerts = []
    for evt in events:
        alert = detector.process_event(evt)
        if alert:
            alerts.append(alert)

    assert len(alerts) >= 1
    assert alerts[0].attack_type == AttackType.DATA_EXFILTRATION


def test_combined_incident_log():
    file_path = Path("data/processed/5_combined_incident.log")
    assert file_path.exists()
    events = LogParser.parse_file(file_path)
    assert len(events) >= 30

    ps_det = PortScanDetector()
    bf_det = BruteForceDetector()
    pe_det = PrivilegeEscalationDetector()
    ex_det = DataExfiltrationDetector()

    triggered_types = set()
    for evt in events:
        for det in [ps_det, bf_det, pe_det, ex_det]:
            a = det.process_event(evt)
            if a:
                triggered_types.add(a.attack_type)

    assert AttackType.PORT_SCAN in triggered_types
    assert AttackType.BRUTE_FORCE in triggered_types
    assert AttackType.PRIVILEGE_ESCALATION in triggered_types
    assert AttackType.DATA_EXFILTRATION in triggered_types
