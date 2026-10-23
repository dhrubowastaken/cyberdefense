"""
Test Consolidated Architecture (Approach A)
===========================================
Validates that the entire end-to-end pipeline executes cleanly and directly
using solely the new consolidated modules:
  - cyberdefense.models
  - cyberdefense.detection
  - cyberdefense.investigation
  - cyberdefense.response
  - cyberdefense.data_stream
  - cyberdefense.server
  - cyberdefense.main
"""

import pytest
from datetime import datetime

from cyberdefense.models import (
    LogEvent,
    EventType,
    AttackType,
    Severity,
    AlertStatus,
    ActionType,
)
from cyberdefense.detection import (
    PortScanDetector,
    BruteForceDetector,
    PrivilegeEscalationDetector,
    DataExfiltrationDetector,
    TriggerAgent,
)
from cyberdefense.investigation import (
    InvestigationAgent,
    MockProvider,
    CrossAlertCorrelator,
)
from cyberdefense.response import (
    FirewallSimulator,
    ActionExecutor,
    AlertQueue,
)
from cyberdefense.data_stream import (
    LogParser,
    SyntheticLogGenerator,
)
from cyberdefense.main import app_core


@pytest.mark.asyncio
async def test_consolidated_detection_pipeline():
    """Verify TriggerAgent and detectors run cleanly from detection.py."""
    trigger = TriggerAgent()
    gen = SyntheticLogGenerator()

    # Generate port scan events
    events = gen.generate_port_scan(datetime.utcnow())
    alerts = []
    for evt in events:
        res = await trigger.handle_log_event(evt)
        alerts.extend(res)

    assert len(alerts) >= 1
    assert alerts[0].attack_type == AttackType.PORT_SCAN
    assert alerts[0].source_ip == "192.168.1.105"


@pytest.mark.asyncio
async def test_consolidated_investigation_and_auto_triage():
    """Verify InvestigationAgent accurately triages both false positives and confirmed threats."""
    agent = InvestigationAgent(provider=MockProvider())
    gen = SyntheticLogGenerator()

    # 1. Test False Positive (Backup)
    fp_event = LogEvent(
        timestamp=datetime.utcnow(),
        source_ip="10.0.0.5",
        dest_ip="10.0.0.200",
        dest_port=445,
        event_type=EventType.DATA_TRANSFER,
        user="backup-svc",
        bytes_transferred=120 * 1024 * 1024,
        details="Scheduled database backup synchronization to internal storage NAS (10.0.0.200)",
    )
    detector = DataExfiltrationDetector()
    alert = detector.process_event(fp_event)
    assert alert is not None

    report = await agent.investigate_alert(alert)
    assert report.is_false_positive is True
    assert report.verdict == "FALSE_POSITIVE"
    assert report.severity == Severity.LOW
    assert "Database Backup" in report.title

    # 2. Test Confirmed Attack (External Brute Force Breach)
    bf_events = gen.generate_brute_force(datetime.utcnow(), attacker_ip="192.168.1.105", failed_attempts=5, succeed_at_end=True)
    bf_detector = BruteForceDetector()
    attack_alert = None
    for e in bf_events:
        a = bf_detector.process_event(e)
        if a and a.severity == Severity.CRITICAL:
            attack_alert = a

    assert attack_alert is not None
    threat_report = await agent.investigate_alert(attack_alert)
    assert threat_report.is_false_positive is False
    assert threat_report.verdict == "CONFIRMED_THREAT"
    assert threat_report.severity == Severity.CRITICAL
    assert attack_alert.status == AlertStatus.REVIEWED
    assert any(act.action == ActionType.BLOCK_IP for act in threat_report.recommended_actions)


@pytest.mark.asyncio
async def test_consolidated_response_containment():
    """Verify FirewallSimulator and ActionExecutor in response.py."""
    fw = FirewallSimulator()
    queue = AlertQueue()

    rule_id = fw.block_ip("192.168.1.105", reason="Credential breach")
    assert fw.is_ip_blocked("192.168.1.105") is True
    assert rule_id.startswith("FW-BLK-")

    fw.unblock_ip("192.168.1.105")
    assert fw.is_ip_blocked("192.168.1.105") is False


@pytest.mark.asyncio
async def test_simulation_midstream_ip_block():
    """Verify that blocking an IP mid-simulation drops all subsequent requests from that IP."""
    from cyberdefense.response import firewall
    app_core.reset_state()
    app_core.initialize()

    test_ip = "192.168.1.222"

    # Event 1: Before block - traffic passes through
    event1 = LogEvent(
        source_ip=test_ip,
        dest_ip="10.0.0.5",
        dest_port=22,
        event_type=EventType.AUTH_LOGIN,
        status="FAILURE",
    )
    await app_core._on_streamed_log_event(event1)
    assert event1.status == "FAILURE"

    # Mid-simulation: Admin blocks the IP!
    firewall.block_ip(test_ip, reason="Admin blocked during simulation")
    assert firewall.is_ip_blocked(test_ip) is True

    # Event 2: After block - traffic is dropped by firewall and marked BLOCKED
    event2 = LogEvent(
        source_ip=test_ip,
        dest_ip="10.0.0.5",
        dest_port=22,
        event_type=EventType.AUTH_LOGIN,
        status="FAILURE",
    )
    await app_core._on_streamed_log_event(event2)
    assert event2.status == "BLOCKED"
    assert "FIREWALL PERIMETER DROP" in event2.details

    # Clean up
    firewall.unblock_ip(test_ip)
