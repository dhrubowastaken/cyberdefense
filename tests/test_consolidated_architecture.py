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
    Alert,
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


@pytest.mark.asyncio
async def test_async_gemini_forwarding_and_midstream_blocking_continuation():
    """Verify that when an alert is blocked, Gemini investigation completes, forwards report, and subsequent logs execute."""
    from cyberdefense.response import firewall, alert_queue
    from cyberdefense.event_bus import bus
    import asyncio

    app_core.reset_state()
    app_core.initialize()

    investigated_alerts = []
    async def on_inv(alert_data):
        investigated_alerts.append(alert_data)
    bus.subscribe("alert_investigated", on_inv)

    attacker_ip = "192.168.1.188"
    other_ip = "192.168.1.199"

    # 1. Fire an alert
    alert = Alert(
        attack_type=AttackType.PORT_SCAN,
        mitre_id="T1046",
        source_ip=attacker_ip,
        target="10.0.0.5",
        rule_summary=f"Port scan from {attacker_ip}",
    )
    await bus.publish("alert_generated", alert)

    # 2. Block the attacker IP immediately
    await alert_queue.take_action(
        alert_id=alert.id,
        action_type="BLOCK_IP",
        target=attacker_ip,
        reason="Manual block mid-simulation",
    )
    assert firewall.is_ip_blocked(attacker_ip) is True

    # 3. Simulate subsequent logs: attacker is dropped, but other IP continues execution
    blocked_evt = LogEvent(source_ip=attacker_ip, dest_ip="10.0.0.5", dest_port=80, event_type=EventType.CONNECTION)
    allowed_evt = LogEvent(source_ip=other_ip, dest_ip="10.0.0.5", dest_port=80, event_type=EventType.CONNECTION)

    await app_core._on_streamed_log_event(blocked_evt)
    assert blocked_evt.status == "BLOCKED"

    await app_core._on_streamed_log_event(allowed_evt)
    assert allowed_evt.status != "BLOCKED"

    # 4. Wait for investigation task to finish without stalling
    if app_core._background_tasks:
        await asyncio.gather(*list(app_core._background_tasks), return_exceptions=True)

    assert len(investigated_alerts) >= 1
    report = alert.investigation_report
    assert report is not None
    assert "title" in report

    # Clean up
    firewall.unblock_ip(attacker_ip)
    bus.unsubscribe("alert_investigated", on_inv)


@pytest.mark.asyncio
async def test_pre_mitigated_alert_skips_llm_if_ip_already_blocked():
    """Verify that when an IP is already blocked in firewall perimeter rules,
    subsequent alerts for that IP completely bypass Gemini and get marked as PRE_MITIGATED."""
    from unittest.mock import AsyncMock
    from cyberdefense.response import firewall
    from cyberdefense.investigation import InvestigationAgent
    from cyberdefense.models import Alert, AttackType, Severity, AlertStatus

    blocked_ip = "192.168.99.77"
    rule_id = firewall.block_ip(blocked_ip, reason="Prior attack containment")

    agent = InvestigationAgent()
    agent.provider.generate_investigation = AsyncMock()

    alert = Alert(
        attack_type=AttackType.PORT_SCAN,
        mitre_id="T1046",
        severity=Severity.HIGH,
        source_ip=blocked_ip,
        target="10.0.0.5",
        rule_summary=f"Port scan reconnaissance from {blocked_ip}",
    )

    report = await agent.investigate_alert(alert)

    # 1. LLM provider must NOT have been called
    agent.provider.generate_investigation.assert_not_called()

    # 2. Report and alert state must be pre-mitigated
    assert report.verdict == "PRE_MITIGATED"
    assert report.model_used == "firewall-containment-cache"
    assert rule_id in report.executive_summary
    assert alert.status == AlertStatus.ACTIONED
    assert alert.admin_action == "ALREADY_BLOCKED"
    assert "already blocked" in alert.admin_notes.lower()
    assert alert.severity == Severity.LOW

    # Clean up
    firewall.unblock_ip(blocked_ip)

