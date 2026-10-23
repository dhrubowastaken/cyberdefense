"""Unit tests for Tier 2 LLM Investigation Layer."""

import pytest
from datetime import datetime
from cyberdefense.models import Alert, AttackType, Severity, LogEvent, EventType
from cyberdefense.investigation import (
    MockProvider,
    CrossAlertCorrelator,
    InvestigationAgent,
    build_investigation_prompt,
    parse_llm_json_response,
)


@pytest.mark.asyncio
async def test_mock_provider_brute_force():
    provider = MockProvider()
    response = await provider.generate_investigation("brute_force compromise detected", "")
    data = parse_llm_json_response(response)
    assert "title" in data
    assert "severity" in data
    assert data["severity"] == "CRITICAL"
    assert len(data["recommended_actions"]) >= 1


def test_cross_alert_correlator():
    correlator = CrossAlertCorrelator()
    alert1 = Alert(id="ALT-1", attack_type=AttackType.PORT_SCAN, mitre_id="T1046", source_ip="192.168.1.100")
    alert2 = Alert(id="ALT-2", attack_type=AttackType.BRUTE_FORCE, mitre_id="T1110", source_ip="192.168.1.100")

    correlator.register_alert(alert1)
    correlated = correlator.register_alert(alert2)
    assert "ALT-1" in correlated


@pytest.mark.asyncio
async def test_investigation_agent_end_to_end():
    agent = InvestigationAgent(provider=MockProvider())
    alert = Alert(
        attack_type=AttackType.BRUTE_FORCE,
        mitre_id="T1110",
        source_ip="192.168.1.105",
        target="admin",
        rule_summary="Password spray crossed threshold",
    )
    report = await agent.investigate_alert(alert)
    assert report.alert_id == alert.id
    assert report.title != ""
    assert len(report.recommended_actions) >= 1
    assert alert.investigation_report is not None


@pytest.mark.asyncio
async def test_false_positive_auto_triage_backup():
    agent = InvestigationAgent(provider=MockProvider())
    alert = Alert(
        attack_type=AttackType.DATA_EXFILTRATION,
        mitre_id="T1041",
        source_ip="10.0.0.5",
        target="10.0.0.200",
        rule_summary="Data transfer crossed 100MB threshold to 10.0.0.200 (user: backup-svc)",
    )
    report = await agent.investigate_alert(alert)
    assert report.verdict == "FALSE_POSITIVE"
    assert report.is_false_positive is True
    assert alert.status.value == "DISMISSED"
    assert alert.admin_action == "AUTO_DISMISSED"
    assert report.severity.value == "LOW"


@pytest.mark.asyncio
async def test_false_positive_auto_triage_employee_typo():
    agent = InvestigationAgent(provider=MockProvider())
    alert = Alert(
        attack_type=AttackType.BRUTE_FORCE,
        mitre_id="T1110",
        source_ip="10.0.0.45",
        target="sarah",
        rule_summary="Multiple authentication failures for sarah on internal workstation 10.0.0.45",
    )
    report = await agent.investigate_alert(alert)
    assert report.verdict == "FALSE_POSITIVE"
    assert report.is_false_positive is True
    assert alert.status.value == "DISMISSED"


@pytest.mark.asyncio
async def test_enterprise_dataset_parsing_and_trigger():
    from cyberdefense.data_stream import LogParser
    from cyberdefense.detection import TriggerAgent
    from pathlib import Path

    dataset_path = Path("data/synthetic/enterprise_mixed_traffic_with_false_positives.log")
    assert dataset_path.exists(), "Enterprise dataset file must exist on disk"

    events = LogParser.parse_file(dataset_path)
    assert len(events) == 100

    trigger_agent = TriggerAgent()
    alerts = []
    for ev in events:
        flagged = await trigger_agent.handle_log_event(ev)
        if flagged:
            alerts.append(flagged)

    # Both false positives (backup, nessus, employee typo) and true attacks triggered Tier 1
    assert len(alerts) >= 3

