"""Unit tests for Response Engine and Firewall Simulator."""

import pytest
from cyberdefense.models import ActionType, AdminAction, Alert, AttackType
from cyberdefense.response import FirewallSimulator, ActionExecutor, AlertQueue


def test_firewall_simulator_block():
    fw = FirewallSimulator()
    rule_id = fw.block_ip("192.168.1.99", "Suspicious scanning")
    assert fw.is_ip_blocked("192.168.1.99")
    assert rule_id.startswith("FW-BLK-")

    # Unblock
    unblocked = fw.unblock_ip("192.168.1.99")
    assert unblocked is True
    assert not fw.is_ip_blocked("192.168.1.99")


@pytest.mark.asyncio
async def test_action_executor_and_queue():
    queue = AlertQueue()
    alert = Alert(attack_type=AttackType.BRUTE_FORCE, mitre_id="T1110", source_ip="192.168.1.200")
    queue.add_alert(alert)

    result_data = await queue.take_action(
        alert_id=alert.id,
        action_type=ActionType.BLOCK_IP,
        target="192.168.1.200",
        reason="Admin approved mitigation",
    )
    assert result_data["result"]["success"] is True
    assert alert.admin_action == "BLOCK_IP"
    assert alert.status.value == "ACTIONED"
