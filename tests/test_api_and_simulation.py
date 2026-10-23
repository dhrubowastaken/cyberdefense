"""Integration tests for FastAPI REST routes, simulation replay, and file uploads."""

import io
import pytest
from fastapi.testclient import TestClient
from cyberdefense.server import app
from cyberdefense.response import alert_queue
from cyberdefense.models import Alert, AttackType, Severity

client = TestClient(app)


def test_api_status():
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "OPERATIONAL"
    assert "total_alerts" in data
    assert "active_firewall_rules" in data


def test_api_alerts_and_action():
    # Insert test alert
    test_alert = Alert(
        attack_type=AttackType.PORT_SCAN,
        mitre_id="T1046",
        severity=Severity.MEDIUM,
        source_ip="192.168.1.188",
        target="10.0.0.5",
        rule_summary="Port scan detected",
    )
    alert_queue.add_alert(test_alert)

    # List alerts
    res = client.get("/api/alerts")
    assert res.status_code == 200
    alerts = res.json()
    assert any(a["id"] == test_alert.id for a in alerts)

    # Take action: BLOCK_IP
    action_res = client.post(
        f"/api/alerts/{test_alert.id}/action",
        json={"action_type": "BLOCK_IP", "target": "192.168.1.188", "reason": "Test block"},
    )
    assert action_res.status_code == 200
    data = action_res.json()
    assert data["result"]["success"] is True

    # Verify firewall list
    fw_res = client.get("/api/firewall/rules")
    assert fw_res.status_code == 200
    rules = fw_res.json()
    assert any(r["target"] == "192.168.1.188" for r in rules)


def test_simulation_upload_custom_log_file():
    """Test user's core dashboard requirement: uploading a custom .log or .txt file to launch simulation."""
    log_content = (
        "2026-10-23T01:15:00Z | AUTH_LOGIN | 192.168.1.105:54321 -> 10.0.0.5:22 | admin | FAILURE | 128 | SSH auth failed 1\n"
        "2026-10-23T01:15:02Z | AUTH_LOGIN | 192.168.1.105:54322 -> 10.0.0.5:22 | admin | FAILURE | 128 | SSH auth failed 2\n"
        "2026-10-23T01:15:04Z | AUTH_LOGIN | 192.168.1.105:54323 -> 10.0.0.5:22 | admin | FAILURE | 128 | SSH auth failed 3\n"
        "2026-10-23T01:15:06Z | AUTH_LOGIN | 192.168.1.105:54324 -> 10.0.0.5:22 | admin | FAILURE | 128 | SSH auth failed 4\n"
        "2026-10-23T01:15:08Z | AUTH_LOGIN | 192.168.1.105:54325 -> 10.0.0.5:22 | admin | FAILURE | 128 | SSH auth failed 5\n"
        "2026-10-23T01:15:10Z | AUTH_LOGIN | 192.168.1.105:54326 -> 10.0.0.5:22 | admin | SUCCESS | 512 | SSH auth accepted\n"
    )

    file_bytes = io.BytesIO(log_content.encode("utf-8"))
    response = client.post(
        "/api/simulation/upload",
        files={"file": ("custom_intrusion.log", file_bytes, "text/plain")},
        data={"auto_start": "false"},
    )
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["status"] == "SUCCESS"
    assert res_data["filename"] == "custom_intrusion.log"
