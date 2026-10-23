"""
CyberDefense SOAR-Lite Root Package
===================================
A lightweight autonomous Security Operations Center (SOAR) platform featuring:
  - High-speed Tier 1 rule-based threat detection
  - Agentic Tier 2 LLM threat investigation & false-positive discrimination
  - Human-in-the-Loop Tier 3 mitigation & stateful firewall containment
"""

from cyberdefense.__main__ import main
from cyberdefense.main import CyberDefenseApp, app_core
from cyberdefense.models import (
    LogEvent,
    EventType,
    Protocol,
    Alert,
    AttackType,
    Severity,
    AlertStatus,
    ActionType,
    AdminAction,
    ExecutionResult,
    InvestigationReport,
    RecommendedAction,
)
from cyberdefense.detection import TriggerAgent
from cyberdefense.investigation import InvestigationAgent
from cyberdefense.response import AlertQueue, alert_queue, FirewallSimulator, firewall, ActionExecutor
from cyberdefense.data_stream import LogParser, LogMonitor, SyntheticLogGenerator
from cyberdefense.server import app

__all__ = [
    "main",
    "CyberDefenseApp",
    "app_core",
    "LogEvent",
    "EventType",
    "Protocol",
    "Alert",
    "AttackType",
    "Severity",
    "AlertStatus",
    "ActionType",
    "AdminAction",
    "ExecutionResult",
    "InvestigationReport",
    "RecommendedAction",
    "TriggerAgent",
    "InvestigationAgent",
    "AlertQueue",
    "alert_queue",
    "FirewallSimulator",
    "firewall",
    "ActionExecutor",
    "LogParser",
    "LogMonitor",
    "SyntheticLogGenerator",
    "app",
]
