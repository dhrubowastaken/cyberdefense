"""
CyberDefense Main Orchestrator
==============================
Ties together Data Streaming, Tier 1 Rule Detection, Tier 2 LLM Threat Investigation,
and Tier 3 Response Mitigation into a unified autonomous pipeline.
"""

import asyncio
import logging
from pathlib import Path
from typing import Any

from cyberdefense.models import LogEvent, Alert
from cyberdefense.data_stream import LogMonitor, LogParser
from cyberdefense.detection import TriggerAgent
from cyberdefense.investigation import InvestigationAgent
from cyberdefense.response import alert_queue, firewall, audit_logger
from cyberdefense.event_bus import bus

logger = logging.getLogger("cyberdefense.core")


class CyberDefenseApp:
    """Core application orchestrator coordinating all detection and response subsystems."""

    def __init__(self):
        self.trigger_agent = TriggerAgent()
        self.investigation_agent = InvestigationAgent()
        self.log_monitor = LogMonitor()
        self._is_initialized = False
        self._background_tasks: set[asyncio.Task] = set()

    def initialize(self) -> None:
        """Wire up event subscriptions across subsystems."""
        if self._is_initialized:
            return

        # Connect LogMonitor stream to TriggerAgent
        self.log_monitor.set_callback(self._on_streamed_log_event)

        # Connect Tier 1 alert generation to Tier 2 LLM Investigation
        bus.subscribe("alert_generated", self._on_alert_generated)

        self._is_initialized = True
        logger.info("CyberDefense Core Orchestrator initialized successfully.")

    async def _on_streamed_log_event(self, event: LogEvent) -> None:
        """Handle individual log events streamed by LogMonitor."""
        # Active Perimeter Containment:
        # Intercept and drop packet if offending external source_ip is blocked,
        # or if external egress dest_ip is blocked, or if an endpoint is quarantined/isolated.
        # Protect internal target server (10.0.0.5) from accidental perimeter blocking.
        is_blocked = (
            firewall.is_ip_blocked(event.source_ip)
            or (event.dest_ip != "10.0.0.5" and firewall.is_ip_blocked(event.dest_ip))
            or firewall.is_host_isolated(event.source_ip)
            or firewall.is_host_isolated(event.dest_ip)
        )

        if is_blocked:
            original_status = event.status
            original_details = event.details
            drop_details = f"[FIREWALL PERIMETER DROP] Traffic blocked by active rule for {event.source_ip}"
            event.status = "BLOCKED"
            event.details = drop_details
            logger.info(f"Firewall intercepted and dropped packet from blocked IP {event.source_ip} -> {event.dest_ip}")
            # Broadcast blocked event to UI so analyst sees active firewall dropping packets in real time
            await bus.publish("log_event", event.model_dump())

            # Evaluate threat pattern in Tier 1 detection so repeated attack attempts
            # from blocked IPs are recognized and flagged as pre-mitigated incidents
            event.status = original_status
            event.details = original_details
            await self.trigger_agent.handle_log_event(event)
            event.status = "BLOCKED"
            event.details = drop_details
            return

        # 1. Broadcast raw event to UI via EventBus
        await bus.publish("log_event", event.model_dump())

        # 2. Process through Tier 1 detection rules
        await self.trigger_agent.handle_log_event(event)

    async def _on_alert_generated(self, alert: Alert) -> None:
        """Handle alert flagged by Tier 1 rule engine."""
        # 1. Enqueue alert into active SOC queue
        alert_queue.add_alert(alert)

        # 2. Trigger Tier 2 LLM Investigation asynchronously
        task = asyncio.create_task(self._run_investigation(alert))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _run_investigation(self, alert: Alert) -> None:
        """Invoke Tier 2 LLM investigation and update queue."""
        try:
            await self.investigation_agent.investigate_alert(alert)
            alert_queue.add_alert(alert)
            logger.info(f"Tier 2 investigation report attached and queue updated for Alert {alert.id}")
        except Exception as e:
            logger.error(f"Tier 2 investigation failed for alert {alert.id}: {e}", exc_info=True)

    async def start_simulation_from_file(
        self,
        file_path: str | Path,
        speed_multiplier: float = 10.0,
        instant: bool = False,
    ) -> int:
        """Start a simulation by reading an uploaded or preset log file."""
        self.initialize()
        # Reset Tier 1 detection sliding windows for fresh replay analysis without resetting firewall containment rules
        self.trigger_agent.reset()
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Simulation file does not exist: {path}")

        events = LogParser.parse_file(path)
        logger.info(f"Loaded {len(events)} events from {path.name}. Starting simulation replay...")

        task = asyncio.create_task(
            self.log_monitor.start_replay(
                events=events,
                speed_multiplier=speed_multiplier,
                instant=instant,
            )
        )
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return len(events)

    def reset_state(self) -> None:
        """Reset simulation state and detection memory."""
        self.trigger_agent.reset()
        self.investigation_agent.reset()
        alert_queue.reset()
        firewall.reset()
        audit_logger.reset()
        logger.info("CyberDefense system state reset.")


# Global application singleton
app_core = CyberDefenseApp()
