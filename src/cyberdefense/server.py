"""
CyberDefense SOC Web Server & API
=================================
Consolidated FastAPI server hosting the REST endpoints, WebSocket live event streaming,
and static admin dashboard assets.
"""

from contextlib import asynccontextmanager
import json
import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, APIRouter, HTTPException, WebSocket, WebSocketDisconnect, UploadFile, File, Form, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from cyberdefense.models import ActionType
from cyberdefense.response import alert_queue, firewall, audit_logger
from cyberdefense.main import app_core
from cyberdefense.config import settings
from cyberdefense.event_bus import bus
from cyberdefense.investigation import fetch_available_gemini_models

logger = logging.getLogger("cyberdefense.server")


# ══════════════════════════════════════════════════════════════════
# 1. WEBSOCKET CONNECTION MANAGER
# ══════════════════════════════════════════════════════════════════

class ConnectionManager:
    """Manages active WebSocket client connections and event broadcasting."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self._is_subscribed = False

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Active: {len(self.active_connections)}")

        if not self._is_subscribed:
            self._wire_event_bus()
            self._is_subscribed = True

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Active: {len(self.active_connections)}")

    async def broadcast(self, message_type: str, data: Any) -> None:
        """Broadcast formatted JSON message to all active dashboard clients."""
        if not self.active_connections:
            return

        payload = json.dumps({"type": message_type, "data": data}, default=str)
        stale = []
        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload)
            except Exception:
                stale.append(connection)

        for s in stale:
            self.disconnect(s)

    def _wire_event_bus(self) -> None:
        """Subscribe to engine events to broadcast them directly to clients."""
        async def on_log(event_data):
            await self.broadcast("log_event", event_data)

        async def on_alert_gen(alert):
            await self.broadcast("alert_generated", alert.model_dump())

        async def on_alert_inv(alert):
            await self.broadcast("alert_investigated", alert.model_dump())

        async def on_action_exec(result):
            await self.broadcast("action_executed", result.model_dump())

        bus.subscribe("log_event", on_log)
        bus.subscribe("alert_generated", on_alert_gen)
        bus.subscribe("alert_investigated", on_alert_inv)
        bus.subscribe("action_executed", on_action_exec)


ws_manager = ConnectionManager()


# ══════════════════════════════════════════════════════════════════
# 2. REST API ROUTER
# ══════════════════════════════════════════════════════════════════

router = APIRouter(prefix="/api")


# ── System Telemetry & Status ────────────────────────────────
@router.get("/status")
async def get_system_status() -> dict[str, Any]:
    """Return high-level telemetry and status metrics for the dashboard."""
    alerts = alert_queue.get_all_alerts()
    active_rules = firewall.get_active_rules()
    progress = app_core.log_monitor.get_progress()

    critical_count = sum(1 for a in alerts if a.severity.value == "CRITICAL")
    high_count = sum(1 for a in alerts if a.severity.value == "HIGH")
    actioned_count = sum(1 for a in alerts if a.status.value in ("ACTIONED", "RESOLVED"))

    return {
        "status": "OPERATIONAL",
        "llm_provider": settings.llm.provider,
        "total_alerts": len(alerts),
        "critical_alerts": critical_count,
        "high_alerts": high_count,
        "actioned_alerts": actioned_count,
        "active_firewall_rules": len(active_rules),
        "simulation": progress,
    }


# ── Alerts Management ────────────────────────────────────────
@router.get("/alerts")
async def list_alerts() -> list[dict[str, Any]]:
    """Return all alerts with investigation reports in reverse chronological order."""
    alerts = alert_queue.get_all_alerts()
    return [a.model_dump() for a in alerts]


@router.get("/alerts/{alert_id}")
async def get_alert_detail(alert_id: str) -> dict[str, Any]:
    """Retrieve full detail and LLM investigation report for a specific alert."""
    alert = alert_queue.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert.model_dump()


class ActionPayload(BaseModel):
    action_type: str
    target: str | None = None
    reason: str = ""
    admin_user: str = "soc_admin"


@router.post("/alerts/{alert_id}/action")
async def execute_alert_action(alert_id: str, payload: ActionPayload) -> dict[str, Any]:
    """Execute a response action against a threat alert (Human-in-the-Loop decision)."""
    try:
        res = await alert_queue.take_action(
            alert_id=alert_id,
            action_type=payload.action_type,
            target=payload.target,
            reason=payload.reason,
            admin_user=payload.admin_user,
        )
        return res
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Firewall & Containment ───────────────────────────────────
@router.get("/firewall/rules")
async def list_firewall_rules() -> list[dict[str, Any]]:
    """List all active firewall rules, isolated hosts, and rate limits."""
    return firewall.get_active_rules()


@router.post("/firewall/unblock/{ip}")
async def unblock_ip_address(ip: str) -> dict[str, Any]:
    """Remove a block rule for a specific IP address."""
    success = firewall.unblock_ip(ip)
    if not success:
        raise HTTPException(status_code=404, detail="IP address is not currently blocked")
    return {"status": "SUCCESS", "message": f"IP {ip} unblocked successfully"}


# ── Audit Trail ──────────────────────────────────────────────
@router.get("/audit")
async def get_audit_trail() -> list[dict[str, Any]]:
    """Retrieve the recent append-only audit trail."""
    return audit_logger.get_recent_entries()


# ── Simulation & File Ingestion ──────────────────────────────
@router.get("/simulation/scenarios")
async def list_available_scenarios() -> list[dict[str, Any]]:
    """List built-in synthetic scenarios available for instant replay."""
    synth_dir = Path("data/synthetic")
    scenarios = []
    if synth_dir.exists():
        for file in synth_dir.glob("*.*"):
            if file.suffix.lower() in (".log", ".txt", ".csv"):
                scenarios.append({
                    "name": file.stem.replace("_", " ").title(),
                    "filename": file.name,
                    "path": str(file),
                    "size_bytes": file.stat().st_size,
                })
    return scenarios


class StartSimulationPayload(BaseModel):
    scenario_path: str
    speed_multiplier: float = 10.0
    instant: bool = False


@router.post("/simulation/start")
async def start_simulation(payload: StartSimulationPayload) -> dict[str, Any]:
    """Launch simulation replay from a file path."""
    try:
        count = await app_core.start_simulation_from_file(
            file_path=payload.scenario_path,
            speed_multiplier=payload.speed_multiplier,
            instant=payload.instant,
        )
        return {"status": "STARTED", "events_queued": count, "file": payload.scenario_path}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/simulation/upload")
async def upload_and_simulate(
    file: UploadFile = File(...),
    auto_start: bool = Form(True),
    speed_multiplier: float = Form(10.0),
) -> dict[str, Any]:
    """Accepts user-uploaded .log, .txt, or .csv files and begins simulation ingestion."""
    allowed_exts = (".log", ".txt", ".csv")
    ext = Path(file.filename or "").suffix.lower()
    if ext not in allowed_exts:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{ext}'. Please upload a .log, .txt, or .csv file.",
        )

    upload_dir = Path("data/uploads")
    upload_dir.mkdir(parents=True, exist_ok=True)
    destination = upload_dir / f"sim_{file.filename}"

    content = await file.read()
    with open(destination, "wb") as f:
        f.write(content)

    events_count = 0
    if auto_start:
        events_count = await app_core.start_simulation_from_file(
            file_path=destination,
            speed_multiplier=speed_multiplier,
        )

    return {
        "status": "SUCCESS",
        "filename": file.filename,
        "saved_path": str(destination),
        "events_count": events_count,
        "auto_started": auto_start,
    }


@router.post("/simulation/pause")
async def pause_simulation() -> dict[str, str]:
    app_core.log_monitor.pause()
    return {"status": "PAUSED"}


@router.post("/simulation/resume")
async def resume_simulation() -> dict[str, str]:
    app_core.log_monitor.resume()
    return {"status": "RESUMED"}


@router.post("/simulation/stop")
async def stop_simulation() -> dict[str, str]:
    await app_core.log_monitor.stop()
    return {"status": "STOPPED"}


@router.post("/simulation/reset")
async def reset_simulation() -> dict[str, str]:
    await app_core.log_monitor.stop()
    app_core.reset_state()
    return {"status": "RESET_COMPLETE"}


@router.get("/simulation/progress")
async def get_simulation_progress() -> dict[str, Any]:
    return app_core.log_monitor.get_progress()


# ══════════════════════════════════════════════════════════════════
# 3. FASTAPI APPLICATION FACTORY
# ══════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting CyberDefense SOC Server...")
    app_core.initialize()
    yield
    logger.info("Shutting down CyberDefense SOC Server...")
    await app_core.log_monitor.stop()


def create_app() -> FastAPI:
    """Factory creating fully configured FastAPI application."""
    app = FastAPI(
        title="CyberDefense SOAR-Lite",
        description="Agentic SOAR-Lite with LLM Threat Investigation and Human-in-the-Loop Response",
        version="0.2.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)

    @app.get("/health")
    async def healthcheck():
        return {"status": "ok", "service": "cyberdefense"}

    @app.get("/v1/models")
    async def list_models():
        models_list = fetch_available_gemini_models(settings.llm.gemini.api_key)
        return {
            "object": "list",
            "data": [
                {
                    "id": m,
                    "object": "model",
                    "created": 1700000000,
                    "owned_by": "cyberdefense",
                }
                for m in models_list
            ],
        }

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        return Response(status_code=204)

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await ws_manager.connect(websocket)
        try:
            while True:
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_text("pong")
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
        except Exception:
            ws_manager.disconnect(websocket)

    dashboard_dir = Path("dashboard")
    dashboard_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/", StaticFiles(directory=str(dashboard_dir), html=True), name="dashboard")

    return app


app = create_app()
