"""
TalonResponse - API Layer
api.py - FastAPI server, WebSocket streaming, REST endpoints

Author  : Rayyan Umair
Date    : 2026-05-25
Purpose : The external interface of TalonResponse. Exposes REST
          endpoints for querying cases, alerts, and playbooks, plus
          a WebSocket endpoint that streams case state changes to
          connected dashboard clients in real time.
          No orchestration logic lives here - the API only reads,
          formats, and streams.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/TalonResponse

"Verify the threat. Execute the isolation. Preserve the evidence."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# -- Standard Library ---------------------------------------------------------
import asyncio
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set

# -- Third Party --------------------------------------------------------------
from fastapi import (
    FastAPI,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware

# -- Internal -----------------------------------------------------------------
from config.settings import Settings
from core.forensic_triage import ForensicTriageEngine
from core.orchestrator import Orchestrator
from core.playbook_engine import PlaybookEngine
from database import Database
from models.schemas import (
    AlertSeverity,
    CaseFile,
    HealthResponse,
    InboundAlert,
    IncidentStatus,
)

logger = logging.getLogger(__name__)


# -- WebSocket Manager --------------------------------------------------------

class ConnectionManager:
    def __init__(self) -> None:
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)

    async def broadcast(self, payload: dict) -> None:
        if not self._connections:
            return
        message = json.dumps(payload, default=str)
        dead: Set[WebSocket] = set()
        async with self._lock:
            connections = set(self._connections)
        for ws in connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        if dead:
            async with self._lock:
                self._connections -= dead

    @property
    def connection_count(self) -> int:
        return len(self._connections)


# -- App Factory --------------------------------------------------------------

def create_app(
    settings            : Settings,
    db                  : Database,
    orchestrator        : Orchestrator,
    playbook_engine     : PlaybookEngine,
    triage_engine       : ForensicTriageEngine,
    zmq_stats_fn        : callable,
    started_at          : datetime,
) -> tuple:

    app = FastAPI(
        title       = "TalonResponse",
        description = "Local-first incident response orchestration and forensic triage engine.",
        version     = settings.app_version,
        docs_url    = "/docs",
        redoc_url   = "/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins     = ["*"],
        allow_credentials = True,
        allow_methods     = ["*"],
        allow_headers     = ["*"],
    )

    manager = ConnectionManager()

    # -- Health ---------------------------------------------------------------

    @app.get("/health", response_model=HealthResponse, tags=["System"])
    async def health() -> HealthResponse:
        uptime  = (datetime.now(timezone.utc) - started_at).total_seconds()
        db_st   = db.get_stats()
        pb_st   = playbook_engine.stats
        return HealthResponse(
            status             = "ok",
            app_name           = settings.app_name,
            version            = settings.app_version,
            zmq_connected      = zmq_stats_fn().get("connected", False),
            playbooks_loaded   = pb_st.get("playbooks_loaded", 0),
            cases_total        = db_st.get("cases_total", 0),
            cases_contained    = db_st.get("cases_contained", 0),
            ai_enabled         = settings.ai_enabled,
            uptime_seconds     = uptime,
            enrichment_enabled = settings.enrichment_enabled,
        )

    @app.get("/stats", tags=["System"])
    async def stats() -> dict:
        return {
            "orchestrator"  : orchestrator.stats,
            "playbooks"     : playbook_engine.stats,
            "triage"        : triage_engine.stats,
            "database"      : db.get_stats(),
            "zmq"           : zmq_stats_fn(),
            "websocket"     : {"active_connections": manager.connection_count},
        }

    # -- Ingest ---------------------------------------------------------------

    @app.post("/ingest", tags=["Ingest"], status_code=status.HTTP_202_ACCEPTED)
    async def ingest_alert(alert: InboundAlert) -> dict:
        """
        Submit an InboundAlert for immediate orchestration.
        Used for direct API submission and testing without ZeroMQ.
        """
        try:
            case = orchestrator.process(alert)
            await manager.broadcast({
                "type": "case_update",
                "data": case.model_dump(mode="json"),
            })
            return {
                "case_id"       : case.case_id,
                "status"        : case.status.value,
                "actions_executed": case.action_count,
                "case_file"     : case.case_file_path,
                "delta_seconds" : case.containment_delta_seconds,
            }
        except Exception as e:
            raise HTTPException(
                status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail      = f"Orchestration failed: {e}",
            )

    # -- Cases ----------------------------------------------------------------

    @app.get("/cases", tags=["Cases"])
    async def get_cases(
        status_filter   : Optional[str] = Query(default=None, alias="status"),
        source_tool     : Optional[str] = Query(default=None),
        detection_code  : Optional[str] = Query(default=None),
        target_entity   : Optional[str] = Query(default=None),
        admin_only      : bool          = Query(default=False),
        since_hours     : int           = Query(default=24),
        limit           : int           = Query(default=100, le=1000),
    ) -> List[dict]:
        since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        st    = None
        if status_filter:
            try:
                st = IncidentStatus(status_filter)
            except ValueError:
                raise HTTPException(
                    status_code = status.HTTP_400_BAD_REQUEST,
                    detail      = f"Invalid status: {status_filter}. Valid: {[s.value for s in IncidentStatus]}",
                )
        return db.get_cases(
            status         = st,
            source_tool    = source_tool,
            detection_code = detection_code,
            target_entity  = target_entity,
            since          = since,
            admin_only     = admin_only,
            limit          = limit,
        )

    @app.get("/cases/summary", tags=["Cases"])
    async def get_case_summary() -> dict:
        return {
            "by_status"             : db.get_case_count_by_status(),
            "by_detection"          : db.get_case_count_by_detection(),
            "avg_containment_delta" : db.get_avg_containment_delta(),
            "recent_contained"      : db.get_recent_contained_cases(limit=5),
        }

    @app.get("/cases/{case_id}", tags=["Cases"])
    async def get_case(case_id: str) -> dict:
        row = db.get_case(case_id)
        if not row:
            raise HTTPException(
                status_code = status.HTTP_404_NOT_FOUND,
                detail      = f"Case {case_id} not found.",
            )
        return row

    @app.get("/cases/{case_id}/file", tags=["Cases"])
    async def get_case_file(case_id: str) -> dict:
        """Return the raw Markdown content of a case file."""
        content = triage_engine.read_case_file(case_id)
        if not content:
            raise HTTPException(
                status_code = status.HTTP_404_NOT_FOUND,
                detail      = f"Case file for {case_id} not found on disk.",
            )
        return {"case_id": case_id, "markdown": content}

    @app.post("/cases/investigate", tags=["Cases"])
    async def investigate(body: dict) -> List[dict]:
        """
        Run a raw SQL SELECT against the cases and alert_history tables.
        Example:
            { "sql": "SELECT * FROM cases WHERE is_admin = TRUE LIMIT 20" }
        SELECT only - mutations are blocked.
        """
        sql = body.get("sql", "").strip()
        if not sql:
            raise HTTPException(
                status_code = status.HTTP_400_BAD_REQUEST,
                detail      = "Request body must contain a 'sql' field.",
            )
        try:
            return db.investigation_query(sql)
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Query failed: {e}")

    # -- Alert History --------------------------------------------------------

    @app.get("/alerts", tags=["Alerts"])
    async def get_alert_history(
        source_tool    : Optional[str] = Query(default=None),
        detection_code : Optional[str] = Query(default=None),
        since_hours    : int           = Query(default=24),
        limit          : int           = Query(default=200, le=2000),
    ) -> List[dict]:
        since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        return db.get_alert_history(
            source_tool    = source_tool,
            detection_code = detection_code,
            since          = since,
            limit          = limit,
        )

    # -- Playbooks ------------------------------------------------------------

    @app.get("/playbooks", tags=["Playbooks"])
    async def get_playbooks() -> List[dict]:
        playbooks = playbook_engine.get_all_playbooks()
        return [p.model_dump(mode="json") for p in playbooks]

    @app.get("/playbooks/coverage", tags=["Playbooks"])
    async def get_coverage() -> dict:
        """Return detection code to playbook ID coverage map."""
        return playbook_engine.get_coverage()

    @app.get("/playbooks/{playbook_id}", tags=["Playbooks"])
    async def get_playbook(playbook_id: str) -> dict:
        pb = playbook_engine.get_playbook(playbook_id)
        if not pb:
            raise HTTPException(
                status_code = status.HTTP_404_NOT_FOUND,
                detail      = f"Playbook {playbook_id} not found.",
            )
        return pb.model_dump(mode="json")

    @app.patch("/playbooks/{playbook_id}/enable", tags=["Playbooks"])
    async def enable_playbook(playbook_id: str) -> dict:
        ok = playbook_engine.enable_playbook(playbook_id)
        if not ok:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Playbook {playbook_id} not found.")
        return {"status": "enabled", "playbook_id": playbook_id}

    @app.patch("/playbooks/{playbook_id}/disable", tags=["Playbooks"])
    async def disable_playbook(playbook_id: str) -> dict:
        ok = playbook_engine.disable_playbook(playbook_id)
        if not ok:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Playbook {playbook_id} not found.")
        return {"status": "disabled", "playbook_id": playbook_id}

    @app.post("/playbooks/reload", tags=["Playbooks"])
    async def reload_playbooks() -> dict:
        count = playbook_engine.reload()
        return {"status": "reloaded", "playbooks_loaded": count}

    # -- Test -----------------------------------------------------------------

    @app.post("/test/fire", tags=["Testing"])
    async def test_fire(body: dict) -> dict:
        """
        Fire a test alert through the full orchestration pipeline.
        Useful for verifying playbook coverage and pipeline health
        without a live ZeroMQ publisher.

        Body:
            {
                "source_tool"   : "AD-Audit",
                "detection_code": "AD-002",
                "target_entity" : "jsmith",
                "severity"      : "Critical"
            }
        """
        try:
            sev = AlertSeverity(body.get("severity", "Critical"))
        except ValueError:
            sev = AlertSeverity.CRITICAL

        alert = InboundAlert(
            source_tool    = body.get("source_tool", "TalonResponse-Test"),
            detection_code = body.get("detection_code", "TEST-001"),
            target_entity  = body.get("target_entity", "test_entity"),
            severity       = sev,
            raw_payload    = body,
            is_admin       = body.get("is_admin", False),
            privilege_level= body.get("privilege_level", "standard"),
        )
        case = orchestrator.process(alert)
        await manager.broadcast({
            "type": "case_update",
            "data": case.model_dump(mode="json"),
        })
        return {
            "case_id"       : case.case_id,
            "status"        : case.status.value,
            "playbook_matched": case.matched_playbook_id,
            "actions_executed": case.action_count,
            "delta_seconds" : case.containment_delta_seconds,
            "case_file"     : case.case_file_path,
        }

    # -- WebSocket ------------------------------------------------------------

    @app.websocket("/ws/cases")
    async def ws_cases(ws: WebSocket) -> None:
        """
        Real-time WebSocket stream of case state changes.

        Message format:
            { "type": "case_update", "data": { ...CaseFile fields... } }
            { "type": "heartbeat",   "timestamp": "UTC ISO8601" }
        """
        await manager.connect(ws)
        try:
            while True:
                await asyncio.sleep(settings.ws_heartbeat_interval)
                await ws.send_text(json.dumps({
                    "type"     : "heartbeat",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.debug(f"WebSocket error: {e}")
        finally:
            await manager.disconnect(ws)

    return app, manager