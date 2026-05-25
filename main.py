"""
TalonResponse - Entry Point
main.py - Application bootstrap, pipeline wiring, startup/shutdown

Author  : Rayyan Umair
Date    : 2026-05-25
Purpose : Wires every engine layer together and starts the application.
          Startup sequence:
            1. Load settings
            2. Connect database
            3. Load playbooks
            4. Start ZeroMQ subscriber thread
            5. Start pipeline worker thread
            6. Start background schedulers
            7. Start FastAPI server (uvicorn)
          Shutdown sequence (SIGINT / SIGTERM):
            1. Stop ZeroMQ subscriber
            2. Stop pipeline worker
            3. Stop schedulers
            4. Close database
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
import queue
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional

# -- Third Party --------------------------------------------------------------
import uvicorn
import zmq

# -- Internal -----------------------------------------------------------------
from api import ConnectionManager, create_app
from config.settings import Settings, generate_env_example
from core.forensic_triage import ForensicTriageEngine
from core.orchestrator import Orchestrator
from core.playbook_engine import PlaybookEngine
from database import Database
from models.schemas import AlertSeverity, InboundAlert


# -- Logging ------------------------------------------------------------------

def _setup_logging(settings: Settings) -> None:
    fmt = "%(asctime)s  %(levelname)-8s  %(name)-28s  %(message)s"
    logging.basicConfig(
        level   = getattr(logging, settings.log_level, logging.INFO),
        format  = fmt,
        datefmt = "%Y-%m-%d %H:%M:%S",
        handlers= [logging.StreamHandler(sys.stdout)],
    )
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


logger = logging.getLogger(__name__)


# -- Banner -------------------------------------------------------------------

_BANNER = """
+------------------------------------------------------------------+
|                                                                  |
|  ████████╗ █████╗ ██╗      ██████╗ ███╗  ██╗                    |
|  ╚══██╔══╝██╔══██╗██║     ██╔═══██╗████╗ ██║                    |
|     ██║   ███████║██║     ██║   ██║██╔██╗██║                    |
|     ██║   ██╔══██║██║     ██║   ██║██║╚████║                    |
|     ██║   ██║  ██║███████╗╚██████╔╝██║ ╚███║                    |
|     ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚══╝                    |
|                                                                  |
|  ██████╗ ███████╗███████╗██████╗  ██████╗ ███╗  ██╗███████╗███████╗|
|  ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗████╗ ██║██╔════╝██╔════╝|
|  ██████╔╝█████╗  ███████╗██████╔╝██║   ██║██╔██╗██║███████╗█████╗  |
|  ██╔══██╗██╔══╝  ╚════██║██╔═══╝ ██║   ██║██║╚████║╚════██║██╔══╝  |
|  ██║  ██║███████╗███████║██║     ╚██████╔╝██║ ╚███║███████║███████╗|
|  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚══╝╚══════╝╚══════╝|
|                                                                  |
|  "Verify the threat. Execute the isolation. Preserve the evidence."|
|  Part of the NetRaptor ecosystem.                                |
|  Built by Rayyan Umair                                           |
|                                                                  |
+------------------------------------------------------------------+
"""


# -- ZeroMQ Subscriber --------------------------------------------------------

class ZMQSubscriber:
    """
    Subscribes to the NetRaptor alert channel and pushes inbound
    alert JSON onto the internal processing queue.
    Runs in its own daemon thread.
    """

    def __init__(self, settings: Settings, alert_queue: queue.Queue) -> None:
        self._settings   = settings
        self._queue      = alert_queue
        self._running    = False
        self._connected  = False
        self._thread     : Optional[threading.Thread] = None
        self._received   = 0
        self._dropped    = 0
        self._errors     = 0

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(
            target = self._run,
            name   = "talon-zmq-subscriber",
            daemon = True,
        )
        self._thread.start()
        logger.info(
            f"ZMQSubscriber started - "
            f"subscribing to {self._settings.zmq_alert_subscriber_address}"
        )

    def stop(self) -> None:
        self._running   = False
        self._connected = False
        logger.info(
            f"ZMQSubscriber stopping. "
            f"Received={self._received} Dropped={self._dropped}"
        )

    def _run(self) -> None:
        context = zmq.Context()
        socket  = context.socket(zmq.SUB)
        socket.setsockopt(zmq.RCVTIMEO, self._settings.zmq_recv_timeout_ms)
        socket.setsockopt_string(zmq.SUBSCRIBE, "")

        try:
            socket.connect(self._settings.zmq_alert_subscriber_address)
            self._connected = True
            logger.info(
                f"ZMQ connected to "
                f"{self._settings.zmq_alert_subscriber_address} - "
                f"waiting for critical alerts..."
            )
        except zmq.ZMQError as e:
            logger.error(f"ZMQ connect failed: {e}")
            self._running = False
            return

        while self._running:
            try:
                raw_bytes = socket.recv()
                self._received += 1
                try:
                    data = json.loads(raw_bytes.decode("utf-8"))
                except Exception:
                    self._errors += 1
                    continue
                try:
                    self._queue.put_nowait(data)
                except queue.Full:
                    self._dropped += 1
                    if self._dropped % 50 == 0:
                        logger.warning(
                            f"Alert queue full - dropped {self._dropped} alerts."
                        )
            except zmq.Again:
                continue
            except zmq.ZMQError as e:
                if self._running:
                    logger.error(f"ZMQ receive error: {e}")
                break

        socket.close()
        context.term()
        self._connected = False
        logger.info("ZMQSubscriber stopped.")

    @property
    def stats(self) -> dict:
        return {
            "connected"  : self._connected,
            "zmq_address": self._settings.zmq_alert_subscriber_address,
            "received"   : self._received,
            "dropped"    : self._dropped,
            "errors"     : self._errors,
        }


# -- Pipeline Worker ----------------------------------------------------------

class PipelineWorker:
    """
    Pulls raw alert dicts from the ZMQ queue, constructs InboundAlert
    objects, and passes them through the orchestrator.
    Broadcasts case state changes to WebSocket clients.
    """

    def __init__(
        self,
        alert_queue  : queue.Queue,
        orchestrator : Orchestrator,
        ws_manager   : ConnectionManager,
        loop         : asyncio.AbstractEventLoop,
    ) -> None:
        self._queue       = alert_queue
        self._orchestrator= orchestrator
        self._ws_manager  = ws_manager
        self._loop        = loop
        self._running     = False
        self._thread      : Optional[threading.Thread] = None
        self._processed   = 0
        self._errors      = 0

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(
            target = self._run,
            name   = "talon-pipeline",
            daemon = True,
        )
        self._thread.start()
        logger.info("PipelineWorker started.")

    def stop(self) -> None:
        self._running = False
        logger.info(
            f"PipelineWorker stopping. "
            f"Processed={self._processed} Errors={self._errors}"
        )

    def _run(self) -> None:
        while self._running:
            try:
                raw = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                alert = self._build_alert(raw)
                if alert is None:
                    continue
                case = self._orchestrator.process(alert)
                self._broadcast_case(case)
                self._processed += 1
            except Exception as e:
                self._errors += 1
                logger.error(f"Pipeline error: {e}")
            finally:
                self._queue.task_done()

    def _build_alert(self, raw: dict) -> Optional[InboundAlert]:
        try:
            # Support both direct InboundAlert format and
            # nested NetRaptor alert format from SIEMulate/AD-Audit
            source = raw.get("source_tool") or raw.get("source", "unknown")
            code   = (
                raw.get("detection_code") or
                raw.get("detection_type") or
                raw.get("strike_type") or
                "UNKNOWN"
            )
            target = (
                raw.get("target_entity") or
                raw.get("actor_username") or
                raw.get("src_ip") or
                "unknown"
            )
            try:
                sev = AlertSeverity(raw.get("severity", "Critical"))
            except ValueError:
                sev = AlertSeverity.CRITICAL

            return InboundAlert(
                source_tool    = str(source),
                detection_code = str(code),
                target_entity  = str(target),
                severity       = sev,
                raw_payload    = raw,
                is_admin       = bool(raw.get("is_admin", False)),
                privilege_level= str(raw.get("privilege_level", "unknown")),
                source_host    = str(raw.get("source_host", "")),
            )
        except Exception as e:
            logger.debug(f"Alert build failed: {e}")
            return None

    def _broadcast_case(self, case) -> None:
        payload = {
            "type": "case_update",
            "data": case.model_dump(mode="json"),
        }
        asyncio.run_coroutine_threadsafe(
            self._ws_manager.broadcast(payload),
            self._loop,
        )

    @property
    def stats(self) -> dict:
        return {
            "processed"  : self._processed,
            "errors"     : self._errors,
            "queue_depth": self._queue.qsize(),
        }


# -- Background Schedulers ----------------------------------------------------

class PlaybookReloadScheduler:
    def __init__(self, engine: PlaybookEngine, interval: int) -> None:
        self._engine   = engine
        self._interval = interval
        self._running  = False
        self._thread   : Optional[threading.Thread] = None

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(
            target = self._run,
            name   = "talon-playbook-reload",
            daemon = True,
        )
        self._thread.start()
        logger.info(f"PlaybookReloadScheduler started - interval={self._interval}s")

    def stop(self) -> None:
        self._running = False

    def _run(self) -> None:
        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            try:
                self._engine.reload()
            except Exception as e:
                logger.error(f"Playbook reload failed: {e}")


# -- Application Bootstrap ----------------------------------------------------

class TalonResponse:
    """Top-level application class. Owns all engine instances."""

    def __init__(self) -> None:
        self._settings    = Settings()
        self._started_at  = datetime.now(timezone.utc)
        self._alert_queue : queue.Queue = queue.Queue(
            maxsize=self._settings.zmq_queue_maxsize
        )

        self._db              = Database(self._settings)
        self._playbook_engine = PlaybookEngine(self._settings)
        self._triage_engine   = ForensicTriageEngine(self._settings)
        self._orchestrator    : Optional[Orchestrator]          = None
        self._zmq_subscriber  = ZMQSubscriber(self._settings, self._alert_queue)
        self._pb_reload       : Optional[PlaybookReloadScheduler] = None

        self._loop            : Optional[asyncio.AbstractEventLoop] = None
        self._pipeline        : Optional[PipelineWorker]            = None
        self._ws_manager      : Optional[ConnectionManager]         = None

    def startup(self) -> None:
        print(_BANNER)
        logger.info("=" * 60)
        logger.info(f"  TalonResponse v{self._settings.app_version} starting")
        logger.info(f"  Port        : {self._settings.port}")
        logger.info(f"  ZMQ         : {self._settings.zmq_alert_subscriber_address}")
        logger.info(f"  DB          : {self._settings.db_path}")
        logger.info(f"  Cases dir   : {self._settings.case_file_storage_dir}")
        logger.info(f"  Enrichment  : {self._settings.enrichment_enabled}")
        logger.info(f"  AI          : {'enabled' if self._settings.ai_enabled else 'disabled'}")
        logger.info("=" * 60)

        self._db.connect()
        pb_count = self._playbook_engine.load()

        if pb_count == 0:
            logger.warning(
                "No playbooks loaded - TalonResponse will receive alerts "
                "but cannot execute automated responses. "
                "Add YAML files to the playbooks/ directory."
            )

        self._zmq_subscriber.start()

        if self._settings.playbook_hot_reload:
            self._pb_reload = PlaybookReloadScheduler(
                self._playbook_engine,
                self._settings.playbook_reload_interval,
            )
            self._pb_reload.start()

        logger.info(
            f"Startup complete - "
            f"{pb_count} playbooks loaded. "
            f"Listening for critical alerts."
        )

    def build_app(self):
        self._loop = asyncio.get_event_loop()

        # Orchestrator needs broadcast fn - wire after ws_manager exists
        def _broadcast(case):
            if self._ws_manager and self._loop:
                asyncio.run_coroutine_threadsafe(
                    self._ws_manager.broadcast({
                        "type": "case_update",
                        "data": case.model_dump(mode="json"),
                    }),
                    self._loop,
                )

        self._orchestrator = Orchestrator(
            settings        = self._settings,
            db              = self._db,
            playbook_engine = self._playbook_engine,
            triage_engine   = self._triage_engine,
            broadcast_fn    = _broadcast,
        )

        app, self._ws_manager = create_app(
            settings         = self._settings,
            db               = self._db,
            orchestrator     = self._orchestrator,
            playbook_engine  = self._playbook_engine,
            triage_engine    = self._triage_engine,
            zmq_stats_fn     = lambda: self._zmq_subscriber.stats,
            started_at       = self._started_at,
        )

        self._pipeline = PipelineWorker(
            alert_queue  = self._alert_queue,
            orchestrator = self._orchestrator,
            ws_manager   = self._ws_manager,
            loop         = self._loop,
        )
        self._pipeline.start()

        @app.on_event("shutdown")
        async def on_shutdown() -> None:
            self.shutdown()

        return app

    def shutdown(self) -> None:
        logger.info("TalonResponse shutting down...")
        if self._zmq_subscriber:
            self._zmq_subscriber.stop()
        if self._pipeline:
            self._pipeline.stop()
        if self._pb_reload:
            self._pb_reload.stop()
        if self._db:
            self._db.close()
        logger.info("TalonResponse shutdown complete.")


# -- Entry Point --------------------------------------------------------------

def main() -> None:
    settings = Settings()
    _setup_logging(settings)

    app_instance = TalonResponse()
    app_instance.startup()
    app = app_instance.build_app()

    def _handle_signal(sig, frame):
        logger.info(f"Signal {sig} received - initiating shutdown.")
        app_instance.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    uvicorn.run(
        app,
        host      = settings.host,
        port      = settings.port,
        log_level = settings.log_level.lower(),
        reload    = False,
    )


if __name__ == "__main__":
    main()