"""
TalonResponse - Database Layer
database.py - DuckDB case index, schema management, case history

Author  : Rayyan Umair
Date    : 2026-05-22
Purpose : All storage operations for TalonResponse. DuckDB maintains
          a queryable index of all case files - metadata, status,
          action results, and evidence chains. The Markdown case files
          on disk are the immutable forensic artifacts. DuckDB is the
          index that makes them searchable.
          Nothing outside this file touches the database directly.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/TalonResponse

"Verify the threat. Execute the isolation. Preserve the evidence."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# -- Standard Library ---------------------------------------------------------
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Optional

# -- Third Party --------------------------------------------------------------
import duckdb

# -- Internal -----------------------------------------------------------------
from config.settings import Settings
from models.schemas import (
    ActionResult,
    ActionStatus,
    ActionType,
    AlertSeverity,
    CaseFile,
    EvidenceArtifact,
    EvidenceType,
    InboundAlert,
    IncidentStatus,
)

logger = logging.getLogger(__name__)


# -- Schema Definitions -------------------------------------------------------

_CASES_DDL = """
CREATE TABLE IF NOT EXISTS cases (
    case_id                     VARCHAR PRIMARY KEY,
    status                      VARCHAR     NOT NULL,
    detection_code              VARCHAR     NOT NULL,
    source_tool                 VARCHAR     NOT NULL,
    target_entity               VARCHAR     NOT NULL,
    severity                    VARCHAR     NOT NULL,
    is_admin                    BOOLEAN     DEFAULT FALSE,
    privilege_level             VARCHAR,
    source_host                 VARCHAR,

    matched_playbook_id         VARCHAR,
    matched_playbook_name       VARCHAR,

    action_count                INTEGER     DEFAULT 0,
    successful_actions          INTEGER     DEFAULT 0,
    evidence_count              INTEGER     DEFAULT 0,

    executed_actions            JSON,
    evidence_artifacts          JSON,
    volatile_triage_data        JSON,

    created_at                  TIMESTAMPTZ NOT NULL,
    contained_at                TIMESTAMPTZ,
    failed_at                   TIMESTAMPTZ,
    containment_delta_seconds   DOUBLE,

    case_file_path              VARCHAR,
    alert_id                    VARCHAR,
    raw_alert                   JSON,
    ai_summary                  TEXT,
    notes                       TEXT
);
"""

_ALERT_HISTORY_DDL = """
CREATE TABLE IF NOT EXISTS alert_history (
    alert_id        VARCHAR PRIMARY KEY,
    timestamp       TIMESTAMPTZ NOT NULL,
    source_tool     VARCHAR     NOT NULL,
    detection_code  VARCHAR     NOT NULL,
    target_entity   VARCHAR     NOT NULL,
    severity        VARCHAR     NOT NULL,
    is_admin        BOOLEAN     DEFAULT FALSE,
    case_id         VARCHAR,
    raw_payload     JSON
);
"""

_INDEXES_DDL = [
    "CREATE INDEX IF NOT EXISTS idx_cases_status         ON cases (status);",
    "CREATE INDEX IF NOT EXISTS idx_cases_detection      ON cases (detection_code);",
    "CREATE INDEX IF NOT EXISTS idx_cases_source         ON cases (source_tool);",
    "CREATE INDEX IF NOT EXISTS idx_cases_target         ON cases (target_entity);",
    "CREATE INDEX IF NOT EXISTS idx_cases_created        ON cases (created_at);",
    "CREATE INDEX IF NOT EXISTS idx_cases_severity       ON cases (severity);",
    "CREATE INDEX IF NOT EXISTS idx_alert_history_ts     ON alert_history (timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_alert_history_source ON alert_history (source_tool);",
    "CREATE INDEX IF NOT EXISTS idx_alert_history_code   ON alert_history (detection_code);",
]


# -- Database Manager ---------------------------------------------------------

class Database:
    """
    TalonResponse database manager.

    Wraps DuckDB for all read/write operations across two tables:
    cases and alert_history.

    The cases table is the primary index of all incident case files.
    The alert_history table records every inbound alert regardless
    of whether a playbook matched - useful for audit and tuning.

    One instance is created at startup and shared across the application.
    All methods are synchronous - DuckDB is not async-native.

    Usage:
        db = Database(settings)
        db.connect()
        db.upsert_case(case_file)
        db.close()
    """

    def __init__(self, settings: Settings) -> None:
        self._settings  = settings
        self._db_path   = settings.db_path
        self._conn      : Optional[duckdb.DuckDBPyConnection] = None
        self._connected : bool = False

    # -- Lifecycle ------------------------------------------------------------

    def connect(self) -> None:
        logger.info(f"Connecting to DuckDB at: {self._db_path}")
        try:
            self._conn = duckdb.connect(self._db_path)
            self._init_schema()
            self._connected = True
            logger.info("Database connected and schema verified.")
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._connected = False
            logger.info("Database connection closed.")

    def _init_schema(self) -> None:
        assert self._conn is not None
        self._conn.execute(_CASES_DDL)
        self._conn.execute(_ALERT_HISTORY_DDL)
        for idx in _INDEXES_DDL:
            self._conn.execute(idx)
        logger.debug("Schema initialised.")

    def _require_connection(self) -> None:
        if not self._connected or self._conn is None:
            raise RuntimeError(
                "Database.connect() must be called before any operations."
            )

    # -- Case Operations ------------------------------------------------------

    def upsert_case(self, case: CaseFile) -> None:
        """Insert or update a case record. Called on every state transition."""
        self._require_connection()
        assert self._conn is not None

        self._conn.execute("""
            INSERT OR REPLACE INTO cases VALUES (
                ?,?,?,?,?,?,?,?,?,
                ?,?,
                ?,?,?,
                ?,?,?,
                ?,?,?,?,
                ?,?,?,?,?
            )
        """, [
            case.case_id,
            case.status.value,
            case.trigger_alert.detection_code,
            case.trigger_alert.source_tool,
            case.trigger_alert.target_entity,
            case.trigger_alert.severity.value,
            case.trigger_alert.is_admin,
            case.trigger_alert.privilege_level,
            case.trigger_alert.source_host,

            case.matched_playbook_id,
            case.matched_playbook_name,

            case.action_count,
            case.successful_actions,
            case.evidence_count,

            json.dumps([a.model_dump(mode="json") for a in case.executed_actions]),
            json.dumps([e.model_dump(mode="json") for e in case.evidence_artifacts]),
            json.dumps(case.volatile_triage_data),

            case.created_at,
            case.contained_at,
            case.failed_at,
            case.containment_delta_seconds,

            case.case_file_path,
            case.trigger_alert.alert_id,
            json.dumps(case.trigger_alert.raw_payload),
            case.ai_summary,
            case.notes,
        ])

    def get_case(self, case_id: str) -> Optional[dict]:
        """Fetch a single case by ID."""
        self._require_connection()
        assert self._conn is not None
        rows = (
            self._conn
            .execute("SELECT * FROM cases WHERE case_id = ?", [case_id])
            .fetchdf()
            .to_dict(orient="records")
        )
        return rows[0] if rows else None

    def get_cases(
        self,
        status          : Optional[IncidentStatus] = None,
        source_tool     : Optional[str]            = None,
        detection_code  : Optional[str]            = None,
        target_entity   : Optional[str]            = None,
        since           : Optional[datetime]       = None,
        admin_only      : bool                     = False,
        limit           : int                      = 200,
    ) -> List[dict]:
        """Fetch cases with optional filters."""
        self._require_connection()
        assert self._conn is not None

        query  = "SELECT * FROM cases WHERE 1=1"
        params : list = []

        if status:
            query += " AND status = ?"
            params.append(status.value)
        if source_tool:
            query += " AND source_tool = ?"
            params.append(source_tool)
        if detection_code:
            query += " AND detection_code = ?"
            params.append(detection_code)
        if target_entity:
            query += " AND target_entity = ?"
            params.append(target_entity)
        if since:
            query += " AND created_at >= ?"
            params.append(since)
        if admin_only:
            query += " AND is_admin = TRUE"

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        return (
            self._conn.execute(query, params)
            .fetchdf()
            .to_dict(orient="records")
        )

    def get_case_count_by_status(self) -> dict:
        """Return case counts grouped by status."""
        self._require_connection()
        assert self._conn is not None
        rows = self._conn.execute("""
            SELECT status, COUNT(*) as count
            FROM cases
            GROUP BY status
            ORDER BY count DESC
        """).fetchall()
        return {row[0]: row[1] for row in rows}

    def get_case_count_by_detection(self) -> dict:
        """Return case counts grouped by detection code."""
        self._require_connection()
        assert self._conn is not None
        rows = self._conn.execute("""
            SELECT detection_code, COUNT(*) as count
            FROM cases
            GROUP BY detection_code
            ORDER BY count DESC
            LIMIT 20
        """).fetchall()
        return {row[0]: row[1] for row in rows}

    def get_avg_containment_delta(self) -> Optional[float]:
        """Return average containment delta in seconds across all contained cases."""
        self._require_connection()
        assert self._conn is not None
        row = self._conn.execute("""
            SELECT AVG(containment_delta_seconds)
            FROM cases
            WHERE status = 'contained'
            AND containment_delta_seconds IS NOT NULL
        """).fetchone()
        if row and row[0] is not None:
            return round(float(row[0]), 3)
        return None

    def get_recent_contained_cases(self, limit: int = 10) -> List[dict]:
        """Return the most recently contained cases."""
        self._require_connection()
        assert self._conn is not None
        return (
            self._conn
            .execute("""
                SELECT * FROM cases
                WHERE status = 'contained'
                ORDER BY contained_at DESC
                LIMIT ?
            """, [limit])
            .fetchdf()
            .to_dict(orient="records")
        )

    # -- Alert History Operations ---------------------------------------------

    def insert_alert_history(self, alert: InboundAlert, case_id: Optional[str] = None) -> None:
        """Record every inbound alert regardless of playbook match."""
        self._require_connection()
        assert self._conn is not None
        self._conn.execute("""
            INSERT OR REPLACE INTO alert_history VALUES (
                ?,?,?,?,?,?,?,?,?
            )
        """, [
            alert.alert_id,
            alert.timestamp,
            alert.source_tool,
            alert.detection_code,
            alert.target_entity,
            alert.severity.value,
            alert.is_admin,
            case_id,
            json.dumps(alert.raw_payload),
        ])

    def get_alert_history(
        self,
        source_tool     : Optional[str]     = None,
        detection_code  : Optional[str]     = None,
        since           : Optional[datetime]= None,
        limit           : int               = 200,
    ) -> List[dict]:
        self._require_connection()
        assert self._conn is not None

        query  = "SELECT * FROM alert_history WHERE 1=1"
        params : list = []

        if source_tool:
            query += " AND source_tool = ?"
            params.append(source_tool)
        if detection_code:
            query += " AND detection_code = ?"
            params.append(detection_code)
        if since:
            query += " AND timestamp >= ?"
            params.append(since)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        return (
            self._conn.execute(query, params)
            .fetchdf()
            .to_dict(orient="records")
        )

    # -- Investigation Query --------------------------------------------------

    def investigation_query(self, sql: str) -> List[dict]:
        """
        Execute a raw SQL SELECT for analyst investigation.
        SELECT only - mutations are blocked.
        """
        self._require_connection()
        assert self._conn is not None
        if not sql.strip().upper().startswith("SELECT"):
            raise ValueError("investigation_query only permits SELECT statements.")
        return (
            self._conn.execute(sql)
            .fetchdf()
            .to_dict(orient="records")
        )

    # -- Stats ----------------------------------------------------------------

    def get_stats(self) -> dict:
        self._require_connection()
        assert self._conn is not None

        total = self._conn.execute(
            "SELECT COUNT(*) FROM cases"
        ).fetchone()[0]

        contained = self._conn.execute(
            "SELECT COUNT(*) FROM cases WHERE status = 'contained'"
        ).fetchone()[0]

        failed = self._conn.execute(
            "SELECT COUNT(*) FROM cases WHERE status = 'failed'"
        ).fetchone()[0]

        processing = self._conn.execute(
            "SELECT COUNT(*) FROM cases WHERE status = 'processing'"
        ).fetchone()[0]

        admin_cases = self._conn.execute(
            "SELECT COUNT(*) FROM cases WHERE is_admin = TRUE"
        ).fetchone()[0]

        alerts_total = self._conn.execute(
            "SELECT COUNT(*) FROM alert_history"
        ).fetchone()[0]

        avg_delta = self.get_avg_containment_delta()

        return {
            "cases_total"               : total,
            "cases_contained"           : contained,
            "cases_failed"              : failed,
            "cases_processing"          : processing,
            "cases_involving_admins"    : admin_cases,
            "alerts_received_total"     : alerts_total,
            "avg_containment_delta_secs": avg_delta,
        }