"""
TalonResponse - Data Models
models/schemas.py - Canonical Pydantic schemas for all internal data structures

Author  : Rayyan Umair
Date    : 2026-05-22
Purpose : Canonical data models for TalonResponse. Every layer of the
          pipeline communicates exclusively through these schemas.
          No raw dicts. No ad-hoc structures. No exceptions.
          If data moves between layers, it is one of these models.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/TalonResponse

"Verify the threat. Execute the isolation. Preserve the evidence."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# -- Standard Library ---------------------------------------------------------
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

# -- Third Party --------------------------------------------------------------
from pydantic import BaseModel, Field, field_validator


# -- Helpers ------------------------------------------------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _new_uuid() -> str:
    return str(uuid.uuid4())

def _generate_case_id() -> str:
    """
    Generate a human-readable case ID.
    Format: CASE-YYYY-XXXX where XXXX is 4 uppercase hex chars.
    Example: CASE-2026-A1B2
    """
    year      = datetime.now().strftime("%Y")
    random_id = uuid.uuid4().hex[:4].upper()
    return f"CASE-{year}-{random_id}"


# -- Enumerations -------------------------------------------------------------

class IncidentStatus(str, Enum):
    TRIGGERED   = "triggered"
    PROCESSING  = "processing"
    CONTAINED   = "contained"
    FAILED      = "failed"
    ESCALATED   = "escalated"


class ActionType(str, Enum):
    IDENTITY_LOCKDOWN       = "identity_lockdown"
    HOST_ISOLATION          = "host_isolation"
    GENERATE_FORENSIC_CASE  = "generate_forensic_case"
    NOTIFY_SIEMULATE        = "notify_siemulate"
    LOG_EVIDENCE            = "log_evidence"


class ActionStatus(str, Enum):
    PENDING     = "pending"
    RUNNING     = "running"
    SUCCESS     = "success"
    FAILED      = "failed"
    SKIPPED     = "skipped"


class AlertSeverity(str, Enum):
    INFO        = "Info"
    LOW         = "Low"
    MEDIUM      = "Medium"
    HIGH        = "High"
    CRITICAL    = "Critical"


class EvidenceType(str, Enum):
    NETWORK_CONNECTIONS = "volatile_network_connections"
    PROCESS_LIST        = "process_execution_tree"
    EVENT_LOG_EXCERPT   = "event_log_excerpt"
    HASH_CHAIN          = "evidence_hash_chain"
    CUSTOM              = "custom"


# -- Inbound Alert ------------------------------------------------------------

class InboundAlert(BaseModel):
    """
    A critical alert received from SIEMulate or AD-Audit over ZeroMQ.
    This is the trigger that initiates the TalonResponse pipeline.

    # NetRaptor integration hook:
    # InboundAlert maps to the NetRaptor universal alert schema.
    # When shared core is built, replace with NetRaptor alert format.
    """

    alert_id        : str           = Field(default_factory=_new_uuid)
    source_tool     : str           = Field(...,  description="Tool that generated this alert - AD-Audit, SIEMulate, DNStalon")
    detection_code  : str           = Field(...,  description="Detection type code e.g. AD-002, STRIKE-005, DNS-001")
    target_entity   : str           = Field(...,  description="Primary entity - username, IP, or host")
    severity        : AlertSeverity = Field(default=AlertSeverity.CRITICAL)
    raw_payload     : Dict[str, Any]= Field(default_factory=dict, description="Full alert payload from source tool")
    timestamp       : datetime      = Field(default_factory=_now_utc)
    is_admin        : bool          = Field(default=False, description="True if target entity holds admin privilege")
    privilege_level : str           = Field(default="unknown", description="Privilege level from AD-Audit handshake")
    source_host     : str           = Field(default="", description="Host that generated the alert")

    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_utc(cls, v):
        if isinstance(v, str):
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc)
        return v

    @property
    def is_ad_alert(self) -> bool:
        return self.source_tool.lower() in ("ad-audit", "ad_audit")

    @property
    def is_network_alert(self) -> bool:
        return self.source_tool.lower() in (
            "siemulate", "packetstrike", "dnstalon"
        )


# -- Playbook Models ----------------------------------------------------------

class PlaybookAction(BaseModel):
    """A single action within a playbook step sequence."""

    type        : ActionType        = Field(...,  description="Action type to execute")
    target      : str               = Field(default="target_entity", description="Which alert field to use as the action target")
    parameters  : Dict[str, Any]    = Field(default_factory=dict, description="Action-specific parameters")
    severity    : Optional[str]     = Field(default=None, description="Override severity for generate_forensic_case action")


class Playbook(BaseModel):
    """
    A parsed playbook entry loaded from a YAML file.
    Maps detection codes to ordered action sequences.
    """

    id              : str               = Field(...,  description="Unique playbook identifier e.g. PLAY-001")
    name            : str               = Field(...,  description="Human-readable playbook name")
    trigger_source  : str               = Field(...,  description="Source tool this playbook responds to")
    match_detections: List[str]         = Field(...,  description="Detection codes that trigger this playbook")
    actions         : List[PlaybookAction] = Field(default_factory=list)
    enabled         : bool              = Field(default=True)
    version         : str               = Field(default="1.0")

    def matches(self, source_tool: str, detection_code: str) -> bool:
        """Return True if this playbook matches the inbound alert."""
        source_match = (
            self.trigger_source.lower() == source_tool.lower() or
            self.trigger_source == "*"
        )
        return source_match and detection_code in self.match_detections


# -- Action Execution Record --------------------------------------------------

class ActionResult(BaseModel):
    """
    The outcome of a single playbook action execution.
    Stored in the CaseFile executed_actions list.
    """

    action_type     : ActionType    = Field(...)
    status          : ActionStatus  = Field(...)
    timestamp       : datetime      = Field(default_factory=_now_utc)
    target          : str           = Field(default="")
    duration_ms     : float         = Field(default=0.0, description="Execution time in milliseconds")
    result_summary  : str           = Field(default="", description="Human-readable outcome description")
    error           : Optional[str] = Field(default=None, description="Error message if status=failed")
    api_response    : Optional[Dict[str, Any]] = Field(default=None, description="Raw API response if applicable")


# -- Evidence Chain -----------------------------------------------------------

class EvidenceArtifact(BaseModel):
    """
    A single captured forensic artifact with its integrity hash.
    Part of the evidence chain in a CaseFile.
    """

    artifact_name   : str           = Field(...,  description="Human-readable artifact name")
    evidence_type   : EvidenceType  = Field(default=EvidenceType.CUSTOM)
    scope           : str           = Field(default="", description="Scope description e.g. Volatile RAM State Snapshot")
    sha256_hash     : str           = Field(...,  description="SHA-256 hash of the artifact content")
    captured_at     : datetime      = Field(default_factory=_now_utc)
    size_bytes      : int           = Field(default=0)
    content_preview : str           = Field(default="", description="First 200 chars of content for case file display")


# -- Case File ----------------------------------------------------------------

class CaseFile(BaseModel):
    """
    The primary output artifact of TalonResponse.
    One CaseFile is created per processed alert.
    Tracks the full lifecycle from trigger to containment.

    CaseFiles are written to disk as immutable Markdown files.
    The DuckDB index stores metadata for queryable history.

    # NetRaptor integration hook:
    # CaseFile is the terminal artifact of the NetRaptor pipeline.
    # When shared core is built, CaseFile feeds the NetRaptor
    # case management layer directly.
    """

    case_id             : str               = Field(default_factory=_generate_case_id)
    status              : IncidentStatus    = Field(default=IncidentStatus.TRIGGERED)
    trigger_alert       : InboundAlert      = Field(...)
    matched_playbook_id : Optional[str]     = Field(default=None)
    matched_playbook_name: Optional[str]    = Field(default=None)

    executed_actions    : List[ActionResult]    = Field(default_factory=list)
    evidence_artifacts  : List[EvidenceArtifact]= Field(default_factory=list)
    volatile_triage_data: Dict[str, Any]        = Field(default_factory=dict)

    created_at          : datetime          = Field(default_factory=_now_utc)
    contained_at        : Optional[datetime]= Field(default=None)
    failed_at           : Optional[datetime]= Field(default=None)

    containment_delta_seconds: Optional[float] = Field(
        default=None,
        description="Seconds from alert received to containment achieved",
    )

    case_file_path      : Optional[str]     = Field(
        default=None,
        description="Absolute path to the written Markdown case file",
    )

    ai_summary          : Optional[str]     = Field(default=None)
    notes               : str               = Field(default="")

    @property
    def is_contained(self) -> bool:
        return self.status == IncidentStatus.CONTAINED

    @property
    def is_failed(self) -> bool:
        return self.status == IncidentStatus.FAILED

    @property
    def action_count(self) -> int:
        return len(self.executed_actions)

    @property
    def successful_actions(self) -> int:
        return sum(
            1 for a in self.executed_actions
            if a.status == ActionStatus.SUCCESS
        )

    @property
    def evidence_count(self) -> int:
        return len(self.evidence_artifacts)

    def compute_delta(self) -> None:
        """Calculate and store containment delta timing."""
        if self.contained_at:
            delta = (self.contained_at - self.created_at).total_seconds()
            self.containment_delta_seconds = round(delta, 3)


# -- API Response Models ------------------------------------------------------

class CaseSummary(BaseModel):
    """Lightweight case representation for API list endpoints."""

    case_id             : str               = Field(...)
    status              : IncidentStatus    = Field(...)
    detection_code      : str               = Field(...)
    source_tool         : str               = Field(...)
    target_entity       : str               = Field(...)
    severity            : AlertSeverity     = Field(...)
    matched_playbook_id : Optional[str]     = Field(default=None)
    created_at          : datetime          = Field(...)
    contained_at        : Optional[datetime]= Field(default=None)
    containment_delta_seconds: Optional[float] = Field(default=None)
    action_count        : int               = Field(default=0)
    case_file_path      : Optional[str]     = Field(default=None)


class HealthResponse(BaseModel):
    """API health check response."""

    status              : str   = Field(default="ok")
    app_name            : str   = Field(...)
    version             : str   = Field(...)
    zmq_connected       : bool  = Field(...)
    playbooks_loaded    : int   = Field(...)
    cases_total         : int   = Field(...)
    cases_contained     : int   = Field(...)
    ai_enabled          : bool  = Field(...)
    uptime_seconds      : float = Field(...)
    enrichment_enabled  : bool  = Field(...)


class PlaybookSummary(BaseModel):
    """Lightweight playbook for API list endpoints."""

    id              : str       = Field(...)
    name            : str       = Field(...)
    trigger_source  : str       = Field(...)
    match_detections: List[str] = Field(...)
    action_count    : int       = Field(...)
    enabled         : bool      = Field(...)
    version         : str       = Field(...)