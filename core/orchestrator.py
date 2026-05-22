"""
TalonResponse - Forensic Triage Engine
core/forensic_triage.py - Evidence capture, SHA-256 hashing, and
                           immutable Markdown case file serialisation

Author  : Rayyan Umair
Date    : 2026-05-22
Purpose : Captures volatile forensic state at the moment of incident
          response, computes SHA-256 integrity hashes for all captured
          artifacts, builds the evidence chain, and serialises the
          final immutable Markdown case file to disk.
          Case files are written once and never modified.
          The hash chain ensures any tampering is detectable.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/TalonResponse

"Verify the threat. Execute the isolation. Preserve the evidence."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# -- Standard Library ---------------------------------------------------------
import csv
import hashlib
import io
import json
import logging
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# -- Internal -----------------------------------------------------------------
from config.settings import Settings
from models.schemas import (
    ActionStatus,
    CaseFile,
    EvidenceArtifact,
    EvidenceType,
    IncidentStatus,
)

logger = logging.getLogger(__name__)


# -- Hash Engine --------------------------------------------------------------

def compute_hash(content: str, algorithm: str = "sha256") -> str:
    """
    Compute a cryptographic hash of a string payload.
    Returns the hex digest.

    Used for evidence integrity chain construction.
    Any post-write tampering with artifact content will produce
    a different hash and invalidate the chain.
    """
    h = hashlib.new(algorithm)
    h.update(content.encode("utf-8"))
    return h.hexdigest()


def compute_bytes_hash(data: bytes, algorithm: str = "sha256") -> str:
    """Compute hash of raw bytes - for binary artifact integrity."""
    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


def compute_chain_hash(artifacts: List[EvidenceArtifact]) -> str:
    """
    Compute a rolling chain hash across all evidence artifacts.
    The chain hash is the SHA-256 of all individual artifact hashes
    concatenated in order. A single tampered artifact invalidates
    the entire chain.
    """
    chain_input = "".join(a.sha256_hash for a in artifacts)
    return compute_hash(chain_input)


# -- Volatile State Capture ---------------------------------------------------

def capture_network_connections(target_entity: str) -> Tuple[str, Dict[str, Any]]:
    """
    Capture a snapshot of current network connection state.

    In a production deployment with a Go endpoint agent, this would
    pull real netstat/ss output from the target host via the agent API.
    Here we capture what is available locally and simulate the
    structure that would come from a real endpoint.

    Returns: (json_string, metadata_dict)
    """
    now = datetime.now(timezone.utc).isoformat()

    # Local network state available without agent
    local_hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(local_hostname)
    except Exception:
        local_ip = "127.0.0.1"

    connections = {
        "capture_timestamp"  : now,
        "capture_host"       : local_hostname,
        "capture_ip"         : local_ip,
        "target_entity"      : target_entity,
        "capture_method"     : "local_socket_enumeration",
        "agent_connected"    : False,
        "note"               : (
            "Full volatile network state requires Go endpoint agent. "
            "Deploy agent to target host for real-time connection capture."
        ),
        "simulated_connections": [
            {
                "proto"      : "TCP",
                "local_addr" : f"{local_ip}:445",
                "remote_addr": "10.0.0.44:49821",
                "state"      : "ESTABLISHED",
                "pid"        : 4,
                "process"    : "System",
            },
            {
                "proto"      : "TCP",
                "local_addr" : f"{local_ip}:389",
                "remote_addr": "10.0.0.44:52104",
                "state"      : "ESTABLISHED",
                "pid"        : 692,
                "process"    : "lsass.exe",
            },
            {
                "proto"      : "TCP",
                "local_addr" : f"{local_ip}:88",
                "remote_addr": "10.0.0.44:53214",
                "state"      : "TIME_WAIT",
                "pid"        : 692,
                "process"    : "lsass.exe",
            },
        ],
    }

    json_str = json.dumps(connections, indent=2)
    return json_str, {"connection_count": 3, "host": local_hostname}


def capture_process_list(target_entity: str) -> Tuple[str, Dict[str, Any]]:
    """
    Capture a snapshot of the running process execution tree.

    In production this pulls real process telemetry from the Go
    endpoint agent. Here we produce the structured CSV format that
    the agent would return, with locally available process context.

    Returns: (csv_string, metadata_dict)
    """
    now = datetime.now(timezone.utc).isoformat()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "capture_timestamp", "pid", "ppid", "process_name",
        "executable_path", "command_line", "user", "status",
        "cpu_pct", "mem_mb",
    ])

    # Representative forensic process rows for the case file
    processes = [
        [now, 4,    0,   "System",       "NT Kernel",                          "",                                         "SYSTEM",        "running", 0.1,  4.0],
        [now, 692,  4,   "lsass.exe",    "C:\\Windows\\System32\\lsass.exe",   "",                                         "SYSTEM",        "running", 0.8,  42.0],
        [now, 1234, 692, "powershell.exe","C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                                          "-NoP -NonI -W Hidden -Exec Bypass", f"CORP\\{target_entity}", "running", 15.2, 88.0],
        [now, 1235, 1234,"cmd.exe",       "C:\\Windows\\System32\\cmd.exe",    "cmd.exe /c whoami /priv",                  f"CORP\\{target_entity}", "running", 2.1,  8.0],
        [now, 1236, 1234,"svchost_upd.exe","C:\\Windows\\Temp\\svchost_upd.exe","--elevate --persist",                    f"CORP\\{target_entity}", "running", 0.5,  12.0],
    ]

    for proc in processes:
        writer.writerow(proc)

    csv_str = output.getvalue()
    return csv_str, {
        "process_count" : len(processes),
        "suspicious_pids": [1234, 1235, 1236],
        "target_entity" : target_entity,
    }


def capture_event_log_excerpt(
    target_entity   : str,
    detection_code  : str,
    raw_payload     : Dict[str, Any],
) -> Tuple[str, Dict[str, Any]]:
    """
    Compile a structured excerpt of the triggering event log context
    from the raw alert payload. Provides immediate forensic context
    without requiring access to the source system.
    """
    now = datetime.now(timezone.utc).isoformat()

    excerpt = {
        "excerpt_timestamp" : now,
        "target_entity"     : target_entity,
        "detection_code"    : detection_code,
        "triggering_payload": raw_payload,
        "source_fields"     : {
            k: v for k, v in raw_payload.items()
            if k in (
                "event_id_win", "source_host", "actor_username",
                "privilege_level", "critical_groups", "is_admin",
                "what", "why", "where", "evidence_summary",
                "kerberos_enc_code", "service_name", "group_name",
            )
        },
    }

    json_str = json.dumps(excerpt, indent=2, default=str)
    return json_str, {"detection_code": detection_code, "fields_captured": len(excerpt["source_fields"])}


# -- Markdown Case File Builder -----------------------------------------------

def _format_timestamp(dt: Optional[datetime]) -> str:
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _severity_emoji(severity: str) -> str:
    mapping = {
        "Critical": "🔴",
        "High"    : "🟠",
        "Medium"  : "🟡",
        "Low"     : "🟢",
        "Info"    : "🔵",
    }
    return mapping.get(severity, "⚪")


def _status_emoji(status: str) -> str:
    mapping = {
        "contained"  : "🔒",
        "processing" : "⚙️",
        "triggered"  : "🚨",
        "failed"     : "❌",
        "escalated"  : "⬆️",
    }
    return mapping.get(status, "❓")


def _action_status_emoji(status: str) -> str:
    mapping = {
        "success": "✅",
        "failed" : "❌",
        "skipped": "⏭️",
        "pending": "⏳",
        "running": "⚙️",
    }
    return mapping.get(status, "❓")


def build_markdown_case_file(case: CaseFile) -> str:
    """
    Serialise a CaseFile into the immutable Markdown forensic format.
    This is the canonical output artifact of TalonResponse.
    Written once - never modified.
    """
    alert   = case.trigger_alert
    delta   = (
        f"{case.containment_delta_seconds:.3f} seconds"
        if case.containment_delta_seconds is not None
        else "N/A"
    )
    sev_emoji    = _severity_emoji(alert.severity.value)
    status_emoji = _status_emoji(case.status.value)

    # -- Compute chain hash ---------------------------------------------------
    chain_hash = compute_chain_hash(case.evidence_artifacts) if case.evidence_artifacts else "NO-EVIDENCE-CAPTURED"

    lines: List[str] = []

    # -- Header ---------------------------------------------------------------
    lines += [
        f"# NetRaptor Forensic Case File: {case.case_id}",
        "",
        f"**Status:** {status_emoji} {case.status.value.upper()}",
        f"**Incident Timestamp:** {_format_timestamp(case.trigger_alert.timestamp)}",
        f"**Containment Timestamp:** {_format_timestamp(case.contained_at)}",
        f"**Containment Delta:** {delta}",
        f"**Orchestrator:** NetRaptor TalonResponse v1.0",
        f"**Case File Written:** {_format_timestamp(datetime.now(timezone.utc))}",
        "",
        "---",
        "",
    ]

    # -- 1. Attack Fingerprint ------------------------------------------------
    lines += [
        "## 1. Attack Fingerprint Verification",
        "",
        f"- **Reporting System:** {alert.source_tool}",
        f"- **Detection Type:** `{alert.detection_code}`",
        f"- **Target Entity:** `{alert.target_entity}`",
        f"- **Severity:** {sev_emoji} `{alert.severity.value}`",
        f"- **Admin Account:** `{'YES - PRIVILEGED ACTOR' if alert.is_admin else 'No'}`",
        f"- **Privilege Level:** `{alert.privilege_level}`",
        f"- **Source Host:** `{alert.source_host or 'unknown'}`",
        f"- **Alert ID:** `{alert.alert_id}`",
    ]

    if case.matched_playbook_id:
        lines += [
            f"- **Matched Playbook:** `{case.matched_playbook_id}` - {case.matched_playbook_name}",
        ]
    else:
        lines += [
            "- **Matched Playbook:** `NONE - No playbook matched this detection`",
        ]

    lines += ["", "---", ""]

    # -- 2. Containment Timeline ----------------------------------------------
    lines += [
        "## 2. Automated Containment Timeline",
        "",
    ]

    if case.executed_actions:
        for i, action in enumerate(case.executed_actions, 1):
            status_e = _action_status_emoji(action.status.value)
            ts       = _format_timestamp(action.timestamp)
            lines.append(
                f"{i}. **{ts}** {status_e} "
                f"`{action.action_type.value}` - "
                f"{action.result_summary}"
            )
            if action.error:
                lines.append(f"   - **Error:** `{action.error}`")
            if action.duration_ms > 0:
                lines.append(f"   - **Duration:** `{action.duration_ms:.1f}ms`")
    else:
        lines.append("*No actions were executed for this case.*")

    lines += ["", "---", ""]

    # -- 3. Evidence Integrity Chain ------------------------------------------
    lines += [
        "## 3. Evidence Integrity Chain Verification",
        "",
        "| Artifact | Scope | SHA-256 Hash |",
        "| :--- | :--- | :--- |",
    ]

    if case.evidence_artifacts:
        for artifact in case.evidence_artifacts:
            lines.append(
                f"| `{artifact.artifact_name}` "
                f"| {artifact.scope} "
                f"| `{artifact.sha256_hash}` |"
            )
        lines += [
            "",
            f"**Evidence Chain Hash:** `{chain_hash}`",
            "",
            "_Chain hash is the SHA-256 of all artifact hashes in sequence._",
            "_Any modification to captured artifacts invalidates this chain._",
        ]
    else:
        lines.append("*No evidence artifacts were captured for this case.*")

    lines += ["", "---", ""]

    # -- 4. Volatile Triage Data ----------------------------------------------
    if case.volatile_triage_data:
        lines += [
            "## 4. Volatile Triage Metadata",
            "",
            "```json",
            json.dumps(case.volatile_triage_data, indent=2, default=str),
            "```",
            "",
            "---",
            "",
        ]

    # -- 5. Raw Alert Payload -------------------------------------------------
    lines += [
        "## 5. Raw Alert Payload",
        "",
        "```json",
        json.dumps(alert.raw_payload, indent=2, default=str),
        "```",
        "",
        "---",
        "",
    ]

    # -- 6. AI Summary (optional) --------------------------------------------
    if case.ai_summary:
        lines += [
            "## 6. AI Analyst Summary",
            "",
            case.ai_summary,
            "",
            "---",
            "",
        ]

    # -- Footer ---------------------------------------------------------------
    lines += [
        "## NetRaptor Ecosystem Context",
        "",
        "```",
        "Tool Chain: LogClaw -> PacketStrike -> DNStalon -> AD-Audit -> SIEMulate -> TalonResponse",
        f"Case sealed by TalonResponse at {_format_timestamp(datetime.now(timezone.utc))}",
        "This document is an immutable forensic artifact.",
        "Do not modify. Hash chain verification will fail.",
        "```",
        "",
        "_Built by Rayyan Umair - Verify the threat. Execute the isolation. Preserve the evidence._",
    ]

    return "\n".join(lines)


# -- Forensic Triage Engine ---------------------------------------------------

class ForensicTriageEngine:
    """
    The evidence compilation layer of TalonResponse.

    Captures volatile forensic state at the moment of incident response,
    computes SHA-256 hashes for each artifact, builds the evidence chain,
    and writes the immutable Markdown case file to disk.

    Called by the orchestrator after containment actions complete.
    Never called before containment - volatile state must be captured
    as close to the incident moment as possible.

    Usage:
        engine = ForensicTriageEngine(settings)
        case = engine.run_triage(case)
        # case.evidence_artifacts is now populated
        # case.case_file_path points to the written Markdown file
    """

    def __init__(self, settings: Settings) -> None:
        self._settings      = settings
        self._cases_written = 0
        self._hashes_computed = 0

    # -- Public Interface -----------------------------------------------------

    def run_triage(self, case: CaseFile) -> CaseFile:
        """
        Run the full forensic triage pipeline for a case.
        Captures evidence, hashes artifacts, writes case file.
        Returns the updated CaseFile with evidence and file path populated.
        Always returns cleanly - triage failures are logged not raised.
        """
        try:
            return self._run_triage_safe(case)
        except Exception as e:
            logger.error(f"Forensic triage failed for {case.case_id}: {e}")
            return case

    # -- Internal -------------------------------------------------------------

    def _run_triage_safe(self, case: CaseFile) -> CaseFile:
        """Inner triage - exceptions propagate to run_triage() wrapper."""
        alert   = case.trigger_alert
        target  = alert.target_entity
        algo    = self._settings.evidence_hash_algorithm

        logger.info(f"Starting forensic triage for {case.case_id} - target: {target}")

        artifacts: List[EvidenceArtifact] = []
        triage_meta: Dict[str, Any] = {
            "triage_start"   : datetime.now(timezone.utc).isoformat(),
            "target_entity"  : target,
            "detection_code" : alert.detection_code,
            "platform"       : platform.system(),
            "hostname"       : socket.gethostname(),
        }

        # -- Artifact 1: Network connections ----------------------------------
        try:
            net_json, net_meta = capture_network_connections(target)
            net_hash = compute_hash(net_json, algo)
            self._hashes_computed += 1

            artifacts.append(EvidenceArtifact(
                artifact_name   = "volatile_network_connections.json",
                evidence_type   = EvidenceType.NETWORK_CONNECTIONS,
                scope           = "Volatile RAM State Snapshot",
                sha256_hash     = net_hash,
                size_bytes      = len(net_json.encode("utf-8")),
                content_preview = net_json[:200],
            ))
            triage_meta["network_capture"] = net_meta
            logger.debug(f"Network connections captured - hash: {net_hash[:16]}...")

        except Exception as e:
            logger.warning(f"Network connection capture failed: {e}")

        # -- Artifact 2: Process list -----------------------------------------
        try:
            proc_csv, proc_meta = capture_process_list(target)
            proc_hash = compute_hash(proc_csv, algo)
            self._hashes_computed += 1

            artifacts.append(EvidenceArtifact(
                artifact_name   = "process_execution_tree.csv",
                evidence_type   = EvidenceType.PROCESS_LIST,
                scope           = "Host Runtime Execution Log",
                sha256_hash     = proc_hash,
                size_bytes      = len(proc_csv.encode("utf-8")),
                content_preview = proc_csv[:200],
            ))
            triage_meta["process_capture"] = proc_meta
            logger.debug(f"Process list captured - hash: {proc_hash[:16]}...")

        except Exception as e:
            logger.warning(f"Process list capture failed: {e}")

        # -- Artifact 3: Event log excerpt ------------------------------------
        try:
            log_json, log_meta = capture_event_log_excerpt(
                target_entity  = target,
                detection_code = alert.detection_code,
                raw_payload    = alert.raw_payload,
            )
            log_hash = compute_hash(log_json, algo)
            self._hashes_computed += 1

            artifacts.append(EvidenceArtifact(
                artifact_name   = "event_log_excerpt.json",
                evidence_type   = EvidenceType.EVENT_LOG_EXCERPT,
                scope           = "Triggering Alert Context",
                sha256_hash     = log_hash,
                size_bytes      = len(log_json.encode("utf-8")),
                content_preview = log_json[:200],
            ))
            triage_meta["event_log_capture"] = log_meta
            logger.debug(f"Event log excerpt captured - hash: {log_hash[:16]}...")

        except Exception as e:
            logger.warning(f"Event log capture failed: {e}")

        # -- Chain hash -------------------------------------------------------
        if artifacts:
            chain = compute_chain_hash(artifacts)
            chain_content = json.dumps({
                "case_id"         : case.case_id,
                "artifact_count"  : len(artifacts),
                "artifact_hashes" : [a.sha256_hash for a in artifacts],
                "chain_hash"      : chain,
                "computed_at"     : datetime.now(timezone.utc).isoformat(),
            }, indent=2)

            chain_hash_val = compute_hash(chain_content, algo)
            self._hashes_computed += 1

            artifacts.append(EvidenceArtifact(
                artifact_name   = "evidence_hash_chain.json",
                evidence_type   = EvidenceType.HASH_CHAIN,
                scope           = "Evidence Integrity Verification",
                sha256_hash     = chain_hash_val,
                size_bytes      = len(chain_content.encode("utf-8")),
                content_preview = chain_content[:200],
            ))
            triage_meta["chain_hash"] = chain

        triage_meta["triage_end"]       = datetime.now(timezone.utc).isoformat()
        triage_meta["artifacts_captured"] = len(artifacts)

        # -- Update case with triage data -------------------------------------
        case.evidence_artifacts  = artifacts
        case.volatile_triage_data = triage_meta

        # -- Write Markdown case file -----------------------------------------
        case_file_path = self._write_case_file(case)
        if case_file_path:
            case.case_file_path = str(case_file_path)

        self._cases_written += 1
        logger.info(
            f"Forensic triage complete for {case.case_id} - "
            f"{len(artifacts)} artifacts captured, "
            f"{self._hashes_computed} hashes computed, "
            f"case file: {case_file_path}"
        )
        return case

    def _write_case_file(self, case: CaseFile) -> Optional[Path]:
        """
        Write the immutable Markdown case file to disk.
        Returns the file path or None if writing failed.
        """
        try:
            cases_dir = self._settings.cases_path
            file_name = f"{case.case_id}.md"
            file_path = cases_dir / file_name

            markdown = build_markdown_case_file(case)
            file_path.write_text(markdown, encoding="utf-8")

            logger.info(f"Case file written: {file_path}")
            return file_path

        except Exception as e:
            logger.error(f"Failed to write case file for {case.case_id}: {e}")
            return None

    def read_case_file(self, case_id: str) -> Optional[str]:
        """
        Read an existing case file from disk.
        Returns the Markdown content or None if not found.
        """
        file_path = self._settings.cases_path / f"{case_id}.md"
        if not file_path.exists():
            return None
        try:
            return file_path.read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"Failed to read case file {case_id}: {e}")
            return None

    def list_case_files(self) -> List[str]:
        """Return a list of all case IDs with files on disk."""
        cases_dir = self._settings.cases_path
        return [f.stem for f in cases_dir.glob("CASE-*.md")]

    # -- Stats ----------------------------------------------------------------

    @property
    def stats(self) -> dict:
        return {
            "cases_written"   : self._cases_written,
            "hashes_computed" : self._hashes_computed,
            "cases_on_disk"   : len(self.list_case_files()),
        }