"""
TalonResponse - Playbook Engine
core/playbook_engine.py - YAML playbook loading, parsing, and matching

Author  : Rayyan Umair
Date    : 2026-05-22
Purpose : Loads YAML playbook files from the playbook directory, parses
          them into typed Playbook models, and matches inbound alerts
          to the correct playbook based on source tool and detection
          code. Supports hot-reload without service restart.
          No action execution lives here. No case logic lives here.
          This layer only routes - it does not act.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/TalonResponse

"Verify the threat. Execute the isolation. Preserve the evidence."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# -- Standard Library ---------------------------------------------------------
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional

# -- Third Party --------------------------------------------------------------
import yaml

# -- Internal -----------------------------------------------------------------
from config.settings import Settings
from models.schemas import (
    ActionType,
    InboundAlert,
    Playbook,
    PlaybookAction,
)

logger = logging.getLogger(__name__)


# -- YAML Loader --------------------------------------------------------------

def _load_playbook_file(path: Path) -> List[Playbook]:
    """
    Parse a single YAML playbook file into a list of Playbook models.
    A single file may contain multiple playbook entries under the
    top-level 'playbooks' key.
    Returns an empty list if the file is malformed or unreadable.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        if not isinstance(raw, dict):
            logger.warning(f"Playbook file {path.name} is not a valid dict - skipping.")
            return []

        playbook_list = raw.get("playbooks", [])
        if not isinstance(playbook_list, list):
            logger.warning(f"Playbook file {path.name} has no 'playbooks' list - skipping.")
            return []

        parsed: List[Playbook] = []

        for entry in playbook_list:
            try:
                # Parse actions
                raw_actions = entry.get("actions", [])
                actions: List[PlaybookAction] = []

                for raw_action in raw_actions:
                    try:
                        action_type_str = raw_action.get("type", "")
                        # Normalise action type string to enum value
                        action_type = ActionType(action_type_str)
                        action = PlaybookAction(
                            type       = action_type,
                            target     = raw_action.get("target", "target_entity"),
                            parameters = raw_action.get("parameters", {}),
                            severity   = raw_action.get("severity"),
                        )
                        actions.append(action)
                    except ValueError as e:
                        logger.warning(
                            f"Unknown action type '{raw_action.get('type')}' "
                            f"in {path.name} - skipping action: {e}"
                        )

                playbook = Playbook(
                    id               = entry.get("id", f"PLAY-{len(parsed)+1:03d}"),
                    name             = entry.get("name", "Unnamed Playbook"),
                    trigger_source   = entry.get("trigger_source", "*"),
                    match_detections = entry.get("match_detections", []),
                    actions          = actions,
                    enabled          = entry.get("enabled", True),
                    version          = str(raw.get("version", "1.0")),
                )
                parsed.append(playbook)

                logger.debug(
                    f"Loaded playbook: {playbook.id} '{playbook.name}' "
                    f"- matches {playbook.match_detections}"
                )

            except Exception as e:
                logger.warning(f"Failed to parse playbook entry in {path.name}: {e}")

        return parsed

    except yaml.YAMLError as e:
        logger.error(f"YAML parse error in {path.name}: {e}")
        return []
    except Exception as e:
        logger.error(f"Failed to load playbook file {path.name}: {e}")
        return []


# -- Playbook Engine ----------------------------------------------------------

class PlaybookEngine:
    """
    The automation routing layer of TalonResponse.

    Loads all YAML playbook files from the configured playbook directory,
    parses them into typed Playbook models, and provides a fast lookup
    interface for matching inbound alerts to their correct playbook.

    Hot-reload is supported - the orchestrator calls reload() on a
    configurable interval so new or updated playbooks take effect
    without restarting the service.

    Thread safety: a single lock protects the playbook registry.

    Usage:
        engine = PlaybookEngine(settings)
        engine.load()
        playbook = engine.match(alert)
        if playbook:
            # execute playbook.actions
    """

    def __init__(self, settings: Settings) -> None:
        self._settings      = settings
        self._lock          = threading.RLock()
        self._playbooks     : Dict[str, Playbook] = {}
        self._loaded_at     = None
        self._load_count    = 0
        self._match_count   = 0
        self._no_match_count= 0

    # -- Lifecycle ------------------------------------------------------------

    def load(self) -> int:
        """
        Load all YAML playbook files from the playbook directory.
        Returns the number of playbooks successfully loaded.
        Called at startup and by the hot-reload scheduler.
        """
        from datetime import datetime, timezone
        playbook_path = self._settings.playbook_path

        if not playbook_path.exists():
            logger.warning(
                f"Playbook directory not found: {playbook_path}. "
                f"Creating directory - add YAML playbook files to enable automation."
            )
            playbook_path.mkdir(parents=True, exist_ok=True)
            return 0

        yaml_files = list(playbook_path.glob("*.yaml")) + list(playbook_path.glob("*.yml"))
        if not yaml_files:
            logger.warning(
                f"No YAML playbook files found in {playbook_path}. "
                f"TalonResponse will receive alerts but cannot execute actions."
            )
            return 0

        new_registry: Dict[str, Playbook] = {}
        loaded = 0
        failed = 0

        for path in yaml_files:
            playbooks = _load_playbook_file(path)
            for playbook in playbooks:
                if playbook.id in new_registry:
                    logger.warning(
                        f"Duplicate playbook ID '{playbook.id}' in {path.name} - "
                        f"overwriting previous entry."
                    )
                new_registry[playbook.id] = playbook
                loaded += 1

        with self._lock:
            self._playbooks  = new_registry
            self._loaded_at  = datetime.now(timezone.utc)
            self._load_count += 1

        enabled  = sum(1 for p in new_registry.values() if p.enabled)
        disabled = loaded - enabled

        logger.info(
            f"Playbooks loaded: {loaded} total "
            f"({enabled} enabled, {disabled} disabled) "
            f"from {playbook_path}"
        )
        return loaded

    def reload(self) -> int:
        """Hot-reload playbooks from disk. Called by the background scheduler."""
        logger.debug("Hot-reloading playbooks...")
        return self.load()

    # -- Matching -------------------------------------------------------------

    def match(self, alert: InboundAlert) -> Optional[Playbook]:
        """
        Find the first enabled playbook that matches the inbound alert.
        Matching is based on source_tool and detection_code.

        Returns the matched Playbook or None if no playbook matches.
        Logs a warning for unmatched alerts so operators can add coverage.
        """
        with self._lock:
            for playbook in self._playbooks.values():
                if not playbook.enabled:
                    continue
                if playbook.matches(alert.source_tool, alert.detection_code):
                    self._match_count += 1
                    logger.info(
                        f"Playbook matched: {playbook.id} '{playbook.name}' "
                        f"for {alert.source_tool}/{alert.detection_code} "
                        f"-> {alert.target_entity}"
                    )
                    return playbook

        self._no_match_count += 1
        logger.warning(
            f"No playbook matched for "
            f"source={alert.source_tool} "
            f"detection={alert.detection_code}. "
            f"Add a playbook entry to automate response to this detection type."
        )
        return None

    def match_all(self, alert: InboundAlert) -> List[Playbook]:
        """
        Return ALL enabled playbooks that match the inbound alert.
        Used when multiple playbooks should fire on the same detection.
        """
        matched: List[Playbook] = []
        with self._lock:
            for playbook in self._playbooks.values():
                if not playbook.enabled:
                    continue
                if playbook.matches(alert.source_tool, alert.detection_code):
                    matched.append(playbook)
        return matched

    # -- Management -----------------------------------------------------------

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        with self._lock:
            return self._playbooks.get(playbook_id)

    def get_all_playbooks(self) -> List[Playbook]:
        with self._lock:
            return list(self._playbooks.values())

    def enable_playbook(self, playbook_id: str) -> bool:
        with self._lock:
            if playbook_id in self._playbooks:
                self._playbooks[playbook_id].enabled = True
                logger.info(f"Playbook {playbook_id} enabled.")
                return True
            return False

    def disable_playbook(self, playbook_id: str) -> bool:
        with self._lock:
            if playbook_id in self._playbooks:
                self._playbooks[playbook_id].enabled = False
                logger.info(f"Playbook {playbook_id} disabled.")
                return True
            return False

    def get_coverage(self) -> Dict[str, List[str]]:
        """
        Return a map of detection_code -> [playbook_ids] showing
        which detections have playbook coverage.
        Useful for identifying gaps in automation.
        """
        coverage: Dict[str, List[str]] = {}
        with self._lock:
            for playbook in self._playbooks.values():
                if not playbook.enabled:
                    continue
                for code in playbook.match_detections:
                    if code not in coverage:
                        coverage[code] = []
                    coverage[code].append(playbook.id)
        return coverage

    # -- Stats ----------------------------------------------------------------

    @property
    def stats(self) -> dict:
        with self._lock:
            enabled = sum(1 for p in self._playbooks.values() if p.enabled)
        return {
            "playbooks_loaded"  : len(self._playbooks),
            "playbooks_enabled" : enabled,
            "load_count"        : self._load_count,
            "match_count"       : self._match_count,
            "no_match_count"    : self._no_match_count,
            "loaded_at"         : (
                self._loaded_at.isoformat() if self._loaded_at else None
            ),
        }