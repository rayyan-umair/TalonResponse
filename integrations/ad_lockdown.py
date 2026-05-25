"""
TalonResponse - AD Lockdown Integration
integrations/ad_lockdown.py - Defensive callback client to AD-Audit

Author  : Rayyan Umair
Date    : 2026-05-25
Purpose : Sends account lockdown directives back to AD-Audit when a
          critical identity detection triggers a containment playbook.
          Calls the AD-Audit REST API to disable the actor account
          and revoke active Kerberos tickets.
          When enrichment is disabled all calls are simulated and
          logged so the pipeline remains fully testable without a
          live AD-Audit instance.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/TalonResponse

"Verify the threat. Execute the isolation. Preserve the evidence."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# -- Standard Library ---------------------------------------------------------
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# -- Third Party --------------------------------------------------------------
import httpx

# -- Internal -----------------------------------------------------------------
from config.settings import Settings

logger = logging.getLogger(__name__)


class ADLockdownClient:
    """
    Defensive callback client to AD-Audit.

    When a playbook fires an identity_lockdown action, this client
    calls the AD-Audit API to:
      - Disable the actor account
      - Revoke all active Kerberos tickets for the account

    In standalone mode (enrichment_enabled=False) all calls are
    simulated - the method logs what it would have done and returns
    a success response so the pipeline can be tested end-to-end
    without a live AD-Audit instance.

    Usage:
        client = ADLockdownClient(settings)
        result = client.disable_account("jsmith", disable=True, revoke_tickets=True)
    """

    def __init__(self, settings: Settings) -> None:
        self._settings  = settings
        self._base_url  = settings.ad_audit_api_url
        self._timeout   = settings.api_timeout_seconds
        self._calls_made = 0
        self._calls_failed = 0

    def disable_account(
        self,
        username        : str,
        disable         : bool = True,
        revoke_tickets  : bool = True,
    ) -> Dict[str, Any]:
        """
        Disable an AD account and optionally revoke Kerberos tickets.
        Returns a result dict with success bool and detail fields.
        Never raises - all exceptions are caught and returned as failures.
        """
        self._calls_made += 1

        if not self._settings.enrichment_enabled:
            return self._simulate_lockdown(username, disable, revoke_tickets)

        try:
            payload = {
                "username"      : username,
                "disable"       : disable,
                "revoke_tickets": revoke_tickets,
                "initiated_by"  : "TalonResponse",
                "timestamp"     : datetime.now(timezone.utc).isoformat(),
            }

            resp = httpx.post(
                f"{self._base_url}/entities/{username}/lockdown",
                json    = payload,
                timeout = self._timeout,
            )

            if resp.status_code in (200, 202):
                logger.info(
                    f"AD-Audit lockdown confirmed: "
                    f"username={username} "
                    f"disable={disable} "
                    f"revoke_tickets={revoke_tickets}"
                )
                return {
                    "success"       : True,
                    "username"      : username,
                    "disabled"      : disable,
                    "tickets_revoked": revoke_tickets,
                    "ad_audit_status": resp.status_code,
                    "response"      : resp.json() if resp.content else {},
                }
            else:
                self._calls_failed += 1
                logger.error(
                    f"AD-Audit lockdown failed: "
                    f"username={username} "
                    f"status={resp.status_code}"
                )
                return {
                    "success": False,
                    "username": username,
                    "error"  : f"AD-Audit returned HTTP {resp.status_code}",
                    "ad_audit_status": resp.status_code,
                }

        except httpx.ConnectError:
            self._calls_failed += 1
            logger.error(
                f"AD-Audit unreachable at {self._base_url} - "
                f"lockdown for '{username}' could not be executed. "
                f"Manual intervention required."
            )
            return {
                "success": False,
                "username": username,
                "error"  : f"AD-Audit unreachable at {self._base_url}",
            }
        except Exception as e:
            self._calls_failed += 1
            logger.error(f"AD lockdown exception for {username}: {e}")
            return {
                "success": False,
                "username": username,
                "error"  : str(e),
            }

    def _simulate_lockdown(
        self,
        username        : str,
        disable         : bool,
        revoke_tickets  : bool,
    ) -> Dict[str, Any]:
        """
        Simulate a lockdown call when enrichment is disabled.
        Logs exactly what would have been sent to AD-Audit.
        """
        logger.info(
            f"[SIMULATED] AD lockdown - "
            f"username={username} "
            f"disable={disable} "
            f"revoke_tickets={revoke_tickets} "
            f"target={self._base_url} "
            f"(set ENRICHMENT_ENABLED=true to execute live)"
        )
        return {
            "success"       : True,
            "username"      : username,
            "disabled"      : disable,
            "tickets_revoked": revoke_tickets,
            "simulated"     : True,
            "note"          : "Lockdown simulated - ENRICHMENT_ENABLED=false",
        }

    @property
    def stats(self) -> dict:
        return {
            "calls_made"  : self._calls_made,
            "calls_failed": self._calls_failed,
            "target_url"  : self._base_url,
            "live_mode"   : self._settings.enrichment_enabled,
        }