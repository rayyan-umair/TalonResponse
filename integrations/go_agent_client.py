"""
TalonResponse - Go Agent Client
integrations/go_agent_client.py - HMAC-signed isolation payload dispatch

Author  : Rayyan Umair
Date    : 2026-05-25
Purpose : Dispatches cryptographically signed isolation payloads to the
          Go endpoint agent running on target hosts. The agent applies
          firewall rules that isolate the host from all subnets except
          the management IP. Every payload is signed with HMAC-SHA256
          using the configured isolation signing key so the agent can
          verify authenticity before executing any network changes.
          When enrichment is disabled all calls are simulated.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/TalonResponse

"Verify the threat. Execute the isolation. Preserve the evidence."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Part of the NetRaptor ecosystem.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

# -- Standard Library ---------------------------------------------------------
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# -- Third Party --------------------------------------------------------------
import httpx

# -- Internal -----------------------------------------------------------------
from config.settings import Settings

logger = logging.getLogger(__name__)


# -- HMAC Token Builder -------------------------------------------------------

def build_isolation_token(
    payload     : Dict[str, Any],
    signing_key : str,
) -> str:
    """
    Build an HMAC-SHA256 signed token for an isolation payload.

    The token is computed as:
        HMAC-SHA256(signing_key, canonical_json_payload)

    The Go agent verifies this token before executing any firewall
    changes. An invalid or expired token is rejected silently.

    Returns the hex digest of the HMAC signature.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    token     = hmac.new(
        signing_key.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return token


def verify_token(
    payload     : Dict[str, Any],
    token       : str,
    signing_key : str,
) -> bool:
    """
    Verify an HMAC token against a payload.
    Used in testing to confirm the signing pipeline is correct.
    """
    expected = build_isolation_token(payload, signing_key)
    return hmac.compare_digest(expected, token)


# -- Go Agent Client ----------------------------------------------------------

class GoAgentClient:
    """
    Dispatches HMAC-signed network isolation payloads to the Go
    endpoint agent installed on target hosts.

    The Go agent listens on a configurable port and accepts signed
    isolation commands. On receipt of a valid command it:
      - Applies iptables/Windows Firewall rules
      - Drops all inbound and outbound traffic
      - Preserves a management IP for forensic access
      - Returns a signed acknowledgement

    In standalone mode (enrichment_enabled=False) all calls are
    simulated with full payload logging so the signing pipeline
    can be verified without a deployed agent.

    Usage:
        client = GoAgentClient(settings)
        result = client.isolate_host("10.0.0.44", allow_management_ip=True, case_id="CASE-2026-A1B2")
    """

    def __init__(self, settings: Settings) -> None:
        self._settings     = settings
        self._signing_key  = settings.isolation_signing_key
        self._agent_port   = settings.go_agent_port
        self._timeout      = settings.api_timeout_seconds
        self._calls_made   = 0
        self._calls_failed = 0

    def isolate_host(
        self,
        host_ip             : str,
        allow_management_ip : bool = True,
        case_id             : str  = "",
    ) -> Dict[str, Any]:
        """
        Dispatch a signed isolation command to the Go agent on the target host.
        Returns a result dict with success bool and detail fields.
        Never raises - all exceptions are caught and returned as failures.
        """
        self._calls_made += 1

        # Build isolation payload
        issued_at = int(time.time())
        expires_at = issued_at + self._settings.isolation_token_expiry_seconds

        payload = {
            "command"           : "ISOLATE_HOST",
            "target_ip"         : host_ip,
            "allow_management_ip": allow_management_ip,
            "case_id"           : case_id,
            "issued_at"         : issued_at,
            "expires_at"        : expires_at,
            "issued_by"         : "TalonResponse",
        }

        token = build_isolation_token(payload, self._signing_key)
        payload["hmac_token"] = token

        if not self._settings.enrichment_enabled:
            return self._simulate_isolation(host_ip, payload, token)

        agent_url = f"http://{host_ip}:{self._agent_port}/isolate"

        try:
            resp = httpx.post(
                agent_url,
                json    = payload,
                timeout = self._timeout,
            )

            if resp.status_code in (200, 202):
                logger.info(
                    f"Go agent isolation confirmed: "
                    f"host={host_ip} "
                    f"case={case_id} "
                    f"token={token[:16]}..."
                )
                return {
                    "success"           : True,
                    "host_ip"           : host_ip,
                    "isolated"          : True,
                    "management_preserved": allow_management_ip,
                    "token_prefix"      : token[:16],
                    "agent_status"      : resp.status_code,
                    "response"          : resp.json() if resp.content else {},
                }
            else:
                self._calls_failed += 1
                logger.error(
                    f"Go agent isolation failed: "
                    f"host={host_ip} "
                    f"status={resp.status_code}"
                )
                return {
                    "success"     : False,
                    "host_ip"     : host_ip,
                    "error"       : f"Agent returned HTTP {resp.status_code}",
                    "agent_status": resp.status_code,
                }

        except httpx.ConnectError:
            self._calls_failed += 1
            logger.error(
                f"Go agent unreachable at {agent_url} - "
                f"host isolation for '{host_ip}' could not be executed. "
                f"Deploy the Go agent to the target host."
            )
            return {
                "success": False,
                "host_ip": host_ip,
                "error"  : f"Go agent unreachable at {agent_url}",
            }
        except Exception as e:
            self._calls_failed += 1
            logger.error(f"Go agent exception for {host_ip}: {e}")
            return {
                "success": False,
                "host_ip": host_ip,
                "error"  : str(e),
            }

    def _simulate_isolation(
        self,
        host_ip : str,
        payload : Dict[str, Any],
        token   : str,
    ) -> Dict[str, Any]:
        """
        Simulate an isolation call when enrichment is disabled.
        Logs the full signed payload so the signing pipeline is verifiable.
        """
        logger.info(
            f"[SIMULATED] Go agent isolation - "
            f"host={host_ip} "
            f"token={token[:16]}... "
            f"payload_keys={list(payload.keys())} "
            f"(set ENRICHMENT_ENABLED=true to execute live)"
        )
        return {
            "success"           : True,
            "host_ip"           : host_ip,
            "isolated"          : True,
            "management_preserved": payload.get("allow_management_ip", True),
            "token_prefix"      : token[:16],
            "simulated"         : True,
            "note"              : "Isolation simulated - ENRICHMENT_ENABLED=false",
            "signed_payload"    : {
                k: v for k, v in payload.items()
                if k != "hmac_token"
            },
        }

    @property
    def stats(self) -> dict:
        return {
            "calls_made"   : self._calls_made,
            "calls_failed" : self._calls_failed,
            "agent_port"   : self._agent_port,
            "live_mode"    : self._settings.enrichment_enabled,
        }