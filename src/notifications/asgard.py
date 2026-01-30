"""Asgard central monitoring server integration for Sirius AI agent."""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp
import structlog

from src.config import AsgardConfig, get_settings
from src.models.incident import Incident, RemediationAction


logger = structlog.get_logger()


@dataclass
class ApprovalStatus:
    """Status of an approval request from Asgard."""

    status: str  # pending, approved, rejected
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    reason: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> "ApprovalStatus":
        """Create ApprovalStatus from API response."""
        approved_at = None
        if data.get("approved_at"):
            try:
                approved_at = datetime.fromisoformat(data["approved_at"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        return cls(
            status=data.get("status", "pending"),
            approved_by=data.get("approved_by"),
            approved_at=approved_at,
            reason=data.get("reason"),
        )


class AsgardNotifier:
    """
    Sends incidents to Asgard central monitoring server and polls for approvals.

    This replaces the Slack-based notification/approval workflow with
    an integrated web dashboard approach.
    """

    def __init__(self, config: Optional[AsgardConfig] = None):
        if config is None:
            config = get_settings().asgard
        self._config = config
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create the HTTP session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self._config.timeout_seconds),
                headers={
                    "X-API-Key": self._config.api_key,
                    "Content-Type": "application/json",
                },
            )
        return self._session

    async def close(self):
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def _post(self, endpoint: str, payload: dict) -> Optional[aiohttp.ClientResponse]:
        """Make a POST request to Asgard."""
        url = f"{self._config.base_url.rstrip('/')}{endpoint}"
        try:
            session = await self._get_session()
            response = await session.post(url, json=payload)
            return response
        except aiohttp.ClientError as e:
            logger.error("Asgard request failed", endpoint=endpoint, error=str(e))
            return None
        except asyncio.TimeoutError:
            logger.error("Asgard request timed out", endpoint=endpoint)
            return None

    async def _get(self, endpoint: str) -> Optional[aiohttp.ClientResponse]:
        """Make a GET request to Asgard."""
        url = f"{self._config.base_url.rstrip('/')}{endpoint}"
        try:
            session = await self._get_session()
            response = await session.get(url)
            return response
        except aiohttp.ClientError as e:
            logger.error("Asgard request failed", endpoint=endpoint, error=str(e))
            return None
        except asyncio.TimeoutError:
            logger.error("Asgard request timed out", endpoint=endpoint)
            return None

    def _format_incident(self, incident: Incident) -> dict:
        """Format an incident for the Asgard webhook."""
        primary_alert = incident.primary_alert

        # Format alerts
        alerts = []
        for alert in incident.alerts:
            alerts.append({
                "alertname": alert.alertname,
                "severity": alert.severity.value if hasattr(alert.severity, 'value') else str(alert.severity),
                "status": alert.status.value if hasattr(alert.status, 'value') else str(alert.status),
                "instance": alert.instance,
                "job": alert.job,
                "description": alert.summary,
                "labels": alert.labels,
                "annotations": alert.annotations,
                "starts_at": alert.starts_at.isoformat() if alert.starts_at else None,
                "ends_at": alert.ends_at.isoformat() if alert.ends_at else None,
                "fingerprint": alert.fingerprint,
            })

        # Format actions
        actions = []
        for idx, action in enumerate(incident.recommended_actions):
            actions.append({
                "action_type": action.action_type,
                "description": action.reasoning,  # Use reasoning as description
                "target_host": action.target_host,
                "target_service": action.target_service,
                "command": action.command,
                "risk_level": action.risk_level,
                "status": "pending",
                "order_index": idx,
            })

        # Format investigation steps
        investigation_steps = []
        for step in incident.investigation_log:
            investigation_steps.append({
                "agent": step.agent,
                "action": step.action,
                "target": step.target,
                "result": step.result,
                "timestamp": step.timestamp.isoformat() if step.timestamp else None,
            })

        return {
            "incident_id": incident.id,
            "title": incident.title,
            "severity": incident.severity.value if hasattr(incident.severity, 'value') else str(incident.severity),
            "status": "awaiting_approval" if incident.recommended_actions else "analyzing",
            "root_cause": incident.root_cause,
            "root_cause_confidence": incident.root_cause_confidence,
            "affected_servers": incident.affected_servers,
            "affected_services": incident.affected_services,
            "detected_at": incident.detected_at.isoformat() if incident.detected_at else None,
            "analyzed_at": datetime.utcnow().isoformat(),
            "alerts": alerts,
            "actions": actions,
            "investigation_steps": investigation_steps,
        }

    async def send_incident(self, incident: Incident) -> bool:
        """
        Send an incident to Asgard central monitoring server.

        Args:
            incident: The incident to send

        Returns:
            True if successful, False otherwise
        """
        if not self._config.enabled:
            logger.debug("Asgard notifications disabled")
            return False

        payload = self._format_incident(incident)

        logger.info(
            "Sending incident to Asgard",
            incident_id=incident.id,
            title=incident.title,
            action_count=len(incident.recommended_actions),
        )

        response = await self._post("/api/v1/sirius/webhook/incident", payload)

        if response is None:
            logger.error("Failed to send incident to Asgard", incident_id=incident.id)
            return False

        if response.status == 200:
            logger.info("Incident sent to Asgard successfully", incident_id=incident.id)
            return True
        else:
            try:
                error = await response.json()
                logger.error(
                    "Asgard rejected incident",
                    incident_id=incident.id,
                    status=response.status,
                    error=error,
                )
            except Exception:
                logger.error(
                    "Asgard rejected incident",
                    incident_id=incident.id,
                    status=response.status,
                )
            return False

    async def check_approval_status(self, incident_id: str) -> ApprovalStatus:
        """
        Check the approval status of an incident.

        Args:
            incident_id: The incident ID to check

        Returns:
            ApprovalStatus with current status
        """
        response = await self._get(f"/api/v1/sirius/approval/{incident_id}")

        if response is None:
            return ApprovalStatus(status="pending", reason="Failed to connect to Asgard")

        if response.status == 200:
            data = await response.json()
            return ApprovalStatus.from_dict(data)
        elif response.status == 404:
            return ApprovalStatus(status="pending", reason="Incident not found in Asgard")
        else:
            return ApprovalStatus(status="pending", reason=f"Asgard returned status {response.status}")

    async def wait_for_approval(
        self,
        incident_id: str,
        timeout_minutes: int = 5,
    ) -> ApprovalStatus:
        """
        Poll Asgard for approval status until approved, rejected, or timeout.

        Args:
            incident_id: The incident ID to wait for
            timeout_minutes: Maximum time to wait

        Returns:
            Final ApprovalStatus
        """
        logger.info(
            "Waiting for approval from Asgard",
            incident_id=incident_id,
            timeout_minutes=timeout_minutes,
        )

        timeout_seconds = timeout_minutes * 60
        start_time = asyncio.get_event_loop().time()

        while True:
            # Check if timeout exceeded
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed >= timeout_seconds:
                logger.warning(
                    "Approval timeout reached",
                    incident_id=incident_id,
                    elapsed_seconds=int(elapsed),
                )
                return ApprovalStatus(status="rejected", reason="Approval timeout")

            # Check approval status
            status = await self.check_approval_status(incident_id)

            if status.status in ["approved", "rejected"]:
                logger.info(
                    "Approval decision received",
                    incident_id=incident_id,
                    status=status.status,
                    approved_by=status.approved_by,
                )
                return status

            # Wait before polling again
            await asyncio.sleep(self._config.poll_interval_seconds)

    async def send_execution_result(
        self,
        incident_id: str,
        action_id: int,
        status: str,
        output: str,
    ) -> bool:
        """
        Send action execution result to Asgard.

        Args:
            incident_id: The incident ID
            action_id: The action ID (order index)
            status: "success" or "failed"
            output: Command output or error message

        Returns:
            True if successful, False otherwise
        """
        if not self._config.enabled:
            return False

        payload = {
            "incident_id": incident_id,
            "action_id": action_id,
            "status": status,
            "output": output,
        }

        logger.info(
            "Sending execution result to Asgard",
            incident_id=incident_id,
            action_id=action_id,
            status=status,
        )

        response = await self._post("/api/v1/sirius/webhook/execution_result", payload)

        if response is None:
            logger.error("Failed to send execution result to Asgard")
            return False

        return response.status == 200

    async def update_incident_status(
        self,
        incident: Incident,
        status: str,
    ) -> bool:
        """
        Update incident status in Asgard.

        Args:
            incident: The incident to update
            status: New status

        Returns:
            True if successful, False otherwise
        """
        payload = self._format_incident(incident)
        payload["status"] = status

        response = await self._post("/api/v1/sirius/webhook/incident", payload)
        return response is not None and response.status == 200


# Global notifier instance
_asgard_notifier: Optional[AsgardNotifier] = None


def get_asgard_notifier() -> AsgardNotifier:
    """Get the global Asgard notifier instance."""
    global _asgard_notifier
    if _asgard_notifier is None:
        _asgard_notifier = AsgardNotifier()
    return _asgard_notifier


async def cleanup_asgard_notifier():
    """Cleanup the global Asgard notifier instance."""
    global _asgard_notifier
    if _asgard_notifier is not None:
        await _asgard_notifier.close()
        _asgard_notifier = None
