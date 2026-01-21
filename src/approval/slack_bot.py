"""Slack integration for approval workflows."""

import asyncio
import json
from datetime import datetime
from typing import Callable, Dict, Optional

import aiohttp
import structlog

from src.config import Settings, ApprovalConfig, get_settings
from src.models.incident import Incident, RemediationAction
from src.models.execution import ExecutionRecord, RiskLevel


logger = structlog.get_logger()


class ApprovalResult:
    """Result of an approval request."""

    def __init__(
        self,
        approved: bool,
        approved_by: Optional[str] = None,
        reason: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ):
        self.approved = approved
        self.approved_by = approved_by
        self.reason = reason
        self.timestamp = timestamp or datetime.utcnow()


class SlackApprovalBot:
    """
    Slack bot for requesting and handling approval workflows.

    Uses Slack's Block Kit for interactive messages with approve/reject buttons.
    """

    def __init__(self, config: ApprovalConfig):
        self._config = config
        self._pending_approvals: Dict[str, asyncio.Future] = {}

    async def request_approval(
        self,
        incident: Incident,
        action: RemediationAction,
        execution_record: ExecutionRecord,
    ) -> ApprovalResult:
        """
        Send an approval request to Slack and wait for response.

        Args:
            incident: The incident requiring remediation
            action: The proposed remediation action
            execution_record: The execution record for audit

        Returns:
            ApprovalResult with approval status
        """
        logger.info(
            "Requesting approval via Slack",
            incident_id=incident.id,
            action_type=action.action_type,
            target=action.target_host,
        )

        # Build the Slack message
        message = self._build_approval_message(incident, action)

        # Send to Slack
        message_ts = await self._send_message(message)

        if not message_ts:
            logger.error("Failed to send Slack message")
            return ApprovalResult(
                approved=False,
                reason="Failed to send approval request to Slack",
            )

        # Record that approval was requested
        execution_record.request_approval("slack", message_ts)

        # Wait for approval with timeout
        try:
            result = await asyncio.wait_for(
                self._wait_for_approval(message_ts),
                timeout=self._config.approval_timeout_minutes * 60,
            )
            return result
        except asyncio.TimeoutError:
            logger.warning(
                "Approval request timed out",
                incident_id=incident.id,
                message_ts=message_ts,
            )

            # Update message to show timeout
            await self._update_message_timeout(message_ts)

            return ApprovalResult(
                approved=False,
                reason="Approval request timed out",
            )

    def _build_approval_message(
        self,
        incident: Incident,
        action: RemediationAction,
    ) -> dict:
        """Build Slack Block Kit message for approval."""
        primary_alert = incident.primary_alert

        # Risk level emoji
        risk_emoji = {
            "low": ":large_green_circle:",
            "medium": ":large_yellow_circle:",
            "high": ":large_orange_circle:",
            "critical": ":red_circle:",
        }.get(action.risk_level, ":white_circle:")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":rotating_light: Remediation Approval Required",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Incident:*\n{incident.id}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{incident.severity.value.upper()}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Server:*\n{action.target_host}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Service:*\n{action.target_service or 'N/A'}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Alert:* {primary_alert.alertname if primary_alert else 'Unknown'}\n"
                           f"*Summary:* {primary_alert.summary if primary_alert else 'No summary'}",
                },
            },
            {
                "type": "divider",
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*AI Analysis:*",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f">{incident.root_cause or 'Analysis in progress...'}",
                },
            },
            {
                "type": "divider",
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommended Action:* `{action.action_type}`\n"
                           f"*Command:* `{action.command}`",
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk Level:* {risk_emoji} {action.risk_level.upper()}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Confidence:* {int(action.confidence * 100)}%",
                    },
                ],
            },
            {
                "type": "actions",
                "block_id": f"approval_{incident.id}",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": ":white_check_mark: Approve",
                            "emoji": True,
                        },
                        "style": "primary",
                        "action_id": "approve_action",
                        "value": json.dumps({
                            "incident_id": incident.id,
                            "action": "approve",
                        }),
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": ":x: Reject",
                            "emoji": True,
                        },
                        "style": "danger",
                        "action_id": "reject_action",
                        "value": json.dumps({
                            "incident_id": incident.id,
                            "action": "reject",
                        }),
                    },
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": ":mag: More Details",
                            "emoji": True,
                        },
                        "action_id": "details_action",
                        "value": json.dumps({
                            "incident_id": incident.id,
                            "action": "details",
                        }),
                    },
                ],
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f":hourglass: This request will timeout in {self._config.approval_timeout_minutes} minutes",
                    },
                ],
            },
        ]

        return {
            "channel": self._config.slack_channel,
            "text": f"Remediation approval required for {incident.id}",
            "blocks": blocks,
        }

    async def _send_message(self, message: dict) -> Optional[str]:
        """Send a message to Slack and return the message timestamp."""
        if not self._config.slack_bot_token:
            logger.warning("Slack bot token not configured, using webhook")
            return await self._send_via_webhook(message)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://slack.com/api/chat.postMessage",
                    headers={
                        "Authorization": f"Bearer {self._config.slack_bot_token}",
                        "Content-Type": "application/json",
                    },
                    json=message,
                ) as response:
                    result = await response.json()

                    if result.get("ok"):
                        return result.get("ts")
                    else:
                        logger.error(
                            "Slack API error",
                            error=result.get("error"),
                        )
                        return None

        except Exception as e:
            logger.error("Failed to send Slack message", error=str(e))
            return None

    async def _send_via_webhook(self, message: dict) -> Optional[str]:
        """Send a message via webhook (limited functionality)."""
        if not self._config.slack_webhook_url:
            logger.error("No Slack webhook URL configured")
            return None

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self._config.slack_webhook_url,
                    json=message,
                ) as response:
                    if response.status == 200:
                        # Webhooks don't return message ts
                        return "webhook-" + datetime.utcnow().isoformat()
                    else:
                        logger.error(
                            "Slack webhook error",
                            status=response.status,
                        )
                        return None

        except Exception as e:
            logger.error("Failed to send Slack webhook", error=str(e))
            return None

    async def _wait_for_approval(self, message_ts: str) -> ApprovalResult:
        """Wait for an approval response."""
        # Create a future to wait on
        future = asyncio.get_event_loop().create_future()
        self._pending_approvals[message_ts] = future

        try:
            result = await future
            return result
        finally:
            self._pending_approvals.pop(message_ts, None)

    async def _update_message_timeout(self, message_ts: str):
        """Update message to show timeout status."""
        # In production, this would update the Slack message
        logger.info("Marking approval request as timed out", message_ts=message_ts)

    def handle_interaction(self, payload: dict) -> Optional[ApprovalResult]:
        """
        Handle a Slack interaction (button click).

        This would be called by a webhook handler when Slack sends
        an interaction payload.
        """
        action = payload.get("actions", [{}])[0]
        action_id = action.get("action_id")
        value = json.loads(action.get("value", "{}"))
        user = payload.get("user", {}).get("name", "unknown")

        message_ts = payload.get("message", {}).get("ts")

        if action_id == "approve_action":
            result = ApprovalResult(
                approved=True,
                approved_by=user,
            )
        elif action_id == "reject_action":
            result = ApprovalResult(
                approved=False,
                approved_by=user,
                reason="Rejected by user",
            )
        else:
            return None

        # Resolve the pending future if exists
        if message_ts and message_ts in self._pending_approvals:
            self._pending_approvals[message_ts].set_result(result)

        return result


class ApprovalManager:
    """
    Manages the approval workflow for remediation actions.

    Determines whether actions need approval and handles the
    approval process via Slack or other channels.
    """

    def __init__(self, settings: Optional[Settings] = None):
        self._settings = settings or get_settings()
        self._config = self._settings.approval
        self._slack_bot = SlackApprovalBot(self._config)

    def requires_approval(self, action: RemediationAction) -> bool:
        """Check if an action requires human approval."""
        risk = action.risk_level.lower()

        if risk in self._config.auto_approve_risk_levels:
            return False

        if risk in self._config.require_approval_risk_levels:
            return True

        # Default to requiring approval for unknown risk levels
        return True

    async def request_approval(
        self,
        incident: Incident,
        action: RemediationAction,
        execution_record: ExecutionRecord,
    ) -> ApprovalResult:
        """
        Request approval for a remediation action.

        Args:
            incident: The incident requiring remediation
            action: The proposed remediation action
            execution_record: The execution record for audit

        Returns:
            ApprovalResult with approval status
        """
        if not self.requires_approval(action):
            logger.info(
                "Action auto-approved",
                incident_id=incident.id,
                action_type=action.action_type,
                risk_level=action.risk_level,
            )
            return ApprovalResult(
                approved=True,
                approved_by="auto",
                reason="Auto-approved based on risk level",
            )

        # Request approval via Slack
        return await self._slack_bot.request_approval(
            incident, action, execution_record
        )


# Global approval manager instance
_approval_manager: Optional[ApprovalManager] = None


def get_approval_manager(settings: Optional[Settings] = None) -> ApprovalManager:
    """Get the global approval manager instance."""
    global _approval_manager
    if _approval_manager is None:
        _approval_manager = ApprovalManager(settings)
    return _approval_manager
