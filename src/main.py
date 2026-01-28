"""DevOps On-Call Agent - Main Entry Point."""

import asyncio
import logging
import signal
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import aiohttp
import structlog
import uvicorn
from fastapi import FastAPI

from src.config import get_settings, Settings
from src.ingestion.webhook_server import router as webhook_router
from src.processing.event_processor import EventProcessor
from src.agents.crew import DevOpsCrew
from src.models.incident import Incident, RemediationAction
from src.models.execution import ExecutionRecord, ExecutionStatus
from src.remediation.executor import get_executor, RemediationExecutor


# Configure structured logging
def setup_logging(settings: Settings):
    """Configure structured logging based on settings."""
    log_level = getattr(logging, settings.logging.level.upper(), logging.INFO)

    if settings.logging.format == "json":
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )
    else:
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.dev.ConsoleRenderer(),
            ],
            wrapper_class=structlog.stdlib.BoundLogger,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=True,
        )

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )


# Global instances
event_processor: Optional[EventProcessor] = None
devops_crew: Optional[DevOpsCrew] = None
remediation_executor: Optional[RemediationExecutor] = None
logger = structlog.get_logger()


def _format_duration(seconds: float) -> str:
    """Format duration in human-readable format."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        mins = int(seconds / 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    else:
        hours = int(seconds / 3600)
        mins = int((seconds % 3600) / 60)
        return f"{hours}h {mins}m"


def _get_incident_age(incident: Incident) -> str:
    """Get incident age as human-readable string."""
    now = datetime.utcnow()
    delta = (now - incident.detected_at).total_seconds()
    return _format_duration(delta)


async def send_slack_notification(
    incident: Incident,
    webhook_url: str,
    execution_record: Optional[ExecutionRecord] = None,
    all_execution_records: Optional[list[ExecutionRecord]] = None,
    stage: str = "complete",
) -> bool:
    """Send a comprehensive Slack notification for an incident.

    Args:
        incident: The incident to notify about
        webhook_url: Slack webhook URL
        execution_record: The last/primary execution record
        all_execution_records: All execution records if multiple actions executed
        stage: Current stage - "analyzing", "awaiting_approval", "complete", "failed"
    """
    primary_alert = incident.primary_alert
    if not primary_alert:
        return False

    # Severity configuration
    severity_config = {
        "critical": (":rotating_light:", "#FF0000", "CRITICAL"),
        "high": (":red_circle:", "#FF6B6B", "HIGH"),
        "medium": (":large_orange_circle:", "#FFA500", "MEDIUM"),
        "low": (":large_yellow_circle:", "#FFD700", "LOW"),
        "info": (":large_blue_circle:", "#4A90D9", "INFO"),
    }
    sev_emoji, sev_color, sev_text = severity_config.get(
        incident.severity.value, (":white_circle:", "#808080", "UNKNOWN")
    )

    # Determine stage and header based on execution status
    if all_execution_records:
        # Check if any action was rejected (awaiting approval)
        rejected_count = sum(1 for r in all_execution_records if r.status == ExecutionStatus.REJECTED)
        success_count = sum(1 for r in all_execution_records if r.status == ExecutionStatus.SUCCESS)
        failed_count = sum(1 for r in all_execution_records if r.status == ExecutionStatus.FAILED)

        if rejected_count > 0 and success_count == 0 and failed_count == 0:
            stage_emoji = ":raised_hand:"
            stage_text = "AWAITING APPROVAL"
            stage_color = "#FFA500"
        elif failed_count > 0:
            stage_emoji = ":x:"
            stage_text = "REMEDIATION FAILED"
            stage_color = "#FF0000"
        elif success_count > 0 and success_count == len(incident.recommended_actions):
            stage_emoji = ":white_check_mark:"
            stage_text = "REMEDIATION COMPLETE"
            stage_color = "#36a64f"
        elif success_count > 0:
            stage_emoji = ":hourglass_flowing_sand:"
            stage_text = "REMEDIATION IN PROGRESS"
            stage_color = "#4A90D9"
        else:
            stage_emoji = ":raised_hand:"
            stage_text = "AWAITING APPROVAL"
            stage_color = "#FFA500"
    elif execution_record:
        if execution_record.status == ExecutionStatus.SUCCESS:
            stage_emoji = ":white_check_mark:"
            stage_text = "REMEDIATION COMPLETE"
            stage_color = "#36a64f"
        elif execution_record.status == ExecutionStatus.FAILED:
            stage_emoji = ":x:"
            stage_text = "REMEDIATION FAILED"
            stage_color = "#FF0000"
        elif execution_record.status == ExecutionStatus.REJECTED:
            stage_emoji = ":raised_hand:"
            stage_text = "AWAITING APPROVAL"
            stage_color = "#FFA500"
        else:
            stage_emoji = ":hourglass:"
            stage_text = "PROCESSING"
            stage_color = "#4A90D9"
    else:
        stage_emoji = ":mag:"
        stage_text = "ANALYSIS COMPLETE"
        stage_color = "#4A90D9"

    # Get service info
    service_name = primary_alert.job or (incident.affected_services[0] if incident.affected_services else "N/A")

    # Get environment from labels
    environment = primary_alert.labels.get("environment", primary_alert.labels.get("env", "N/A"))

    # Calculate incident age
    incident_age = _get_incident_age(incident)

    # Build message blocks
    blocks = [
        # Header with stage
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{stage_emoji} Sirius: {stage_text}",
                "emoji": True,
            },
        },
        # Alert summary section
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*:bell: Alert:*\n`{primary_alert.alertname}`"},
                {"type": "mrkdwn", "text": f"*{sev_emoji} Severity:*\n*{sev_text}*"},
                {"type": "mrkdwn", "text": f"*:computer: Server:*\n`{primary_alert.host}`"},
                {"type": "mrkdwn", "text": f"*:gear: Service:*\n`{service_name}`"},
            ],
        },
        # Additional context
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*:ticket: Incident:*\n`{incident.id}`"},
                {"type": "mrkdwn", "text": f"*:earth_americas: Environment:*\n`{environment}`"},
                {"type": "mrkdwn", "text": f"*:stopwatch: Age:*\n`{incident_age}`"},
                {"type": "mrkdwn", "text": f"*:bar_chart: Status:*\n`{incident.status.value.upper()}`"},
            ],
        },
    ]

    # Alert description/summary if available
    if primary_alert.summary or primary_alert.description:
        alert_detail = primary_alert.summary or primary_alert.description
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*:page_facing_up: Alert Summary:*\n>{alert_detail[:500]}{'...' if len(alert_detail) > 500 else ''}",
            },
        })

    # Runbook link if available
    if primary_alert.runbook_url:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*:book: Runbook:* <{primary_alert.runbook_url}|View Runbook>",
            },
        })

    blocks.append({"type": "divider"})

    # Root Cause Analysis - show analysis with proper truncation for Slack limits
    if incident.root_cause:
        root_cause = incident.root_cause.strip()

        # Slack text block limit is 3000 chars - keep under 2500 for safety
        if len(root_cause) > 2000:
            # Extract key findings for summary
            lines = root_cause.split('\n')
            key_lines = []
            for line in lines:
                line_stripped = line.strip()
                if line_stripped:
                    lower = line_stripped.lower()
                    if any(kw in lower for kw in ['root cause', 'conclusion', 'finding', 'summary', 'issue', 'evidence', 'fix']):
                        key_lines.append(line_stripped)

            if key_lines:
                root_cause_display = '\n'.join(key_lines[-15:])[:1800]
            else:
                root_cause_display = root_cause[-1800:]
        else:
            root_cause_display = root_cause

        # Add confidence indicator
        confidence_pct = int(incident.root_cause_confidence * 100)
        confidence_bar = "█" * (confidence_pct // 10) + "░" * (10 - confidence_pct // 10)

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*:brain: Root Cause Analysis:* (Confidence: {confidence_pct}% {confidence_bar})\n\n{root_cause_display[:2500]}",
            },
        })
        blocks.append({"type": "divider"})

    # Recommended Actions - comprehensive details
    if incident.recommended_actions:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*:wrench: Recommended Remediation Actions* ({len(incident.recommended_actions)} action{'s' if len(incident.recommended_actions) > 1 else ''})",
            },
        })

        for i, action in enumerate(incident.recommended_actions):
            # Get execution status for this action
            exec_status = None
            exec_output = None
            exec_error = None
            if all_execution_records and i < len(all_execution_records):
                rec = all_execution_records[i]
                exec_status = rec.status
                exec_output = rec.output
                exec_error = rec.error

            # Status icon based on execution state
            status_icons = {
                ExecutionStatus.SUCCESS: ":white_check_mark:",
                ExecutionStatus.FAILED: ":x:",
                ExecutionStatus.REJECTED: ":raised_hand:",
                ExecutionStatus.PENDING: ":hourglass:",
                ExecutionStatus.EXECUTING: ":gear:",
                ExecutionStatus.APPROVED: ":thumbsup:",
            }
            status_icon = status_icons.get(exec_status, ":black_square_button:") if exec_status else ":black_square_button:"

            # Risk level badge
            risk_badges = {
                "low": ":large_green_circle: LOW",
                "medium": ":large_yellow_circle: MEDIUM",
                "high": ":red_circle: HIGH",
                "critical": ":rotating_light: CRITICAL",
            }
            risk_badge = risk_badges.get(action.risk_level.lower(), ":white_circle: UNKNOWN")

            # Confidence indicator
            action_confidence = int(action.confidence * 100)

            # Build action block - keep under 2500 chars for Slack limit
            cmd_display = action.command[:200] + "..." if len(action.command) > 200 else action.command

            action_text = f"{status_icon} *Action {i+1}: `{action.action_type}`*\n"
            action_text += f"├─ *Target:* `{action.target_host}`"
            if action.target_service:
                action_text += f" → `{action.target_service[:50]}`"
            action_text += f"\n├─ *Risk:* {risk_badge} | *Confidence:* {action_confidence}%\n"
            action_text += f"├─ *Command:*\n```{cmd_display}```\n"

            # Add reasoning if available (truncated)
            if action.reasoning:
                reasoning_short = action.reasoning[:200] + "..." if len(action.reasoning) > 200 else action.reasoning
                action_text += f"├─ *Reasoning:* {reasoning_short}\n"

            # Add execution status details
            if exec_status:
                status_text = exec_status.value.upper()
                if exec_status == ExecutionStatus.REJECTED:
                    action_text += f"└─ *Status:* `{status_text}` - Requires manual approval\n"
                elif exec_status == ExecutionStatus.SUCCESS:
                    action_text += f"└─ *Status:* `{status_text}` :white_check_mark:\n"
                elif exec_status == ExecutionStatus.FAILED:
                    action_text += f"└─ *Status:* `{status_text}` :x:\n"
                else:
                    action_text += f"└─ *Status:* `{status_text}`\n"

            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": action_text},
            })

            # Show execution output or error for this action
            if exec_status == ExecutionStatus.SUCCESS and exec_output:
                output_display = exec_output[:600] + "..." if len(exec_output) > 600 else exec_output
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*:terminal: Output for Action {i+1}:*\n```{output_display}```",
                    },
                })
            elif exec_status == ExecutionStatus.FAILED and exec_error:
                error_display = exec_error[:400] + "..." if len(exec_error) > 400 else exec_error
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*:warning: Error for Action {i+1}:*\n```{error_display}```",
                    },
                })

        blocks.append({"type": "divider"})

    # Approval section - if actions are awaiting approval
    awaiting_approval = False
    if all_execution_records:
        awaiting_approval = any(r.status == ExecutionStatus.REJECTED for r in all_execution_records)
    elif execution_record and execution_record.status == ExecutionStatus.REJECTED:
        awaiting_approval = True

    if awaiting_approval:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    "*:raised_hand: Action Required*\n"
                    "The above remediation action(s) require manual approval before execution.\n\n"
                    "*To approve and execute:*\n"
                    "1. Review the recommended actions and commands above\n"
                    "2. Verify the target server and service are correct\n"
                    "3. Execute the command(s) manually on the target server, or\n"
                    "4. Use your infrastructure automation tools to execute\n\n"
                    "_All actions are logged for audit purposes._"
                ),
            },
        })
        blocks.append({"type": "divider"})

    # Affected resources summary
    if len(incident.affected_servers) > 1 or len(incident.affected_services) > 1:
        affected_text = "*:link: Affected Resources:*\n"
        if incident.affected_servers:
            affected_text += f"• *Servers:* {', '.join(f'`{s}`' for s in incident.affected_servers[:5])}"
            if len(incident.affected_servers) > 5:
                affected_text += f" (+{len(incident.affected_servers) - 5} more)"
            affected_text += "\n"
        if incident.affected_services:
            affected_text += f"• *Services:* {', '.join(f'`{s}`' for s in incident.affected_services[:5])}"
            if len(incident.affected_services) > 5:
                affected_text += f" (+{len(incident.affected_services) - 5} more)"

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": affected_text},
        })

    # Footer with timeline and metadata
    footer_parts = [
        f"Detected: {incident.detected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
    ]
    if incident.acknowledged_at:
        footer_parts.append(f"Acked: {incident.acknowledged_at.strftime('%H:%M:%S UTC')}")
    if incident.resolved_at:
        footer_parts.append(f"Resolved: {incident.resolved_at.strftime('%H:%M:%S UTC')}")

    footer_text = " | ".join(footer_parts)
    footer_text += f"\n:robot_face: Sirius AI DevOps Agent | Incident: {incident.id}"

    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": footer_text}],
    })

    # Slack has a 50 block limit - truncate if needed
    if len(blocks) > 45:
        blocks = blocks[:44]
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"_Message truncated. {len(blocks)} blocks total._"}],
        })

    # Build final message
    message = {
        "text": f"Sirius {stage_text}: {primary_alert.alertname} on {primary_alert.host} ({sev_text})",
        "blocks": blocks,
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=message) as response:
                if response.status == 200:
                    logger.info(
                        "Slack notification sent successfully",
                        incident_id=incident.id,
                        stage=stage_text,
                    )
                    return True
                else:
                    response_text = await response.text()
                    logger.error(
                        "Failed to send Slack notification",
                        incident_id=incident.id,
                        status=response.status,
                        response=response_text[:200],
                    )
                    return False
    except Exception as e:
        logger.error("Error sending Slack notification", incident_id=incident.id, error=str(e))
        return False


async def execute_and_notify(
    incident: Incident,
    executor: RemediationExecutor,
    webhook_url: str,
) -> list[ExecutionRecord]:
    """Execute all remediation actions sequentially and send notification with results.

    Executes each action in order, stopping on first failure.
    Returns list of all execution records.
    """
    if not incident.recommended_actions:
        logger.info(
            "No remediation actions to execute",
            incident_id=incident.id,
        )
        # Still send analysis-only notification
        await send_slack_notification(incident, webhook_url)
        return []

    execution_records = []
    total_actions = len(incident.recommended_actions)

    logger.info(
        "Starting remediation sequence",
        incident_id=incident.id,
        total_actions=total_actions,
    )

    for i, action in enumerate(incident.recommended_actions):
        logger.info(
            f"Executing action {i+1}/{total_actions}",
            incident_id=incident.id,
            action_type=action.action_type,
            target=action.target_host,
            risk_level=action.risk_level,
            requires_approval=action.requires_approval,
        )

        try:
            # Execute the remediation action
            execution_record = await executor.execute(incident, action)
            execution_records.append(execution_record)

            # Update incident status on first successful action
            if execution_record.status == ExecutionStatus.SUCCESS:
                if incident.selected_action is None:
                    incident.start_mitigation(action)

                # Brief pause between actions (except for last one)
                if i < total_actions - 1:
                    await asyncio.sleep(2)
            else:
                # Stop sequence on failure
                logger.warning(
                    f"Action {i+1} failed, stopping remediation sequence",
                    incident_id=incident.id,
                    action_type=action.action_type,
                    status=execution_record.status.value,
                )
                break

        except Exception as e:
            logger.error(
                f"Action {i+1} execution error",
                incident_id=incident.id,
                action_type=action.action_type,
                error=str(e),
            )
            break

    # Log completion summary
    successful = sum(1 for r in execution_records if r.status == ExecutionStatus.SUCCESS)
    logger.info(
        "Remediation sequence complete",
        incident_id=incident.id,
        total_actions=total_actions,
        executed=len(execution_records),
        successful=successful,
    )

    # Send notification with all execution results
    # Use the last execution record for the main status display
    last_record = execution_records[-1] if execution_records else None
    await send_slack_notification(incident, webhook_url, last_record, execution_records)

    return execution_records


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global event_processor, devops_crew, remediation_executor

    settings = get_settings()
    setup_logging(settings)

    logger.info(
        "Starting DevOps On-Call Agent (Sirius)",
        version="1.0.0",
        environment=settings.nvidia_environment,
        host=settings.server.host,
        port=settings.server.port,
    )

    # Initialize AI crew
    devops_crew = DevOpsCrew(settings)
    logger.info("AI DevOps Crew initialized", model=settings.nvidia.model)

    # Initialize remediation executor
    remediation_executor = get_executor(settings)
    logger.info("Remediation executor initialized")

    # Initialize event processor
    event_processor = EventProcessor(settings)

    # Get Slack webhook URL for notifications
    slack_webhook_url = settings.approval.slack_webhook_url

    # Wire up AI analysis callback that also triggers remediation
    async def analyze_and_remediate(incident):
        """Callback to analyze incidents with AI crew and execute remediation."""
        logger.info(
            "Starting AI analysis",
            incident_id=incident.id,
            alertname=incident.primary_alert.alertname if incident.primary_alert else "unknown",
        )
        try:
            # Phase 1: AI Analysis
            analyzed_incident = await devops_crew.analyze_incident(incident)
            logger.info(
                "AI analysis complete",
                incident_id=incident.id,
                root_cause=analyzed_incident.root_cause[:100] if analyzed_incident.root_cause else None,
                actions_recommended=len(analyzed_incident.recommended_actions),
            )

            # Phase 2: Execute remediation and notify
            if slack_webhook_url:
                await execute_and_notify(
                    analyzed_incident,
                    remediation_executor,
                    slack_webhook_url,
                )
            else:
                logger.warning(
                    "Slack webhook not configured, skipping remediation execution",
                    incident_id=incident.id,
                )

            return analyzed_incident

        except Exception as e:
            logger.error(
                "AI analysis or remediation failed",
                incident_id=incident.id,
                error=str(e),
            )
            # Try to send error notification
            if slack_webhook_url:
                try:
                    await send_slack_notification(incident, slack_webhook_url)
                except Exception:
                    pass
            raise

    event_processor.set_analysis_callback(analyze_and_remediate)

    # No separate notification callback needed - it's integrated into analyze_and_remediate
    if slack_webhook_url:
        logger.info("Slack notifications configured", channel=settings.approval.slack_channel)
    else:
        logger.warning("Slack webhook URL not configured, notifications disabled")

    await event_processor.start()

    # Store in app state for access from routes
    app.state.event_processor = event_processor
    app.state.devops_crew = devops_crew
    app.state.remediation_executor = remediation_executor
    app.state.settings = settings

    logger.info("DevOps On-Call Agent (Sirius) started successfully")

    yield

    # Shutdown
    logger.info("Shutting down DevOps On-Call Agent")

    if event_processor:
        await event_processor.stop()

    logger.info("DevOps On-Call Agent stopped")


# Create FastAPI application
app = FastAPI(
    title="DevOps On-Call Agent",
    description="AI-powered on-call DevOps agent for alert analysis and automated remediation",
    version="1.0.0",
    lifespan=lifespan,
)


# Include routers
app.include_router(webhook_router, prefix="/webhooks", tags=["Webhooks"])


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "1.0.0",
    }


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "DevOps On-Call Agent",
        "version": "1.0.0",
        "description": "AI-powered on-call DevOps agent",
        "endpoints": {
            "health": "/health",
            "webhooks": {
                "prometheus": "/webhooks/prometheus",
                "custom": "/webhooks/custom",
            },
            "incidents": "/incidents",
        },
    }


@app.get("/incidents")
async def list_incidents():
    """List active incidents."""
    if not event_processor:
        return {"incidents": [], "error": "Event processor not initialized"}

    incidents = event_processor.get_active_incidents()
    return {
        "incidents": [inc.to_dict() for inc in incidents],
        "count": len(incidents),
    }


@app.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    """Get a specific incident by ID."""
    if not event_processor:
        return {"error": "Event processor not initialized"}

    incident = event_processor.get_incident(incident_id)
    if not incident:
        return {"error": f"Incident {incident_id} not found"}

    return incident.to_dict()


@app.get("/stats")
async def get_stats():
    """Get comprehensive system statistics including memory and training data."""
    if not event_processor:
        return {"error": "Event processor not initialized"}

    try:
        stats = await event_processor.get_system_stats()
        return stats
    except Exception as e:
        logger.error("Failed to get system stats", error=str(e))
        return {
            "error": str(e),
            "queue_size": event_processor.queue_size,
            "incident_count": event_processor.incident_count,
            "active_incident_count": event_processor.active_incident_count,
        }


@app.post("/clear/dedup")
async def clear_deduplication():
    """Clear deduplication cache to allow reprocessing of alerts."""
    if not event_processor:
        return {"error": "Event processor not initialized"}

    await event_processor.clear_deduplication()
    return {"status": "ok", "message": "Deduplication cache cleared"}


@app.post("/clear/all")
async def clear_all_state():
    """Clear all state (dedup, incidents, analyzed). Use with caution!"""
    if not event_processor:
        return {"error": "Event processor not initialized"}

    await event_processor.clear_all_state()
    return {"status": "ok", "message": "All state cleared"}


def handle_signal(signum, frame):
    """Handle shutdown signals."""
    logger.info(f"Received signal {signum}, initiating shutdown")
    sys.exit(0)


def main():
    """Main entry point."""
    # Register signal handlers
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Load settings
    settings = get_settings()

    # Run the server
    uvicorn.run(
        "src.main:app",
        host=settings.server.host,
        port=settings.server.port,
        workers=settings.server.workers,
        reload=False,
        log_level=settings.logging.level.lower(),
    )


if __name__ == "__main__":
    main()
