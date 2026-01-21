"""DevOps On-Call Agent - Main Entry Point."""

import asyncio
import logging
import signal
import sys
from contextlib import asynccontextmanager
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


async def send_slack_notification(
    incident: Incident,
    webhook_url: str,
    execution_record: Optional[ExecutionRecord] = None,
) -> bool:
    """Send a Slack notification for an incident with analysis and execution results."""
    primary_alert = incident.primary_alert

    # Severity emoji
    severity_emoji = {
        "critical": ":red_circle:",
        "high": ":large_orange_circle:",
        "medium": ":large_yellow_circle:",
        "low": ":large_green_circle:",
        "info": ":large_blue_circle:",
    }.get(incident.severity.value, ":white_circle:")

    # Determine header based on execution status
    if execution_record:
        if execution_record.status == ExecutionStatus.SUCCESS:
            header_text = ":white_check_mark: Sirius Remediation Complete"
            header_emoji = ":white_check_mark:"
        elif execution_record.status == ExecutionStatus.FAILED:
            header_text = ":x: Sirius Remediation Failed"
            header_emoji = ":x:"
        elif execution_record.status == ExecutionStatus.REJECTED:
            header_text = ":no_entry: Sirius Remediation Rejected"
            header_emoji = ":no_entry:"
        elif execution_record.status == ExecutionStatus.PENDING:
            header_text = ":hourglass: Sirius Awaiting Approval"
            header_emoji = ":hourglass:"
        else:
            header_text = ":robot_face: Sirius AI Analysis Complete"
            header_emoji = ":robot_face:"
    else:
        header_text = ":robot_face: Sirius AI Analysis Complete"
        header_emoji = ":robot_face:"

    # Build the message blocks
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": header_text,
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Incident ID:*\n`{incident.id}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Severity:*\n{severity_emoji} {incident.severity.value.upper()}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Alert:*\n{primary_alert.alertname if primary_alert else 'Unknown'}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Server:*\n{primary_alert.host if primary_alert else 'Unknown'}",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Summary:*\n{primary_alert.summary if primary_alert else 'No summary available'}",
            },
        },
        {"type": "divider"},
    ]

    # Add root cause analysis (truncated for readability)
    root_cause_text = incident.root_cause or "Analysis pending..."
    if len(root_cause_text) > 800:
        root_cause_text = root_cause_text[:800] + "..."

    blocks.extend([
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*:mag: Root Cause Analysis:*",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f">{root_cause_text}",
            },
        },
    ])

    # Add recommended action info
    if incident.recommended_actions:
        action = incident.recommended_actions[0]
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*:wrench: Recommended Action:*\n• *Type:* `{action.action_type}`\n• *Target:* `{action.target_host}`\n• *Command:* `{action.command}`",
            },
        })
        blocks.append({
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Risk Level:*\n{action.risk_level.upper()}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Confidence:*\n{int(action.confidence * 100)}%",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Requires Approval:*\n{'Yes' if action.requires_approval else 'No (Auto-approved)'}",
                },
            ],
        })

    # Add execution results if available
    if execution_record:
        blocks.append({"type": "divider"})

        status_emoji = {
            ExecutionStatus.SUCCESS: ":white_check_mark:",
            ExecutionStatus.FAILED: ":x:",
            ExecutionStatus.REJECTED: ":no_entry:",
            ExecutionStatus.PENDING: ":hourglass:",
            ExecutionStatus.EXECUTING: ":gear:",
            ExecutionStatus.ROLLED_BACK: ":rewind:",
        }.get(execution_record.status, ":question:")

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*:zap: Execution Result:*\n{status_emoji} *Status:* {execution_record.status.value.upper()}",
            },
        })

        exec_fields = [
            {
                "type": "mrkdwn",
                "text": f"*Approved By:*\n{execution_record.approved_by or 'N/A'}",
            },
        ]

        if execution_record.exit_code is not None:
            exec_fields.append({
                "type": "mrkdwn",
                "text": f"*Exit Code:*\n{execution_record.exit_code}",
            })

        if execution_record.execution_duration_seconds:
            exec_fields.append({
                "type": "mrkdwn",
                "text": f"*Duration:*\n{execution_record.execution_duration_seconds:.1f}s",
            })

        blocks.append({
            "type": "section",
            "fields": exec_fields,
        })

        # Show output or error
        if execution_record.status == ExecutionStatus.SUCCESS and execution_record.output:
            output_text = execution_record.output[:500]
            if len(execution_record.output) > 500:
                output_text += "..."
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Output:*\n```{output_text}```",
                },
            })
        elif execution_record.error:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Error:*\n```{execution_record.error[:500]}```",
                },
            })

        if execution_record.verification_result:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Verification:*\n{':white_check_mark:' if execution_record.verified else ':warning:'} {execution_record.verification_result}",
                },
            })

    # Add timestamp
    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": f":clock1: Detected at {incident.detected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            },
        ],
    })

    message = {
        "text": f"Sirius: {header_text} for incident {incident.id}",
        "blocks": blocks,
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=message) as response:
                if response.status == 200:
                    logger.info(
                        "Slack notification sent successfully",
                        incident_id=incident.id,
                        execution_status=execution_record.status.value if execution_record else "analysis_only",
                    )
                    return True
                else:
                    logger.error(
                        "Failed to send Slack notification",
                        incident_id=incident.id,
                        status=response.status,
                        response_text=await response.text(),
                    )
                    return False
    except Exception as e:
        logger.error(
            "Error sending Slack notification",
            incident_id=incident.id,
            error=str(e),
        )
        return False


async def execute_and_notify(
    incident: Incident,
    executor: RemediationExecutor,
    webhook_url: str,
) -> Optional[ExecutionRecord]:
    """Execute remediation action and send notification with results."""
    if not incident.recommended_actions:
        logger.info(
            "No remediation actions to execute",
            incident_id=incident.id,
        )
        # Still send analysis-only notification
        await send_slack_notification(incident, webhook_url)
        return None

    action = incident.recommended_actions[0]

    logger.info(
        "Executing remediation action",
        incident_id=incident.id,
        action_type=action.action_type,
        target=action.target_host,
        requires_approval=action.requires_approval,
    )

    try:
        # Execute the remediation
        execution_record = await executor.execute(incident, action)

        # Update incident status based on execution
        if execution_record.status == ExecutionStatus.SUCCESS:
            incident.start_mitigation(action)

        # Send notification with execution results
        await send_slack_notification(incident, webhook_url, execution_record)

        return execution_record

    except Exception as e:
        logger.error(
            "Remediation execution failed",
            incident_id=incident.id,
            error=str(e),
        )
        # Send notification about the failure
        await send_slack_notification(incident, webhook_url)
        return None


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
