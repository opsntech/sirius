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
from src.models.incident import Incident


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
logger = structlog.get_logger()


async def send_slack_notification(incident: Incident, webhook_url: str) -> bool:
    """Send a Slack notification for an analyzed incident."""
    primary_alert = incident.primary_alert

    # Severity emoji
    severity_emoji = {
        "critical": ":red_circle:",
        "high": ":large_orange_circle:",
        "medium": ":large_yellow_circle:",
        "low": ":large_green_circle:",
        "info": ":large_blue_circle:",
    }.get(incident.severity.value, ":white_circle:")

    # Build the message blocks
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": ":robot_face: Sirius AI Analysis Complete",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Incident ID:*\n`{incident.id[:8]}...`",
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
        {
            "type": "divider",
        },
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
                "text": f">{(incident.root_cause or 'Analysis pending...')[:500]}",
            },
        },
    ]

    # Add recommended actions if available
    if incident.recommended_actions:
        action = incident.recommended_actions[0]
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*:wrench: Recommended Action:*\n`{action.action_type}` on `{action.target_host}`\nCommand: `{action.command}`",
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
            ],
        })

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
        "text": f"Sirius AI analysis complete for incident {incident.id[:8]}",
        "blocks": blocks,
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(webhook_url, json=message) as response:
                if response.status == 200:
                    logger.info(
                        "Slack notification sent successfully",
                        incident_id=incident.id,
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global event_processor, devops_crew

    settings = get_settings()
    setup_logging(settings)

    logger.info(
        "Starting DevOps On-Call Agent",
        version="1.0.0",
        environment=settings.nvidia_environment,
        host=settings.server.host,
        port=settings.server.port,
    )

    # Initialize AI crew
    devops_crew = DevOpsCrew(settings)
    logger.info("AI DevOps Crew initialized", model=settings.nvidia.model)

    # Initialize event processor
    event_processor = EventProcessor(settings)

    # Wire up AI analysis callback
    async def analyze_incident(incident):
        """Callback to analyze incidents with AI crew."""
        logger.info(
            "Starting AI analysis",
            incident_id=incident.id,
            alertname=incident.primary_alert.alertname if incident.primary_alert else "unknown",
        )
        try:
            analyzed_incident = await devops_crew.analyze_incident(incident)
            logger.info(
                "AI analysis complete",
                incident_id=incident.id,
                root_cause=analyzed_incident.root_cause[:100] if analyzed_incident.root_cause else None,
                actions_recommended=len(analyzed_incident.recommended_actions),
            )
            return analyzed_incident
        except Exception as e:
            logger.error(
                "AI analysis failed",
                incident_id=incident.id,
                error=str(e),
            )
            raise

    event_processor.set_analysis_callback(analyze_incident)

    # Wire up Slack notification callback
    slack_webhook_url = settings.approval.slack_webhook_url
    if slack_webhook_url:
        async def notify_incident(incident: Incident):
            """Callback to send Slack notification after analysis."""
            await send_slack_notification(incident, slack_webhook_url)

        event_processor.set_notification_callback(notify_incident)
        logger.info("Slack notification callback configured")
    else:
        logger.warning("Slack webhook URL not configured, notifications disabled")

    await event_processor.start()

    # Store in app state for access from routes
    app.state.event_processor = event_processor
    app.state.devops_crew = devops_crew
    app.state.settings = settings

    logger.info("DevOps On-Call Agent started successfully")

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
