"""DevOps On-Call Agent - Main Entry Point."""

import asyncio
import logging
import signal
import sys
from contextlib import asynccontextmanager
from typing import Optional

import structlog
import uvicorn
from fastapi import FastAPI

from src.config import get_settings, Settings
from src.ingestion.webhook_server import router as webhook_router
from src.processing.event_processor import EventProcessor
from src.agents.crew import DevOpsCrew


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
