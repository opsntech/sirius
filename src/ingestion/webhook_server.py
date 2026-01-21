"""Webhook server for receiving alerts from Prometheus AlertManager and custom sources."""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel, Field

from src.models.alert import Alert, AlertSeverity, AlertStatus


logger = structlog.get_logger()

router = APIRouter()


# Pydantic models for request validation

class PrometheusAlert(BaseModel):
    """Single alert from Prometheus AlertManager."""
    status: str
    labels: Dict[str, str] = Field(default_factory=dict)
    annotations: Dict[str, str] = Field(default_factory=dict)
    startsAt: Optional[str] = None
    endsAt: Optional[str] = None
    generatorURL: Optional[str] = None
    fingerprint: Optional[str] = None


class PrometheusWebhookPayload(BaseModel):
    """Prometheus AlertManager webhook payload."""
    receiver: str = "devops-agent"
    status: str = "firing"
    alerts: List[PrometheusAlert] = Field(default_factory=list)
    groupLabels: Dict[str, str] = Field(default_factory=dict)
    commonLabels: Dict[str, str] = Field(default_factory=dict)
    commonAnnotations: Dict[str, str] = Field(default_factory=dict)
    externalURL: Optional[str] = None
    version: Optional[str] = None
    groupKey: Optional[str] = None


class CustomAlert(BaseModel):
    """Custom alert from monitoring scripts."""
    alertname: str
    severity: str = "medium"
    instance: str
    summary: str
    description: Optional[str] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    annotations: Dict[str, str] = Field(default_factory=dict)


class WebhookResponse(BaseModel):
    """Standard webhook response."""
    status: str
    message: str
    alerts_received: int = 0
    alerts_processed: int = 0
    incident_ids: List[str] = Field(default_factory=list)


async def process_alert_background(request: Request, alert: Alert):
    """Process an alert in the background."""
    try:
        event_processor = request.app.state.event_processor
        if event_processor:
            incident = await event_processor.process_alert(alert)
            if incident:
                logger.info(
                    "Alert processed",
                    alert_id=alert.id,
                    alertname=alert.alertname,
                    incident_id=incident.id,
                )
        else:
            logger.warning("Event processor not available")
    except Exception as e:
        logger.error(
            "Failed to process alert",
            alert_id=alert.id,
            error=str(e),
        )


@router.post("/prometheus", response_model=WebhookResponse)
async def receive_prometheus_webhook(
    payload: PrometheusWebhookPayload,
    request: Request,
    background_tasks: BackgroundTasks,
):
    """
    Receive alerts from Prometheus AlertManager.

    AlertManager sends alerts as a batch in a single webhook call.
    Each alert is normalized and processed independently.
    """
    logger.info(
        "Received Prometheus webhook",
        receiver=payload.receiver,
        status=payload.status,
        alert_count=len(payload.alerts),
        group_key=payload.groupKey,
    )

    processed_count = 0
    incident_ids = []

    for prom_alert in payload.alerts:
        try:
            # Convert to our Alert model
            alert = Alert.from_prometheus(prom_alert.model_dump())

            logger.debug(
                "Processing Prometheus alert",
                alertname=alert.alertname,
                instance=alert.instance,
                severity=alert.severity.value,
                status=alert.status.value,
                fingerprint=alert.fingerprint,
            )

            # Process in background to avoid blocking the webhook response
            background_tasks.add_task(process_alert_background, request, alert)
            processed_count += 1

        except Exception as e:
            logger.error(
                "Failed to parse Prometheus alert",
                error=str(e),
                alert_data=prom_alert.model_dump(),
            )

    return WebhookResponse(
        status="accepted",
        message=f"Received {len(payload.alerts)} alerts, queued {processed_count} for processing",
        alerts_received=len(payload.alerts),
        alerts_processed=processed_count,
        incident_ids=incident_ids,
    )


@router.post("/custom", response_model=WebhookResponse)
async def receive_custom_alert(
    alert_data: CustomAlert,
    request: Request,
    background_tasks: BackgroundTasks,
):
    """
    Receive custom alerts from monitoring scripts.

    This endpoint allows custom monitoring scripts to send alerts
    directly to the DevOps agent without going through Prometheus.
    """
    logger.info(
        "Received custom alert",
        alertname=alert_data.alertname,
        instance=alert_data.instance,
        severity=alert_data.severity,
    )

    try:
        # Map severity string to enum
        try:
            severity = AlertSeverity(alert_data.severity.lower())
        except ValueError:
            severity = AlertSeverity.MEDIUM

        # Create Alert model
        alert = Alert(
            source="custom",
            alertname=alert_data.alertname,
            instance=alert_data.instance,
            severity=severity,
            status=AlertStatus.FIRING,
            summary=alert_data.summary,
            description=alert_data.description or alert_data.summary,
            labels=alert_data.labels,
            annotations=alert_data.annotations,
            received_at=datetime.utcnow(),
        )

        # Generate fingerprint from alertname and instance
        alert.fingerprint = f"{alert_data.alertname}:{alert_data.instance}"

        # Process in background
        background_tasks.add_task(process_alert_background, request, alert)

        return WebhookResponse(
            status="accepted",
            message="Custom alert received and queued for processing",
            alerts_received=1,
            alerts_processed=1,
        )

    except Exception as e:
        logger.error(
            "Failed to process custom alert",
            error=str(e),
            alert_data=alert_data.model_dump(),
        )
        raise HTTPException(status_code=500, detail=f"Failed to process alert: {str(e)}")


@router.post("/test")
async def test_webhook(request: Request):
    """
    Test endpoint to verify webhook connectivity.

    Returns the received payload for debugging.
    """
    body = await request.body()
    content_type = request.headers.get("content-type", "")

    logger.info(
        "Test webhook received",
        content_type=content_type,
        body_length=len(body),
    )

    return {
        "status": "received",
        "content_type": content_type,
        "body_length": len(body),
        "timestamp": datetime.utcnow().isoformat(),
    }
