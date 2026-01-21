"""Alert data model for Prometheus AlertManager alerts."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Optional
import uuid


class AlertStatus(str, Enum):
    """Alert status values."""
    FIRING = "firing"
    RESOLVED = "resolved"


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Alert:
    """
    Normalized alert model.

    Supports alerts from Prometheus AlertManager and custom sources.
    """
    # Unique identifier
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Deduplication key from AlertManager
    fingerprint: str = ""

    # Status
    status: AlertStatus = AlertStatus.FIRING
    severity: AlertSeverity = AlertSeverity.MEDIUM

    # Source information
    source: str = "prometheus"  # prometheus, custom, datadog, etc.
    alertname: str = ""

    # Target information
    instance: str = ""  # e.g., "server1:9100"
    job: str = ""  # e.g., "node"

    # Alert details
    summary: str = ""
    description: str = ""

    # Labels and annotations from AlertManager
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)

    # Timestamps
    starts_at: Optional[datetime] = None
    ends_at: Optional[datetime] = None
    received_at: datetime = field(default_factory=datetime.utcnow)

    # Optional runbook URL
    runbook_url: Optional[str] = None

    # Generator URL (link to Prometheus/source)
    generator_url: Optional[str] = None

    def __post_init__(self):
        """Extract common fields from labels/annotations if not set."""
        if not self.alertname and "alertname" in self.labels:
            self.alertname = self.labels["alertname"]

        if not self.instance and "instance" in self.labels:
            self.instance = self.labels["instance"]

        if not self.job and "job" in self.labels:
            self.job = self.labels["job"]

        if not self.summary and "summary" in self.annotations:
            self.summary = self.annotations["summary"]

        if not self.description and "description" in self.annotations:
            self.description = self.annotations["description"]

        if not self.runbook_url and "runbook_url" in self.annotations:
            self.runbook_url = self.annotations["runbook_url"]

        # Map severity from labels if present
        if "severity" in self.labels:
            try:
                self.severity = AlertSeverity(self.labels["severity"].lower())
            except ValueError:
                pass  # Keep default severity

    @property
    def host(self) -> str:
        """Extract hostname from instance (removes port)."""
        if ":" in self.instance:
            return self.instance.split(":")[0]
        return self.instance

    @property
    def dedup_key(self) -> str:
        """Generate deduplication key."""
        return self.fingerprint or f"{self.alertname}:{self.instance}"

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "status": self.status.value,
            "severity": self.severity.value,
            "source": self.source,
            "alertname": self.alertname,
            "instance": self.instance,
            "job": self.job,
            "summary": self.summary,
            "description": self.description,
            "labels": self.labels,
            "annotations": self.annotations,
            "starts_at": self.starts_at.isoformat() if self.starts_at else None,
            "ends_at": self.ends_at.isoformat() if self.ends_at else None,
            "received_at": self.received_at.isoformat(),
            "runbook_url": self.runbook_url,
            "generator_url": self.generator_url,
        }

    @classmethod
    def from_prometheus(cls, alert_data: Dict, receiver: str = "devops-agent") -> "Alert":
        """
        Create Alert from Prometheus AlertManager webhook payload.

        Expected format:
        {
            "status": "firing",
            "labels": {"alertname": "...", "severity": "...", "instance": "..."},
            "annotations": {"summary": "...", "description": "..."},
            "startsAt": "2024-01-15T10:30:00Z",
            "endsAt": "0001-01-01T00:00:00Z",
            "fingerprint": "abc123"
        }
        """
        # Parse timestamps
        starts_at = None
        ends_at = None

        if alert_data.get("startsAt"):
            try:
                starts_at = datetime.fromisoformat(
                    alert_data["startsAt"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        if alert_data.get("endsAt") and alert_data["endsAt"] != "0001-01-01T00:00:00Z":
            try:
                ends_at = datetime.fromisoformat(
                    alert_data["endsAt"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        # Parse status
        status = AlertStatus.FIRING
        if alert_data.get("status") == "resolved":
            status = AlertStatus.RESOLVED

        return cls(
            fingerprint=alert_data.get("fingerprint", ""),
            status=status,
            source="prometheus",
            labels=alert_data.get("labels", {}),
            annotations=alert_data.get("annotations", {}),
            starts_at=starts_at,
            ends_at=ends_at,
            generator_url=alert_data.get("generatorURL"),
        )
