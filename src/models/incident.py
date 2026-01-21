"""Incident data model for correlated alerts."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
import uuid

from src.models.alert import Alert, AlertSeverity


class IncidentStatus(str, Enum):
    """Incident lifecycle status."""
    OPEN = "open"
    INVESTIGATING = "investigating"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"


class IncidentSeverity(str, Enum):
    """Incident severity levels (SEV1-4)."""
    SEV1 = "sev1"  # Critical - immediate response required
    SEV2 = "sev2"  # High - urgent response required
    SEV3 = "sev3"  # Medium - response during business hours
    SEV4 = "sev4"  # Low - informational


@dataclass
class InvestigationStep:
    """Record of an investigation step taken by the AI agent."""
    timestamp: datetime
    agent: str  # triage, analysis, remediation
    action: str  # e.g., "check_cpu_usage", "query_logs"
    target: str  # e.g., "server1.example.com"
    result: str  # Output of the action
    reasoning: str  # AI reasoning for this step

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "agent": self.agent,
            "action": self.action,
            "target": self.target,
            "result": self.result,
            "reasoning": self.reasoning,
        }


@dataclass
class RemediationAction:
    """Recommended remediation action from the AI agent."""
    action_type: str  # e.g., "restart_service", "kill_process"
    target_host: str
    target_service: Optional[str] = None
    command: str = ""
    parameters: Dict = field(default_factory=dict)
    risk_level: str = "medium"  # low, medium, high, critical
    confidence: float = 0.0  # 0.0 - 1.0
    reasoning: str = ""
    requires_approval: bool = True

    def to_dict(self) -> Dict:
        return {
            "action_type": self.action_type,
            "target_host": self.target_host,
            "target_service": self.target_service,
            "command": self.command,
            "parameters": self.parameters,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "requires_approval": self.requires_approval,
        }


@dataclass
class Incident:
    """
    Incident representing a correlated group of alerts.

    An incident is created when alerts are correlated together,
    and tracks the full lifecycle from detection to resolution.
    """
    # Unique identifier
    id: str = field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")

    # Status and severity
    status: IncidentStatus = IncidentStatus.OPEN
    severity: IncidentSeverity = IncidentSeverity.SEV3

    # Title and summary
    title: str = ""
    summary: str = ""

    # Related alerts
    alerts: List[Alert] = field(default_factory=list)
    primary_alert_id: Optional[str] = None

    # Root cause analysis
    root_cause: Optional[str] = None
    root_cause_confidence: float = 0.0

    # Investigation log
    investigation_log: List[InvestigationStep] = field(default_factory=list)

    # Remediation
    recommended_actions: List[RemediationAction] = field(default_factory=list)
    selected_action: Optional[RemediationAction] = None

    # Affected resources
    affected_servers: List[str] = field(default_factory=list)
    affected_services: List[str] = field(default_factory=list)

    # Timeline
    detected_at: datetime = field(default_factory=datetime.utcnow)
    acknowledged_at: Optional[datetime] = None
    investigation_started_at: Optional[datetime] = None
    mitigation_started_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    # Assignment
    assigned_to: Optional[str] = None

    # Approval tracking
    approval_requested_at: Optional[datetime] = None
    approval_status: Optional[str] = None  # pending, approved, rejected
    approved_by: Optional[str] = None
    approval_timestamp: Optional[datetime] = None

    def __post_init__(self):
        """Initialize derived fields."""
        if self.alerts and not self.primary_alert_id:
            self.primary_alert_id = self.alerts[0].id

        if self.alerts and not self.title:
            primary = self.primary_alert
            if primary:
                self.title = f"{primary.alertname} on {primary.host}"

        if self.alerts:
            self._update_affected_resources()
            self._update_severity()

    @property
    def primary_alert(self) -> Optional[Alert]:
        """Get the primary alert for this incident."""
        if not self.alerts:
            return None
        if self.primary_alert_id:
            for alert in self.alerts:
                if alert.id == self.primary_alert_id:
                    return alert
        return self.alerts[0]

    def _update_affected_resources(self):
        """Update affected servers and services from alerts."""
        servers = set()
        services = set()

        for alert in self.alerts:
            if alert.host:
                servers.add(alert.host)
            if alert.job:
                services.add(alert.job)

        self.affected_servers = list(servers)
        self.affected_services = list(services)

    def _update_severity(self):
        """Update incident severity based on alert severities."""
        severity_map = {
            AlertSeverity.CRITICAL: IncidentSeverity.SEV1,
            AlertSeverity.HIGH: IncidentSeverity.SEV2,
            AlertSeverity.MEDIUM: IncidentSeverity.SEV3,
            AlertSeverity.LOW: IncidentSeverity.SEV4,
            AlertSeverity.INFO: IncidentSeverity.SEV4,
        }

        # Use highest severity from alerts
        highest = IncidentSeverity.SEV4
        for alert in self.alerts:
            incident_sev = severity_map.get(alert.severity, IncidentSeverity.SEV4)
            if incident_sev.value < highest.value:  # SEV1 < SEV2 < SEV3 < SEV4
                highest = incident_sev

        self.severity = highest

    def add_alert(self, alert: Alert):
        """Add an alert to this incident."""
        self.alerts.append(alert)
        self._update_affected_resources()
        self._update_severity()

    def add_investigation_step(self, step: InvestigationStep):
        """Add an investigation step to the log."""
        self.investigation_log.append(step)

        if self.status == IncidentStatus.OPEN:
            self.status = IncidentStatus.INVESTIGATING
            self.investigation_started_at = datetime.utcnow()

    def set_root_cause(self, root_cause: str, confidence: float):
        """Set the root cause analysis result."""
        self.root_cause = root_cause
        self.root_cause_confidence = confidence

    def add_recommended_action(self, action: RemediationAction):
        """Add a recommended remediation action."""
        self.recommended_actions.append(action)

    def acknowledge(self, user: Optional[str] = None):
        """Acknowledge the incident."""
        self.acknowledged_at = datetime.utcnow()
        if user:
            self.assigned_to = user

    def start_mitigation(self, action: RemediationAction):
        """Start mitigation with the selected action."""
        self.status = IncidentStatus.MITIGATING
        self.mitigation_started_at = datetime.utcnow()
        self.selected_action = action

    def resolve(self):
        """Mark the incident as resolved."""
        self.status = IncidentStatus.RESOLVED
        self.resolved_at = datetime.utcnow()

    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate incident duration in seconds."""
        if not self.resolved_at:
            return None
        return (self.resolved_at - self.detected_at).total_seconds()

    @property
    def time_to_acknowledge_seconds(self) -> Optional[float]:
        """Calculate time to acknowledge in seconds."""
        if not self.acknowledged_at:
            return None
        return (self.acknowledged_at - self.detected_at).total_seconds()

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "status": self.status.value,
            "severity": self.severity.value,
            "title": self.title,
            "summary": self.summary,
            "alerts": [a.to_dict() for a in self.alerts],
            "primary_alert_id": self.primary_alert_id,
            "root_cause": self.root_cause,
            "root_cause_confidence": self.root_cause_confidence,
            "investigation_log": [s.to_dict() for s in self.investigation_log],
            "recommended_actions": [a.to_dict() for a in self.recommended_actions],
            "selected_action": self.selected_action.to_dict() if self.selected_action else None,
            "affected_servers": self.affected_servers,
            "affected_services": self.affected_services,
            "detected_at": self.detected_at.isoformat(),
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "investigation_started_at": self.investigation_started_at.isoformat() if self.investigation_started_at else None,
            "mitigation_started_at": self.mitigation_started_at.isoformat() if self.mitigation_started_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "assigned_to": self.assigned_to,
            "approval_status": self.approval_status,
            "approved_by": self.approved_by,
        }
