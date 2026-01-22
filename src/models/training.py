"""Training data models for ML pipeline.

These models define the schema for collecting, storing, and exporting
training data from incident lifecycle events.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
from enum import Enum
import uuid
import json


class TaskType(str, Enum):
    """Types of tasks for training examples."""
    TRIAGE = "triage"
    ANALYSIS = "analysis"
    REMEDIATION = "remediation"
    END_TO_END = "end_to_end"


@dataclass
class AlertData:
    """Normalized alert data for training input."""

    fingerprint: str
    alertname: str
    severity: str
    status: str
    instance: str
    job: str
    summary: str
    description: str
    labels: Dict[str, str]
    annotations: Dict[str, str]
    starts_at: Optional[str] = None
    source: str = "prometheus"

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ServerInfo:
    """Server context information."""

    hostname: str
    ip: str
    role: str
    services: List[str]
    environment: str = "production"
    tags: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DeploymentInfo:
    """Recent deployment information."""

    service: str
    version: str
    deployed_at: str
    deployed_by: str
    status: str = "success"

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class AlertSummary:
    """Summary of a recent alert."""

    alertname: str
    severity: str
    host: str
    timestamp: str
    status: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class InvestigationStepData:
    """Investigation step data for training."""

    timestamp: str
    agent: str
    tool: str
    command: str
    target_host: str
    output: str
    interpretation: str
    success: bool = True

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class SimilarIncidentSummary:
    """Summary of a similar past incident."""

    incident_id: str
    similarity_score: float
    root_cause: str
    resolution_type: str
    mttr_seconds: Optional[int] = None

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class InputContext:
    """All context available to the model at decision time."""

    alert: AlertData
    investigation_steps: List[InvestigationStepData] = field(default_factory=list)
    similar_incidents: List[SimilarIncidentSummary] = field(default_factory=list)
    server_info: Optional[ServerInfo] = None
    recent_deployments: List[DeploymentInfo] = field(default_factory=list)
    recent_alerts: List[AlertSummary] = field(default_factory=list)
    incident_age_seconds: int = 0

    def to_dict(self) -> Dict:
        return {
            "alert": self.alert.to_dict(),
            "investigation_steps": [s.to_dict() for s in self.investigation_steps],
            "similar_incidents": [s.to_dict() for s in self.similar_incidents],
            "server_info": self.server_info.to_dict() if self.server_info else None,
            "recent_deployments": [d.to_dict() for d in self.recent_deployments],
            "recent_alerts": [a.to_dict() for a in self.recent_alerts],
            "incident_age_seconds": self.incident_age_seconds,
        }

    def to_prompt_text(self) -> str:
        """Convert to a text format suitable for prompts."""
        lines = []

        # Alert info
        lines.append("## Alert Information")
        lines.append(f"- **Alert**: {self.alert.alertname}")
        lines.append(f"- **Severity**: {self.alert.severity}")
        lines.append(f"- **Status**: {self.alert.status}")
        lines.append(f"- **Instance**: {self.alert.instance}")
        lines.append(f"- **Summary**: {self.alert.summary}")
        if self.alert.description:
            lines.append(f"- **Description**: {self.alert.description}")

        # Server info
        if self.server_info:
            lines.append("\n## Server Context")
            lines.append(f"- **Hostname**: {self.server_info.hostname}")
            lines.append(f"- **Role**: {self.server_info.role}")
            lines.append(f"- **Services**: {', '.join(self.server_info.services)}")
            lines.append(f"- **Environment**: {self.server_info.environment}")

        # Investigation steps
        if self.investigation_steps:
            lines.append("\n## Investigation History")
            for i, step in enumerate(self.investigation_steps, 1):
                lines.append(f"\n### Step {i}: {step.tool}")
                lines.append(f"- **Command**: `{step.command}`")
                lines.append(f"- **Target**: {step.target_host}")
                lines.append(f"- **Output** (truncated):\n```\n{step.output[:500]}...\n```")
                lines.append(f"- **Interpretation**: {step.interpretation}")

        # Similar incidents
        if self.similar_incidents:
            lines.append("\n## Similar Past Incidents")
            for inc in self.similar_incidents[:3]:
                lines.append(f"- **{inc.incident_id}** (similarity: {inc.similarity_score:.2f})")
                lines.append(f"  - Root cause: {inc.root_cause}")
                lines.append(f"  - Resolution: {inc.resolution_type}")

        # Recent alerts
        if self.recent_alerts:
            lines.append("\n## Recent Alerts on Same Host")
            for alert in self.recent_alerts[:5]:
                lines.append(f"- {alert.alertname} ({alert.severity}) - {alert.timestamp}")

        return "\n".join(lines)


@dataclass
class OutcomeLabels:
    """Labels for training signal quality."""

    resolution_success: Optional[bool] = None
    mttr_seconds: Optional[int] = None
    human_approved: Optional[bool] = None
    human_feedback_text: Optional[str] = None
    human_corrections: Optional[Dict[str, Any]] = None
    verification_passed: Optional[bool] = None
    verification_output: Optional[str] = None
    root_cause_accuracy: Optional[float] = None
    remediation_effectiveness: Optional[float] = None
    caused_additional_alerts: bool = False
    required_rollback: bool = False
    escalated_to_human: bool = False

    def to_dict(self) -> Dict:
        return asdict(self)

    @property
    def is_positive_example(self) -> bool:
        """Check if this is a positive training example."""
        if self.resolution_success is False:
            return False
        if self.required_rollback:
            return False
        if self.caused_additional_alerts:
            return False
        if self.human_approved is False:
            return False
        return True

    @property
    def quality_score(self) -> float:
        """Calculate quality score for this example (0-1)."""
        score = 0.5  # Base score

        if self.resolution_success:
            score += 0.2
        if self.human_approved:
            score += 0.15
        if self.verification_passed:
            score += 0.1
        if self.root_cause_accuracy and self.root_cause_accuracy > 0.7:
            score += 0.05

        # Penalties
        if self.required_rollback:
            score -= 0.3
        if self.caused_additional_alerts:
            score -= 0.2
        if self.escalated_to_human:
            score -= 0.1

        return max(0.0, min(1.0, score))


@dataclass
class ExampleMetadata:
    """Metadata for dataset management and stratification."""

    alert_type: str
    severity: str
    environment: str = "production"
    service_category: str = "unknown"
    complexity_score: float = 0.5
    data_quality_score: float = 0.5
    is_edge_case: bool = False
    is_rare_alert_type: bool = False
    collection_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class TrainingExample:
    """Single training example for model fine-tuning."""

    example_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    input_context: InputContext = field(default_factory=lambda: InputContext(
        alert=AlertData(
            fingerprint="", alertname="", severity="", status="",
            instance="", job="", summary="", description="",
            labels={}, annotations={}
        )
    ))
    task_type: str = TaskType.TRIAGE.value
    expected_output: Dict[str, Any] = field(default_factory=dict)
    outcome: OutcomeLabels = field(default_factory=OutcomeLabels)
    metadata: ExampleMetadata = field(default_factory=lambda: ExampleMetadata(
        alert_type="unknown", severity="unknown"
    ))

    def to_dict(self) -> Dict:
        return {
            "example_id": self.example_id,
            "incident_id": self.incident_id,
            "timestamp": self.timestamp,
            "input_context": self.input_context.to_dict(),
            "task_type": self.task_type,
            "expected_output": self.expected_output,
            "outcome": self.outcome.to_dict(),
            "metadata": self.metadata.to_dict(),
        }

    def to_jsonl(self) -> str:
        """Convert to JSONL format for export."""
        return json.dumps(self.to_dict())

    def to_instruction_format(self, system_prompt: str = "") -> Dict:
        """Convert to instruction fine-tuning format."""
        return {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": self.input_context.to_prompt_text()},
                {"role": "assistant", "content": json.dumps(self.expected_output, indent=2)}
            ],
            "metadata": {
                "example_id": self.example_id,
                "task_type": self.task_type,
                "quality_score": self.outcome.quality_score,
            }
        }


@dataclass
class PartialExample:
    """Partially constructed example during incident lifecycle."""

    incident_id: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    input_context: Optional[InputContext] = None
    triage_output: Optional[Dict] = None
    analysis_output: Optional[Dict] = None
    remediation_output: Optional[Dict] = None
    outcome: OutcomeLabels = field(default_factory=OutcomeLabels)

    def is_complete(self) -> bool:
        """Check if all required data is collected."""
        return (
            self.input_context is not None and
            self.triage_output is not None and
            self.analysis_output is not None
        )


# System prompts for each task type
TASK_SYSTEM_PROMPTS = {
    TaskType.TRIAGE.value: """You are a Triage Specialist for a DevOps incident response system.
Your job is to quickly classify incoming alerts, assess their severity and blast radius,
and determine the appropriate response urgency. You should identify affected services
and suggest areas to investigate first.

Output your analysis as a JSON object with the following fields:
- severity: "critical", "high", "medium", "low", or "info"
- urgency: "immediate", "soon", or "scheduled"
- blast_radius: "single_host", "service", "multi_service", or "platform"
- affected_services: list of service names
- suggested_focus: list of investigation areas (max 5)
- escalation_required: boolean
- reasoning: brief explanation""",

    TaskType.ANALYSIS.value: """You are a Senior SRE Analyst investigating production incidents.
Your job is to use available diagnostic tools to identify the root cause of issues.
You should form hypotheses, test them with tools, and build evidence for your conclusions.

Output your analysis as a JSON object with the following fields:
- hypotheses_tested: list of hypotheses you considered
- findings: list of investigation findings
- root_cause: identified root cause
- root_cause_confidence: confidence score 0-1
- contributing_factors: list of additional factors
- remaining_unknowns: list of unanswered questions
- recommended_next_steps: list of suggested actions
- evidence_summary: summary of key evidence""",

    TaskType.REMEDIATION.value: """You are a Remediation Expert for production systems.
Your job is to plan safe, effective remediation actions based on root cause analysis.
You should consider risks, include verification steps, and plan for rollback.

Output your plan as a JSON object with the following fields:
- steps: list of remediation steps with action_type, command, risk_level, etc.
- execution_order: description of how steps should be executed
- total_estimated_duration_seconds: estimated time to complete
- blast_radius_mitigation: how impact is being limited
- overall_confidence: confidence in the plan 0-1
- post_remediation_validation: list of validation steps
- warnings: list of important warnings""",

    TaskType.END_TO_END.value: """You are an AI DevOps agent handling production incidents.
Given an alert, you should analyze the situation, investigate the root cause,
and recommend appropriate remediation actions.

Provide a complete incident response including:
1. Triage classification
2. Root cause analysis
3. Remediation plan""",
}
