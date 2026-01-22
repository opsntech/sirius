"""Structured output models for AI agents.

These Pydantic models define the exact schema for agent outputs,
replacing brittle regex-based parsing with type-safe structured data.
"""

from datetime import datetime
from typing import List, Optional, Literal
from pydantic import BaseModel, Field


class TriageOutput(BaseModel):
    """Structured triage output from the Triage Agent."""

    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
        description="Alert severity classification"
    )
    urgency: Literal["immediate", "soon", "scheduled"] = Field(
        description="Response urgency level"
    )
    blast_radius: Literal["single_host", "service", "multi_service", "platform"] = Field(
        description="Estimated impact scope"
    )
    affected_services: List[str] = Field(
        default_factory=list,
        description="List of affected services"
    )
    suggested_focus: List[str] = Field(
        default_factory=list,
        max_length=5,
        description="Top areas to investigate first"
    )
    escalation_required: bool = Field(
        default=False,
        description="Whether human escalation is needed"
    )
    reasoning: str = Field(
        max_length=1000,
        description="Brief explanation of triage decision"
    )


class InvestigationFinding(BaseModel):
    """Single investigation finding from a tool execution."""

    tool_used: str = Field(description="Name of the tool executed")
    command_executed: str = Field(description="Actual command run")
    raw_output: str = Field(description="Raw output from the command")
    interpretation: str = Field(description="What this output means")
    supports_hypothesis: Optional[str] = Field(
        default=None,
        description="Hypothesis this finding supports"
    )
    refutes_hypothesis: Optional[str] = Field(
        default=None,
        description="Hypothesis this finding refutes"
    )
    confidence_delta: float = Field(
        default=0.0,
        ge=-1.0,
        le=1.0,
        description="How much this changes confidence (-1 to 1)"
    )
    is_critical: bool = Field(
        default=False,
        description="Whether this is a critical finding"
    )


class AnalysisOutput(BaseModel):
    """Structured analysis output from the Analysis Agent."""

    hypotheses_tested: List[str] = Field(
        default_factory=list,
        description="List of hypotheses that were tested"
    )
    findings: List[InvestigationFinding] = Field(
        default_factory=list,
        description="Investigation findings from tool executions"
    )
    root_cause: str = Field(
        description="Identified root cause of the incident"
    )
    root_cause_confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence in root cause (0-1)"
    )
    contributing_factors: List[str] = Field(
        default_factory=list,
        description="Additional factors contributing to the issue"
    )
    remaining_unknowns: List[str] = Field(
        default_factory=list,
        description="Questions that remain unanswered"
    )
    recommended_next_steps: List[str] = Field(
        default_factory=list,
        description="Suggested next investigation steps if needed"
    )
    evidence_summary: str = Field(
        default="",
        description="Summary of key evidence supporting the root cause"
    )


class RemediationStep(BaseModel):
    """Single remediation step in a remediation plan."""

    action_type: str = Field(description="Type of action (e.g., restart_service, kill_process)")
    description: str = Field(description="Human-readable description of the action")
    target_host: str = Field(description="Target server hostname or IP")
    target_service: str = Field(description="Target service or process name")
    command: str = Field(description="Actual command to execute")
    risk_level: Literal["low", "medium", "high", "critical"] = Field(
        description="Risk level of this action"
    )
    risk_factors: List[str] = Field(
        default_factory=list,
        description="Specific risks associated with this action"
    )
    expected_outcome: str = Field(description="What should happen if successful")
    verification_command: str = Field(
        default="",
        description="Command to verify the action succeeded"
    )
    rollback_command: Optional[str] = Field(
        default=None,
        description="Command to rollback if action fails"
    )
    timeout_seconds: int = Field(
        default=60,
        ge=10,
        le=600,
        description="Maximum execution time"
    )
    requires_approval: bool = Field(
        default=True,
        description="Whether human approval is needed"
    )
    prerequisites: List[str] = Field(
        default_factory=list,
        description="Conditions that must be met before execution"
    )


class RemediationOutput(BaseModel):
    """Structured remediation output from the Remediation Agent."""

    steps: List[RemediationStep] = Field(
        default_factory=list,
        description="Ordered list of remediation steps"
    )
    execution_order: str = Field(
        default="sequential",
        description="Description of execution order and dependencies"
    )
    total_estimated_duration_seconds: int = Field(
        default=60,
        ge=0,
        description="Total estimated time to complete all steps"
    )
    blast_radius_mitigation: str = Field(
        default="",
        description="How blast radius is being limited"
    )
    overall_confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Overall confidence in remediation plan"
    )
    post_remediation_validation: List[str] = Field(
        default_factory=list,
        description="Steps to validate remediation was successful"
    )
    alternative_approaches: List[str] = Field(
        default_factory=list,
        description="Alternative remediation approaches if primary fails"
    )
    warnings: List[str] = Field(
        default_factory=list,
        description="Important warnings about this remediation"
    )


class OrchestratorDecision(BaseModel):
    """Decision output from the Orchestrator Agent."""

    workflow_path: Literal["fast_path", "standard", "extended", "escalate"] = Field(
        description="Which workflow path to take"
    )
    similar_incident_id: Optional[str] = Field(
        default=None,
        description="ID of similar past incident if found"
    )
    similarity_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Similarity to past incident"
    )
    iteration_budget: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum investigation iterations"
    )
    priority_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Priority score for queue ordering"
    )
    reasoning: str = Field(
        description="Explanation of orchestration decision"
    )


class IncidentResolution(BaseModel):
    """Final resolution summary for an incident."""

    incident_id: str = Field(description="Incident identifier")
    resolved: bool = Field(description="Whether incident was resolved")
    resolution_type: Literal["auto_resolved", "manual_resolved", "escalated", "timeout"] = Field(
        description="How the incident was resolved"
    )
    root_cause: str = Field(description="Final determined root cause")
    actions_taken: List[str] = Field(
        default_factory=list,
        description="List of actions that were executed"
    )
    mttr_seconds: Optional[int] = Field(
        default=None,
        description="Mean time to resolution in seconds"
    )
    lessons_learned: List[str] = Field(
        default_factory=list,
        description="Key takeaways from this incident"
    )
    prevention_recommendations: List[str] = Field(
        default_factory=list,
        description="Recommendations to prevent recurrence"
    )
