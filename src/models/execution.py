"""Execution record model for audit logging."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Optional
import uuid


class RiskLevel(str, Enum):
    """Risk level for remediation actions."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other):
        order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other):
        return self == other or self < other

    def __gt__(self, other):
        return not self <= other

    def __ge__(self, other):
        return not self < other


class ExecutionStatus(str, Enum):
    """Execution status values."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    TIMEOUT = "timeout"


@dataclass
class ExecutionRecord:
    """
    Audit record for a remediation action execution.

    Captures the full context of an AI-recommended action,
    including the reasoning, approval status, and execution result.
    """
    # Unique identifier
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Related incident
    incident_id: str = ""

    # Action details
    action_type: str = ""  # restart_service, kill_process, etc.
    target_host: str = ""
    target_service: Optional[str] = None
    command: str = ""
    parameters: Dict = field(default_factory=dict)

    # Risk assessment
    risk_level: RiskLevel = RiskLevel.MEDIUM
    blast_radius: int = 1  # Number of services/users affected

    # AI context
    ai_agent: str = ""  # Which agent recommended this
    ai_reasoning: str = ""  # Chain of thought
    confidence_score: float = 0.0  # 0.0 - 1.0
    alternative_actions: list = field(default_factory=list)

    # Approval workflow
    requires_approval: bool = True
    approval_requested_at: Optional[datetime] = None
    approval_channel: Optional[str] = None  # slack, manual, auto
    approval_message_id: Optional[str] = None  # Slack message ID
    approved_by: Optional[str] = None
    approval_timestamp: Optional[datetime] = None
    rejection_reason: Optional[str] = None

    # Execution
    status: ExecutionStatus = ExecutionStatus.PENDING
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    output: str = ""
    error: Optional[str] = None
    exit_code: Optional[int] = None

    # Rollback
    checkpoint_id: Optional[str] = None
    rolled_back: bool = False
    rollback_reason: Optional[str] = None
    rollback_at: Optional[datetime] = None

    # Verification
    verified: bool = False
    verification_result: Optional[str] = None
    verification_at: Optional[datetime] = None

    # Timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def request_approval(self, channel: str, message_id: Optional[str] = None):
        """Record that approval was requested."""
        self.approval_requested_at = datetime.utcnow()
        self.approval_channel = channel
        self.approval_message_id = message_id
        self.status = ExecutionStatus.PENDING
        self.updated_at = datetime.utcnow()

    def approve(self, approved_by: str):
        """Approve the action."""
        self.approved_by = approved_by
        self.approval_timestamp = datetime.utcnow()
        self.status = ExecutionStatus.APPROVED
        self.updated_at = datetime.utcnow()

    def reject(self, rejected_by: str, reason: str):
        """Reject the action."""
        self.approved_by = rejected_by  # Record who rejected
        self.approval_timestamp = datetime.utcnow()
        self.rejection_reason = reason
        self.status = ExecutionStatus.REJECTED
        self.updated_at = datetime.utcnow()

    def start_execution(self):
        """Mark execution as started."""
        self.status = ExecutionStatus.EXECUTING
        self.executed_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def complete_success(self, output: str, exit_code: int = 0):
        """Mark execution as successful."""
        self.status = ExecutionStatus.SUCCESS
        self.output = output
        self.exit_code = exit_code
        self.completed_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def complete_failure(self, error: str, exit_code: int = 1):
        """Mark execution as failed."""
        self.status = ExecutionStatus.FAILED
        self.error = error
        self.exit_code = exit_code
        self.completed_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def record_rollback(self, reason: str):
        """Record that a rollback was performed."""
        self.rolled_back = True
        self.rollback_reason = reason
        self.rollback_at = datetime.utcnow()
        self.status = ExecutionStatus.ROLLED_BACK
        self.updated_at = datetime.utcnow()

    def verify(self, success: bool, result: str):
        """Record verification result."""
        self.verified = True
        self.verification_result = result
        self.verification_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

        if not success and self.status == ExecutionStatus.SUCCESS:
            # Verification failed, mark as failed
            self.status = ExecutionStatus.FAILED
            self.error = f"Verification failed: {result}"

    @property
    def execution_duration_seconds(self) -> Optional[float]:
        """Calculate execution duration in seconds."""
        if not self.executed_at or not self.completed_at:
            return None
        return (self.completed_at - self.executed_at).total_seconds()

    @property
    def approval_wait_seconds(self) -> Optional[float]:
        """Calculate time waiting for approval in seconds."""
        if not self.approval_requested_at or not self.approval_timestamp:
            return None
        return (self.approval_timestamp - self.approval_requested_at).total_seconds()

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization and audit logging."""
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "action_type": self.action_type,
            "target_host": self.target_host,
            "target_service": self.target_service,
            "command": self.command,
            "parameters": self.parameters,
            "risk_level": self.risk_level.value,
            "blast_radius": self.blast_radius,
            "ai_agent": self.ai_agent,
            "ai_reasoning": self.ai_reasoning,
            "confidence_score": self.confidence_score,
            "alternative_actions": self.alternative_actions,
            "requires_approval": self.requires_approval,
            "approval_requested_at": self.approval_requested_at.isoformat() if self.approval_requested_at else None,
            "approval_channel": self.approval_channel,
            "approved_by": self.approved_by,
            "approval_timestamp": self.approval_timestamp.isoformat() if self.approval_timestamp else None,
            "rejection_reason": self.rejection_reason,
            "status": self.status.value,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "output": self.output,
            "error": self.error,
            "exit_code": self.exit_code,
            "rolled_back": self.rolled_back,
            "rollback_reason": self.rollback_reason,
            "rollback_at": self.rollback_at.isoformat() if self.rollback_at else None,
            "verified": self.verified,
            "verification_result": self.verification_result,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    def to_audit_log(self) -> str:
        """Generate a human-readable audit log entry."""
        lines = [
            f"=== Execution Record {self.id} ===",
            f"Incident: {self.incident_id}",
            f"Action: {self.action_type} on {self.target_host}",
            f"Command: {self.command}",
            f"Risk Level: {self.risk_level.value}",
            f"Confidence: {self.confidence_score:.2%}",
            f"",
            f"AI Reasoning:",
            f"  {self.ai_reasoning}",
            f"",
            f"Approval:",
            f"  Required: {self.requires_approval}",
            f"  Status: {self.status.value}",
            f"  Approved By: {self.approved_by or 'N/A'}",
            f"",
            f"Execution:",
            f"  Started: {self.executed_at}",
            f"  Completed: {self.completed_at}",
            f"  Exit Code: {self.exit_code}",
            f"  Output: {self.output[:500]}..." if len(self.output) > 500 else f"  Output: {self.output}",
        ]

        if self.error:
            lines.append(f"  Error: {self.error}")

        if self.rolled_back:
            lines.append(f"")
            lines.append(f"Rollback:")
            lines.append(f"  Reason: {self.rollback_reason}")
            lines.append(f"  At: {self.rollback_at}")

        return "\n".join(lines)
