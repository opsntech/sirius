"""Remediation executor with safety controls."""

import asyncio
from datetime import datetime
from typing import Dict, Optional

import structlog

from src.config import Settings, get_settings
from src.models.incident import Incident, RemediationAction
from src.models.execution import ExecutionRecord, ExecutionStatus, RiskLevel
from src.tools.ssh_client import get_ssh_client, SSHExecutionError
from src.approval.slack_bot import ApprovalManager, ApprovalResult, get_approval_manager


logger = structlog.get_logger()


class CircuitBreaker:
    """
    Circuit breaker to prevent repeated failures.

    If an action type fails too many times, the circuit opens
    and prevents further attempts for a cooldown period.
    """

    def __init__(
        self,
        failure_threshold: int = 3,
        cooldown_seconds: int = 300,
    ):
        self._failure_threshold = failure_threshold
        self._cooldown_seconds = cooldown_seconds
        self._failures: Dict[str, list] = {}  # action_type -> list of failure times
        self._lock = asyncio.Lock()

    async def is_open(self, action_type: str) -> bool:
        """Check if the circuit is open for an action type."""
        async with self._lock:
            if action_type not in self._failures:
                return False

            failures = self._failures[action_type]
            now = datetime.utcnow()

            # Remove old failures outside cooldown window
            cutoff = now.timestamp() - self._cooldown_seconds
            failures = [f for f in failures if f > cutoff]
            self._failures[action_type] = failures

            return len(failures) >= self._failure_threshold

    async def record_failure(self, action_type: str):
        """Record a failure for an action type."""
        async with self._lock:
            if action_type not in self._failures:
                self._failures[action_type] = []
            self._failures[action_type].append(datetime.utcnow().timestamp())

    async def record_success(self, action_type: str):
        """Record a success (resets failure count)."""
        async with self._lock:
            self._failures.pop(action_type, None)

    async def reset(self, action_type: Optional[str] = None):
        """Reset the circuit breaker."""
        async with self._lock:
            if action_type:
                self._failures.pop(action_type, None)
            else:
                self._failures.clear()


class RemediationExecutor:
    """
    Executes remediation actions with safety controls.

    Features:
    - Circuit breaker to prevent repeated failures
    - Pre-execution validation
    - Post-execution verification
    - Audit logging
    - Rollback support (where possible)
    """

    def __init__(self, settings: Optional[Settings] = None):
        self._settings = settings or get_settings()
        self._ssh_client = get_ssh_client(settings)
        self._approval_manager = get_approval_manager(settings)
        self._circuit_breaker = CircuitBreaker()

        # Execution records for audit
        self._execution_records: Dict[str, ExecutionRecord] = {}

    async def execute(
        self,
        incident: Incident,
        action: RemediationAction,
    ) -> ExecutionRecord:
        """
        Execute a remediation action with full safety controls.

        1. Check circuit breaker
        2. Request approval if needed
        3. Validate pre-conditions
        4. Execute the action
        5. Verify success
        6. Record result

        Args:
            incident: The incident being remediated
            action: The remediation action to execute

        Returns:
            ExecutionRecord with full audit trail
        """
        # Create execution record
        record = ExecutionRecord(
            incident_id=incident.id,
            action_type=action.action_type,
            target_host=action.target_host,
            target_service=action.target_service,
            command=action.command,
            parameters=action.parameters,
            risk_level=RiskLevel(action.risk_level),
            ai_agent="remediation",
            ai_reasoning=action.reasoning,
            confidence_score=action.confidence,
            requires_approval=action.requires_approval,
        )

        logger.info(
            "Starting remediation execution",
            incident_id=incident.id,
            action_type=action.action_type,
            target=action.target_host,
        )

        try:
            # Step 1: Check circuit breaker
            if await self._circuit_breaker.is_open(action.action_type):
                record.complete_failure(
                    f"Circuit breaker open for {action.action_type}"
                )
                logger.warning(
                    "Circuit breaker open",
                    action_type=action.action_type,
                )
                return record

            # Step 2: Request approval
            approval = await self._approval_manager.request_approval(
                incident, action, record
            )

            if not approval.approved:
                record.reject(
                    approval.approved_by or "unknown",
                    approval.reason or "Approval denied",
                )
                logger.info(
                    "Remediation rejected",
                    incident_id=incident.id,
                    reason=approval.reason,
                )
                return record

            record.approve(approval.approved_by or "auto")

            # Step 3: Validate pre-conditions
            valid, reason = await self._validate_preconditions(action)
            if not valid:
                record.complete_failure(f"Pre-condition failed: {reason}")
                return record

            # Step 4: Execute the action
            record.start_execution()

            try:
                stdout, stderr, exit_code = await self._ssh_client.execute(
                    host=action.target_host,
                    command=action.command,
                    timeout=60,
                )

                if exit_code == 0:
                    record.complete_success(stdout, exit_code)
                    await self._circuit_breaker.record_success(action.action_type)
                else:
                    record.complete_failure(
                        f"Command failed: {stderr}",
                        exit_code,
                    )
                    await self._circuit_breaker.record_failure(action.action_type)

            except SSHExecutionError as e:
                record.complete_failure(str(e))
                await self._circuit_breaker.record_failure(action.action_type)

            # Step 5: Verify success
            if record.status == ExecutionStatus.SUCCESS:
                verified, result = await self._verify_execution(action)
                record.verify(verified, result)

            logger.info(
                "Remediation execution complete",
                incident_id=incident.id,
                status=record.status.value,
                exit_code=record.exit_code,
            )

        except Exception as e:
            logger.error(
                "Remediation execution error",
                incident_id=incident.id,
                error=str(e),
            )
            record.complete_failure(str(e))
            await self._circuit_breaker.record_failure(action.action_type)

        # Store record
        self._execution_records[record.id] = record

        return record

    async def _validate_preconditions(
        self,
        action: RemediationAction,
    ) -> tuple[bool, str]:
        """Validate that preconditions are met for the action."""
        # Check that we can reach the target host
        try:
            stdout, _, exit_code = await self._ssh_client.execute(
                host=action.target_host,
                command="echo ok",
                timeout=10,
            )
            if exit_code != 0:
                return False, f"Cannot connect to {action.target_host}"
        except Exception as e:
            return False, f"SSH connection failed: {str(e)}"

        # Action-specific validations
        if action.action_type == "restart_service":
            # Check if service exists
            try:
                _, _, exit_code = await self._ssh_client.execute(
                    host=action.target_host,
                    command=f"systemctl cat {action.target_service}",
                    timeout=10,
                )
                if exit_code != 0:
                    return False, f"Service {action.target_service} not found"
            except Exception:
                pass  # Continue if check fails

        return True, "Preconditions met"

    async def _verify_execution(
        self,
        action: RemediationAction,
    ) -> tuple[bool, str]:
        """Verify that the action was successful."""
        await asyncio.sleep(5)  # Wait for action to take effect

        try:
            if action.action_type == "restart_service":
                # Check if service is running
                stdout, _, exit_code = await self._ssh_client.execute(
                    host=action.target_host,
                    command=f"systemctl is-active {action.target_service}",
                    timeout=10,
                )
                if exit_code == 0 and "active" in stdout.lower():
                    return True, f"Service {action.target_service} is active"
                else:
                    return False, f"Service {action.target_service} not active after restart"

            elif action.action_type == "restart_docker":
                # Check if container is running
                container = action.parameters.get("container") or action.target_service
                stdout, _, exit_code = await self._ssh_client.execute(
                    host=action.target_host,
                    command=f"docker inspect -f '{{{{.State.Running}}}}' {container}",
                    timeout=10,
                )
                if "true" in stdout.lower():
                    return True, f"Container {container} is running"
                else:
                    return False, f"Container {container} not running after restart"

            else:
                # Default verification - just check command succeeded
                return True, "Action completed successfully"

        except Exception as e:
            return False, f"Verification failed: {str(e)}"

    def get_execution_record(self, record_id: str) -> Optional[ExecutionRecord]:
        """Get an execution record by ID."""
        return self._execution_records.get(record_id)

    def get_execution_records_for_incident(
        self,
        incident_id: str,
    ) -> list[ExecutionRecord]:
        """Get all execution records for an incident."""
        return [
            r for r in self._execution_records.values()
            if r.incident_id == incident_id
        ]


# Global executor instance
_executor: Optional[RemediationExecutor] = None


def get_executor(settings: Optional[Settings] = None) -> RemediationExecutor:
    """Get the global remediation executor instance."""
    global _executor
    if _executor is None:
        _executor = RemediationExecutor(settings)
    return _executor


async def execute_remediation(
    incident: Incident,
    action: RemediationAction,
) -> ExecutionRecord:
    """Convenience function to execute a remediation action."""
    executor = get_executor()
    return await executor.execute(incident, action)
