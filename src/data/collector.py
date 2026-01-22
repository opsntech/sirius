"""Training data collector for ML pipeline.

Collects data at various points during incident lifecycle and
assembles complete training examples.
"""

from datetime import datetime
from typing import Dict, Optional, Any
import asyncio

import structlog

from src.models.alert import Alert
from src.models.incident import Incident, InvestigationStep
from src.models.training import (
    TrainingExample, PartialExample, InputContext, AlertData,
    OutcomeLabels, ExampleMetadata, InvestigationStepData,
    SimilarIncidentSummary, ServerInfo, TaskType
)
from src.data.storage import TrainingDataStorage, get_storage


logger = structlog.get_logger()


class TrainingDataCollector:
    """
    Collects and stores training data from incident lifecycle.

    Hooks into the incident processing pipeline to capture:
    - Alert data and context
    - Triage decisions
    - Investigation tool outputs
    - Analysis results
    - Remediation plans
    - Execution outcomes
    - Human feedback
    """

    def __init__(self, storage: Optional[TrainingDataStorage] = None, enabled: bool = True):
        self.storage = storage or get_storage()
        self.enabled = enabled
        self._partial_examples: Dict[str, PartialExample] = {}
        self._lock = asyncio.Lock()

    async def on_alert_received(
        self,
        alert: Alert,
        incident: Incident,
        server_info: Optional[Dict] = None,
    ):
        """Called when alert creates/updates incident."""
        if not self.enabled:
            return

        async with self._lock:
            # Create AlertData from Alert model
            alert_data = AlertData(
                fingerprint=alert.fingerprint,
                alertname=alert.alertname,
                severity=alert.severity.value,
                status=alert.status.value,
                instance=alert.instance,
                job=alert.job,
                summary=alert.summary,
                description=alert.description,
                labels=alert.labels,
                annotations=alert.annotations,
                starts_at=alert.starts_at.isoformat() if alert.starts_at else None,
                source=alert.source,
            )

            # Create server info if provided
            srv_info = None
            if server_info:
                srv_info = ServerInfo(
                    hostname=server_info.get("hostname", alert.host),
                    ip=server_info.get("ip", alert.host),
                    role=server_info.get("role", "unknown"),
                    services=server_info.get("services", []),
                    environment=server_info.get("environment", "production"),
                    tags=server_info.get("tags", {}),
                )

            input_context = InputContext(
                alert=alert_data,
                investigation_steps=[],
                similar_incidents=[],
                server_info=srv_info,
                recent_deployments=[],
                recent_alerts=[],
                incident_age_seconds=0,
            )

            partial = PartialExample(
                incident_id=incident.id,
                timestamp=datetime.utcnow().isoformat(),
                input_context=input_context,
            )

            self._partial_examples[incident.id] = partial

            logger.debug(
                "Started collecting training data",
                incident_id=incident.id,
                alertname=alert.alertname,
            )

    async def on_similar_incidents_found(
        self,
        incident_id: str,
        similar_incidents: list,
    ):
        """Called when similar past incidents are found."""
        if not self.enabled:
            return

        async with self._lock:
            partial = self._partial_examples.get(incident_id)
            if not partial or not partial.input_context:
                return

            for sim in similar_incidents:
                partial.input_context.similar_incidents.append(
                    SimilarIncidentSummary(
                        incident_id=sim.get("incident_id", ""),
                        similarity_score=sim.get("similarity_score", 0.0),
                        root_cause=sim.get("root_cause", ""),
                        resolution_type=sim.get("resolution_type", ""),
                        mttr_seconds=sim.get("mttr_seconds"),
                    )
                )

    async def on_triage_complete(
        self,
        incident_id: str,
        triage_output: Dict[str, Any],
    ):
        """Called after triage agent completes."""
        if not self.enabled:
            return

        async with self._lock:
            partial = self._partial_examples.get(incident_id)
            if not partial:
                logger.warning(
                    "No partial example found for triage",
                    incident_id=incident_id,
                )
                return

            partial.triage_output = triage_output

            # Store triage-specific training example
            if partial.input_context:
                triage_example = TrainingExample(
                    incident_id=incident_id,
                    input_context=partial.input_context,
                    task_type=TaskType.TRIAGE.value,
                    expected_output=triage_output,
                    metadata=ExampleMetadata(
                        alert_type=partial.input_context.alert.alertname,
                        severity=partial.input_context.alert.severity,
                        environment=partial.input_context.server_info.environment
                            if partial.input_context.server_info else "production",
                    ),
                )

                await self.storage.store(triage_example)

                logger.debug(
                    "Stored triage training example",
                    incident_id=incident_id,
                    example_id=triage_example.example_id,
                )

    async def on_investigation_step(
        self,
        incident_id: str,
        step: InvestigationStep,
    ):
        """Called after each investigation tool execution."""
        if not self.enabled:
            return

        async with self._lock:
            partial = self._partial_examples.get(incident_id)
            if not partial or not partial.input_context:
                return

            step_data = InvestigationStepData(
                timestamp=step.timestamp.isoformat() if step.timestamp else datetime.utcnow().isoformat(),
                agent=step.agent,
                tool=step.action,
                command=step.action,
                target_host=step.target,
                output=step.result[:2000] if step.result else "",  # Truncate long outputs
                interpretation=step.reasoning or "",
                success=step.success,
            )

            partial.input_context.investigation_steps.append(step_data)

    async def on_analysis_complete(
        self,
        incident_id: str,
        analysis_output: Dict[str, Any],
    ):
        """Called after analysis agent completes."""
        if not self.enabled:
            return

        async with self._lock:
            partial = self._partial_examples.get(incident_id)
            if not partial:
                return

            partial.analysis_output = analysis_output

            # Store analysis-specific training example
            if partial.input_context:
                # Update incident age
                try:
                    start_time = datetime.fromisoformat(partial.timestamp)
                    partial.input_context.incident_age_seconds = int(
                        (datetime.utcnow() - start_time).total_seconds()
                    )
                except:
                    pass

                analysis_example = TrainingExample(
                    incident_id=incident_id,
                    input_context=partial.input_context,
                    task_type=TaskType.ANALYSIS.value,
                    expected_output=analysis_output,
                    metadata=ExampleMetadata(
                        alert_type=partial.input_context.alert.alertname,
                        severity=partial.input_context.alert.severity,
                        complexity_score=self._calculate_complexity(partial),
                    ),
                )

                await self.storage.store(analysis_example)

                logger.debug(
                    "Stored analysis training example",
                    incident_id=incident_id,
                    example_id=analysis_example.example_id,
                )

    async def on_remediation_complete(
        self,
        incident_id: str,
        remediation_output: Dict[str, Any],
    ):
        """Called after remediation planning completes."""
        if not self.enabled:
            return

        async with self._lock:
            partial = self._partial_examples.get(incident_id)
            if not partial:
                return

            partial.remediation_output = remediation_output

            # Store remediation-specific training example
            if partial.input_context:
                remediation_example = TrainingExample(
                    incident_id=incident_id,
                    input_context=partial.input_context,
                    task_type=TaskType.REMEDIATION.value,
                    expected_output=remediation_output,
                    metadata=ExampleMetadata(
                        alert_type=partial.input_context.alert.alertname,
                        severity=partial.input_context.alert.severity,
                        complexity_score=self._calculate_complexity(partial),
                    ),
                )

                await self.storage.store(remediation_example)

                logger.debug(
                    "Stored remediation training example",
                    incident_id=incident_id,
                    example_id=remediation_example.example_id,
                )

    async def on_human_feedback(
        self,
        incident_id: str,
        approved: bool,
        feedback_text: Optional[str] = None,
        corrections: Optional[Dict] = None,
    ):
        """Called when human provides feedback (approval/rejection)."""
        if not self.enabled:
            return

        async with self._lock:
            partial = self._partial_examples.get(incident_id)
            if not partial:
                return

            partial.outcome.human_approved = approved
            partial.outcome.human_feedback_text = feedback_text
            partial.outcome.human_corrections = corrections

            logger.debug(
                "Recorded human feedback",
                incident_id=incident_id,
                approved=approved,
            )

    async def on_execution_complete(
        self,
        incident_id: str,
        success: bool,
        verification_passed: bool,
        verification_output: Optional[str] = None,
        required_rollback: bool = False,
    ):
        """Called when remediation execution completes."""
        if not self.enabled:
            return

        async with self._lock:
            partial = self._partial_examples.get(incident_id)
            if not partial:
                return

            partial.outcome.resolution_success = success
            partial.outcome.verification_passed = verification_passed
            partial.outcome.verification_output = verification_output
            partial.outcome.required_rollback = required_rollback

    async def on_incident_resolved(
        self,
        incident_id: str,
        resolution_success: bool,
        mttr_seconds: Optional[int] = None,
        caused_additional_alerts: bool = False,
        escalated: bool = False,
    ):
        """Called when incident is resolved - finalize training data."""
        if not self.enabled:
            return

        async with self._lock:
            partial = self._partial_examples.get(incident_id)
            if not partial:
                return

            # Update final outcome
            partial.outcome.resolution_success = resolution_success
            partial.outcome.mttr_seconds = mttr_seconds
            partial.outcome.caused_additional_alerts = caused_additional_alerts
            partial.outcome.escalated_to_human = escalated

            # Create end-to-end training example if we have complete data
            if partial.is_complete() and partial.input_context:
                e2e_output = {
                    "triage": partial.triage_output,
                    "analysis": partial.analysis_output,
                    "remediation": partial.remediation_output,
                }

                e2e_example = TrainingExample(
                    incident_id=incident_id,
                    input_context=partial.input_context,
                    task_type=TaskType.END_TO_END.value,
                    expected_output=e2e_output,
                    outcome=partial.outcome,
                    metadata=ExampleMetadata(
                        alert_type=partial.input_context.alert.alertname,
                        severity=partial.input_context.alert.severity,
                        complexity_score=self._calculate_complexity(partial),
                        data_quality_score=partial.outcome.quality_score,
                    ),
                )

                await self.storage.store(e2e_example)

                logger.info(
                    "Stored end-to-end training example",
                    incident_id=incident_id,
                    example_id=e2e_example.example_id,
                    quality_score=partial.outcome.quality_score,
                    is_positive=partial.outcome.is_positive_example,
                )

            # Cleanup
            del self._partial_examples[incident_id]

    def _calculate_complexity(self, partial: PartialExample) -> float:
        """Calculate complexity score for an incident."""
        score = 0.5  # Base complexity

        if partial.input_context:
            # More investigation steps = more complex
            step_count = len(partial.input_context.investigation_steps)
            if step_count > 5:
                score += 0.2
            elif step_count > 2:
                score += 0.1

            # Critical severity = more complex
            if partial.input_context.alert.severity == "critical":
                score += 0.15
            elif partial.input_context.alert.severity == "high":
                score += 0.1

            # Multiple similar incidents = potentially complex pattern
            if len(partial.input_context.similar_incidents) > 2:
                score += 0.05

        return min(1.0, score)

    async def get_stats(self) -> Dict:
        """Get collection statistics."""
        storage_stats = await self.storage.get_stats()
        return {
            **storage_stats,
            "pending_examples": len(self._partial_examples),
        }


# Global collector instance
_collector: Optional[TrainingDataCollector] = None


def get_collector(
    storage_path: str = "/var/lib/sirius/training_data",
    enabled: bool = True,
) -> TrainingDataCollector:
    """Get the global collector instance."""
    global _collector
    if _collector is None:
        storage = get_storage(storage_path)
        _collector = TrainingDataCollector(storage=storage, enabled=enabled)
    return _collector
