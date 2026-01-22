"""CrewAI agent definitions for the DevOps On-Call Agent.

Enhanced with:
- Pattern memory for similar incident detection
- Training data collection hooks
- Improved confidence extraction
"""

import asyncio
import os
import re
from datetime import datetime
from typing import Optional, Dict, Any, List

import structlog
from crewai import Agent, Crew, Process, Task, LLM

from src.config import Settings, get_settings
from src.models.incident import Incident, IncidentStatus, InvestigationStep, RemediationAction
from src.models.outputs import TriageOutput, AnalysisOutput, RemediationOutput
from src.prompts.triage_prompt import TRIAGE_SYSTEM_PROMPT, format_triage_prompt
from src.prompts.analysis_prompt import ANALYSIS_SYSTEM_PROMPT, format_analysis_prompt
from src.prompts.remediation_prompt import REMEDIATION_SYSTEM_PROMPT, format_remediation_prompt
from src.tools.crewai_tools import CREWAI_INVESTIGATION_TOOLS


logger = structlog.get_logger()


# Try to import optional components
try:
    from src.data.collector import get_collector, TrainingDataCollector
    DATA_COLLECTION_AVAILABLE = True
except ImportError:
    DATA_COLLECTION_AVAILABLE = False
    logger.warning("Training data collection not available")

try:
    from src.memory.incident_memory import get_memory, IncidentMemory, SimilarIncident
    MEMORY_AVAILABLE = True
except ImportError:
    MEMORY_AVAILABLE = False
    logger.warning("Incident memory not available")


class DevOpsCrew:
    """
    CrewAI-based multi-agent system for DevOps incident response.

    Enhanced v2.0 with:
    - Pattern memory for similar incident detection
    - Training data collection for ML pipeline
    - Improved structured output parsing

    Agents:
    - Triage Agent: Classifies and prioritizes alerts
    - Analysis Agent: Investigates root cause via SSH tools
    - Remediation Agent: Recommends safe remediation actions
    """

    def __init__(
        self,
        settings: Optional[Settings] = None,
        enable_data_collection: bool = True,
        enable_memory: bool = True,
    ):
        self._settings = settings or get_settings()
        self._llm = self._create_llm()
        self._agents = self._create_agents()

        # Initialize data collector
        self._collector: Optional[Any] = None
        if enable_data_collection and DATA_COLLECTION_AVAILABLE:
            try:
                self._collector = get_collector(enabled=True)
                logger.info("Training data collection enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize data collector: {e}")

        # Initialize memory system
        self._memory: Optional[Any] = None
        if enable_memory and MEMORY_AVAILABLE:
            try:
                self._memory = get_memory()
                logger.info("Incident memory enabled")
            except Exception as e:
                logger.warning(f"Failed to initialize memory: {e}")

    def _create_llm(self) -> LLM:
        """Create the CrewAI LLM for agents using NVIDIA NIM."""
        config = self._settings.nvidia

        # Set environment variable for API key
        os.environ["OPENAI_API_KEY"] = config.api_key

        # Use CrewAI's LLM wrapper with OpenAI-compatible endpoint
        return LLM(
            model=f"openai/{config.model}",
            base_url=config.base_url,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
        )

    def _create_agents(self) -> dict:
        """Create all agents."""
        # Triage Agent - Quick classification, no tools needed
        triage_agent = Agent(
            role="Triage Specialist",
            goal="Quickly classify alert severity and determine appropriate response",
            backstory=TRIAGE_SYSTEM_PROMPT,
            llm=self._llm,
            verbose=True,
            allow_delegation=False,
        )

        # Analysis Agent - Investigates via SSH tools
        analysis_agent = Agent(
            role="Senior SRE Analyst",
            goal="Investigate root cause by SSHing into affected servers and running diagnostic commands",
            backstory=ANALYSIS_SYSTEM_PROMPT,
            llm=self._llm,
            tools=CREWAI_INVESTIGATION_TOOLS,
            verbose=True,
            allow_delegation=False,
        )

        # Remediation Agent - Plans safe remediation
        remediation_agent = Agent(
            role="Remediation Expert",
            goal="Determine the safest and most effective remediation action",
            backstory=REMEDIATION_SYSTEM_PROMPT,
            llm=self._llm,
            verbose=True,
            allow_delegation=False,
        )

        return {
            "triage": triage_agent,
            "analysis": analysis_agent,
            "remediation": remediation_agent,
        }

    async def analyze_incident(self, incident: Incident) -> Incident:
        """
        Run the full incident analysis workflow.

        Enhanced v2.0 workflow:
        0. Check memory for similar past incidents
        1. Triage: Classify and prioritize
        2. Analysis: Investigate root cause
        3. Remediation: Recommend actions
        4. Collect training data

        Returns the updated incident with analysis results.
        """
        logger.info(
            "Starting incident analysis",
            incident_id=incident.id,
            title=incident.title,
            severity=incident.severity.value,
        )

        # Initialize data collection for this incident
        if self._collector and incident.primary_alert:
            try:
                await self._collector.on_alert_received(
                    incident.primary_alert,
                    incident,
                )
            except Exception as e:
                logger.warning(f"Data collection failed on alert: {e}")

        # Check memory for similar incidents
        similar_incidents: List[Any] = []
        if self._memory:
            try:
                similar_incidents = await self._memory.find_similar(incident)
                if similar_incidents:
                    logger.info(
                        "Found similar past incidents",
                        incident_id=incident.id,
                        similar_count=len(similar_incidents),
                        top_similarity=similar_incidents[0].similarity if similar_incidents else 0,
                    )
                    # Notify data collector
                    if self._collector:
                        await self._collector.on_similar_incidents_found(
                            incident.id,
                            [s.to_dict() for s in similar_incidents],
                        )
            except Exception as e:
                logger.warning(f"Memory lookup failed: {e}")

        try:
            # Phase 1: Triage
            triage_result = await self._run_triage(incident, similar_incidents)
            incident.add_investigation_step(InvestigationStep(
                timestamp=datetime.utcnow(),
                agent="triage",
                action="classify_alert",
                target=incident.primary_alert.host if incident.primary_alert else "unknown",
                result=triage_result,
                reasoning="Initial triage classification",
            ))

            # Collect triage data
            if self._collector:
                try:
                    triage_data = self._parse_triage_output(triage_result)
                    await self._collector.on_triage_complete(incident.id, triage_data)
                except Exception as e:
                    logger.warning(f"Data collection failed on triage: {e}")

            # Phase 2: Analysis
            analysis_result = await self._run_analysis(incident, similar_incidents)
            # Note: Analysis agent will add its own investigation steps via tool calls

            # Extract root cause from analysis
            root_cause, confidence = self._extract_root_cause(analysis_result)
            incident.set_root_cause(root_cause, confidence)

            # Collect analysis data
            if self._collector:
                try:
                    analysis_data = self._parse_analysis_output(analysis_result, root_cause, confidence)
                    await self._collector.on_analysis_complete(incident.id, analysis_data)
                except Exception as e:
                    logger.warning(f"Data collection failed on analysis: {e}")

            # Phase 3: Remediation
            remediation_result = await self._run_remediation(incident)

            # Extract recommended actions (can be multiple)
            actions = self._extract_remediation_actions(remediation_result, incident)
            for action in actions:
                incident.add_recommended_action(action)

            # Collect remediation data
            if self._collector:
                try:
                    remediation_data = self._parse_remediation_output(remediation_result, actions)
                    await self._collector.on_remediation_complete(incident.id, remediation_data)
                except Exception as e:
                    logger.warning(f"Data collection failed on remediation: {e}")

            logger.info(
                "Incident analysis complete",
                incident_id=incident.id,
                root_cause=incident.root_cause[:100] if incident.root_cause else None,
                confidence=incident.root_cause_confidence,
                has_recommendation=len(incident.recommended_actions) > 0,
            )

            return incident

        except Exception as e:
            logger.error(
                "Incident analysis failed",
                incident_id=incident.id,
                error=str(e),
            )
            raise

    async def _run_triage(
        self,
        incident: Incident,
        similar_incidents: Optional[List[Any]] = None,
    ) -> str:
        """Run triage classification."""
        logger.debug("Running triage", incident_id=incident.id)

        prompt = format_triage_prompt(incident.primary_alert)

        # Add similar incident context if available
        if similar_incidents:
            prompt += "\n\n## Similar Past Incidents:\n"
            for sim in similar_incidents[:3]:
                prompt += f"- **{sim.incident_id}** (similarity: {sim.similarity:.0%})\n"
                prompt += f"  Root cause: {sim.root_cause[:200]}\n"
                prompt += f"  Resolution: {sim.resolution_type}\n"

        task = Task(
            description=prompt,
            agent=self._agents["triage"],
            expected_output="Triage classification with severity, affected service, and urgency assessment",
        )

        crew = Crew(
            agents=[self._agents["triage"]],
            tasks=[task],
            process=Process.sequential,
            verbose=True,
        )

        # Run synchronously (CrewAI doesn't support async yet)
        result = await asyncio.to_thread(crew.kickoff)
        return str(result)

    async def _run_analysis(
        self,
        incident: Incident,
        similar_incidents: Optional[List[Any]] = None,
    ) -> str:
        """Run root cause analysis."""
        logger.debug("Running analysis", incident_id=incident.id)

        prompt = format_analysis_prompt(incident)

        # Add similar incident context if available
        if similar_incidents:
            prompt += "\n\n## Similar Past Incidents (for reference):\n"
            for sim in similar_incidents[:3]:
                prompt += f"- **{sim.incident_id}** (similarity: {sim.similarity:.0%})\n"
                prompt += f"  Root cause: {sim.root_cause[:300]}\n"
                if sim.actions_taken:
                    prompt += f"  Actions: {', '.join(sim.actions_taken[:3])}\n"

        task = Task(
            description=prompt,
            agent=self._agents["analysis"],
            expected_output="Root cause analysis with evidence, confidence score, and recommended actions",
        )

        crew = Crew(
            agents=[self._agents["analysis"]],
            tasks=[task],
            process=Process.sequential,
            verbose=True,
        )

        result = await asyncio.to_thread(crew.kickoff)
        return str(result)

    async def _run_remediation(self, incident: Incident) -> str:
        """Run remediation planning."""
        logger.debug("Running remediation planning", incident_id=incident.id)

        prompt = format_remediation_prompt(incident)

        task = Task(
            description=prompt,
            agent=self._agents["remediation"],
            expected_output="Remediation recommendation with action, risk assessment, and verification steps",
        )

        crew = Crew(
            agents=[self._agents["remediation"]],
            tasks=[task],
            process=Process.sequential,
            verbose=True,
        )

        result = await asyncio.to_thread(crew.kickoff)
        return str(result)

    def _extract_root_cause(self, analysis_result: str) -> tuple[str, float]:
        """Extract root cause and confidence from analysis result.

        Improved extraction with proper confidence clamping.
        """
        # Simple extraction - in production, use structured output
        root_cause = analysis_result

        # Look for confidence score in result - look for specific patterns
        confidence = 0.7  # Default confidence

        # Try multiple patterns to find confidence
        confidence_patterns = [
            r'confidence[:\s]+(\d+)\s*%',  # "confidence: 85%"
            r'confidence[:\s]+(\d+\.?\d*)',  # "confidence: 0.85" or "confidence: 85"
            r'(\d+)%\s+confidence',  # "85% confidence"
            r'confidence\s+(?:level|score)?[:\s]+(\d+)',  # "confidence level: 85"
        ]

        for pattern in confidence_patterns:
            match = re.search(pattern, analysis_result.lower())
            if match:
                try:
                    val = float(match.group(1))
                    # If value > 1, assume it's a percentage
                    if val > 1:
                        val = val / 100
                    # Clamp to valid range
                    confidence = max(0.0, min(1.0, val))
                    break
                except (ValueError, IndexError):
                    continue

        return root_cause, confidence

    def _parse_triage_output(self, triage_result: str) -> Dict[str, Any]:
        """Parse triage output into structured format for data collection."""
        # Extract key fields from triage result
        severity = "medium"
        urgency = "soon"

        # Try to extract severity
        severity_match = re.search(
            r'severity[:\s]*(critical|high|medium|low|info)',
            triage_result.lower()
        )
        if severity_match:
            severity = severity_match.group(1)

        # Try to extract urgency
        urgency_match = re.search(
            r'urgency[:\s]*(immediate|soon|scheduled)',
            triage_result.lower()
        )
        if urgency_match:
            urgency = urgency_match.group(1)

        return {
            "severity": severity,
            "urgency": urgency,
            "reasoning": triage_result[:500],
            "raw_output": triage_result,
        }

    def _parse_analysis_output(
        self,
        analysis_result: str,
        root_cause: str,
        confidence: float,
    ) -> Dict[str, Any]:
        """Parse analysis output into structured format for data collection."""
        return {
            "root_cause": root_cause[:1000],
            "root_cause_confidence": confidence,
            "raw_output": analysis_result,
            "evidence_summary": analysis_result[:500],
        }

    def _parse_remediation_output(
        self,
        remediation_result: str,
        actions: List[RemediationAction],
    ) -> Dict[str, Any]:
        """Parse remediation output into structured format for data collection."""
        return {
            "steps": [
                {
                    "action_type": a.action_type,
                    "target_host": a.target_host,
                    "command": a.command,
                    "risk_level": a.risk_level,
                    "requires_approval": a.requires_approval,
                }
                for a in actions
            ],
            "raw_output": remediation_result,
        }

    def _extract_remediation_actions(
        self,
        remediation_result: str,
        incident: Incident,
    ) -> list[RemediationAction]:
        """Extract one or more remediation actions from AI response.

        Parses the new ACTIONS format:
        ACTIONS:
        1. action_type: desc | target: host | service: svc | risk: level | command: cmd
        2. ...

        Falls back to old single-action extraction if new format not found.
        """
        import re

        actions = []
        primary_alert = incident.primary_alert
        if not primary_alert:
            return actions

        # Try to find ACTIONS: section with numbered items
        # Pattern: "1. action_type: ... | target: ... | service: ... | risk: ... | command: ..."
        action_pattern = re.compile(
            r'^\d+\.\s*(\w+):\s*([^|]+)\|'  # action_type: description |
            r'\s*target:\s*([^|]+)\|'        # target: hostname |
            r'\s*service:\s*([^|]+)\|'       # service: name |
            r'\s*risk:\s*(\w+)\|'            # risk: level |
            r'\s*command:\s*(.+)$',          # command: cmd
            re.IGNORECASE | re.MULTILINE
        )

        matches = action_pattern.findall(remediation_result)

        if matches:
            # Parse each matched action
            for match in matches:
                action_type, description, target, service, risk, command = match
                action_type = action_type.strip()
                target = target.strip()
                service = service.strip()
                risk_level = risk.strip().lower()
                command = command.strip()

                # Determine if approval is required based on risk
                requires_approval = risk_level in ["medium", "high", "critical"]

                # Extract confidence from overall result (clamp to 0-1)
                confidence = incident.root_cause_confidence
                conf_match = re.search(r'confidence[:\s]*(\d+)\s*%', remediation_result.lower())
                if conf_match:
                    conf_val = min(100, int(conf_match.group(1)))  # Clamp to 100 max
                    confidence = conf_val / 100

                action = RemediationAction(
                    action_type=action_type,
                    target_host=target or primary_alert.host,
                    target_service=service or primary_alert.job or "unknown",
                    command=command,
                    risk_level=risk_level,
                    confidence=confidence,
                    reasoning=description.strip(),
                    requires_approval=requires_approval,
                )
                actions.append(action)

                logger.info(
                    "Extracted remediation action",
                    incident_id=incident.id,
                    action_type=action_type,
                    risk_level=risk_level,
                    requires_approval=requires_approval,
                    command=command[:100],
                )

        # If no valid actions found, create safe diagnostic action based on alert type
        if not actions:
            logger.info("ACTIONS format not found, creating safe diagnostic action")
            single_action = self._create_safe_diagnostic_action(incident)
            if single_action:
                actions.append(single_action)

        logger.info(
            "Total remediation actions extracted",
            incident_id=incident.id,
            action_count=len(actions),
        )

        return actions

    def _create_safe_diagnostic_action(
        self,
        incident: Incident,
    ) -> Optional[RemediationAction]:
        """Create a safe diagnostic action based on alert type.

        Always creates LOW RISK investigation actions that are auto-approved.
        These gather information without making changes.
        """
        primary_alert = incident.primary_alert
        if not primary_alert:
            return None

        alertname = primary_alert.alertname.lower()
        host = primary_alert.host
        service = primary_alert.job or "system"

        # Map alert types to safe diagnostic commands
        if "disk" in alertname or "storage" in alertname:
            action_type = "check_disk"
            command = f"df -h && echo '' && echo '=== Largest dirs ===' && du -sh /var/log/* /tmp/* 2>/dev/null | sort -hr | head -10"

        elif "memory" in alertname or "oom" in alertname or "mem" in alertname:
            action_type = "check_memory"
            command = "free -h && echo '' && echo '=== Top Memory Processes ===' && ps aux --sort=-%mem | head -10"

        elif "cpu" in alertname or "load" in alertname:
            action_type = "check_cpu"
            command = "uptime && echo '' && echo '=== Top CPU Processes ===' && ps aux --sort=-%cpu | head -15"

        elif "kafka" in alertname or "lag" in alertname or "consumer" in alertname:
            action_type = "check_kafka"
            command = "echo '=== Kafka Consumer Groups ===' && kafka-consumer-groups.sh --bootstrap-server localhost:9092 --list 2>/dev/null || echo 'kafka-consumer-groups not available'"

        elif "service" in alertname or "unavailable" in alertname or "health" in alertname:
            action_type = "check_service"
            command = f"systemctl status {service} --no-pager 2>/dev/null || echo 'Service status check' && journalctl -u {service} -n 30 --no-pager 2>/dev/null || echo 'No journald logs'"

        elif "docker" in alertname or "container" in alertname:
            action_type = "check_docker"
            command = "docker ps -a --format 'table {{{{.Names}}}}\\t{{{{.Status}}}}\\t{{{{.Ports}}}}' | head -20"

        elif "network" in alertname or "connection" in alertname:
            action_type = "check_network"
            command = "ss -tuln | head -20 && echo '' && echo '=== Connection counts ===' && ss -s"

        else:
            # Generic system overview for any other alert
            action_type = "check_system"
            command = "uptime && echo '' && free -h && echo '' && df -h | head -5 && echo '' && ps aux --sort=-%cpu | head -10"

        action = RemediationAction(
            action_type=action_type,
            target_host=host,
            target_service=service,
            command=command,
            risk_level="low",
            confidence=incident.root_cause_confidence,
            reasoning=f"Safe diagnostic check for {alertname} alert on {host}",
            requires_approval=False,  # Low risk = auto-approved
        )

        logger.info(
            "Created safe diagnostic action",
            incident_id=incident.id,
            action_type=action_type,
            target=host,
            risk_level="low",
        )

        return action

    async def record_incident_resolution(
        self,
        incident: Incident,
        success: bool,
        mttr_seconds: Optional[int] = None,
        actions_taken: Optional[List[str]] = None,
    ):
        """Record incident resolution in memory and data collector.

        Call this after an incident is resolved to:
        1. Store the incident in memory for future pattern matching
        2. Complete the training data collection
        """
        resolution_type = "auto_resolved" if success else "manual"
        actions = actions_taken or [a.action_type for a in incident.recommended_actions]

        # Store in memory for future pattern matching
        if self._memory and incident.root_cause:
            try:
                await self._memory.store_incident(
                    incident=incident,
                    root_cause=incident.root_cause,
                    resolution_type=resolution_type,
                    actions_taken=actions,
                    success=success,
                    mttr_seconds=mttr_seconds,
                )
                logger.info(
                    "Stored incident in memory",
                    incident_id=incident.id,
                    success=success,
                )
            except Exception as e:
                logger.warning(f"Failed to store incident in memory: {e}")

        # Record in data collector
        if self._collector:
            try:
                await self._collector.on_incident_resolved(
                    incident_id=incident.id,
                    resolution_success=success,
                    mttr_seconds=mttr_seconds,
                    caused_additional_alerts=False,
                    escalated=not success,
                )
            except Exception as e:
                logger.warning(f"Failed to record incident resolution: {e}")

    async def record_human_feedback(
        self,
        incident_id: str,
        approved: bool,
        feedback_text: Optional[str] = None,
    ):
        """Record human feedback (approval/rejection) for training data."""
        if self._collector:
            try:
                await self._collector.on_human_feedback(
                    incident_id=incident_id,
                    approved=approved,
                    feedback_text=feedback_text,
                )
            except Exception as e:
                logger.warning(f"Failed to record human feedback: {e}")

    async def get_memory_stats(self) -> Dict[str, Any]:
        """Get memory system statistics."""
        if self._memory:
            return await self._memory.get_stats()
        return {"enabled": False}

    async def get_collector_stats(self) -> Dict[str, Any]:
        """Get data collector statistics."""
        if self._collector:
            return await self._collector.get_stats()
        return {"enabled": False}


# Global crew instance
_crew: Optional[DevOpsCrew] = None


def get_crew(settings: Optional[Settings] = None) -> DevOpsCrew:
    """Get the global DevOps crew instance."""
    global _crew
    if _crew is None:
        _crew = DevOpsCrew(settings)
    return _crew


async def analyze_incident(incident: Incident) -> Incident:
    """Convenience function to analyze an incident."""
    crew = get_crew()
    return await crew.analyze_incident(incident)
