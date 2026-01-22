"""CrewAI agent definitions for the DevOps On-Call Agent."""

import asyncio
import os
from datetime import datetime
from typing import Optional

import structlog
from crewai import Agent, Crew, Process, Task, LLM

from src.config import Settings, get_settings
from src.models.incident import Incident, IncidentStatus, InvestigationStep, RemediationAction
from src.prompts.triage_prompt import TRIAGE_SYSTEM_PROMPT, format_triage_prompt
from src.prompts.analysis_prompt import ANALYSIS_SYSTEM_PROMPT, format_analysis_prompt
from src.prompts.remediation_prompt import REMEDIATION_SYSTEM_PROMPT, format_remediation_prompt
from src.tools.crewai_tools import CREWAI_INVESTIGATION_TOOLS


logger = structlog.get_logger()


class DevOpsCrew:
    """
    CrewAI-based multi-agent system for DevOps incident response.

    Agents:
    - Triage Agent: Classifies and prioritizes alerts
    - Analysis Agent: Investigates root cause via SSH tools
    - Remediation Agent: Recommends safe remediation actions
    """

    def __init__(self, settings: Optional[Settings] = None):
        self._settings = settings or get_settings()
        self._llm = self._create_llm()
        self._agents = self._create_agents()

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

        1. Triage: Classify and prioritize
        2. Analysis: Investigate root cause
        3. Remediation: Recommend actions

        Returns the updated incident with analysis results.
        """
        logger.info(
            "Starting incident analysis",
            incident_id=incident.id,
            title=incident.title,
            severity=incident.severity.value,
        )

        try:
            # Phase 1: Triage
            triage_result = await self._run_triage(incident)
            incident.add_investigation_step(InvestigationStep(
                timestamp=datetime.utcnow(),
                agent="triage",
                action="classify_alert",
                target=incident.primary_alert.host if incident.primary_alert else "unknown",
                result=triage_result,
                reasoning="Initial triage classification",
            ))

            # Phase 2: Analysis
            analysis_result = await self._run_analysis(incident)
            # Note: Analysis agent will add its own investigation steps via tool calls

            # Extract root cause from analysis
            root_cause, confidence = self._extract_root_cause(analysis_result)
            incident.set_root_cause(root_cause, confidence)

            # Phase 3: Remediation
            remediation_result = await self._run_remediation(incident)

            # Extract recommended actions (can be multiple)
            actions = self._extract_remediation_actions(remediation_result, incident)
            for action in actions:
                incident.add_recommended_action(action)

            logger.info(
                "Incident analysis complete",
                incident_id=incident.id,
                root_cause=incident.root_cause,
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

    async def _run_triage(self, incident: Incident) -> str:
        """Run triage classification."""
        logger.debug("Running triage", incident_id=incident.id)

        prompt = format_triage_prompt(incident.primary_alert)

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

    async def _run_analysis(self, incident: Incident) -> str:
        """Run root cause analysis."""
        logger.debug("Running analysis", incident_id=incident.id)

        prompt = format_analysis_prompt(incident)

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
        """Extract root cause and confidence from analysis result."""
        # Simple extraction - in production, use structured output
        root_cause = analysis_result

        # Look for confidence score in result
        confidence = 0.7  # Default confidence
        if "confidence" in analysis_result.lower():
            # Try to extract percentage
            import re
            match = re.search(r'(\d+)%', analysis_result)
            if match:
                confidence = int(match.group(1)) / 100

        return root_cause, confidence

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
