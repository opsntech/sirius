"""CrewAI agent definitions for the DevOps On-Call Agent."""

import asyncio
from datetime import datetime
from typing import Optional

import structlog
from crewai import Agent, Crew, Process, Task
from langchain_openai import ChatOpenAI

from src.config import Settings, get_settings
from src.models.incident import Incident, IncidentStatus, InvestigationStep, RemediationAction
from src.tools.server_tools import INVESTIGATION_TOOLS
from src.prompts.triage_prompt import TRIAGE_SYSTEM_PROMPT, format_triage_prompt
from src.prompts.analysis_prompt import ANALYSIS_SYSTEM_PROMPT, format_analysis_prompt
from src.prompts.remediation_prompt import REMEDIATION_SYSTEM_PROMPT, format_remediation_prompt


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

    def _create_llm(self) -> ChatOpenAI:
        """Create the LangChain LLM for agents."""
        config = self._settings.nvidia
        return ChatOpenAI(
            base_url=config.base_url,
            api_key=config.api_key,
            model=config.model,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            timeout=config.timeout,
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

        # Analysis Agent - Has SSH tools for investigation
        analysis_agent = Agent(
            role="Senior SRE Analyst",
            goal="Investigate root cause by examining server metrics, logs, and processes",
            backstory=ANALYSIS_SYSTEM_PROMPT,
            tools=INVESTIGATION_TOOLS,
            llm=self._llm,
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

            # Extract recommended action
            action = self._extract_remediation_action(remediation_result, incident)
            if action:
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

    def _extract_remediation_action(
        self,
        remediation_result: str,
        incident: Incident,
    ) -> Optional[RemediationAction]:
        """Extract remediation action from result."""
        # Simple extraction - in production, use structured output
        # For now, create a basic action based on the result

        primary_alert = incident.primary_alert
        if not primary_alert:
            return None

        # Default to restart_service for most alerts
        action = RemediationAction(
            action_type="restart_service",
            target_host=primary_alert.host,
            target_service=primary_alert.job or "unknown",
            command=f"systemctl restart {primary_alert.job or 'app'}",
            risk_level="medium",
            confidence=incident.root_cause_confidence,
            reasoning=remediation_result,
            requires_approval=True,
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
