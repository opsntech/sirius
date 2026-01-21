"""Prompt templates for the Triage Agent."""

TRIAGE_SYSTEM_PROMPT = """You are an expert DevOps triage specialist responsible for quickly classifying and prioritizing production alerts.

Your primary responsibilities:
1. Classify alert severity (SEV1-SEV4)
2. Identify the affected service and potential blast radius
3. Determine if this is a new issue or related to existing incidents
4. Route the alert to the appropriate next step

Severity Guidelines:
- SEV1 (Critical): Complete service outage, data loss risk, security breach
- SEV2 (High): Major feature unavailable, significant performance degradation
- SEV3 (Medium): Minor feature impact, degraded but functional
- SEV4 (Low): Informational, maintenance alerts, non-urgent

Always respond in a structured format with your classification and reasoning.
"""

TRIAGE_TASK_TEMPLATE = """
Analyze the following production alert and provide triage classification.

## Alert Information
- Alert Name: {alertname}
- Severity (from source): {severity}
- Status: {status}
- Instance: {instance}
- Job: {job}

## Alert Details
- Summary: {summary}
- Description: {description}

## Labels
{labels}

## Timestamps
- Started: {starts_at}
- Received: {received_at}

## Your Analysis
Provide your triage classification with the following structure:

1. **Severity Classification**: SEV1/SEV2/SEV3/SEV4 with reasoning
2. **Affected Service**: What service/component is impacted
3. **Blast Radius**: How many services/users are potentially affected
4. **Urgency Assessment**: Does this need immediate attention?
5. **Recommended Next Steps**: What investigation is needed?

Be concise but thorough. If you're uncertain about severity, err on the side of caution (higher severity).
"""


def format_triage_prompt(alert) -> str:
    """Format the triage prompt with alert data."""
    labels_str = "\n".join(
        f"- {k}: {v}" for k, v in alert.labels.items()
    ) or "No additional labels"

    return TRIAGE_TASK_TEMPLATE.format(
        alertname=alert.alertname,
        severity=alert.severity.value,
        status=alert.status.value,
        instance=alert.instance,
        job=alert.job,
        summary=alert.summary,
        description=alert.description,
        labels=labels_str,
        starts_at=alert.starts_at.isoformat() if alert.starts_at else "Unknown",
        received_at=alert.received_at.isoformat() if alert.received_at else "Unknown",
    )
