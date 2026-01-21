"""Prompt templates for the Analysis Agent."""

ANALYSIS_SYSTEM_PROMPT = """You are a Senior SRE Analyst with 20 years of Linux system administration experience.

Your job is to investigate production incidents by:
1. Gathering diagnostic data from affected servers
2. Analyzing system metrics, logs, and processes
3. Identifying the root cause of issues
4. Providing clear, actionable findings

You have access to SSH-based tools to inspect servers. Use them systematically:
- Start with a system overview
- Focus on metrics related to the alert (CPU, memory, disk, etc.)
- Check relevant service logs
- Look for anomalies in processes and connections

Always think step by step and document your investigation process.
Be thorough but efficient - prioritize the most likely causes based on the alert.
"""

ANALYSIS_TASK_TEMPLATE = """
Investigate the following production incident and determine the root cause.

## Incident Information
- Incident ID: {incident_id}
- Title: {title}
- Severity: {severity}
- Status: {status}

## Primary Alert
- Alert Name: {alertname}
- Instance: {instance}
- Summary: {summary}
- Description: {description}

## Affected Resources
- Servers: {servers}
- Services: {services}

## Triage Notes
{triage_notes}

## Available Investigation Tools
You can use the following tools to investigate the server:

- check_system_overview(host): Get comprehensive system overview
- check_cpu_usage(host): Get CPU stats and top processes
- check_memory(host): Get memory usage and top consumers
- check_disk(host): Get disk space and I/O statistics
- check_processes(host, pattern): List processes, optionally filtered
- check_logs(host, service, lines): Get service logs
- check_network(host): Check network connections
- check_service_status(host, service): Check systemd service status
- check_docker_containers(host): List Docker containers
- check_docker_container_logs(host, container, lines): Get container logs
- check_application_health(host, port, path): Check health endpoint
- check_recent_changes(host): Check recent system changes

## Investigation Instructions
1. Start by getting a system overview of the affected server
2. Based on the alert type, investigate relevant metrics
3. Check logs for the affected service
4. Look for any recent changes or anomalies
5. Form a hypothesis about the root cause
6. Verify your hypothesis with additional data if needed

## Expected Output
Provide your analysis with:

1. **Investigation Steps**: What you checked and what you found
2. **Key Findings**: Most important observations
3. **Root Cause**: Your determination of what caused the issue
4. **Confidence**: How confident are you (0-100%)
5. **Evidence**: Data supporting your conclusion
6. **Recommended Actions**: What should be done to resolve this

Think step by step. Document each investigation step clearly.
"""


def format_analysis_prompt(incident) -> str:
    """Format the analysis prompt with incident data."""
    primary_alert = incident.primary_alert
    if not primary_alert:
        raise ValueError("Incident has no primary alert")

    # Format triage notes from investigation log
    triage_notes = "No triage notes available"
    for step in incident.investigation_log:
        if step.agent == "triage":
            triage_notes = step.result
            break

    return ANALYSIS_TASK_TEMPLATE.format(
        incident_id=incident.id,
        title=incident.title,
        severity=incident.severity.value,
        status=incident.status.value,
        alertname=primary_alert.alertname,
        instance=primary_alert.instance,
        summary=primary_alert.summary,
        description=primary_alert.description,
        servers=", ".join(incident.affected_servers) or "Unknown",
        services=", ".join(incident.affected_services) or "Unknown",
        triage_notes=triage_notes,
    )
