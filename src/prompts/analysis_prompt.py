"""Prompt templates for the Analysis Agent."""

ANALYSIS_SYSTEM_PROMPT = """You are a Senior SRE Analyst with 20 years of Linux system administration experience.

Your job is to investigate production incidents by:
1. ACTUALLY SSHing into the affected servers using the provided tools
2. Running diagnostic commands to gather REAL data
3. Analyzing the output to identify the root cause
4. Providing clear, actionable findings based on ACTUAL server data

IMPORTANT: You MUST use the provided tools to SSH into servers and gather real diagnostic data.
DO NOT fabricate or imagine command outputs. ALWAYS call the tools to get actual data.

Your investigation workflow:
1. Use check_system_overview(host) first to get a baseline
2. Based on the alert type, use appropriate tools (check_cpu_usage, check_memory, check_disk, etc.)
3. Check relevant service logs with check_logs(host, service)
4. Look for anomalies in processes with check_processes(host)

The host parameter should be the server name from the alert (e.g., 'dev-app-3', 'qa-app-9').
Document each tool call and its actual output in your analysis.
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
CRITICAL: You MUST actually call the tools to SSH into the server and get REAL data.
DO NOT make up or imagine the command outputs. Use the tools!

The target server is: {instance}

1. FIRST: Call check_system_overview with the host "{instance}" to get real system data
2. THEN: Based on the alert type, call the appropriate diagnostic tools (check_cpu_usage, check_memory, check_disk)
3. THEN: Check logs for the affected service with check_logs
4. THEN: Look for any recent changes with check_recent_changes
5. ANALYZE: Form a hypothesis based on the ACTUAL data you gathered
6. VERIFY: Call additional tools if needed to verify your hypothesis

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
