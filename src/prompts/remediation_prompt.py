"""Prompt templates for the Remediation Agent."""

REMEDIATION_SYSTEM_PROMPT = """You are an expert remediation specialist responsible for resolving production incidents safely and effectively.

Your responsibilities:
1. Review the root cause analysis
2. Determine the safest and most effective remediation action
3. Assess the risk and blast radius of each option
4. Provide clear, actionable recommendations

Safety Guidelines:
- Always prefer less invasive actions (restart before reboot)
- Consider the blast radius of each action
- Provide confidence scores for recommendations
- Flag any actions that require human approval

Available Remediation Actions:
- LOW RISK: check_status, view_logs (auto-approved)
- MEDIUM RISK: restart_service, restart_docker, scale_service (may need approval)
- HIGH RISK: kill_process, clear_disk_space (requires approval)
- CRITICAL RISK: reboot_server (requires approval + confirmation)

Always explain your reasoning and provide alternatives when possible.
"""

REMEDIATION_TASK_TEMPLATE = """
Based on the root cause analysis, recommend the appropriate remediation action.

## Incident Information
- Incident ID: {incident_id}
- Title: {title}
- Severity: {severity}

## Affected Resources
- Servers: {servers}
- Services: {services}

## Root Cause Analysis
{root_cause}

Confidence: {confidence}%

## Investigation Findings
{findings}

## Available Actions
Choose from the following remediation actions:

### Low Risk (Auto-approved)
- check_status: Verify current service status
- view_logs: Review additional logs

### Medium Risk (May require approval)
- restart_service: Restart a systemd service
  Command: systemctl restart <service>

- restart_docker: Restart a Docker container
  Command: docker restart <container>

- scale_service: Scale up/down replicas
  Command: varies by orchestrator

- clear_cache: Clear application cache
  Command: varies by application

### High Risk (Requires approval)
- kill_process: Kill a specific process
  Command: kill -9 <pid>

- clear_disk_space: Clear disk space (logs, temp files)
  Command: journalctl --vacuum-size=500M

- reset_connections: Reset database connections
  Command: varies by database

### Critical Risk (Requires approval + confirmation)
- reboot_server: Reboot the server
  Command: shutdown -r now

- rollback_deployment: Roll back to previous version
  Command: varies by deployment system

## Recommendation Format
Provide your recommendation with:

1. **Primary Action**: The recommended action with all parameters
   - Action Type: (e.g., restart_service)
   - Target Host: (server hostname)
   - Target Service: (service name if applicable)
   - Command: (exact command to run)

2. **Risk Assessment**
   - Risk Level: low/medium/high/critical
   - Blast Radius: Number of affected services/users
   - Rollback Plan: How to undo if needed

3. **Confidence Score**: 0-100%

4. **Reasoning**: Why this action is recommended

5. **Alternative Actions**: Other options if primary fails

6. **Pre-flight Checks**: What to verify before executing

7. **Post-action Verification**: How to verify success
"""


def format_remediation_prompt(incident) -> str:
    """Format the remediation prompt with incident data."""
    # Get root cause from incident
    root_cause = incident.root_cause or "Root cause not yet determined"
    confidence = int(incident.root_cause_confidence * 100)

    # Format investigation findings
    findings = []
    for step in incident.investigation_log:
        if step.agent == "analysis":
            findings.append(f"**{step.action}** on {step.target}:")
            findings.append(f"  {step.result[:500]}...")  # Truncate long results
            findings.append("")

    findings_str = "\n".join(findings) if findings else "No detailed findings available"

    return REMEDIATION_TASK_TEMPLATE.format(
        incident_id=incident.id,
        title=incident.title,
        severity=incident.severity.value,
        servers=", ".join(incident.affected_servers) or "Unknown",
        services=", ".join(incident.affected_services) or "Unknown",
        root_cause=root_cause,
        confidence=confidence,
        findings=findings_str,
    )
