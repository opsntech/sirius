"""Prompt templates for the Remediation Agent."""

REMEDIATION_SYSTEM_PROMPT = """You are an expert remediation specialist responsible for resolving production incidents safely and effectively.

Your responsibilities:
1. Review the root cause analysis
2. Determine the safest and most effective remediation actions
3. Assess the risk and blast radius of each option
4. Provide clear, actionable recommendations

Safety Guidelines:
- Always prefer less invasive actions (restart before reboot)
- Consider the blast radius of each action
- Provide confidence scores for recommendations
- Flag any actions that require human approval

Available Remediation Actions:
- LOW RISK: check_status, view_logs, check_logs (auto-approved)
- MEDIUM RISK: restart_service, restart_docker, scale_service, clear_cache (may need approval)
- HIGH RISK: kill_process, clear_disk_space (requires approval)
- CRITICAL RISK: reboot_server (requires approval + confirmation)

MULTIPLE ACTIONS: You can recommend ONE or MULTIPLE actions. If the situation calls for a
sequence of actions (e.g., gather more info → apply fix → verify recovery), list them in order.
Each action will be executed sequentially, stopping on failure.

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

You can recommend ONE action or MULTIPLE actions. Format your response with:

### ACTIONS (list one or more):
```
ACTIONS:
1. action_type: description | target: hostname | service: name | risk: level | command: exact_command
2. action_type: description | target: hostname | service: name | risk: level | command: exact_command
3. action_type: description | target: hostname | service: name | risk: level | command: exact_command
```

Example single action:
```
ACTIONS:
1. restart_service: Restart the data processor | target: dev-app-3 | service: data-processor | risk: medium | command: systemctl restart data-processor
```

Example multiple actions:
```
ACTIONS:
1. check_logs: Get more service logs | target: dev-app-3 | service: data-processor | risk: low | command: journalctl -u data-processor -n 200 --no-pager
2. restart_service: Restart the service | target: dev-app-3 | service: data-processor | risk: medium | command: systemctl restart data-processor
3. verify_status: Confirm service is healthy | target: dev-app-3 | service: data-processor | risk: low | command: systemctl status data-processor --no-pager
```

### After ACTIONS, provide:
- **Confidence Score**: 0-100%
- **Reasoning**: Why these action(s) are recommended
- **Rollback Plan**: How to undo if needed
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
