# Sirius

AI-powered on-call DevOps agent that monitors Prometheus alerts, performs root cause analysis using NVIDIA NIM, and can SSH into servers to investigate and remediate issues.

## Features

- **Alert Ingestion**: Receives alerts from Prometheus AlertManager via webhooks
- **Deduplication & Correlation**: Groups related alerts into incidents
- **AI Analysis**: Uses NVIDIA NIM (Llama 3.1) for root cause analysis
- **Server Investigation**: SSH-based tools to check CPU, memory, disk, logs, and processes
- **Human-in-the-Loop**: Slack integration for approval workflows
- **Safe Remediation**: Circuit breakers, rollback support, and audit logging

## Quick Start

### Prerequisites

- Python 3.11+
- Docker (optional)
- NVIDIA API key (from [build.nvidia.com](https://build.nvidia.com))
- SSH access to target servers
- Slack webhook URL (optional, for approvals)

### Installation

1. Clone the repository:
```bash
git clone git@github.com:opsntech/sirius.git
cd sirius
```

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment:
```bash
export NVIDIA_API_KEY="your-nvidia-api-key"
export SLACK_WEBHOOK_URL="your-slack-webhook-url"
```

5. Edit configuration:
```bash
cp config/config.yaml config/config.local.yaml
# Edit config/config.local.yaml with your settings
```

6. Run the agent:
```bash
python -m src.main
```

### Docker Deployment

```bash
# Set environment variables
export NVIDIA_API_KEY="your-nvidia-api-key"
export SLACK_WEBHOOK_URL="your-slack-webhook-url"

# Build and run
cd docker
docker-compose up -d
```

## Configuration

### config/config.yaml

```yaml
server:
  host: 0.0.0.0
  port: 8080

nvidia:
  environment: development  # or production for self-hosted
  development:
    base_url: https://integrate.api.nvidia.com/v1
    model: meta/llama-3.1-70b-instruct

ssh:
  private_key_path: ~/.ssh/sirius
  username: sirius
  timeout_seconds: 30

approval:
  auto_approve_risk_levels: [low]
  require_approval_risk_levels: [medium, high, critical]
  slack_channel: "#oncall-approvals"
```

### config/servers.yaml

```yaml
servers:
  - hostname: web-server-1.example.com
    ip: 192.168.1.10
    role: web
    services: [nginx, app-frontend]
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/webhooks/prometheus` | POST | Prometheus AlertManager webhook |
| `/webhooks/custom` | POST | Custom alert webhook |
| `/incidents` | GET | List active incidents |
| `/incidents/{id}` | GET | Get incident details |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     DEVOPS AGENT                                 │
│                                                                 │
│  ┌───────────────┐    ┌───────────────┐    ┌───────────────┐   │
│  │    WEBHOOK    │───▶│    EVENT      │───▶│  AI DECISION  │   │
│  │    SERVER     │    │   PROCESSOR   │    │    ENGINE     │   │
│  └───────────────┘    └───────────────┘    └───────────────┘   │
│                                                   │             │
│                                      ┌────────────┴──────────┐  │
│                                      ▼                       ▼  │
│                               ┌───────────┐          ┌──────────┐
│                               │  APPROVAL │          │REMEDIATION
│                               │  (Slack)  │          │ EXECUTOR │
│                               └───────────┘          └──────────┘
└─────────────────────────────────────────────────────────────────┘
                                      │
                                      │ SSH
                                      ▼
                          ┌────────────────────────┐
                          │    TARGET SERVERS      │
                          └────────────────────────┘
```

## AI Agents

The system uses CrewAI with three specialized agents:

1. **Triage Agent**: Classifies alert severity and priority
2. **Analysis Agent**: Investigates root cause using SSH tools
3. **Remediation Agent**: Recommends safe remediation actions

## Server Investigation Tools

Available tools for the AI agent:

- `check_cpu_usage` - CPU stats and top processes
- `check_memory` - Memory usage and top consumers
- `check_disk` - Disk space and I/O statistics
- `check_processes` - Process list with filtering
- `check_logs` - Service logs via journalctl
- `check_network` - Network connections
- `check_service_status` - Systemd service status
- `check_docker_containers` - Docker container status
- `check_docker_container_logs` - Container logs
- `check_application_health` - Health endpoint checks
- `check_system_overview` - Comprehensive system overview
- `check_recent_changes` - Recent system changes

## Testing

```bash
# Run tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

### Send test alert

```bash
curl -X POST http://localhost:8080/webhooks/prometheus \
  -H "Content-Type: application/json" \
  -d @tests/fixtures/sample_alert.json
```

## Prometheus AlertManager Configuration

```yaml
# alertmanager.yml
receivers:
  - name: sirius
    webhook_configs:
      - url: 'http://sirius:8080/webhooks/prometheus'
        send_resolved: true
```

## Safety Controls

- **Risk Levels**: Low (auto-approve), Medium/High/Critical (require approval)
- **Circuit Breaker**: Prevents repeated failures (3 failures = 5-min cooldown)
- **Pre-flight Checks**: Validates preconditions before execution
- **Post-execution Verification**: Confirms action was successful
- **Audit Logging**: Full trail of AI decisions and actions

## License

MIT License
