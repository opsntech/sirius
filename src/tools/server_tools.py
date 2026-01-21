"""Server investigation tools for the AI agent.

These tools allow the AI agent to SSH into servers and gather
diagnostic information about system health, processes, logs, etc.
"""

from typing import Optional

import structlog
from langchain.tools import tool

from src.tools.ssh_client import get_ssh_client, ssh_exec


logger = structlog.get_logger()


class ServerTools:
    """
    Collection of server investigation tools.

    Each tool executes commands via SSH to gather diagnostic information.
    Tools are designed to be safe (read-only) for investigation purposes.
    """

    @staticmethod
    async def check_cpu_usage(host: str) -> str:
        """
        Get CPU usage breakdown for a server.

        Returns top processes by CPU usage and overall CPU statistics.
        """
        logger.info("Checking CPU usage", host=host)
        command = """
        echo "=== CPU Overview ==="
        uptime
        echo ""
        echo "=== CPU Stats (mpstat) ==="
        mpstat 1 1 2>/dev/null || echo "mpstat not available"
        echo ""
        echo "=== Top CPU Processes ==="
        ps aux --sort=-%cpu | head -15
        """
        return await ssh_exec(host, command)

    @staticmethod
    async def check_memory(host: str) -> str:
        """
        Get memory usage information for a server.

        Returns memory overview, top memory consumers, and swap usage.
        """
        logger.info("Checking memory usage", host=host)
        command = """
        echo "=== Memory Overview ==="
        free -h
        echo ""
        echo "=== Memory Details ==="
        cat /proc/meminfo | head -15
        echo ""
        echo "=== Top Memory Processes ==="
        ps aux --sort=-%mem | head -15
        """
        return await ssh_exec(host, command)

    @staticmethod
    async def check_disk(host: str) -> str:
        """
        Get disk usage and I/O statistics for a server.

        Returns disk space usage and I/O activity.
        """
        logger.info("Checking disk usage", host=host)
        command = """
        echo "=== Disk Space ==="
        df -h
        echo ""
        echo "=== Inode Usage ==="
        df -i | head -10
        echo ""
        echo "=== I/O Stats ==="
        iostat -x 1 2 2>/dev/null | tail -20 || echo "iostat not available"
        """
        return await ssh_exec(host, command)

    @staticmethod
    async def check_processes(host: str, pattern: str = "") -> str:
        """
        List running processes, optionally filtered by pattern.

        Args:
            host: Target server
            pattern: Optional grep pattern to filter processes
        """
        logger.info("Checking processes", host=host, pattern=pattern)

        if pattern:
            command = f"""
            echo "=== Processes matching '{pattern}' ==="
            ps aux | grep -E '{pattern}' | grep -v grep
            echo ""
            echo "=== Process tree ==="
            pstree -ap | grep -E '{pattern}' | head -20 || echo "pstree not available"
            """
        else:
            command = """
            echo "=== All Processes (by CPU) ==="
            ps aux --sort=-%cpu | head -25
            echo ""
            echo "=== Process Count by User ==="
            ps aux | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
            """
        return await ssh_exec(host, command)

    @staticmethod
    async def check_logs(host: str, service: str, lines: int = 100) -> str:
        """
        Get recent logs for a systemd service.

        Args:
            host: Target server
            service: Service name (e.g., nginx, postgresql)
            lines: Number of log lines to retrieve
        """
        logger.info("Checking logs", host=host, service=service, lines=lines)
        command = f"""
        echo "=== Recent logs for {service} ==="
        journalctl -u {service} -n {lines} --no-pager 2>/dev/null || echo "Service logs not available via journalctl"
        echo ""
        echo "=== Service Status ==="
        systemctl status {service} --no-pager 2>/dev/null || echo "Service status not available"
        """
        return await ssh_exec(host, command)

    @staticmethod
    async def check_network(host: str) -> str:
        """
        Check network connections and statistics.

        Returns listening ports, active connections, and network stats.
        """
        logger.info("Checking network", host=host)
        command = """
        echo "=== Listening Ports ==="
        ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null || echo "Network tools not available"
        echo ""
        echo "=== Connection Summary ==="
        ss -s 2>/dev/null || echo "ss not available"
        echo ""
        echo "=== Active Connections (top 20) ==="
        ss -tun 2>/dev/null | head -20 || netstat -tun 2>/dev/null | head -20
        """
        return await ssh_exec(host, command)

    @staticmethod
    async def check_service_status(host: str, service: str) -> str:
        """
        Check the status of a systemd service.

        Args:
            host: Target server
            service: Service name to check
        """
        logger.info("Checking service status", host=host, service=service)
        command = f"""
        echo "=== Service Status: {service} ==="
        systemctl status {service} --no-pager
        echo ""
        echo "=== Service Properties ==="
        systemctl show {service} --property=ActiveState,SubState,MainPID,MemoryCurrent,CPUUsageNSec 2>/dev/null
        echo ""
        echo "=== Recent Restarts ==="
        journalctl -u {service} --since "1 hour ago" | grep -i "started\|stopped\|failed" | tail -10
        """
        return await ssh_exec(host, command)

    @staticmethod
    async def check_docker_containers(host: str) -> str:
        """
        List Docker containers and their resource usage.
        """
        logger.info("Checking Docker containers", host=host)
        command = """
        echo "=== Docker Containers ==="
        docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "Docker not available"
        echo ""
        echo "=== Container Resource Usage ==="
        docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" 2>/dev/null || echo "Docker stats not available"
        echo ""
        echo "=== Recent Container Events ==="
        docker events --since "10m" --until "0s" 2>/dev/null | tail -10 || echo "No recent events"
        """
        return await ssh_exec(host, command)

    @staticmethod
    async def check_docker_container_logs(host: str, container: str, lines: int = 50) -> str:
        """
        Get logs from a specific Docker container.

        Args:
            host: Target server
            container: Container name or ID
            lines: Number of log lines to retrieve
        """
        logger.info("Checking Docker container logs", host=host, container=container)
        command = f"""
        echo "=== Container Info: {container} ==="
        docker inspect {container} --format '{{{{.State.Status}}}} - Started: {{{{.State.StartedAt}}}}' 2>/dev/null
        echo ""
        echo "=== Container Logs (last {lines} lines) ==="
        docker logs --tail {lines} {container} 2>&1
        """
        return await ssh_exec(host, command)

    @staticmethod
    async def check_application_health(host: str, port: int, path: str = "/health") -> str:
        """
        Check an application's health endpoint.

        Args:
            host: Target server
            port: Application port
            path: Health endpoint path
        """
        logger.info("Checking application health", host=host, port=port, path=path)
        command = f"""
        echo "=== Health Check: localhost:{port}{path} ==="
        curl -s -w "\\n\\nHTTP Status: %{{http_code}}\\nTime: %{{time_total}}s\\n" http://localhost:{port}{path} 2>&1 || echo "Health check failed"
        echo ""
        echo "=== Port Status ==="
        ss -tln | grep :{port} || echo "Port {port} not listening"
        """
        return await ssh_exec(host, command)

    @staticmethod
    async def check_system_overview(host: str) -> str:
        """
        Get a comprehensive system overview.

        Useful as a first step in investigation.
        """
        logger.info("Getting system overview", host=host)
        command = """
        echo "=== System Information ==="
        uname -a
        echo ""
        echo "=== Uptime ==="
        uptime
        echo ""
        echo "=== Load Average ==="
        cat /proc/loadavg
        echo ""
        echo "=== Memory Summary ==="
        free -h
        echo ""
        echo "=== Disk Summary ==="
        df -h | grep -E '^/dev'
        echo ""
        echo "=== Top 5 CPU Processes ==="
        ps aux --sort=-%cpu | head -6
        echo ""
        echo "=== Top 5 Memory Processes ==="
        ps aux --sort=-%mem | head -6
        echo ""
        echo "=== Failed Services ==="
        systemctl --failed --no-pager 2>/dev/null || echo "systemctl not available"
        """
        return await ssh_exec(host, command)

    @staticmethod
    async def check_recent_changes(host: str) -> str:
        """
        Check for recent system changes (packages, configs, logins).
        """
        logger.info("Checking recent changes", host=host)
        command = """
        echo "=== Recent Package Changes ==="
        rpm -qa --last 2>/dev/null | head -10 || dpkg -l --no-pager 2>/dev/null | tail -10 || echo "Package manager not available"
        echo ""
        echo "=== Recent Logins ==="
        last -10 2>/dev/null || echo "last command not available"
        echo ""
        echo "=== Recently Modified Config Files (last 24h) ==="
        find /etc -type f -mtime -1 2>/dev/null | head -20 || echo "No recent config changes"
        echo ""
        echo "=== Recent Cron Jobs ==="
        grep -h "" /var/log/cron* 2>/dev/null | tail -10 || journalctl -u cron --since "1 hour ago" --no-pager 2>/dev/null | tail -10 || echo "Cron logs not available"
        """
        return await ssh_exec(host, command)


# Create LangChain tool wrappers for the AI agent

@tool
async def check_cpu_usage(host: str) -> str:
    """Check CPU usage on a server. Returns CPU stats and top processes."""
    return await ServerTools.check_cpu_usage(host)


@tool
async def check_memory(host: str) -> str:
    """Check memory usage on a server. Returns memory stats and top consumers."""
    return await ServerTools.check_memory(host)


@tool
async def check_disk(host: str) -> str:
    """Check disk usage and I/O on a server. Returns disk space and I/O stats."""
    return await ServerTools.check_disk(host)


@tool
async def check_processes(host: str, pattern: str = "") -> str:
    """Check running processes on a server. Optionally filter by pattern."""
    return await ServerTools.check_processes(host, pattern)


@tool
async def check_logs(host: str, service: str, lines: int = 100) -> str:
    """Get recent logs for a systemd service on a server."""
    return await ServerTools.check_logs(host, service, lines)


@tool
async def check_network(host: str) -> str:
    """Check network connections on a server. Returns ports and connections."""
    return await ServerTools.check_network(host)


@tool
async def check_service_status(host: str, service: str) -> str:
    """Check the status of a systemd service on a server."""
    return await ServerTools.check_service_status(host, service)


@tool
async def check_docker_containers(host: str) -> str:
    """List Docker containers and their resource usage on a server."""
    return await ServerTools.check_docker_containers(host)


@tool
async def check_docker_container_logs(host: str, container: str, lines: int = 50) -> str:
    """Get logs from a specific Docker container on a server."""
    return await ServerTools.check_docker_container_logs(host, container, lines)


@tool
async def check_application_health(host: str, port: int, path: str = "/health") -> str:
    """Check an application's health endpoint on a server."""
    return await ServerTools.check_application_health(host, port, path)


@tool
async def check_system_overview(host: str) -> str:
    """Get a comprehensive system overview for a server."""
    return await ServerTools.check_system_overview(host)


@tool
async def check_recent_changes(host: str) -> str:
    """Check for recent system changes on a server (packages, logins, configs)."""
    return await ServerTools.check_recent_changes(host)


# List of all available tools for the AI agent
INVESTIGATION_TOOLS = [
    check_cpu_usage,
    check_memory,
    check_disk,
    check_processes,
    check_logs,
    check_network,
    check_service_status,
    check_docker_containers,
    check_docker_container_logs,
    check_application_health,
    check_system_overview,
    check_recent_changes,
]
