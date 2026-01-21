"""CrewAI-compatible server investigation tools.

These tools wrap the async SSH functions to work with CrewAI's synchronous tool system.
"""

import asyncio
from typing import Optional

from crewai.tools import tool
import structlog

from src.tools.ssh_client import get_ssh_client


logger = structlog.get_logger()


def _run_async(coro):
    """Run an async coroutine synchronously."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If we're already in an async context, create a new thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result(timeout=60)
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        # No event loop, create one
        return asyncio.run(coro)


async def _ssh_exec(host: str, command: str) -> str:
    """Execute SSH command and return result."""
    try:
        client = get_ssh_client()
        result = await client.execute_simple(host, command)
        return result
    except Exception as e:
        logger.error("SSH execution failed", host=host, error=str(e))
        return f"Error executing command on {host}: {str(e)}"


@tool("Check CPU Usage")
def check_cpu_usage(host: str) -> str:
    """
    Check CPU usage on a server. Returns CPU statistics and top processes by CPU consumption.
    Use this to diagnose high CPU alerts or performance issues.

    Args:
        host: The hostname or IP address of the server to check (e.g., 'dev-app-3', '10.2.4.5')
    """
    logger.info("Checking CPU usage", host=host)
    command = """
    echo "=== CPU Overview ==="
    uptime
    echo ""
    echo "=== CPU Stats ==="
    mpstat 1 1 2>/dev/null || cat /proc/stat | head -5
    echo ""
    echo "=== Top CPU Processes ==="
    ps aux --sort=-%cpu | head -15
    """
    return _run_async(_ssh_exec(host, command))


@tool("Check Memory Usage")
def check_memory(host: str) -> str:
    """
    Check memory usage on a server. Returns memory overview and top memory consumers.
    Use this to diagnose low memory alerts or memory leaks.

    Args:
        host: The hostname or IP address of the server to check
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
    return _run_async(_ssh_exec(host, command))


@tool("Check Disk Usage")
def check_disk(host: str) -> str:
    """
    Check disk usage and I/O statistics on a server. Returns disk space and I/O activity.
    Use this to diagnose low disk space alerts or I/O issues.

    Args:
        host: The hostname or IP address of the server to check
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
    return _run_async(_ssh_exec(host, command))


@tool("Check Processes")
def check_processes(host: str, pattern: str = "") -> str:
    """
    List running processes on a server, optionally filtered by pattern.
    Use this to find specific processes or identify resource-heavy processes.

    Args:
        host: The hostname or IP address of the server to check
        pattern: Optional grep pattern to filter processes (e.g., 'java', 'python', 'nginx')
    """
    logger.info("Checking processes", host=host, pattern=pattern)

    if pattern:
        command = f"""
        echo "=== Processes matching '{pattern}' ==="
        ps aux | grep -E '{pattern}' | grep -v grep
        echo ""
        echo "=== Process tree ==="
        pstree -ap 2>/dev/null | grep -E '{pattern}' | head -20 || echo "pstree not available"
        """
    else:
        command = """
        echo "=== All Processes (by CPU) ==="
        ps aux --sort=-%cpu | head -25
        echo ""
        echo "=== Process Count by User ==="
        ps aux | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
        """
    return _run_async(_ssh_exec(host, command))


@tool("Check Service Logs")
def check_logs(host: str, service: str, lines: int = 100) -> str:
    """
    Get recent logs for a systemd service on a server.
    Use this to find error messages or investigate service behavior.

    Args:
        host: The hostname or IP address of the server
        service: Service name (e.g., 'nginx', 'postgresql', 'docker')
        lines: Number of log lines to retrieve (default 100)
    """
    logger.info("Checking logs", host=host, service=service, lines=lines)
    command = f"""
    echo "=== Recent logs for {service} ==="
    journalctl -u {service} -n {lines} --no-pager 2>/dev/null || echo "Service logs not available via journalctl"
    echo ""
    echo "=== Service Status ==="
    systemctl status {service} --no-pager 2>/dev/null || echo "Service status not available"
    """
    return _run_async(_ssh_exec(host, command))


@tool("Check Network Connections")
def check_network(host: str) -> str:
    """
    Check network connections and listening ports on a server.
    Use this to verify services are listening or diagnose connection issues.

    Args:
        host: The hostname or IP address of the server to check
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
    return _run_async(_ssh_exec(host, command))


@tool("Check Service Status")
def check_service_status(host: str, service: str) -> str:
    """
    Check the detailed status of a systemd service on a server.
    Use this to verify if a service is running and check its properties.

    Args:
        host: The hostname or IP address of the server
        service: Service name to check (e.g., 'nginx', 'mysql', 'redis')
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
    journalctl -u {service} --since "1 hour ago" 2>/dev/null | grep -i "started\|stopped\|failed" | tail -10
    """
    return _run_async(_ssh_exec(host, command))


@tool("Check Docker Containers")
def check_docker_containers(host: str) -> str:
    """
    List Docker containers and their resource usage on a server.
    Use this to check container status and resource consumption.

    Args:
        host: The hostname or IP address of the server to check
    """
    logger.info("Checking Docker containers", host=host)
    command = """
    echo "=== Docker Containers ==="
    docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "Docker not available"
    echo ""
    echo "=== Container Resource Usage ==="
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" 2>/dev/null || echo "Docker stats not available"
    """
    return _run_async(_ssh_exec(host, command))


@tool("Check System Overview")
def check_system_overview(host: str) -> str:
    """
    Get a comprehensive system overview for a server. This is a good first step in any investigation.
    Returns system info, load, memory, disk, and top processes.

    Args:
        host: The hostname or IP address of the server to check
    """
    logger.info("Getting system overview", host=host)
    command = """
    echo "=== System Information ==="
    uname -a
    echo ""
    echo "=== Uptime and Load ==="
    uptime
    cat /proc/loadavg
    echo ""
    echo "=== Memory Summary ==="
    free -h
    echo ""
    echo "=== Disk Summary ==="
    df -h | grep -E '^/dev|Filesystem'
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
    return _run_async(_ssh_exec(host, command))


@tool("Check Recent Changes")
def check_recent_changes(host: str) -> str:
    """
    Check for recent system changes on a server (packages, logins, config changes).
    Use this to correlate issues with recent changes.

    Args:
        host: The hostname or IP address of the server to check
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
    """
    return _run_async(_ssh_exec(host, command))


# List of all investigation tools for CrewAI agents
CREWAI_INVESTIGATION_TOOLS = [
    check_cpu_usage,
    check_memory,
    check_disk,
    check_processes,
    check_logs,
    check_network,
    check_service_status,
    check_docker_containers,
    check_system_overview,
    check_recent_changes,
]
