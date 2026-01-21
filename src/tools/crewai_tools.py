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


async def _ssh_exec(host: str, command: str, max_output_chars: int = 3000) -> str:
    """Execute SSH command and return result (truncated to prevent context overflow)."""
    try:
        client = get_ssh_client()
        result = await client.execute_simple(host, command)
        # Truncate output to prevent context overflow in CrewAI
        if len(result) > max_output_chars:
            result = result[:max_output_chars] + f"\n\n... [Output truncated at {max_output_chars} chars]"
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


# ============================================================================
# DATABASE TOOLS
# ============================================================================

@tool("Check PostgreSQL")
def check_postgresql(host: str) -> str:
    """
    Check PostgreSQL database health, connections, and slow queries.
    Use this for PostgreSQL-related alerts or database performance issues.

    Args:
        host: The hostname or IP address of the server
    """
    logger.info("Checking PostgreSQL", host=host)
    command = """
    echo "=== PostgreSQL Status ==="
    systemctl status postgresql --no-pager 2>/dev/null || echo "PostgreSQL service not found"
    echo ""
    echo "=== Connection Count ==="
    sudo -u postgres psql -c "SELECT count(*) as connections FROM pg_stat_activity;" 2>/dev/null || echo "Cannot query PostgreSQL"
    echo ""
    echo "=== Active Queries ==="
    sudo -u postgres psql -c "SELECT pid, now() - pg_stat_activity.query_start AS duration, query FROM pg_stat_activity WHERE state = 'active' ORDER BY duration DESC LIMIT 5;" 2>/dev/null || echo "Cannot get active queries"
    echo ""
    echo "=== Database Sizes ==="
    sudo -u postgres psql -c "SELECT datname, pg_size_pretty(pg_database_size(datname)) FROM pg_database ORDER BY pg_database_size(datname) DESC LIMIT 10;" 2>/dev/null || echo "Cannot get database sizes"
    """
    return _run_async(_ssh_exec(host, command))


@tool("Check MongoDB")
def check_mongodb(host: str) -> str:
    """
    Check MongoDB database health, connections, and operations.
    Use this for MongoDB-related alerts or database issues.

    Args:
        host: The hostname or IP address of the server
    """
    logger.info("Checking MongoDB", host=host)
    command = """
    echo "=== MongoDB Status ==="
    systemctl status mongod --no-pager 2>/dev/null || echo "MongoDB service not found"
    echo ""
    echo "=== Server Status ==="
    mongosh --eval "db.serverStatus().connections" 2>/dev/null || mongo --eval "db.serverStatus().connections" 2>/dev/null || echo "Cannot connect to MongoDB"
    echo ""
    echo "=== Current Operations ==="
    mongosh --eval "db.currentOp().inprog.length" 2>/dev/null || mongo --eval "db.currentOp().inprog.length" 2>/dev/null || echo "Cannot get operations"
    echo ""
    echo "=== Replication Status ==="
    mongosh --eval "rs.status()" 2>/dev/null || mongo --eval "rs.status()" 2>/dev/null || echo "Not a replica set"
    """
    return _run_async(_ssh_exec(host, command))


@tool("Check MySQL")
def check_mysql(host: str) -> str:
    """
    Check MySQL database health, connections, and queries.
    Use this for MySQL-related alerts or database issues.

    Args:
        host: The hostname or IP address of the server
    """
    logger.info("Checking MySQL", host=host)
    command = """
    echo "=== MySQL Status ==="
    systemctl status mysql --no-pager 2>/dev/null || systemctl status mariadb --no-pager 2>/dev/null || echo "MySQL service not found"
    echo ""
    echo "=== Connection Count ==="
    mysql -e "SHOW STATUS LIKE 'Threads_connected';" 2>/dev/null || echo "Cannot query MySQL"
    echo ""
    echo "=== Process List ==="
    mysql -e "SHOW FULL PROCESSLIST;" 2>/dev/null | head -20 || echo "Cannot get process list"
    echo ""
    echo "=== Slow Queries ==="
    mysql -e "SHOW GLOBAL STATUS LIKE 'Slow_queries';" 2>/dev/null || echo "Cannot get slow queries"
    """
    return _run_async(_ssh_exec(host, command))


@tool("Check Redis")
def check_redis(host: str) -> str:
    """
    Check Redis health, memory usage, and connections.
    Use this for Redis-related alerts or caching issues.

    Args:
        host: The hostname or IP address of the server
    """
    logger.info("Checking Redis", host=host)
    command = """
    echo "=== Redis Status ==="
    systemctl status redis --no-pager 2>/dev/null || systemctl status redis-server --no-pager 2>/dev/null || echo "Redis service not found"
    echo ""
    echo "=== Redis Info - Memory ==="
    redis-cli info memory 2>/dev/null | head -15 || echo "Cannot connect to Redis"
    echo ""
    echo "=== Redis Info - Clients ==="
    redis-cli info clients 2>/dev/null || echo "Cannot get client info"
    echo ""
    echo "=== Redis Info - Stats ==="
    redis-cli info stats 2>/dev/null | head -15 || echo "Cannot get stats"
    """
    return _run_async(_ssh_exec(host, command))


# ============================================================================
# DOCKER TOOLS
# ============================================================================

@tool("Check Docker Container Logs")
def check_docker_logs(host: str, container: str, lines: int = 100) -> str:
    """
    Get logs from a specific Docker container.
    Use this to investigate container issues or application errors.

    Args:
        host: The hostname or IP address of the server
        container: Container name or ID
        lines: Number of log lines to retrieve (default 100)
    """
    logger.info("Checking Docker logs", host=host, container=container)
    command = f"""
    echo "=== Container Info ==="
    docker inspect {container} --format '{{{{.State.Status}}}} - Started: {{{{.State.StartedAt}}}}' 2>/dev/null || echo "Container not found"
    echo ""
    echo "=== Container Logs (last {lines} lines) ==="
    docker logs --tail {lines} {container} 2>&1 || echo "Cannot get container logs"
    """
    return _run_async(_ssh_exec(host, command))


@tool("Check Docker Container Details")
def check_docker_inspect(host: str, container: str) -> str:
    """
    Get detailed information about a Docker container including config, network, and mounts.
    Use this for deep container investigation.

    Args:
        host: The hostname or IP address of the server
        container: Container name or ID
    """
    logger.info("Inspecting Docker container", host=host, container=container)
    command = f"""
    echo "=== Container Status ==="
    docker inspect {container} --format 'Status: {{{{.State.Status}}}}
Running: {{{{.State.Running}}}}
Restarting: {{{{.State.Restarting}}}}
OOMKilled: {{{{.State.OOMKilled}}}}
ExitCode: {{{{.State.ExitCode}}}}' 2>/dev/null || echo "Container not found"
    echo ""
    echo "=== Resource Limits ==="
    docker inspect {container} --format 'Memory Limit: {{{{.HostConfig.Memory}}}}
CPU Shares: {{{{.HostConfig.CpuShares}}}}' 2>/dev/null
    echo ""
    echo "=== Network ==="
    docker inspect {container} --format '{{{{range .NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}' 2>/dev/null
    echo ""
    echo "=== Mounts ==="
    docker inspect {container} --format '{{{{range .Mounts}}}}{{{{.Source}}}} -> {{{{.Destination}}}}{{{{end}}}}' 2>/dev/null
    """
    return _run_async(_ssh_exec(host, command))


# ============================================================================
# LOG TOOLS
# ============================================================================

@tool("Check Error Logs")
def check_error_logs(host: str, service: str = "") -> str:
    """
    Search for recent errors in system and service logs.
    Use this to find error patterns and recent failures.

    Args:
        host: The hostname or IP address of the server
        service: Optional service name to filter logs
    """
    logger.info("Checking error logs", host=host, service=service)
    if service:
        command = f"""
        echo "=== Errors in {service} logs (last 1 hour) ==="
        journalctl -u {service} -p err --since "1 hour ago" --no-pager 2>/dev/null | tail -50 || echo "No journalctl errors"
        """
    else:
        command = """
        echo "=== System Errors (last 1 hour) ==="
        journalctl -p err --since "1 hour ago" --no-pager 2>/dev/null | tail -50 || echo "No journalctl errors"
        echo ""
        echo "=== Syslog Errors ==="
        grep -i 'error\|fail\|exception\|critical' /var/log/syslog 2>/dev/null | tail -30 || grep -i 'error\|fail\|exception\|critical' /var/log/messages 2>/dev/null | tail -30 || echo "No syslog errors found"
        """
    return _run_async(_ssh_exec(host, command))


@tool("Check Dmesg Logs")
def check_dmesg(host: str) -> str:
    """
    Check kernel ring buffer for hardware errors, OOM kills, and system issues.
    Use this for hardware-related issues or kernel-level problems.

    Args:
        host: The hostname or IP address of the server
    """
    logger.info("Checking dmesg", host=host)
    command = """
    echo "=== Recent Kernel Messages ==="
    dmesg -T 2>/dev/null | tail -50 || dmesg | tail -50
    echo ""
    echo "=== OOM Killer Events ==="
    dmesg -T 2>/dev/null | grep -i 'oom\|killed process' | tail -10 || echo "No OOM events found"
    echo ""
    echo "=== Hardware Errors ==="
    dmesg -T 2>/dev/null | grep -i 'error\|fail\|warn' | tail -20 || echo "No hardware errors found"
    """
    return _run_async(_ssh_exec(host, command))


@tool("Check Application Log File")
def check_log_file(host: str, log_path: str, lines: int = 100) -> str:
    """
    Read a specific log file on the server.
    Use this for application-specific logs not managed by systemd.

    Args:
        host: The hostname or IP address of the server
        log_path: Full path to the log file (e.g., '/var/log/nginx/error.log')
        lines: Number of lines to retrieve (default 100)
    """
    logger.info("Checking log file", host=host, log_path=log_path)
    command = f"""
    echo "=== Log File: {log_path} ==="
    if [ -f "{log_path}" ]; then
        echo "Size: $(ls -lh {log_path} | awk '{{print $5}}')"
        echo "Modified: $(stat -c %y {log_path} 2>/dev/null || stat -f %Sm {log_path})"
        echo ""
        tail -n {lines} {log_path}
    else
        echo "Log file not found: {log_path}"
    fi
    """
    return _run_async(_ssh_exec(host, command))


@tool("Search Logs")
def search_logs(host: str, pattern: str, log_path: str = "/var/log") -> str:
    """
    Search for a pattern in log files.
    Use this to find specific errors or events across logs.

    Args:
        host: The hostname or IP address of the server
        pattern: Search pattern (grep regex)
        log_path: Directory or file to search (default /var/log)
    """
    logger.info("Searching logs", host=host, pattern=pattern)
    command = f"""
    echo "=== Searching for '{pattern}' in {log_path} ==="
    grep -r -i '{pattern}' {log_path} 2>/dev/null | tail -50 || echo "No matches found"
    """
    return _run_async(_ssh_exec(host, command))


# ============================================================================
# APPLICATION TOOLS
# ============================================================================

@tool("Check HTTP Endpoint")
def check_http_endpoint(host: str, url: str, port: int = 80) -> str:
    """
    Check an HTTP endpoint health and response.
    Use this to verify application health endpoints or API availability.

    Args:
        host: The hostname or IP address of the server
        url: The URL path to check (e.g., '/health', '/api/status')
        port: The port number (default 80)
    """
    logger.info("Checking HTTP endpoint", host=host, url=url, port=port)
    command = f"""
    echo "=== HTTP Check: localhost:{port}{url} ==="
    curl -s -o /dev/null -w "HTTP Status: %{{http_code}}\\nTime Total: %{{time_total}}s\\nTime Connect: %{{time_connect}}s\\n" http://localhost:{port}{url} 2>/dev/null || echo "Curl failed"
    echo ""
    echo "=== Response Body ==="
    curl -s http://localhost:{port}{url} 2>/dev/null | head -50 || echo "No response"
    """
    return _run_async(_ssh_exec(host, command))


@tool("Check JVM Stats")
def check_jvm(host: str, process_pattern: str = "java") -> str:
    """
    Check JVM heap, garbage collection, and thread stats for Java applications.
    Use this for Java application performance issues.

    Args:
        host: The hostname or IP address of the server
        process_pattern: Pattern to find Java process (default 'java')
    """
    logger.info("Checking JVM", host=host)
    command = f"""
    echo "=== Java Processes ==="
    ps aux | grep -E '{process_pattern}' | grep -v grep | head -5
    echo ""
    PID=$(pgrep -f '{process_pattern}' | head -1)
    if [ -n "$PID" ]; then
        echo "=== JVM Memory (PID: $PID) ==="
        jstat -gc $PID 2>/dev/null || echo "jstat not available"
        echo ""
        echo "=== JVM Threads ==="
        jstack $PID 2>/dev/null | grep -E "^\"" | wc -l || echo "jstack not available"
    else
        echo "No Java process found matching '{process_pattern}'"
    fi
    """
    return _run_async(_ssh_exec(host, command))


@tool("Check Node.js App")
def check_nodejs(host: str, port: int = 3000) -> str:
    """
    Check Node.js application status and metrics.
    Use this for Node.js application issues.

    Args:
        host: The hostname or IP address of the server
        port: The port the app is running on (default 3000)
    """
    logger.info("Checking Node.js", host=host, port=port)
    command = f"""
    echo "=== Node.js Processes ==="
    ps aux | grep -E 'node|npm' | grep -v grep
    echo ""
    echo "=== Node.js Memory ==="
    ps -o pid,rss,vsz,cmd -C node 2>/dev/null || echo "No node processes"
    echo ""
    echo "=== Health Check (port {port}) ==="
    curl -s http://localhost:{port}/health 2>/dev/null || curl -s http://localhost:{port}/ 2>/dev/null | head -10 || echo "Cannot connect to port {port}"
    """
    return _run_async(_ssh_exec(host, command))


# ============================================================================
# FILESYSTEM TOOLS
# ============================================================================

@tool("Find Large Files")
def find_large_files(host: str, path: str = "/", min_size: str = "100M") -> str:
    """
    Find large files consuming disk space.
    Use this when investigating disk space issues.

    Args:
        host: The hostname or IP address of the server
        path: Directory to search (default '/')
        min_size: Minimum file size (default '100M')
    """
    logger.info("Finding large files", host=host, path=path)
    command = f"""
    echo "=== Large Files (>{min_size}) in {path} ==="
    find {path} -type f -size +{min_size} -exec ls -lh {{}} \\; 2>/dev/null | sort -k5 -hr | head -20 || echo "No large files found"
    echo ""
    echo "=== Directory Sizes ==="
    du -sh {path}/* 2>/dev/null | sort -hr | head -15 || echo "Cannot check directory sizes"
    """
    return _run_async(_ssh_exec(host, command))


@tool("Check Open Files")
def check_open_files(host: str, process: str = "") -> str:
    """
    Check open files and file descriptors.
    Use this for 'too many open files' errors or file descriptor leaks.

    Args:
        host: The hostname or IP address of the server
        process: Optional process name to filter
    """
    logger.info("Checking open files", host=host)
    if process:
        command = f"""
        echo "=== Open Files for '{process}' ==="
        PID=$(pgrep -f '{process}' | head -1)
        if [ -n "$PID" ]; then
            echo "PID: $PID"
            ls -l /proc/$PID/fd 2>/dev/null | wc -l
            echo ""
            echo "=== File Types ==="
            ls -l /proc/$PID/fd 2>/dev/null | awk '{{print $NF}}' | sed 's/.*://' | sort | uniq -c | sort -rn | head -10
        else
            echo "Process not found"
        fi
        """
    else:
        command = """
        echo "=== System-wide Open Files ==="
        cat /proc/sys/fs/file-nr
        echo ""
        echo "=== Top Processes by Open Files ==="
        for pid in $(ls /proc | grep -E '^[0-9]+$' | head -50); do
            count=$(ls /proc/$pid/fd 2>/dev/null | wc -l)
            name=$(cat /proc/$pid/comm 2>/dev/null)
            [ "$count" -gt 100 ] && echo "$count $name ($pid)"
        done | sort -rn | head -10
        """
    return _run_async(_ssh_exec(host, command))


# ============================================================================
# NETWORK TOOLS
# ============================================================================

@tool("Check TCP Connections")
def check_tcp_connections(host: str, port: int = 0) -> str:
    """
    Check TCP connection states and counts.
    Use this for connection-related issues or connection leaks.

    Args:
        host: The hostname or IP address of the server
        port: Optional port to filter (0 for all ports)
    """
    logger.info("Checking TCP connections", host=host, port=port)
    if port > 0:
        command = f"""
        echo "=== TCP Connections on Port {port} ==="
        ss -tan 'sport = :{port} or dport = :{port}' 2>/dev/null | head -30 || netstat -tan | grep ':{port}' | head -30
        echo ""
        echo "=== Connection States ==="
        ss -tan 'sport = :{port} or dport = :{port}' 2>/dev/null | awk '{{print $1}}' | sort | uniq -c | sort -rn || echo "Cannot get states"
        """
    else:
        command = """
        echo "=== TCP Connection States ==="
        ss -tan 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn || netstat -tan | awk '{print $6}' | sort | uniq -c | sort -rn
        echo ""
        echo "=== Connections by Port ==="
        ss -tan 2>/dev/null | awk '{print $4}' | grep -oE ':[0-9]+$' | sort | uniq -c | sort -rn | head -10
        """
    return _run_async(_ssh_exec(host, command))


@tool("Check DNS Resolution")
def check_dns(host: str, domain: str) -> str:
    """
    Check DNS resolution for a domain.
    Use this for DNS-related connectivity issues.

    Args:
        host: The hostname or IP address of the server
        domain: Domain name to resolve
    """
    logger.info("Checking DNS", host=host, domain=domain)
    command = f"""
    echo "=== DNS Resolution for {domain} ==="
    nslookup {domain} 2>/dev/null || dig {domain} 2>/dev/null || host {domain} 2>/dev/null || echo "DNS tools not available"
    echo ""
    echo "=== DNS Servers ==="
    cat /etc/resolv.conf | grep nameserver
    """
    return _run_async(_ssh_exec(host, command))


@tool("Check Port Connectivity")
def check_port(host: str, target_host: str, port: int) -> str:
    """
    Check if a port is reachable from the server.
    Use this for connectivity troubleshooting.

    Args:
        host: The hostname or IP address of the server to run the check from
        target_host: The target hostname or IP to connect to
        port: The port to check
    """
    logger.info("Checking port connectivity", host=host, target=target_host, port=port)
    command = f"""
    echo "=== Port Check: {target_host}:{port} ==="
    timeout 5 bash -c 'cat < /dev/null > /dev/tcp/{target_host}/{port}' 2>/dev/null && echo "Port {port} is OPEN" || echo "Port {port} is CLOSED or unreachable"
    echo ""
    echo "=== Traceroute ==="
    traceroute -n -m 10 {target_host} 2>/dev/null || echo "traceroute not available"
    """
    return _run_async(_ssh_exec(host, command))


# ============================================================================
# SECURITY TOOLS
# ============================================================================

@tool("Check Failed Logins")
def check_failed_logins(host: str) -> str:
    """
    Check for failed login attempts and security events.
    Use this for security investigation.

    Args:
        host: The hostname or IP address of the server
    """
    logger.info("Checking failed logins", host=host)
    command = """
    echo "=== Failed Login Attempts ==="
    grep -i 'failed\|failure' /var/log/auth.log 2>/dev/null | tail -20 || grep -i 'failed\|failure' /var/log/secure 2>/dev/null | tail -20 || echo "No auth logs found"
    echo ""
    echo "=== Recent SSH Logins ==="
    last -10 2>/dev/null || echo "Cannot get login history"
    echo ""
    echo "=== Currently Logged In ==="
    who
    """
    return _run_async(_ssh_exec(host, command))


@tool("Check Firewall Rules")
def check_firewall(host: str) -> str:
    """
    Check firewall rules and status.
    Use this for network connectivity issues that might be firewall-related.

    Args:
        host: The hostname or IP address of the server
    """
    logger.info("Checking firewall", host=host)
    command = """
    echo "=== IPTables Rules ==="
    iptables -L -n 2>/dev/null | head -30 || echo "iptables not available"
    echo ""
    echo "=== UFW Status ==="
    ufw status 2>/dev/null || echo "ufw not available"
    echo ""
    echo "=== Firewalld Status ==="
    firewall-cmd --list-all 2>/dev/null || echo "firewalld not available"
    """
    return _run_async(_ssh_exec(host, command))


# ============================================================================
# PERFORMANCE TOOLS
# ============================================================================

@tool("Check IO Stats")
def check_io_stats(host: str) -> str:
    """
    Check disk I/O statistics and wait times.
    Use this for I/O performance issues or high iowait.

    Args:
        host: The hostname or IP address of the server
    """
    logger.info("Checking IO stats", host=host)
    command = """
    echo "=== IO Statistics ==="
    iostat -x 1 3 2>/dev/null | tail -30 || echo "iostat not available"
    echo ""
    echo "=== IO Wait ==="
    vmstat 1 3 2>/dev/null || echo "vmstat not available"
    echo ""
    echo "=== Top IO Processes ==="
    iotop -b -n 1 2>/dev/null | head -15 || echo "iotop not available"
    """
    return _run_async(_ssh_exec(host, command))


@tool("Check Swap Usage")
def check_swap(host: str) -> str:
    """
    Check swap usage and swappiness.
    Use this for memory pressure issues.

    Args:
        host: The hostname or IP address of the server
    """
    logger.info("Checking swap", host=host)
    command = """
    echo "=== Swap Usage ==="
    free -h
    echo ""
    echo "=== Swap Details ==="
    swapon --show 2>/dev/null || cat /proc/swaps
    echo ""
    echo "=== Swappiness ==="
    cat /proc/sys/vm/swappiness
    echo ""
    echo "=== Top Swap Consumers ==="
    for pid in $(ls /proc | grep -E '^[0-9]+$'); do
        swap=$(awk '/VmSwap/{print $2}' /proc/$pid/status 2>/dev/null)
        name=$(cat /proc/$pid/comm 2>/dev/null)
        [ -n "$swap" ] && [ "$swap" -gt 1000 ] && echo "$swap kB $name ($pid)"
    done | sort -rn | head -10
    """
    return _run_async(_ssh_exec(host, command))


# ============================================================================
# GENERIC COMMAND TOOL
# ============================================================================

@tool("Run Custom Command")
def run_command(host: str, command: str) -> str:
    """
    Execute any custom SSH command on a server.
    Use this for any investigation not covered by other tools.

    Args:
        host: The hostname or IP address of the server
        command: The command to execute
    """
    logger.info("Running custom command", host=host, command=command[:50])
    return _run_async(_ssh_exec(host, command))


# ============================================================================
# TOOL LIST
# ============================================================================

# All investigation tools for CrewAI agents - AI decides which to use
CREWAI_INVESTIGATION_TOOLS = [
    # System
    check_system_overview,
    check_cpu_usage,
    check_memory,
    check_disk,
    check_processes,
    check_recent_changes,

    # Services
    check_service_status,
    check_logs,

    # Network
    check_network,
    check_tcp_connections,
    check_dns,
    check_port,
    check_firewall,

    # Docker
    check_docker_containers,
    check_docker_logs,
    check_docker_inspect,

    # Databases
    check_postgresql,
    check_mongodb,
    check_mysql,
    check_redis,

    # Logs
    check_error_logs,
    check_dmesg,
    check_log_file,
    search_logs,

    # Applications
    check_http_endpoint,
    check_jvm,
    check_nodejs,

    # Filesystem
    find_large_files,
    check_open_files,

    # Performance
    check_io_stats,
    check_swap,

    # Security
    check_failed_logins,

    # Generic
    run_command,
]
