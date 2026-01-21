"""SSH client for remote server execution."""

import asyncio
from pathlib import Path
from typing import Optional, Tuple

import asyncssh
import structlog

from src.config import Settings, SSHConfig


logger = structlog.get_logger()


class SSHExecutionError(Exception):
    """Exception raised when SSH command execution fails."""

    def __init__(self, host: str, command: str, exit_code: int, stderr: str):
        self.host = host
        self.command = command
        self.exit_code = exit_code
        self.stderr = stderr
        super().__init__(f"SSH command failed on {host}: {stderr}")


class SSHClient:
    """
    Async SSH client for executing commands on remote servers.

    Uses asyncssh for non-blocking operations.
    """

    def __init__(self, config: SSHConfig):
        self._config = config
        self._connections: dict = {}
        self._lock = asyncio.Lock()

    @property
    def private_key_path(self) -> Path:
        """Get the expanded private key path."""
        return Path(self._config.private_key_path).expanduser()

    async def connect(self, host: str, port: Optional[int] = None) -> asyncssh.SSHClientConnection:
        """
        Get or create an SSH connection to a host.

        Connections are cached for reuse.
        """
        port = port or self._config.port
        key = f"{host}:{port}"

        async with self._lock:
            # Check for existing connection
            if key in self._connections:
                conn = self._connections[key]
                # Verify connection is still alive
                try:
                    # Simple check - will fail if disconnected
                    await conn.run("echo ping", check=True, timeout=5)
                    return conn
                except Exception:
                    # Connection dead, remove it
                    del self._connections[key]

            # Create new connection
            logger.debug(
                "Creating SSH connection",
                host=host,
                port=port,
                username=self._config.username,
            )

            try:
                conn = await asyncssh.connect(
                    host=host,
                    port=port,
                    username=self._config.username,
                    client_keys=[str(self.private_key_path)],
                    known_hosts=str(Path(self._config.known_hosts_path).expanduser()),
                    connect_timeout=self._config.timeout_seconds,
                )
                self._connections[key] = conn
                return conn

            except asyncssh.DisconnectError as e:
                logger.error(
                    "SSH connection failed",
                    host=host,
                    port=port,
                    error=str(e),
                )
                raise
            except Exception as e:
                logger.error(
                    "SSH connection error",
                    host=host,
                    port=port,
                    error=str(e),
                )
                raise

    async def execute(
        self,
        host: str,
        command: str,
        timeout: Optional[int] = None,
        check: bool = False,
    ) -> Tuple[str, str, int]:
        """
        Execute a command on a remote host.

        Args:
            host: Target hostname or IP
            command: Command to execute
            timeout: Command timeout in seconds
            check: If True, raise exception on non-zero exit code

        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        timeout = timeout or self._config.timeout_seconds

        logger.debug(
            "Executing SSH command",
            host=host,
            command=command[:100],  # Truncate for logging
        )

        try:
            conn = await self.connect(host)
            result = await conn.run(
                command,
                timeout=timeout,
                check=False,  # We'll check manually
            )

            stdout = result.stdout or ""
            stderr = result.stderr or ""
            exit_code = result.exit_status or 0

            logger.debug(
                "SSH command completed",
                host=host,
                exit_code=exit_code,
                stdout_length=len(stdout),
                stderr_length=len(stderr),
            )

            if check and exit_code != 0:
                raise SSHExecutionError(host, command, exit_code, stderr)

            return stdout, stderr, exit_code

        except asyncssh.TimeoutError:
            logger.error(
                "SSH command timeout",
                host=host,
                command=command[:100],
                timeout=timeout,
            )
            raise SSHExecutionError(host, command, -1, f"Command timed out after {timeout}s")

        except SSHExecutionError:
            raise

        except Exception as e:
            logger.error(
                "SSH execution error",
                host=host,
                command=command[:100],
                error=str(e),
            )
            raise SSHExecutionError(host, command, -1, str(e))

    async def execute_simple(self, host: str, command: str) -> str:
        """
        Execute a command and return stdout only.

        Useful for simple queries where you just want the output.
        """
        stdout, stderr, exit_code = await self.execute(host, command)

        if exit_code != 0:
            # Include stderr in output for diagnostic commands
            return f"{stdout}\n[Exit code: {exit_code}]\n{stderr}".strip()

        return stdout.strip()

    async def close(self, host: Optional[str] = None):
        """
        Close SSH connections.

        If host is specified, close only that connection.
        Otherwise, close all connections.
        """
        async with self._lock:
            if host:
                # Close specific connection
                for key, conn in list(self._connections.items()):
                    if key.startswith(f"{host}:"):
                        conn.close()
                        del self._connections[key]
            else:
                # Close all connections
                for conn in self._connections.values():
                    conn.close()
                self._connections.clear()

    async def test_connection(self, host: str) -> bool:
        """Test if we can connect to a host."""
        try:
            await self.execute(host, "echo ok", timeout=10)
            return True
        except Exception:
            return False


# Global SSH client instance
_ssh_client: Optional[SSHClient] = None


def get_ssh_client(settings: Optional[Settings] = None) -> SSHClient:
    """Get the global SSH client instance."""
    global _ssh_client
    if _ssh_client is None:
        if settings is None:
            from src.config import get_settings
            settings = get_settings()
        _ssh_client = SSHClient(settings.ssh)
    return _ssh_client


async def ssh_exec(host: str, command: str) -> str:
    """Convenience function to execute a command via SSH."""
    client = get_ssh_client()
    return await client.execute_simple(host, command)
