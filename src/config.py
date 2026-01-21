"""Configuration management for DevOps On-Call Agent."""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class ServerConfig(BaseModel):
    """Configuration for a monitored server."""
    hostname: str
    ip: str
    role: str = "general"
    services: List[str] = Field(default_factory=list)
    tags: Dict[str, str] = Field(default_factory=dict)


class NvidiaConfig(BaseModel):
    """NVIDIA NIM configuration."""
    base_url: str = "https://integrate.api.nvidia.com/v1"
    model: str = "meta/llama-3.1-70b-instruct"
    api_key: str = ""
    timeout: int = 60
    max_tokens: int = 4096
    temperature: float = 0.3


class SSHConfig(BaseModel):
    """SSH configuration for server access."""
    private_key_path: str = "~/.ssh/id_rsa"
    username: str = "devops-agent"
    timeout_seconds: int = 30
    known_hosts_path: str = "~/.ssh/known_hosts"
    port: int = 22


class ApprovalConfig(BaseModel):
    """Approval workflow configuration."""
    auto_approve_risk_levels: List[str] = Field(default_factory=lambda: ["low"])
    require_approval_risk_levels: List[str] = Field(
        default_factory=lambda: ["medium", "high", "critical"]
    )
    slack_webhook_url: str = ""
    slack_bot_token: str = ""
    slack_channel: str = "#oncall-approvals"
    approval_timeout_minutes: int = 5
    escalation_timeout_minutes: int = 10


class ProcessingConfig(BaseModel):
    """Alert processing configuration."""
    dedup_window_seconds: int = 300
    correlation_window_seconds: int = 600
    max_queue_size: int = 1000


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = "INFO"
    format: str = "json"
    audit_log_path: str = "/var/log/devops-agent/audit.log"


class ServerSettings(BaseModel):
    """HTTP server settings."""
    host: str = "0.0.0.0"
    port: int = 8080
    workers: int = 4


class Settings(BaseSettings):
    """Main application settings."""

    # Server
    server: ServerSettings = Field(default_factory=ServerSettings)

    # NVIDIA NIM
    nvidia_environment: str = "development"
    nvidia_api_key: str = ""
    nvidia_development: NvidiaConfig = Field(default_factory=NvidiaConfig)
    nvidia_production: NvidiaConfig = Field(default_factory=lambda: NvidiaConfig(
        base_url="http://localhost:8000/v1"
    ))

    # SSH
    ssh: SSHConfig = Field(default_factory=SSHConfig)

    # Approval
    approval: ApprovalConfig = Field(default_factory=ApprovalConfig)

    # Processing
    processing: ProcessingConfig = Field(default_factory=ProcessingConfig)

    # Logging
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    # Redis (optional)
    redis_url: Optional[str] = None

    # Server inventory
    servers: List[ServerConfig] = Field(default_factory=list)

    class Config:
        env_prefix = "DEVOPS_AGENT_"
        env_nested_delimiter = "__"

    @property
    def nvidia(self) -> NvidiaConfig:
        """Get the active NVIDIA configuration based on environment."""
        if self.nvidia_environment == "production":
            config = self.nvidia_production
        else:
            config = self.nvidia_development

        # Override API key from environment if set
        if self.nvidia_api_key:
            config.api_key = self.nvidia_api_key

        return config

    def get_server_by_hostname(self, hostname: str) -> Optional[ServerConfig]:
        """Find a server by hostname."""
        for server in self.servers:
            if server.hostname == hostname or server.ip == hostname:
                return server
        return None

    def get_servers_by_role(self, role: str) -> List[ServerConfig]:
        """Get all servers with a specific role."""
        return [s for s in self.servers if s.role == role]

    def get_servers_by_tag(self, key: str, value: str) -> List[ServerConfig]:
        """Get all servers with a specific tag."""
        return [s for s in self.servers if s.tags.get(key) == value]


def load_yaml_config(path: str) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    path = Path(path).expanduser()
    if not path.exists():
        return {}

    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def load_server_inventory(path: str) -> List[ServerConfig]:
    """Load server inventory from YAML file."""
    data = load_yaml_config(path)
    servers = data.get("servers", [])
    return [ServerConfig(**s) for s in servers]


def load_settings(config_path: Optional[str] = None) -> Settings:
    """
    Load settings from configuration file and environment variables.

    Priority (highest to lowest):
    1. Environment variables
    2. Config file
    3. Default values
    """
    # Determine config path
    if config_path is None:
        config_path = os.environ.get(
            "DEVOPS_AGENT_CONFIG_PATH",
            "config/config.yaml"
        )

    # Load YAML config
    yaml_config = load_yaml_config(config_path)

    # Build settings dict
    settings_dict = {}

    # Server settings
    if "server" in yaml_config:
        settings_dict["server"] = ServerSettings(**yaml_config["server"])

    # NVIDIA settings
    if "nvidia" in yaml_config:
        nvidia_config = yaml_config["nvidia"]
        settings_dict["nvidia_environment"] = nvidia_config.get("environment", "development")

        if "development" in nvidia_config:
            settings_dict["nvidia_development"] = NvidiaConfig(**nvidia_config["development"])
        if "production" in nvidia_config:
            settings_dict["nvidia_production"] = NvidiaConfig(**nvidia_config["production"])

    # SSH settings
    if "ssh" in yaml_config:
        settings_dict["ssh"] = SSHConfig(**yaml_config["ssh"])

    # Approval settings
    if "approval" in yaml_config:
        settings_dict["approval"] = ApprovalConfig(**yaml_config["approval"])

    # Processing settings
    if "processing" in yaml_config:
        settings_dict["processing"] = ProcessingConfig(**yaml_config["processing"])

    # Logging settings
    if "logging" in yaml_config:
        settings_dict["logging"] = LoggingConfig(**yaml_config["logging"])

    # Redis
    if "redis" in yaml_config:
        settings_dict["redis_url"] = yaml_config["redis"].get("url")

    # Load server inventory
    inventory_config = yaml_config.get("inventory", {})
    if inventory_config.get("type") == "file":
        inventory_path = inventory_config.get("path", "config/servers.yaml")
        settings_dict["servers"] = load_server_inventory(inventory_path)

    # Create settings (environment variables will override)
    settings = Settings(**settings_dict)

    # Override API keys from environment
    nvidia_api_key = os.environ.get("NVIDIA_API_KEY", "")
    if nvidia_api_key:
        settings.nvidia_api_key = nvidia_api_key

    slack_webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if slack_webhook_url:
        settings.approval.slack_webhook_url = slack_webhook_url

    slack_bot_token = os.environ.get("SLACK_BOT_TOKEN", "")
    if slack_bot_token:
        settings.approval.slack_bot_token = slack_bot_token

    # Override SSH settings from environment
    ssh_key_path = os.environ.get("SSH_KEY_PATH", "")
    if ssh_key_path:
        settings.ssh.private_key_path = ssh_key_path

    ssh_username = os.environ.get("SSH_USERNAME", "")
    if ssh_username:
        settings.ssh.username = ssh_username

    ssh_known_hosts = os.environ.get("SSH_KNOWN_HOSTS", "")
    if ssh_known_hosts:
        settings.ssh.known_hosts_path = ssh_known_hosts

    return settings


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get the global settings instance."""
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def reset_settings():
    """Reset the global settings instance (for testing)."""
    global _settings
    _settings = None
