"""Configuration loading and validation."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True, slots=True)
class IngestionConfig:
    log_path: str = "/var/log/auth.log"
    poll_interval_seconds: float = 1.0
    source: str = "file"
    log_names: tuple[str, ...] = (
        "Security",
        "System",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-Windows Defender/Operational",
    )


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    window_seconds: int = 300
    failed_attempt_threshold: int = 5
    baseline_path: str | None = "globalban-baseline.json"
    baseline_warmup_events: int = 20
    behavior_state_path: str | None = "globalban-behavior-state.json"


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    allowlist: tuple[str, ...] = ("127.0.0.1", "::1")
    block_private_addresses: bool = True


@dataclass(frozen=True, slots=True)
class ActionsConfig:
    dry_run: bool = True
    firewall_command: tuple[str, ...] = (
        "iptables", "-I", "INPUT", "-s", "{ip}", "-j", "DROP"
    )
    rollback_command: tuple[str, ...] = (
        "iptables", "-D", "INPUT", "-s", "{ip}", "-j", "DROP"
    )


@dataclass(frozen=True, slots=True)
class AuditConfig:
    path: str = "globalban-audit.jsonl"


@dataclass(frozen=True, slots=True)
class AIConfig:
    enabled: bool = False
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o-mini"


@dataclass(frozen=True, slots=True)
class NotificationsConfig:
    whatsapp_enabled: bool = False


@dataclass(frozen=True, slots=True)
class AppConfig:
    ingestion: IngestionConfig = field(default_factory=IngestionConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    actions: ActionsConfig = field(default_factory=ActionsConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ValueError(f"Configuration section '{name}' must be a mapping")
    return value


def load_config(path: str | Path) -> AppConfig:
    """Load YAML configuration, validating values rather than silently defaulting."""
    with Path(path).open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        raise ValueError("Configuration root must be a mapping")

    ingestion = _section(data, "ingestion")
    detection = _section(data, "detection")
    policy = _section(data, "policy")
    actions = _section(data, "actions")
    audit = _section(data, "audit")
    ai = _section(data, "ai")
    notifications = _section(data, "notifications")

    config = AppConfig(
        ingestion=IngestionConfig(
            log_path=str(ingestion.get("log_path", "/var/log/auth.log")),
            poll_interval_seconds=float(ingestion.get("poll_interval_seconds", 1.0)),
            source=str(ingestion.get("source", "file")),
            log_names=_string_tuple(
                ingestion.get(
                    "log_names",
                    (
                        "Security",
                        "System",
                        "Microsoft-Windows-PowerShell/Operational",
                        "Microsoft-Windows-Sysmon/Operational",
                        "Microsoft-Windows-Windows Defender/Operational",
                    ),
                ),
                "ingestion.log_names",
            ),
        ),
        detection=DetectionConfig(
            window_seconds=int(detection.get("window_seconds", 300)),
            failed_attempt_threshold=int(detection.get("failed_attempt_threshold", 5)),
            baseline_path=(
                str(detection["baseline_path"])
                if detection.get("baseline_path")
                else None
            ),
            baseline_warmup_events=int(detection.get("baseline_warmup_events", 20)),
            behavior_state_path=(
                str(detection["behavior_state_path"])
                if detection.get("behavior_state_path")
                else None
            ),
        ),
        policy=PolicyConfig(
            allowlist=tuple(policy.get("allowlist", ("127.0.0.1", "::1"))),
            block_private_addresses=bool(policy.get("block_private_addresses", True)),
        ),
        actions=ActionsConfig(
            dry_run=bool(actions.get("dry_run", True)),
            firewall_command=_string_tuple(
                actions.get(
                    "firewall_command",
                    ("iptables", "-I", "INPUT", "-s", "{ip}", "-j", "DROP"),
                ),
                "actions.firewall_command",
            ),
            rollback_command=_string_tuple(
                actions.get(
                    "rollback_command",
                    ("iptables", "-D", "INPUT", "-s", "{ip}", "-j", "DROP"),
                ),
                "actions.rollback_command",
            ),
        ),
        audit=AuditConfig(path=str(audit.get("path", "globalban-audit.jsonl"))),
        ai=AIConfig(
            enabled=bool(ai.get("enabled", False)),
            base_url=str(ai.get("base_url", "https://api.openai.com/v1")),
            model=str(ai.get("model", "gpt-4o-mini")),
        ),
        notifications=NotificationsConfig(
            whatsapp_enabled=bool(notifications.get("whatsapp_enabled", False))
        ),
    )
    if config.ingestion.poll_interval_seconds <= 0:
        raise ValueError("ingestion.poll_interval_seconds must be greater than zero")
    if config.ingestion.source not in {"file", "windows_event_log"}:
        raise ValueError("ingestion.source must be 'file' or 'windows_event_log'")
    if config.detection.window_seconds <= 0:
        raise ValueError("detection.window_seconds must be greater than zero")
    if config.detection.failed_attempt_threshold <= 0:
        raise ValueError("detection.failed_attempt_threshold must be greater than zero")
    if config.detection.baseline_warmup_events <= 0:
        raise ValueError("detection.baseline_warmup_events must be greater than zero")
    if not config.actions.firewall_command:
        raise ValueError("actions.firewall_command cannot be empty")
    return config


def _string_tuple(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ValueError(f"{name} must be a sequence of non-empty strings")
    return tuple(value)
