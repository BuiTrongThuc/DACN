"""Firewall blocking adapter with dry-run support."""

import subprocess
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address


@dataclass(frozen=True, slots=True)
class BlockResult:
    blocked: bool
    command: tuple[str, ...]
    message: str


class IPBlocker:
    def __init__(
        self,
        *,
        command_template: tuple[str, ...] | list[str],
        rollback_command_template: tuple[str, ...] | list[str] | None = None,
        dry_run: bool = True,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not command_template:
            raise ValueError("command_template cannot be empty")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        self._command_template = tuple(command_template)
        self._rollback_command_template = (
            tuple(rollback_command_template) if rollback_command_template else None
        )
        self._dry_run = dry_run
        self._timeout_seconds = timeout_seconds

    def block(self, address: IPv4Address | IPv6Address) -> BlockResult:
        command = tuple(part.replace("{ip}", str(address)) for part in self._command_template)
        if any("{ip}" in part for part in command):
            raise ValueError("Invalid firewall command template")
        if self._dry_run:
            return BlockResult(False, command, "dry-run: firewall command not executed")

        completed = subprocess.run(
            list(command),
            check=True,
            capture_output=True,
            text=True,
            timeout=self._timeout_seconds,
        )
        message = completed.stdout.strip() or "firewall command completed"
        return BlockResult(True, command, message)

    def rollback(self, address: IPv4Address | IPv6Address) -> BlockResult:
        if self._rollback_command_template is None:
            raise ValueError("rollback command template is not configured")
        command = tuple(
            part.replace("{ip}", str(address)) for part in self._rollback_command_template
        )
        if any("{ip}" in part for part in command):
            raise ValueError("Invalid rollback command template")
        if self._dry_run:
            return BlockResult(False, command, "dry-run: rollback command not executed")
        completed = subprocess.run(
            list(command),
            check=True,
            capture_output=True,
            text=True,
            timeout=self._timeout_seconds,
        )
        message = completed.stdout.strip() or "rollback command completed"
        return BlockResult(True, command, message)
