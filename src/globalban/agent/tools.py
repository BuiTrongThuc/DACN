"""Allowlisted tool registry for the AI agent.

Tool handlers are registered by trusted application code. User/LLM input can
select a name and arguments, but cannot import modules or execute shell text.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    description: str
    requires_approval: bool


@dataclass(frozen=True, slots=True)
class ToolResult:
    tool: str
    ok: bool
    output: Any
    error: str | None = None


class ToolRegistry:
    def __init__(self) -> None:
        self._handlers: dict[str, tuple[ToolSpec, Callable[..., Any]]] = {}

    def register(
        self,
        spec: ToolSpec,
        handler: Callable[..., Any],
    ) -> None:
        if spec.name in self._handlers:
            raise ValueError(f"tool already registered: {spec.name}")
        self._handlers[spec.name] = (spec, handler)

    def specs(self) -> tuple[ToolSpec, ...]:
        return tuple(spec for spec, _ in self._handlers.values())

    def invoke(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        approved: bool = False,
    ) -> ToolResult:
        registered = self._handlers.get(name)
        if registered is None:
            return ToolResult(name, False, None, "tool is not allowlisted")
        spec, handler = registered
        if spec.requires_approval and not approved:
            return ToolResult(name, False, None, "explicit approval is required")
        try:
            return ToolResult(name, True, handler(**dict(arguments)))
        except (TypeError, ValueError, PermissionError, RuntimeError) as exc:
            return ToolResult(name, False, None, str(exc))


TOOL_SPECS = (
    ToolSpec("log_ingestion_parser", "Collect and normalize Windows Event XML", False),
    ToolSpec("process_monitor", "Build parent-child process observations", False),
    ToolSpec("security_event_collector", "Collect configured security channels", False),
    ToolSpec("behavioral_context_builder", "Build time and entity context", False),
    ToolSpec("anomaly_detection_engine", "Run rules, baseline, and sequence detection", False),
    ToolSpec("threat_intelligence_lookup", "Look up an indicator when explicitly enabled", False),
    ToolSpec("privacy_masking_proxy", "Validate minimized outbound payloads", False),
    ToolSpec("ai_decision_engine", "Return structured evidence-based advisory", False),
    ToolSpec("policy_gate", "Apply allowlist, score, and approval policy", False),
    ToolSpec("action_enforcer", "Execute an already approved defensive action", True),
    ToolSpec("audit_rollback_manager", "Record TTL and perform approved rollback", True),
    ToolSpec("evaluation_reporting", "Calculate labeled detection metrics", False),
)


def empty_registry() -> ToolRegistry:
    """Return a catalog-only registry until trusted handlers are wired by main."""
    def not_wired(**_: Any) -> None:
        raise RuntimeError("tool handler is not wired")

    registry = ToolRegistry()
    for spec in TOOL_SPECS:
        registry.register(spec, not_wired)
    return registry